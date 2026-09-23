"""Static CAP0/HBC requirement matching; emits candidates, never verification."""
from __future__ import annotations

from typing import Literal

from pydantic import model_validator

from chipchain.domain.common import Contract
from chipchain.cross_layer.resource_binding import HardwareResourceBindingSet, Status
from chipchain.firmware.capability import FirmwareCapability, NumericConstraint, IdentityConstraint
from chipchain.firmware.static_ir import content_id
from chipchain.hardware.behavior_contract import HardwareBehaviorContract
from chipchain.hardware.resources import HardwareResourceCatalog


class CrossLayerRequirementMatch(Contract):
    match_id: str
    requirement_id: str
    matched_capability_ids: tuple[str, ...]
    resource_binding_ids: tuple[str, ...]
    static_compatibility_status: Status
    reason: str
    missing_requirements: tuple[str, ...]

    @model_validator(mode="after")
    def identity(self):
        if self.match_id != content_id("xlrequirement", self.model_dump(mode="json", exclude={"match_id"})):
            raise ValueError("Requirement match identity mismatch")
        return self


def _match(**fields) -> CrossLayerRequirementMatch:
    return CrossLayerRequirementMatch.model_validate({**fields, "match_id": content_id("xlrequirement", fields)})


class CrossLayerCandidate(Contract):
    schema_version: Literal["cross-layer-candidate/v1"] = "cross-layer-candidate/v1"
    candidate_id: str
    contract_id: str
    capability_ids: tuple[str, ...]
    binding_set_id: str
    requirements: tuple[CrossLayerRequirementMatch, ...]
    static_compatibility_status: Status
    verification_required: bool
    missing_requirements: tuple[str, ...]

    @model_validator(mode="after")
    def identity(self):
        if self.candidate_id != content_id("xlcandidate", self.model_dump(mode="json", exclude={"candidate_id"})):
            raise ValueError("Candidate identity mismatch")
        if not self.verification_required:
            raise ValueError("Static candidate always requires runtime verification")
        return self


def match_requirements(capabilities: tuple[FirmwareCapability, ...],
                       bindings: HardwareResourceBindingSet,
                       contract: HardwareBehaviorContract) -> CrossLayerCandidate:
    if any(c.architecture != contract.architecture for c in capabilities):
        raise ValueError("Capability and contract architecture differ")
    if bindings.firmware_source_id != content_id("fwcapset", sorted(c.capability_id for c in capabilities)):
        raise ValueError("Resource bindings are for a different capability set")
    by_primitive = {b.firmware_behavior_id: b for b in bindings.bindings}
    options = []
    for capability in capabilities:
        constraint_by_id = {c.constraint_id: c for c in capability.constraints}
        for primitive in capability.primitives:
            selected = [constraint_by_id[x] for x in primitive.constraint_ids]
            def exact(kind):
                return next((x.domain.exact for x in selected if isinstance(x, NumericConstraint)
                             and x.kind == kind), None)
            csr = next((x.identity for x in selected if isinstance(x, IdentityConstraint)
                        and x.kind == "CSR"), None)
            options.append((capability, primitive, exact("address"), exact("value"),
                            exact("access_width"), by_primitive.get(primitive.primitive_id), csr))
    matches = []
    access_status = []
    for condition in contract.trigger:
        if condition.condition_kind == "MMIO_access" and condition.access is not None:
            atom = condition.access
            at_address = [item for item in options if item[2] == atom.address]
            eligible = [item for item in at_address if (atom.access == "either" or
                        item[1].kind.value == f"MMIO_{atom.access.upper()}")]
            compatible = []
            conflicted = []
            unknown = []
            for item in eligible:
                cap, primitive, _, value, width, binding, csr = item
                if binding is None or binding.status not in {"SUPPORTED", "CONTRADICTED"}:
                    unknown.append(item)
                    continue
                if binding.status == "CONTRADICTED" or atom.width_bits is not None and width is not None and atom.width_bits != width:
                    conflicted.append(item)
                    continue
                if atom.width_bits is not None and width is None:
                    unknown.append(item)
                    continue
                expected = atom.value_constraint
                if expected is not None:
                    if value is None:
                        unknown.append(item)
                        continue
                    verdict = {"eq": lambda: value == expected.value,
                               "neq": lambda: value != expected.value,
                               "masked_eq": lambda: value & expected.mask == expected.value,
                               "in_range": lambda: expected.range_min <= value <= expected.range_max}[expected.operator]()
                    (compatible if verdict else conflicted).append(item)
                else:
                    compatible.append(item)
            chosen = compatible or conflicted or unknown
            status: Status = ("SUPPORTED" if compatible else "CONTRADICTED" if conflicted
                              else "AMBIGUOUS" if any(x[5] and x[5].status == "AMBIGUOUS" for x in unknown)
                              else "UNKNOWN")
            reason = {"SUPPORTED": "Exact typed resource, access, width and known value compatible",
                      "CONTRADICTED": "Exact address access conflicts with required value, width or resource permission",
                      "AMBIGUOUS": "Resource binding ambiguous",
                      "UNKNOWN": "Matching address/access or exact value not established"}[status]
            matches.append(_match(requirement_id=condition.condition_id,
                                  matched_capability_ids=tuple(sorted({x[0].capability_id for x in chosen})),
                                  resource_binding_ids=tuple(sorted({x[5].binding_id for x in chosen if x[5]})),
                                  static_compatibility_status=status, reason=reason,
                                  missing_requirements=() if status in {"SUPPORTED", "CONTRADICTED"} else
                                  ("exact_access_and_resource_binding",)))
            access_status.append(status)
        elif condition.condition_kind == "CSR_access" and condition.access is not None:
            atom = condition.access
            def csr_equal(text):
                if text is None: return False
                if atom.csr_identity is not None: return text.casefold() == atom.csr_identity.casefold()
                try: return int(text, 0) == atom.csr_address
                except ValueError: return False
            eligible = [x for x in options if csr_equal(x[6]) and
                        (atom.access == "either" or x[1].kind.value == f"CSR_{atom.access.upper()}")]
            supported = [x for x in eligible if x[5] and x[5].status == "SUPPORTED"]
            contradicted = [x for x in eligible if x[5] and x[5].status == "CONTRADICTED"]
            value_known = [x for x in supported if atom.value_constraint is None or x[3] is not None]
            if atom.value_constraint is not None:
                requirement = atom.value_constraint
                value_known = [x for x in value_known if (
                    requirement.operator == "eq" and x[3] == requirement.value or
                    requirement.operator == "neq" and x[3] != requirement.value or
                    requirement.operator == "masked_eq" and x[3] & requirement.mask == requirement.value or
                    requirement.operator == "in_range" and requirement.range_min <= x[3] <= requirement.range_max)]
                contradicted += [x for x in supported if x[3] is not None and x not in value_known]
            status = "SUPPORTED" if value_known else "CONTRADICTED" if contradicted else "UNKNOWN"
            chosen = value_known or contradicted or eligible
            matches.append(_match(requirement_id=condition.condition_id,
                                  matched_capability_ids=tuple(sorted({x[0].capability_id for x in chosen})),
                                  resource_binding_ids=tuple(sorted({x[5].binding_id for x in chosen if x[5]})),
                                  static_compatibility_status=status,
                                  reason="Typed CSR identity, access and value match" if status == "SUPPORTED" else
                                  "Observed static CSR constraint conflicts" if status == "CONTRADICTED" else
                                  "Exact CSR capability or resource binding missing",
                                  missing_requirements=() if status != "UNKNOWN" else ("exact_csr_binding",)))
            access_status.append(status)
        elif condition.condition_kind == "memory_operation" and condition.required_relation is not None:
            relation = condition.required_relation
            if relation.subject != "address" or relation.operator != "eq" or type(relation.operands[0]) is not int:
                matches.append(_match(requirement_id=condition.condition_id, matched_capability_ids=(),
                                      resource_binding_ids=(), static_compatibility_status="UNKNOWN",
                                      reason="Memory predicate not expressible as an exact static address",
                                      missing_requirements=("typed_memory_predicate",)))
                access_status.append("UNKNOWN")
                continue
            eligible = [x for x in options if x[2] == relation.operands[0] and
                        x[1].kind.value in {"MEMORY_READ", "MEMORY_WRITE"}]
            supported = [x for x in eligible if x[5] and x[5].status == "SUPPORTED"]
            status = "SUPPORTED" if supported else "UNKNOWN"
            chosen = supported or eligible
            matches.append(_match(requirement_id=condition.condition_id,
                                  matched_capability_ids=tuple(sorted({x[0].capability_id for x in chosen})),
                                  resource_binding_ids=tuple(sorted({x[5].binding_id for x in chosen if x[5]})),
                                  static_compatibility_status=status,
                                  reason="Exact memory address and typed resource match" if supported else
                                  "Exact memory resource binding not established",
                                  missing_requirements=() if supported else ("exact_memory_binding",)))
            access_status.append(status)
        else:
            matches.append(_match(requirement_id=condition.condition_id,
                                  matched_capability_ids=(), resource_binding_ids=(),
                                  static_compatibility_status="UNKNOWN",
                                  reason="Ordering/state requires runtime evidence; static sequence is insufficient",
                                  missing_requirements=("runtime_order_or_state_evidence",)))
    for collection, reason in ((contract.preconditions, "prestate_requires_runtime_evidence"),
                               (contract.deviation, "deviation_requires_runtime_evidence"),
                               (contract.observation, "observation_requires_runtime_evidence")):
        for item in collection:
            matches.append(_match(requirement_id=item.condition_id, matched_capability_ids=(),
                                  resource_binding_ids=(), static_compatibility_status="UNKNOWN",
                                  reason="This contract condition requires authoritative runtime verification",
                                  missing_requirements=(reason,)))
    matches.append(_match(requirement_id="hbc:platform-and-scope",
                          matched_capability_ids=(), resource_binding_ids=(),
                          static_compatibility_status="UNKNOWN",
                          reason="Catalog identity and architecture match do not establish pinned platform, firmware or RTL scope",
                          missing_requirements=("runtime_platform_and_source_binding",)))
    overall: Status = ("CONTRADICTED" if "CONTRADICTED" in access_status else
                       "AMBIGUOUS" if "AMBIGUOUS" in access_status else
                       "SUPPORTED" if access_status and all(x == "SUPPORTED" for x in access_status) else "UNKNOWN")
    fields = {"schema_version": "cross-layer-candidate/v1", "contract_id": contract.contract_id,
              "capability_ids": tuple(sorted(c.capability_id for c in capabilities)),
              "binding_set_id": bindings.binding_set_id,
              "requirements": tuple(sorted(matches, key=lambda x: x.requirement_id)),
              "static_compatibility_status": overall, "verification_required": True,
              "missing_requirements": tuple(sorted({need for x in matches for need in x.missing_requirements}))}
    return CrossLayerCandidate.model_validate({**fields, "candidate_id": content_id("xlcandidate", fields)})


def render_cross_layer_report(candidate: CrossLayerCandidate,
                              bindings: HardwareResourceBindingSet,
                              contract: HardwareBehaviorContract,
                              *, catalog: HardwareResourceCatalog | None = None,
                              capabilities: tuple[FirmwareCapability, ...] = ()) -> str:
    translations = {
        "Unique exact typed resource match": "地址或寄存器身份唯一且精确匹配",
        "Exact typed resource, access, width and known value compatible": "资源、访问方向、位宽和已知值与合同一致",
        "Exact address access conflicts with required value, width or resource permission":
            "该地址的已知访问与要求的值、位宽或权限冲突；请对照上表实际值",
        "Catalog identity and architecture match do not establish pinned platform, firmware or RTL scope":
            "架构和资源目录一致，但尚未证明平台、固件及 RTL 修订范围",
        "This contract condition requires authoritative runtime verification": "此条件必须由运行证据验证",
        "Ordering/state requires runtime evidence; static sequence is insufficient":
            "前态或顺序必须由运行证据确认，静态指令排列不足以证明",
    }
    def readable(reason: str) -> str:
        return translations.get(reason, reason)
    lines = ["# Cross-Layer Candidate Report", "",
             f"硬件合同 `{contract.contract_id}`；静态相容性 **{candidate.static_compatibility_status}**。",
             "这只是候选匹配，不是硬件触发、偏差或漏洞验证。", "",
             "## Hardware contract summary", "",
             f"架构 `{contract.architecture.value}`；触发要求 {len(contract.trigger)} 项，"
             f"前态要求 {len(contract.preconditions)} 项，偏差要求 {len(contract.deviation)} 项，"
             f"观测要求 {len(contract.observation)} 项。"
             "目标平台、RTL 修订和观测来源仍需运行验证器核对。", "",
             "## Firmware behaviors considered", "",
             f"{len(candidate.capability_ids)} 份 FirmwareCapability，"
             f"{len(bindings.bindings)} 个待绑定 primitive。", "",
             "| PC | 行为 | 地址 / CSR | 已知写值 | 资源 | 静态绑定 |",
             "|---|---|---|---|---|---|"]
    by_binding = {b.firmware_behavior_id: b for b in bindings.bindings}
    by_resource = {r.resource_id: r for r in catalog.resources} if catalog else {}
    for capability in capabilities:
        constraints = {c.constraint_id: c for c in capability.constraints}
        for primitive in capability.primitives:
            selected = [constraints[x] for x in primitive.constraint_ids]
            address = next((x.domain.exact for x in selected if isinstance(x, NumericConstraint)
                            and x.kind == "address"), None)
            known_value = next((x.domain.exact for x in selected if isinstance(x, NumericConstraint)
                                and x.kind == "value"), None)
            csr = next((x.identity for x in selected if isinstance(x, IdentityConstraint)
                        and x.kind == "CSR"), None)
            binding = by_binding.get(primitive.primitive_id)
            resource = by_resource.get(binding.hardware_resource_id) if binding else None
            pc = f"0x{primitive.source_pc:x}" if primitive.source_pc is not None else "not established"
            lines.append(f"| `{pc}` | {primitive.kind.value} | "
                         f"{f'0x{address:x}' if address is not None else csr or 'not established'} | "
                         f"{f'0x{known_value:x}' if known_value is not None else 'not established'} | "
                         f"{resource.name if resource else 'unbound'} | "
                         f"{binding.status if binding else 'UNKNOWN'} |")
    lines += ["",
             "## Hardware resource bindings", "",
             "| 固件 primitive | 硬件资源 | 绑定方式 | 状态 | 理由 |", "|---|---|---|---|---|"]
    for item in bindings.bindings:
        resource = by_resource.get(item.hardware_resource_id)
        resource_label = f"{resource.name} (`{item.hardware_resource_id}`)" if resource else "not established"
        lines.append(f"| `{item.firmware_behavior_id}` | {resource_label} | "
                     f"{item.binding_kind} | {item.status} | {readable(item.reason)} |")
    lines += ["", "## Requirement-by-requirement matching", "",
              "| Requirement | Capability IDs | Binding IDs | 静态状态 | 理由 |",
              "|---|---|---|---|---|"]
    descriptions = {item.condition_id: item.description for collection in (
        contract.preconditions, contract.trigger, contract.deviation, contract.observation)
        for item in collection}
    for item in candidate.requirements:
        caps = ", ".join(f"`{x}`" for x in item.matched_capability_ids) or "—"
        bound = ", ".join(f"`{x}`" for x in item.resource_binding_ids) or "—"
        label = descriptions.get(item.requirement_id, item.requirement_id)
        lines.append(f"| {label} (`{item.requirement_id}`) | {caps} | {bound} | "
                     f"{item.static_compatibility_status} | {readable(item.reason)} |")
    for title, status in (("Supported static conditions", "SUPPORTED"),
                          ("Contradicted static conditions", "CONTRADICTED"),
                          ("Unknown / ambiguous conditions", "UNKNOWN")):
        lines += ["", f"## {title}", ""]
        selected = [x for x in candidate.requirements if x.static_compatibility_status == status or
                    status == "UNKNOWN" and x.static_compatibility_status == "AMBIGUOUS"]
        lines.extend(f"- `{x.requirement_id}`: {readable(x.reason)}" for x in selected)
        if not selected: lines.append("- 无。")
    lines += ["", "## Verification requirements", "",
              *[f"- {x}" for x in candidate.missing_requirements], "",
              "Candidate != verified chain. 静态次序不等于运行次序；"
              "资源绑定不等于触发，正常固件行为不等于攻击者控制。", ""]
    return "\n".join(lines)
