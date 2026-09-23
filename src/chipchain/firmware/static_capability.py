"""Conservative CAP0 projection for explicitly synthetic static firmware analyses.

CAP0's frozen SourceKind has no general Ghidra-static source. The adapter uses
`synthetic_fixture` only when the caller explicitly declares synthetic inputs;
it cannot automatically label arbitrary research ELF as a synthetic fixture.
"""
from __future__ import annotations

from hashlib import sha256

from chipchain.domain.case import TargetDescriptor
from chipchain.domain.evidence import EvidenceLocation, EvidenceRef
from chipchain.firmware import capability as cap
from chipchain.firmware.static_ir import (
    FirmwareStaticAnalysis, StaticBehaviorFact, StaticBehaviorKind as K, serialize_analysis,
)
from chipchain.cross_layer.resource_binding import HardwareResourceBindingSet
from chipchain.hardware.resources import HardwareResourceCatalog, ResourceKind

MAPPING = {
    K.INSTRUCTION: cap.PrimitiveKind.INSTRUCTION_EXECUTION,
    K.DIRECT_CALL: cap.PrimitiveKind.DIRECT_CONTROL_TRANSFER,
    K.DIRECT_BRANCH: cap.PrimitiveKind.DIRECT_CONTROL_TRANSFER,
    K.CONDITIONAL_BRANCH: cap.PrimitiveKind.DIRECT_CONTROL_TRANSFER,
    K.INDIRECT_CALL: cap.PrimitiveKind.INDIRECT_CONTROL_TRANSFER,
    K.INDIRECT_BRANCH: cap.PrimitiveKind.INDIRECT_CONTROL_TRANSFER,
    K.RETURN: cap.PrimitiveKind.INDIRECT_CONTROL_TRANSFER,
    K.MEMORY_LOAD: cap.PrimitiveKind.MEMORY_READ,
    K.MEMORY_STORE: cap.PrimitiveKind.MEMORY_WRITE,
    K.MMIO_READ: cap.PrimitiveKind.MMIO_READ,
    K.MMIO_WRITE: cap.PrimitiveKind.MMIO_WRITE,
    K.SYSTEM_REGISTER_READ: cap.PrimitiveKind.CSR_READ,
    K.SYSTEM_REGISTER_WRITE: cap.PrimitiveKind.CSR_WRITE,
    K.EXCEPTION_RETURN: cap.PrimitiveKind.EXCEPTION_RETURN,
}


def materialize_synthetic_static_capabilities(
    analysis: FirmwareStaticAnalysis, *,
    synthetic_fixture: bool,
    bindings: HardwareResourceBindingSet | None = None,
    catalog: HardwareResourceCatalog | None = None,
) -> tuple[cap.FirmwareCapability, ...]:
    """One static-only CAP0 capability per expressible behavior PC.

    `synthetic_fixture` is an explicit provenance declaration, not inferred from
    a path, ELF content, model output or evaluation label. A real firmware
    analyzer source kind requires a separately reviewed additive CAP0 version.
    """
    if not synthetic_fixture:
        raise ValueError("Frozen CAP0 lacks a general firmware-static source kind")
    analysis = FirmwareStaticAnalysis.model_validate(analysis.model_dump(mode="json"))
    if (bindings is None) != (catalog is None):
        raise ValueError("Binding set and catalog must be supplied together")
    if bindings is not None and (bindings.firmware_source_id != analysis.analysis_id
                                 or bindings.catalog_id != catalog.catalog_id):
        raise ValueError("Static resource binding source mismatch")
    by_binding = {b.firmware_behavior_id: b for b in bindings.bindings} if bindings else {}
    by_resource = {r.resource_id: r for r in catalog.resources} if catalog else {}
    instructions = {i.fact_id: i for i in analysis.instructions}
    functions = {f.fact_id: f for f in analysis.functions}
    results = []
    for behavior in analysis.behaviors:
        if (behavior.kind not in MAPPING or behavior.semantic_status == "unsupported"
            or behavior.kind in {K.SYSTEM_REGISTER_READ, K.SYSTEM_REGISTER_WRITE}
            and analysis.artifact.architecture != "riscv"):
            continue
        instruction = instructions[behavior.instruction_id]
        binding = by_binding.get(behavior.fact_id)
        resource = by_resource.get(binding.hardware_resource_id) if binding and binding.status == "SUPPORTED" else None
        results.append(_one(analysis, behavior, instruction, functions, resource))
    return tuple(results)


def _one(analysis, behavior, instruction, functions, resource):
    sha = analysis.artifact.sha256
    elf_id = "elf:" + sha
    analysis_bytes = serialize_analysis(analysis).encode()
    sources = [
        cap.SourceArtifact(artifact_id=elf_id, sha256=sha, source_kind="synthetic_fixture"),
        cap.SourceArtifact(artifact_id=analysis.analysis_id, sha256=sha256(analysis_bytes).hexdigest(),
                           source_kind="synthetic_fixture"),
    ]
    source_ids = [s.artifact_id for s in sources]
    evidence = EvidenceRef(evidence_id=behavior.fact_id, source_type="synthetic",
                           artifact_id=analysis.analysis_id, analyzer="ghidra-elf-static/v1",
                           location=EvidenceLocation(address=behavior.pc),
                           summary="Synthetic fixture instruction; ELF bytes checked, static semantics only.",
                           epistemic_status="derived")
    provenance = [cap.Provenance(source_kind="synthetic_fixture", source_artifact_ids=[sid],
                                  source_ids=[behavior.fact_id, instruction.fact_id]) for sid in source_ids]
    bound = dict(source_artifact_ids=source_ids, evidence_ids=[behavior.fact_id], provenance=provenance)
    entry_id = "entry:" + behavior.fact_id
    entry = cap.Entry(entry_id=entry_id, entry_kind="code_site", formalization_status="formalized",
                      pc=behavior.pc, function_id=instruction.function_ids[0]
                      if len(instruction.function_ids) == 1 else None,
                      function_name=functions[instruction.function_ids[0]].name
                      if len(instruction.function_ids) == 1 else None,
                      ownership_status="unique" if len(instruction.function_ids) == 1 else
                      "ambiguous" if instruction.function_ids else "missing",
                      execution_status="static_only", **bound)
    constraints = []
    primitive_kind = MAPPING[behavior.kind]
    if primitive_kind == cap.PrimitiveKind.DIRECT_CONTROL_TRANSFER and behavior.target is None:
        primitive_kind = cap.PrimitiveKind.INDIRECT_CONTROL_TRANSFER
    resource_identity = resource.resource_id if resource else None
    resource_kind = None
    if behavior.kind in {K.MEMORY_LOAD, K.MEMORY_STORE, K.MMIO_READ, K.MMIO_WRITE}:
        if resource and resource.kind == ResourceKind.MMIO_REGISTER:
            primitive_kind = cap.PrimitiveKind.MMIO_READ if behavior.kind in {K.MEMORY_LOAD, K.MMIO_READ} else cap.PrimitiveKind.MMIO_WRITE
            resource_kind = "mmio"
        elif resource and resource.kind == ResourceKind.MEMORY_REGION:
            resource_kind = "memory"
        else:
            resource_kind = "memory" if behavior.kind in {K.MEMORY_LOAD, K.MEMORY_STORE} else "mmio"
    if resource_kind:
        constraints.append(cap.ResourceConstraint(
            constraint_id="resource:" + behavior.fact_id, resource_kind=resource_kind,
            identity=resource_identity,
            formalization_status="formalized" if resource_identity else "partially_formalized", **bound))
        for kind, value in (("address", behavior.address), ("access_width", behavior.access_width_bits),
                            ("value", behavior.known_value if behavior.kind in {K.MEMORY_STORE, K.MMIO_WRITE} else None)):
            if value is not None:
                constraints.append(cap.NumericConstraint(
                    constraint_id=f"{kind}:{behavior.fact_id}", kind=kind,
                    domain=cap.NumericDomain(exact=value, bit_width=analysis.artifact.bit_width
                                             if kind == "address" else behavior.access_width_bits or analysis.artifact.bit_width),
                    **bound))
    if primitive_kind == cap.PrimitiveKind.DIRECT_CONTROL_TRANSFER and behavior.target is not None:
        constraints.append(cap.TargetSetConstraint(constraint_id="target:" + behavior.fact_id,
                                                   targets=[behavior.target], **bound))
    if primitive_kind in {cap.PrimitiveKind.DIRECT_CONTROL_TRANSFER,
                          cap.PrimitiveKind.INDIRECT_CONTROL_TRANSFER,
                          cap.PrimitiveKind.EXCEPTION_RETURN}:
        constraints.append(cap.ResourceConstraint(
            constraint_id="resource:" + behavior.fact_id, resource_kind="control_flow",
            identity=f"code:0x{behavior.target:x}" if behavior.target is not None else None,
            formalization_status="formalized" if behavior.target is not None else "partially_formalized", **bound))
    if analysis.artifact.architecture == "riscv" and behavior.kind in {K.SYSTEM_REGISTER_READ,
                                                                         K.SYSTEM_REGISTER_WRITE}:
        primitive_kind = cap.PrimitiveKind.CSR_READ if behavior.kind == K.SYSTEM_REGISTER_READ else cap.PrimitiveKind.CSR_WRITE
        constraints.append(cap.ResourceConstraint(constraint_id="resource:" + behavior.fact_id,
                                                  resource_kind="csr", identity=behavior.system_register,
                                                  **bound))
        constraints.append(cap.IdentityConstraint(constraint_id="csr:" + behavior.fact_id,
                                                  kind="CSR", identity=behavior.system_register, **bound))
    transfer = {K.DIRECT_CALL: "direct_call", K.DIRECT_BRANCH: "direct_jump",
                K.CONDITIONAL_BRANCH: "conditional_branch", K.INDIRECT_CALL: "indirect_call",
                K.INDIRECT_BRANCH: "indirect_jump", K.RETURN: "return"}.get(behavior.kind)
    partial = ((resource_kind is not None and (resource_identity is None or behavior.address is None
                                                or behavior.access_width_bits is None)) or
               primitive_kind in {cap.PrimitiveKind.DIRECT_CONTROL_TRANSFER,
                                  cap.PrimitiveKind.INDIRECT_CONTROL_TRANSFER,
                                  cap.PrimitiveKind.EXCEPTION_RETURN} and behavior.target is None)
    condition = cap.Condition(condition_id="condition:" + behavior.fact_id, condition_kind="path",
                              formalization_status="unknown",
                              description="Static site does not establish runtime path feasibility.", **bound)
    primitive = cap.Primitive(
        primitive_id="primitive:" + behavior.fact_id, architecture=analysis.artifact.architecture,
        kind=primitive_kind, entry_id=entry_id, formalization_status="partially_formalized" if partial else "formalized",
        basis="static_instruction", control=cap.ControlAuthority(status="not_established", **bound),
        constraint_ids=[c.constraint_id for c in constraints], condition_ids=[condition.condition_id],
        source_pc=behavior.pc, instruction_sequence=[instruction.raw_bytes],
        transfer_kind=transfer,
        target_status="resolved_direct" if primitive_kind == cap.PrimitiveKind.DIRECT_CONTROL_TRANSFER else
                      "indirect_unknown" if primitive_kind == cap.PrimitiveKind.INDIRECT_CONTROL_TRANSFER else "not_applicable",
        **bound)
    scope = cap.Scope(target=TargetDescriptor(architecture=analysis.artifact.architecture,
                          processor_id="not-established", firmware_id=elf_id,
                          word_size_bits=analysis.artifact.bit_width, endianness=analysis.artifact.endianness),
                      origin_kind="synthetic_fixture", firmware_artifact_ids=[elf_id], site_pcs=[behavior.pc],
                      applicability="synthetic_only", formalization_status="partially_formalized",
                      assumptions=["Synthetic fixture; no arbitrary-input path feasibility."],
                      unmodeled_aspects=["external_control", "runtime_order", "hardware_trigger", "deviation"], **bound)
    return cap.build_firmware_capability(cap.FirmwareCapabilityInput(
        architecture=analysis.artifact.architecture, origin=cap.Origin(kind="synthetic_fixture", **bound),
        entry=entry, conditions=[condition], primitives=[primitive], constraints=constraints,
        scope=scope, source_artifacts=sources, evidence=[evidence],
        limitations=["Static-only does not prove execution or attacker control."], **bound))
