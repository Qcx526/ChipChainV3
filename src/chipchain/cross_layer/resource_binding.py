"""Exact typed binding of static firmware facts or CAP0 primitives to hardware resources."""
from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from chipchain.domain.common import Contract
from chipchain.firmware.static_ir import FirmwareStaticAnalysis, StaticBehaviorKind as K, content_id
from chipchain.firmware.capability import FirmwareCapability, NumericConstraint, IdentityConstraint
from chipchain.hardware.resources import HardwareResourceCatalog, ResourceKind

Status = Literal["SUPPORTED", "CONTRADICTED", "UNKNOWN", "AMBIGUOUS", "NOT_APPLICABLE"]


class HardwareResourceBinding(Contract):
    binding_id: str
    firmware_behavior_id: str
    hardware_resource_id: str | None
    binding_kind: Literal["exact_address", "range_containment", "exact_system_register",
                          "exact_csr", "explicit_manual_binding", "unknown", "ambiguous"]
    status: Status
    reason: str
    evidence_ids: tuple[str, ...]

    @model_validator(mode="after")
    def identity(self):
        if self.binding_id != content_id("hwbind", self.model_dump(mode="json", exclude={"binding_id"})):
            raise ValueError("Resource binding identity mismatch")
        return self


class ExplicitManualBinding(Contract):
    firmware_behavior_id: str = Field(min_length=1)
    hardware_resource_id: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)


def _binding(**fields) -> HardwareResourceBinding:
    return HardwareResourceBinding.model_validate({**fields, "binding_id": content_id("hwbind", fields)})


class HardwareResourceBindingSet(Contract):
    schema_version: Literal["hardware-resource-bindings/v1"] = "hardware-resource-bindings/v1"
    binding_set_id: str
    firmware_source_id: str
    catalog_id: str
    bindings: tuple[HardwareResourceBinding, ...]

    @model_validator(mode="after")
    def identity(self):
        if self.binding_set_id != content_id("hwbindings", self.model_dump(mode="json", exclude={"binding_set_id"})):
            raise ValueError("Binding set identity mismatch")
        return self


def _select(fact_id: str, *, architecture: str, kind: str, address: int | None,
            register: str | None, width_bits: int | None, catalog: HardwareResourceCatalog,
            evidence_ids: tuple[str, ...],
            manual: ExplicitManualBinding | None = None) -> HardwareResourceBinding:
    if architecture != catalog.architecture:
        raise ValueError("Firmware and hardware architecture differ")
    memory = kind in {"MEMORY_LOAD", "MEMORY_STORE", "MEMORY_READ", "MEMORY_WRITE",
                      "MMIO_READ", "MMIO_WRITE"}
    system = kind in {"SYSTEM_REGISTER_READ", "SYSTEM_REGISTER_WRITE", "CSR_READ", "CSR_WRITE"}
    if manual is not None:
        resource = next((r for r in catalog.resources if r.resource_id == manual.hardware_resource_id), None)
        if resource is None:
            raise ValueError("Manual binding selects unknown hardware resource")
        compatible = ((memory and resource.kind in {ResourceKind.MMIO_REGISTER, ResourceKind.MEMORY_REGION}) or
                      (system and resource.kind in {ResourceKind.SYSTEM_REGISTER, ResourceKind.CSR}))
        if not compatible:
            raise ValueError("Manual binding resource kind conflicts with behavior kind")
        conflict = (address is not None and resource.address_start is not None and
                    not resource.address_start <= address <= resource.address_end or
                    register is not None and resource.register_identity is not None and
                    register.casefold() != resource.register_identity.casefold())
        return _binding(firmware_behavior_id=fact_id, hardware_resource_id=resource.resource_id,
                        binding_kind="explicit_manual_binding",
                        status="CONTRADICTED" if conflict else "UNKNOWN",
                        reason=("Manual declaration conflicts with exact static identity" if conflict else
                                "Manual resource declaration recorded; independent exact binding not established: "
                                + manual.reason), evidence_ids=(*evidence_ids, manual.source_id))
    if not memory and not system:
        return _binding(firmware_behavior_id=fact_id, hardware_resource_id=None,
                        binding_kind="unknown", status="NOT_APPLICABLE",
                        reason="No current typed resource requirement for this behavior", evidence_ids=evidence_ids)
    if memory and address is None or system and not register:
        return _binding(firmware_behavior_id=fact_id, hardware_resource_id=None,
                        binding_kind="unknown", status="UNKNOWN",
                        reason="Exact address/register identity not established", evidence_ids=evidence_ids)
    allowed = {ResourceKind.MMIO_REGISTER, ResourceKind.MEMORY_REGION} if memory else (
        {ResourceKind.CSR} if architecture == "riscv" or kind.startswith("CSR") else {ResourceKind.SYSTEM_REGISTER})
    matches = [r for r in catalog.resources if r.kind in allowed and (
        r.address_start <= address <= r.address_end if memory else
        r.register_identity.casefold() == register.casefold())]
    if len(matches) > 1:
        return _binding(firmware_behavior_id=fact_id, hardware_resource_id=None,
                        binding_kind="ambiguous", status="AMBIGUOUS",
                        reason="Multiple typed resources overlap; no automatic selection", evidence_ids=evidence_ids)
    if not matches:
        return _binding(firmware_behavior_id=fact_id, hardware_resource_id=None,
                        binding_kind="unknown", status="UNKNOWN",
                        reason="No catalog resource contains the exact identity", evidence_ids=evidence_ids)
    item = matches[0]
    binding_kind = ("exact_address" if item.address_start == item.address_end else "range_containment") if memory else (
        "exact_csr" if item.kind == ResourceKind.CSR else "exact_system_register")
    access = "read" if kind.endswith(("LOAD", "READ")) else "write"
    if item.access and access not in item.access:
        return _binding(firmware_behavior_id=fact_id, hardware_resource_id=item.resource_id,
                        binding_kind=binding_kind, status="CONTRADICTED",
                        reason=f"Resource prohibits {access}", evidence_ids=evidence_ids)
    if item.width_bits is not None and width_bits is None:
        return _binding(firmware_behavior_id=fact_id, hardware_resource_id=item.resource_id,
                        binding_kind=binding_kind, status="UNKNOWN",
                        reason="Access width not established", evidence_ids=evidence_ids)
    if item.width_bits is not None and width_bits != item.width_bits:
        return _binding(firmware_behavior_id=fact_id, hardware_resource_id=item.resource_id,
                        binding_kind=binding_kind, status="CONTRADICTED",
                        reason="Access width conflicts with resource width", evidence_ids=evidence_ids)
    return _binding(firmware_behavior_id=fact_id, hardware_resource_id=item.resource_id,
                    binding_kind=binding_kind, status="SUPPORTED",
                    reason="Unique exact typed resource match", evidence_ids=evidence_ids)


def _set(source_id: str, catalog: HardwareResourceCatalog,
         bindings: list[HardwareResourceBinding]) -> HardwareResourceBindingSet:
    fields = {"schema_version": "hardware-resource-bindings/v1", "firmware_source_id": source_id,
              "catalog_id": catalog.catalog_id,
              "bindings": tuple(sorted(bindings, key=lambda b: (b.firmware_behavior_id, b.binding_id)))}
    return HardwareResourceBindingSet.model_validate({**fields, "binding_set_id": content_id("hwbindings", fields)})


def bind_resources(analysis: FirmwareStaticAnalysis,
                   catalog: HardwareResourceCatalog,
                   *, manual_bindings: tuple[ExplicitManualBinding, ...] = ()) -> HardwareResourceBindingSet:
    manual = {b.firmware_behavior_id: b for b in manual_bindings}
    if len(manual) != len(manual_bindings) or not set(manual) <= {b.fact_id for b in analysis.behaviors}:
        raise ValueError("Invalid manual behavior binding set")
    values = [_select(b.fact_id, architecture=analysis.artifact.architecture, kind=b.kind.value,
                      address=b.address, register=b.system_register, width_bits=b.access_width_bits, catalog=catalog,
                      evidence_ids=(b.instruction_id, analysis.artifact.sha256), manual=manual.get(b.fact_id))
              for b in analysis.behaviors]
    return _set(analysis.analysis_id, catalog, values)


def bind_capabilities(capabilities: tuple[FirmwareCapability, ...],
                      catalog: HardwareResourceCatalog,
                      *, manual_bindings: tuple[ExplicitManualBinding, ...] = ()) -> HardwareResourceBindingSet:
    values = []
    ids = sorted(c.capability_id for c in capabilities)
    known_primitives = {p.primitive_id for c in capabilities for p in c.primitives}
    manual = {b.firmware_behavior_id: b for b in manual_bindings}
    if len(manual) != len(manual_bindings) or not set(manual) <= known_primitives:
        raise ValueError("Invalid manual capability binding set")
    for capability in capabilities:
        constraints = {c.constraint_id: c for c in capability.constraints}
        for primitive in capability.primitives:
            selected = [constraints[key] for key in primitive.constraint_ids]
            address = next((x.domain.exact for x in selected if isinstance(x, NumericConstraint)
                            and x.kind == "address"), None)
            register = next((x.identity for x in selected if isinstance(x, IdentityConstraint)
                             and x.kind == "CSR"), None)
            width = next((x.domain.exact for x in selected if isinstance(x, NumericConstraint)
                          and x.kind == "access_width"), None)
            values.append(_select(primitive.primitive_id, architecture=capability.architecture.value,
                                  kind=primitive.kind.value, address=address, register=register, width_bits=width,
                                  catalog=catalog, evidence_ids=(capability.capability_id,),
                                  manual=manual.get(primitive.primitive_id)))
    return _set(content_id("fwcapset", ids), catalog, values)
