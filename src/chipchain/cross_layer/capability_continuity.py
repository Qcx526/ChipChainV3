"""Exact static-to-runtime CAP0 semantic continuity, independent of scenario labels."""
from __future__ import annotations

from typing import Literal

from pydantic import model_validator

from chipchain.domain.common import Contract
from chipchain.firmware.capability import FirmwareCapability, NumericConstraint, ResourceConstraint
from chipchain.firmware.static_ir import content_id

Status = Literal["BOUND", "CONTRADICTED", "UNKNOWN", "AMBIGUOUS"]


class StaticRuntimeCapabilityBinding(Contract):
    binding_id: str
    static_capability_id: str
    runtime_capability_ids: tuple[str, ...]
    status: Status
    reason: str

    @model_validator(mode="after")
    def identity(self):
        if self.binding_id != content_id("fwcontinuity", self.model_dump(mode="json", exclude={"binding_id"})):
            raise ValueError("Continuity binding identity mismatch")
        return self


class StaticRuntimeCapabilityBindingSet(Contract):
    schema_version: str = "static-runtime-capability-bindings/v1"
    binding_set_id: str
    bindings: tuple[StaticRuntimeCapabilityBinding, ...]

    @model_validator(mode="after")
    def identity(self):
        if self.binding_set_id != content_id("fwcontinuity-set", self.model_dump(mode="json", exclude={"binding_set_id"})):
            raise ValueError("Continuity set identity mismatch")
        return self


def _elf_sha(cap: FirmwareCapability) -> str | None:
    candidates = {x.sha256 for x in cap.source_artifacts
                  if x.artifact_id.startswith(("elf:", "mmio-firmware:"))}
    return next(iter(candidates)) if len(candidates) == 1 else None


def _semantics(cap: FirmwareCapability) -> tuple | None:
    if len(cap.primitives) != 1:
        return None
    p = cap.primitives[0]
    by_id = {x.constraint_id: x for x in cap.constraints}
    constraints = [by_id[x] for x in p.constraint_ids]
    def numeric(kind):
        values = [x.domain.exact for x in constraints if isinstance(x, NumericConstraint) and x.kind == kind]
        return values[0] if len(values) == 1 else None
    resource = [x.resource_kind for x in constraints if isinstance(x, ResourceConstraint)]
    return (_elf_sha(cap), cap.architecture, p.source_pc, p.kind.value,
            resource[0] if len(resource) == 1 else None,
            numeric("address"), numeric("access_width"), numeric("value"),
            tuple(p.instruction_sequence))


def bind_static_runtime_capabilities(static: tuple[FirmwareCapability, ...],
                                     runtime: tuple[FirmwareCapability, ...]) -> StaticRuntimeCapabilityBindingSet:
    records = []
    for source in sorted(static, key=lambda c: c.capability_id):
        s = _semantics(source)
        if s is None or s[0] is None or s[2] is None:
            status, selected, reason = "UNKNOWN", (), "Static ELF, PC or primitive identity missing"
        else:
            same_site = [(cap, _semantics(cap)) for cap in runtime]
            same_site = [(cap, sem) for cap, sem in same_site if sem is not None and sem[:3] == s[:3]]
            exact = [(cap, sem) for cap, sem in same_site if sem == s]
            if len(exact) == 1:
                status, selected, reason = "BOUND", (exact[0][0].capability_id,), "Unique exact ELF/ISA/PC/primitive/resource/address/width/value/encoding match"
            elif len(exact) > 1:
                status, selected, reason = "AMBIGUOUS", tuple(sorted(cap.capability_id for cap, _ in exact)), "Multiple exact runtime candidates"
            elif same_site and all(all(sem[k] is not None and s[k] is not None for k in (3, 4, 5, 6)) for _, sem in same_site):
                status, selected, reason = "CONTRADICTED", tuple(sorted(cap.capability_id for cap, _ in same_site)), "Same ELF/ISA/PC but incompatible complete semantic fields"
            else:
                status, selected, reason = "UNKNOWN", tuple(sorted(cap.capability_id for cap, _ in same_site)), "Missing or incomplete runtime semantic match"
        fields = dict(static_capability_id=source.capability_id, runtime_capability_ids=selected,
                      status=status, reason=reason)
        records.append(StaticRuntimeCapabilityBinding(binding_id=content_id("fwcontinuity", fields), **fields))
    fields = dict(schema_version="static-runtime-capability-bindings/v1", bindings=tuple(records))
    return StaticRuntimeCapabilityBindingSet(binding_set_id=content_id("fwcontinuity-set", fields), **fields)
