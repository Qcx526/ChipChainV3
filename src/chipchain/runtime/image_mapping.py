"""Declared runtime-address to ELF-VA mappings; no loader or MMU inference."""
from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from chipchain.domain.common import Contract, Sha256
from chipchain.firmware.static_ir import FirmwareArtifactIdentity


class RuntimeImageRegion(Contract):
    model_config = ConfigDict(frozen=True)
    runtime_base: int = Field(strict=True, ge=0)
    elf_virtual_base: int = Field(strict=True, ge=0)
    size: int = Field(strict=True, gt=0)


class RuntimeImageMapping(Contract):
    """Exact source context plus disjoint, explicitly declared byte ranges.

    Identity is a declaration for a particular image, not an ISA property.
    Relocation support here only translates addresses; it does not configure
    QEMU to load a relocated image, relocate instructions, or model page tables.
    """
    model_config = ConfigDict(frozen=True)
    firmware_sha256: Sha256
    mapping_kind: Literal["identity", "relocated"]
    regions: tuple[RuntimeImageRegion, ...]

    @model_validator(mode="after")
    def unambiguous(self):
        if not self.regions:
            raise ValueError("Runtime image mapping requires explicit regions")
        if self.regions != tuple(sorted(self.regions, key=lambda r: r.runtime_base)):
            raise ValueError("Runtime image mapping regions must be canonically ordered")
        if self.mapping_kind == "identity" and any(
            r.runtime_base != r.elf_virtual_base for r in self.regions
        ):
            raise ValueError("Identity mapping cannot relocate an image")
        if self.mapping_kind == "relocated" and not any(
            r.runtime_base != r.elf_virtual_base for r in self.regions
        ):
            raise ValueError("Relocated mapping must declare a non-identity range")
        for key in ("runtime_base", "elf_virtual_base"):
            ordered = sorted(self.regions, key=lambda r: getattr(r, key))
            if any(getattr(a, key) + a.size > getattr(b, key)
                   for a, b in zip(ordered, ordered[1:])):
                raise ValueError("Ambiguous runtime image mapping ranges")
        return self

    def validate_source(self, identity: FirmwareArtifactIdentity) -> None:
        if self.firmware_sha256 != identity.sha256:
            raise ValueError("Runtime image mapping firmware identity mismatch")
        for r in self.regions:
            if max(r.runtime_base + r.size, r.elf_virtual_base + r.size) > 1 << identity.bit_width:
                raise ValueError("Runtime image mapping exceeds source address width")
            matches = [s for s in identity.segments if s.flags & 1
                       and s.virtual_address <= r.elf_virtual_base
                       and r.elf_virtual_base + r.size <= s.virtual_address + s.file_size]
            if len(matches) != 1:
                raise ValueError("Runtime image mapping is not uniquely backed by executable ELF bytes")

    def elf_address(self, runtime_pc: int, instruction_size: int) -> int:
        if type(runtime_pc) is not int or runtime_pc < 0 or type(instruction_size) is not int or instruction_size < 1:
            raise ValueError("Invalid runtime instruction span")
        matches = [r for r in self.regions if r.runtime_base <= runtime_pc
                   and runtime_pc + instruction_size <= r.runtime_base + r.size]
        if len(matches) != 1:
            raise ValueError("Runtime instruction has no unambiguous declared image mapping")
        region = matches[0]
        return region.elf_virtual_base + runtime_pc - region.runtime_base


def declared_identity_mapping(identity: FirmwareArtifactIdentity) -> RuntimeImageMapping:
    """Called only when the caller's load policy explicitly declares identity."""
    mapping = RuntimeImageMapping(
        firmware_sha256=identity.sha256, mapping_kind="identity",
        regions=tuple(RuntimeImageRegion(runtime_base=s.virtual_address,
                                        elf_virtual_base=s.virtual_address, size=s.file_size)
                      for s in sorted(identity.segments, key=lambda s: s.virtual_address)
                      if s.flags & 1 and s.file_size),
    )
    mapping.validate_source(identity)
    return mapping
