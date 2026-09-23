"""ELF identity and address-to-file mapping; filenames never determine ISA."""
from __future__ import annotations

from hashlib import sha256
from io import BytesIO
from pathlib import Path

from elftools.elf.elffile import ELFFile

from chipchain.firmware.static_ir import FirmwareArtifactIdentity, SegmentFact, SectionFact

MACHINES = {"EM_ARM": "arm", "EM_RISCV": "riscv", "EM_PPC": "powerpc"}


class ElfImage:
    def __init__(self, data: bytes):
        self.data = data
        elf = ELFFile(BytesIO(data))
        machine = elf.header["e_machine"]
        if machine not in MACHINES:
            raise ValueError(f"Unsupported ELF machine: {machine}")
        width = elf.elfclass
        endian = "little" if elf.little_endian else "big"
        architecture = MACHINES[machine]
        if (architecture, width, endian) not in {
            ("arm", 32, "little"), ("arm", 32, "big"),
            ("riscv", 32, "little"), ("riscv", 64, "little"),
            ("powerpc", 32, "big"), ("powerpc", 64, "big"),
        }:
            raise ValueError(f"Unsupported ELF architecture/width/endian: {architecture}/{width}/{endian}")
        self.segments = tuple(SegmentFact(
            virtual_address=int(s["p_vaddr"]), file_offset=int(s["p_offset"]),
            file_size=int(s["p_filesz"]), memory_size=int(s["p_memsz"]),
            flags=int(s["p_flags"]),
        ) for s in elf.iter_segments() if s["p_type"] == "PT_LOAD")
        sections = tuple(SectionFact(
            name=s.name, address=int(s["sh_addr"]), size=int(s["sh_size"]),
            flags=int(s["sh_flags"]), section_type=str(s["sh_type"]),
        ) for s in elf.iter_sections())
        arm_profile = None
        arm_cpu_name = None
        if architecture == "arm":
            attributes = elf.get_section_by_name(".ARM.attributes")
            if attributes is not None:
                for subsection in attributes.iter_subsections():
                    for subsubsection in subsection.iter_subsubsections():
                        for attribute in subsubsection.iter_attributes():
                            if attribute.tag == "TAG_CPU_ARCH_PROFILE":
                                arm_profile = chr(attribute.value)
                            elif attribute.tag == "TAG_CPU_NAME":
                                arm_cpu_name = attribute.value
        self.identity = FirmwareArtifactIdentity(
            sha256=sha256(data).hexdigest(), architecture=architecture,
            bit_width=width, endianness=endian, entry=int(elf.header["e_entry"]),
            arm_profile=arm_profile, arm_cpu_name=arm_cpu_name,
            segments=self.segments, sections=sections,
        )

    @classmethod
    def from_path(cls, path: str | Path) -> "ElfImage":
        return cls(Path(path).read_bytes())

    def mapped_bytes(self, address: int, size: int, *, executable: bool = False) -> bytes:
        matches = [s for s in self.segments if s.virtual_address <= address
                   and address + size <= s.virtual_address + s.file_size
                   and (not executable or s.flags & 1)]
        if len(matches) != 1:
            raise ValueError(f"Address 0x{address:x} is not uniquely file-backed in ELF")
        segment = matches[0]
        start = segment.file_offset + address - segment.virtual_address
        return self.data[start:start + size]


def ghidra_language(identity: FirmwareArtifactIdentity) -> str:
    mapping = {
        ("arm", 32, "little", "M"): "ARM:LE:32:Cortex",
        ("arm", 32, "big", "M"): "ARM:BE:32:Cortex",
        ("riscv", 32, "little", None): "RISCV:LE:32:default",
        ("riscv", 64, "little", None): "RISCV:LE:64:default",
        ("powerpc", 32, "big", None): "PowerPC:BE:32:default",
        ("powerpc", 64, "big", None): "PowerPC:BE:64:default",
    }
    key = (identity.architecture, identity.bit_width, identity.endianness, identity.arm_profile)
    if key not in mapping:
        raise ValueError(f"No Ghidra language for {key}")
    return mapping[key]
