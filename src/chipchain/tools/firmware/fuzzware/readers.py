"""Bounded, in-memory readers. Only read_artifact opens an explicit input file."""

from dataclasses import dataclass
import hashlib
from io import BytesIO
import os
from pathlib import Path
import stat
from typing import Self

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from pydantic import Field, model_validator
import yaml
from yaml.events import AliasEvent

from chipchain.domain.case import ArtifactRef
from chipchain.domain.common import Contract
from chipchain.tools.contracts import InterruptTriggerDetails, MmioModelDetails, MmioModelKind

IMAGE_CAP = 4 * 1024 * 1024
CONFIG_CAP = 256 * 1024
INPUT_CAP = 1024 * 1024
MODEL_CAP = 128
SYMBOL_CAP = 10000
FUNCTION_CAP = 4096


class FirmwareIngestionError(ValueError):
    """Malformed, unsupported or identity-inconsistent input; no partial batch."""


def read_artifact(ref: ArtifactRef, cap: int) -> bytes:
    if ref.sha256 is None or ref.size_bytes is None:
        raise FirmwareIngestionError("All four artifacts require declared sha256 and size_bytes")
    try:
        # Nonblocking open allows rejecting special files without waiting on a FIFO.
        fd = os.open(ref.path, os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > cap:
                raise FirmwareIngestionError("Artifact must be a bounded regular file")
            data = stream.read(cap + 1)
            after = os.fstat(stream.fileno())
        if len(data) > cap or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise FirmwareIngestionError("Artifact exceeds bound or changed during read")
    except OSError as exc:
        raise FirmwareIngestionError("Cannot read declared artifact") from exc
    if len(data) != ref.size_bytes or hashlib.sha256(data).hexdigest() != ref.sha256:
        raise FirmwareIngestionError("Declared artifact fingerprint does not match local bytes")
    return data


class _Loader(yaml.SafeLoader):
    """Reject aliases; bound syntax before constructing Python collections."""

    def __init__(self, stream):
        super().__init__(stream)
        self._depth = 0
        self._nodes = 0

    def compose_node(self, parent, index):
        if self.check_event(AliasEvent):
            raise FirmwareIngestionError("YAML aliases are unsupported")
        self._nodes += 1
        self._depth += 1
        try:
            if self._depth > 12 or self._nodes > 8192:
                raise FirmwareIngestionError("YAML depth/node bound exceeded")
            node = super().compose_node(parent, index)
            if isinstance(node, yaml.ScalarNode) and len(node.value) > 512:
                raise FirmwareIngestionError("YAML scalar bound exceeded")
            if isinstance(node, (yaml.MappingNode, yaml.SequenceNode)) and len(node.value) > 256:
                raise FirmwareIngestionError("YAML collection bound exceeded")
            return node
        finally:
            self._depth -= 1

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if type(key) is not str or key in result:
                raise FirmwareIngestionError("YAML requires unique string mapping keys")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


class Region(Contract):
    base_addr: int = Field(ge=0, le=0xffffffff, strict=True)
    size: int = Field(gt=0, le=0x100000000, strict=True)
    permissions: str = Field(pattern=r"^[r-][w-][x-]$")
    file: str | None = Field(default=None, min_length=1, max_length=512)

    @model_validator(mode="after")
    def no_wrap(self) -> Self:
        if self.base_addr + self.size > 0x100000000:
            raise ValueError("Memory region wraps ARM32 address space")
        return self


@dataclass(frozen=True)
class Configuration:
    regions: dict[str, Region]
    models: tuple[MmioModelDetails, ...]
    trigger: InterruptTriggerDetails


def _keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise FirmwareIngestionError("Unsupported Heat_Press YAML layout/fields")


def parse_configuration(data: bytes, config_path: str, bin_path: str) -> Configuration:
    if len(data) > CONFIG_CAP:
        raise FirmwareIngestionError("YAML byte bound exceeded")
    try:
        d = yaml.load(data.decode("utf-8"), Loader=_Loader)
        _keys(d, {"interrupt_triggers", "memory_map", "mmio_models"})
        _keys(d["interrupt_triggers"], {"trigger"})
        _keys(d["interrupt_triggers"]["trigger"], {"every_nth_tick", "fuzz_mode"})
        trigger = InterruptTriggerDetails(config_key="trigger", **d["interrupt_triggers"]["trigger"])
        _keys(d["memory_map"], {"irq_ret", "mmio", "nvic", "ram", "text"})
        regions = {}
        for name, raw in d["memory_map"].items():
            _keys(raw, {"base_addr", "size", "permissions"} | ({"file"} if name == "text" else set()))
            regions[name] = Region.model_validate(raw)
        if regions["text"].permissions != "r-x" or any(regions[n].permissions != "rw-" for n in ("mmio", "nvic", "ram")) or regions["irq_ret"].permissions != "--x":
            raise FirmwareIngestionError("Unsupported region permissions")
        ordered = sorted(regions.values(), key=lambda r: r.base_addr)
        if any(a.base_addr + a.size > b.base_addr for a, b in zip(ordered, ordered[1:])):
            raise FirmwareIngestionError("Overlapping configuration regions")
        # Normalize only: never open the config's path or any implied companion.
        declared = Path(config_path).resolve().parent / regions["text"].file
        if declared.resolve() != Path(bin_path).resolve():
            raise FirmwareIngestionError("Configuration file reference does not match explicit BIN artifact")
        groups = d["mmio_models"]
        if not isinstance(groups, dict) or not groups or set(groups) - {k.value for k in MmioModelKind}:
            raise FirmwareIngestionError("Unsupported MMIO model groups")
        models, keys = [], set()
        for kind, entries in sorted(groups.items()):
            if not isinstance(entries, dict):
                raise FirmwareIngestionError("MMIO model group must be a mapping")
            for key, value in sorted(entries.items()):
                if not isinstance(value, dict) or not {"pc", "addr", "access_size"} <= value.keys():
                    raise FirmwareIngestionError("Missing MMIO model fields")
                if any(type(value[k]) is not int for k in ("pc", "addr", "access_size")):
                    raise FirmwareIngestionError("MMIO fields require integers, not coerced values")
                if key in keys:
                    raise FirmwareIngestionError("Duplicate MMIO identifier across groups")
                keys.add(key)
                model = MmioModelDetails(pc=value["pc"], mmio_address=value["addr"],
                    access_size_bytes=value["access_size"], model_kind=kind, config_key=key,
                    parameters={k: v for k, v in value.items() if k not in ("pc", "addr", "access_size")})
                text, mmio = regions["text"], regions["mmio"]
                if not text.base_addr <= model.pc < text.base_addr + text.size:
                    raise FirmwareIngestionError("Model PC outside configured image")
                if not mmio.base_addr <= model.mmio_address <= mmio.base_addr + mmio.size - model.access_size_bytes:
                    raise FirmwareIngestionError("Model address outside configured MMIO")
                models.append(model)
                if len(models) > MODEL_CAP:
                    raise FirmwareIngestionError("MMIO entry bound exceeded")
        if not models:
            raise FirmwareIngestionError("Empty MMIO model set")
        return Configuration(regions, tuple(models), trigger)
    except (yaml.YAMLError, UnicodeError, ValueError, TypeError, OSError) as exc:
        if isinstance(exc, FirmwareIngestionError):
            raise
        raise FirmwareIngestionError("Malformed or unsupported configuration") from exc


@dataclass(frozen=True)
class LoadSegment:
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    flags: int


@dataclass(frozen=True)
class Function:
    name: str
    raw_value: int
    address: int
    size: int


@dataclass(frozen=True)
class Image:
    entry: int
    segments: tuple[LoadSegment, ...]
    functions: tuple[Function, ...]

    def locate(self, address: int, size: int) -> LoadSegment:
        matches = [s for s in self.segments if s.flags & 1 and s.vaddr <= address and address + size <= s.vaddr + s.filesz]
        if len(matches) != 1:
            raise FirmwareIngestionError("Code range is not in one file-backed executable LOAD")
        return matches[0]


def _range(offset: int, length: int, total: int) -> None:
    if offset < 0 or length < 0 or offset + length > total:
        raise FirmwareIngestionError("ELF/BIN range exceeds file bounds")


def parse_image(data: bytes, binary: bytes, text: Region) -> Image:
    if len(data) > IMAGE_CAP or len(binary) > IMAGE_CAP or len(binary) > text.size:
        raise FirmwareIngestionError("Image bound exceeded")
    try:
        elf = ELFFile(BytesIO(data))
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM" or elf["e_type"] != "ET_EXEC":
            raise FirmwareIngestionError("Only ELF32 little-endian ARM executables are supported")
        if not 0 < elf["e_phnum"] <= 32 or not 0 < elf["e_shnum"] <= 256:
            raise FirmwareIngestionError("ELF segment/section count unsupported")
        if elf["e_phentsize"] != 32 or elf["e_shentsize"] != 40 or elf["e_ehsize"] != 52:
            raise FirmwareIngestionError("Unsupported ELF header sizes")
        _range(elf["e_phoff"], elf["e_phnum"] * 32, len(data))
        _range(elf["e_shoff"], elf["e_shnum"] * 40, len(data))
        segments = []
        for ph in elf.iter_segments():
            if ph["p_type"] != "PT_LOAD":
                continue
            s = LoadSegment(*(ph[k] for k in ("p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz", "p_flags")))
            _range(s.offset, s.filesz, len(data))
            if s.filesz > s.memsz or max(s.vaddr + s.memsz, s.paddr + s.filesz) > 0x100000000:
                raise FirmwareIngestionError("Invalid LOAD memory/file range")
            if s.filesz:
                index = s.paddr - text.base_addr
                _range(index, s.filesz, len(binary))
                if data[s.offset:s.offset+s.filesz] != binary[index:index+s.filesz]:
                    raise FirmwareIngestionError("ELF/BIN LOAD bytes differ")
            segments.append(s)
        if not segments or not any(s.filesz and s.flags & 1 for s in segments):
            raise FirmwareIngestionError("ELF lacks file-backed executable LOAD")
        for attr, sizeattr in (("vaddr", "memsz"), ("paddr", "filesz")):
            ordered = sorted((s for s in segments if getattr(s, sizeattr)), key=lambda s: getattr(s, attr))
            if any(getattr(a, attr)+getattr(a, sizeattr) > getattr(b, attr) for a, b in zip(ordered, ordered[1:])):
                raise FirmwareIngestionError("Overlapping LOAD ranges")
        functions, count = [], 0
        for section in elf.iter_sections():
            if section["sh_type"] != "SHT_NOBITS":
                _range(section["sh_offset"], section["sh_size"], len(data))
            if isinstance(section, SymbolTableSection):
                if section["sh_entsize"] != 16 or section["sh_size"] % 16:
                    raise FirmwareIngestionError("Malformed symbol table")
                count += section.num_symbols()
                if count > SYMBOL_CAP or not 0 <= section["sh_link"] < elf["e_shnum"]:
                    raise FirmwareIngestionError("Symbol count/link bound exceeded")
                strings = elf.get_section(section["sh_link"])
                _range(strings["sh_offset"], strings["sh_size"], len(data))
                if strings["sh_type"] != "SHT_STRTAB" or strings["sh_size"] > INPUT_CAP:
                    raise FirmwareIngestionError("Invalid symbol string table")
                for symbol in section.iter_symbols():
                    if symbol["st_name"] >= strings["sh_size"]:
                        raise FirmwareIngestionError("Invalid symbol name offset")
                    if symbol["st_info"]["type"] == "STT_FUNC" and isinstance(symbol["st_shndx"], int) and symbol["st_size"]:
                        if symbol["st_shndx"] >= elf["e_shnum"] or len(symbol.name) > 256:
                            raise FirmwareIngestionError("Invalid function symbol")
                        raw = symbol["st_value"]
                        if (raw & ~1) + symbol["st_size"] > 0x100000000:
                            raise FirmwareIngestionError("Function address wraps")
                        functions.append(Function(symbol.name, raw, raw & ~1, symbol["st_size"]))
        image = Image(elf["e_entry"], tuple(segments), tuple(sorted(set(functions), key=lambda f: (f.address, f.size, f.name))))
        if not image.entry & 1:
            raise FirmwareIngestionError("Entry does not declare Thumb state")
        image.locate(image.entry & ~1, 2)
        return image
    except Exception as exc:
        # pyelftools may raise ELFError, struct errors or assertions for corrupt input.
        if isinstance(exc, FirmwareIngestionError):
            raise
        raise FirmwareIngestionError("Malformed or unsupported ELF") from exc
