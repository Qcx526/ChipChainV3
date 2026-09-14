"""Explicit read-only extraction API; never writes persistent outputs implicitly."""
from pathlib import Path

from chipchain.tools.architecture.cortex_m import CortexMVectorResult, vector_table
from .elf import parse_elf
from .models import GhidraStaticStructureResult
from .normalize import normalize_export
from .process import export_heat_press, ELF_SIZE, ELF_SHA256, GhidraError


def extract_heat_press_structure(
    elf_path: Path, *, ghidra_home: Path, script_path: Path,
    case_id: str = 'fuzzware:heat-press:scenario-13',
    temporary_parent: Path | None = None,
) -> tuple[GhidraStaticStructureResult, CortexMVectorResult]:
    raw, version, script_hash = export_heat_press(
        elf_path, ghidra_home=ghidra_home, script_path=script_path,
        temporary_parent=temporary_parent,
    )
    import hashlib
    with elf_path.open('rb') as stream:
        data = stream.read(ELF_SIZE + 1)
    if len(data) != ELF_SIZE or hashlib.sha256(data).hexdigest() != ELF_SHA256:
        raise GhidraError('ELF changed before normalization')
    result = normalize_export(raw, data, case_id=case_id,
                              expected_version=version, script_sha256=script_hash)
    return result, vector_table(parse_elf(data), result.functions)
