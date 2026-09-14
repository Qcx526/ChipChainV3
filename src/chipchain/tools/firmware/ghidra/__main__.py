"""Explicit local CLI; writes only a new UUID output directory on success."""
import argparse
import os
from pathlib import Path
from uuid import uuid4

from .api import extract_heat_press_structure
from .models import semantic_json
from .process import GhidraError


def main() -> None:
    parser = argparse.ArgumentParser(description='Headless Heat_Press static structure (no model)')
    parser.add_argument('--elf', required=True, type=Path)
    parser.add_argument('--ghidra-home', type=Path, default=os.environ.get('CHIPCHAIN_GHIDRA_HOME'))
    parser.add_argument('--script', type=Path,
                        default=Path(__file__).resolve().parents[5]/'scripts/ghidra/ExportFirmwareStructure.java')
    parser.add_argument('--output-root', type=Path, default=Path('output'))
    args = parser.parse_args()
    if args.ghidra_home is None:
        parser.error('Provide --ghidra-home or CHIPCHAIN_GHIDRA_HOME explicitly')
    try:
        structure, vectors = extract_heat_press_structure(args.elf, ghidra_home=args.ghidra_home,
                                                          script_path=args.script)
    except (GhidraError, OSError):
        parser.exit(1, 'Static extraction failed; verify installation and the approved ELF.\n')
    destination = args.output_root/structure.case_id/str(uuid4())
    destination.mkdir(parents=True, exist_ok=False)
    (destination/'ghidra_static_structure.json').write_text(semantic_json(structure), encoding='utf-8')
    (destination/'cortex_m_vectors.json').write_text(vectors.model_dump_json(indent=2), encoding='utf-8')
    print(destination)


if __name__ == '__main__':
    main()
