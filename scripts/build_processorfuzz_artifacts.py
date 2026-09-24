"""Re-run a reviewed ProcessorFuzz ZIP and sync canonical review artifacts."""
from __future__ import annotations

import argparse
from pathlib import Path
from shutil import copy2

from chipchain.workflow.processorfuzz import analyze_package, HARDWARE_TRIGGER_VALIDATION

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--output", default="output/processorfuzz-real-case-001")
    args = parser.parse_args()
    target = analyze_package(ROOT / args.package, ROOT / args.output,
                             role_declaration=HARDWARE_TRIGGER_VALIDATION)
    destinations = (ROOT / "samples/processorfuzz/real_case_001/expected",
                    ROOT / "artifacts/demo/processorfuzz/real_case_001")
    for destination in destinations:
        destination.mkdir(parents=True, exist_ok=True)
        for source in sorted(target.iterdir()):
            if source.is_file():
                copy2(source, destination / source.name)
    print(f"Synced {len(list(target.iterdir()))} artifacts from {target}")


if __name__ == "__main__":
    main()
