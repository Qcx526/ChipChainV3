"""Thin CLI over the existing-artifact Type-II workflow."""
from __future__ import annotations

import argparse

from chipchain.workflow.type2 import analyze_manifest, write_result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="chipchain")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="verify existing Type-II artifacts")
    analyze.add_argument("--manifest", required=True, help="canonical artifact index JSON")
    analyze.add_argument("--output", default="output/type2-result", help="result directory")
    analyze.add_argument("--verbose-artifacts", action="store_true")
    firmware = commands.add_parser("firmware", help="multi-architecture static firmware analysis")
    firmware_commands = firmware.add_subparsers(dest="firmware_command", required=True)
    firmware_analyze = firmware_commands.add_parser("analyze", help="analyze ELF with project Ghidra")
    firmware_analyze.add_argument("--elf", required=True)
    firmware_analyze.add_argument("--output", required=True)
    firmware_analyze.add_argument("--ghidra-home")
    args = parser.parse_args(argv)
    try:
        if args.command == "firmware":
            from chipchain.firmware.elf import ElfImage
            from chipchain.firmware.ghidra import analyze_headless
            from chipchain.firmware.ghidra_normalize import normalize
            from chipchain.firmware.report import write_firmware_result
            image = ElfImage.from_path(args.elf)
            exported = analyze_headless(args.elf, image, ghidra_home=args.ghidra_home)
            result = normalize(image, exported)
            output = write_firmware_result(result, args.output,
                                           export=exported.model_dump(mode="json", by_alias=True))
            print(f"{result.analysis_id}: {output}")
            return 0
        analysis = analyze_manifest(args.manifest)
        output = write_result(analysis, args.output, verbose_artifacts=args.verbose_artifacts)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"chipchain: {type(exc).__name__}: {exc}\n")
    print(f"{analysis.result.final_status}: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
