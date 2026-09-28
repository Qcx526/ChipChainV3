"""Thin CLI over the existing-artifact Type-II workflow."""
from __future__ import annotations

import argparse
from pathlib import Path
from zipfile import BadZipFile

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
    processorfuzz = commands.add_parser("processorfuzz", help="ingest ProcessorFuzz delivery")
    processorfuzz_commands = processorfuzz.add_subparsers(dest="processorfuzz_command", required=True)
    processorfuzz_analyze = processorfuzz_commands.add_parser("analyze", help="analyze package without LLM")
    processorfuzz_analyze.add_argument("--package", required=True)
    processorfuzz_analyze.add_argument("--output", required=True)
    processorfuzz_analyze.add_argument("--ghidra-home")
    processorfuzz_analyze.add_argument("--si-member", help="exact package-relative SI member for analysis; not a provenance binding")
    processorfuzz_analyze.add_argument("--elf-member", help="exact package-relative ELF member for analysis; not a provenance binding")
    processorfuzz_analyze.add_argument("--hardware-trigger-validation", action="store_true",
                                      help="explicitly classify this hardware-team delivery and its trigger-test ELF")
    type2 = commands.add_parser("type2", help="prepare an independently analyzed cross-layer case")
    type2_commands = type2.add_subparsers(dest="type2_command", required=True)
    type2_prepare = type2_commands.add_parser("prepare", help="assemble readiness without verification")
    type2_prepare.add_argument("--firmware", required=True, help="firmware analyze output directory")
    type2_prepare.add_argument("--hardware", required=True, help="processorfuzz analyze output directory")
    type2_prepare.add_argument("--output", required=True, help="new or empty case directory")
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
        if args.command == "processorfuzz":
            from chipchain.workflow.processorfuzz import analyze_package, HARDWARE_TRIGGER_VALIDATION
            output = analyze_package(args.package, args.output, ghidra_home=args.ghidra_home,
                                     si_member=args.si_member, elf_member=args.elf_member,
                                     role_declaration=HARDWARE_TRIGGER_VALIDATION
                                     if args.hardware_trigger_validation else None)
            print(f"ProcessorFuzz analysis: {output}")
            return 0
        if args.command == "type2":
            from chipchain.cross_layer.case_assembly import prepare_case, write_case
            target = Path(args.output).resolve()
            if any(target.is_relative_to(Path(source).resolve())
                   for source in (args.firmware, args.hardware)):
                raise ValueError("Case output must be outside both input directories")
            prepared = prepare_case(args.firmware, args.hardware)
            output = write_case(prepared, args.output)
            print(f"{prepared.case_manifest['case_id']}: {output}; "
                  f"verification_ready={str(prepared.readiness['ready']).lower()}")
            return 0
        analysis = analyze_manifest(args.manifest)
        output = write_result(analysis, args.output, verbose_artifacts=args.verbose_artifacts)
    except (OSError, ValueError, TypeError, RuntimeError, BadZipFile) as exc:
        parser.exit(2, f"chipchain: {type(exc).__name__}: {exc}\n")
    print(f"{analysis.result.final_status}: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
