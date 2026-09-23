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
    args = parser.parse_args(argv)
    try:
        analysis = analyze_manifest(args.manifest)
        output = write_result(analysis, args.output, verbose_artifacts=args.verbose_artifacts)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"chipchain: {type(exc).__name__}: {exc}\n")
    print(f"{analysis.result.final_status}: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
