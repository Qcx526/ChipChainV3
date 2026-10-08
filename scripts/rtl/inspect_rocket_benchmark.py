#!/usr/bin/env python3
"""Read-only ZIP/Verilog diagnostics for an explicit RTL reproduction input.

This is a textual inventory, not a Verilog elaborator or an execution attestation.
No imported archive code is executed. The CLI writes only into the ignored RTL
research workspace and never edits or repacks the supplied archive.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile


MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024


class InspectionError(ValueError):
    """The supplied input cannot be safely and unambiguously inventoried."""


def _digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def _check_digest(actual: str, expected: str | None, label: str) -> None:
    if expected is not None:
        if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise InspectionError(f"Invalid expected SHA256 for {label}")
        if actual != expected:
            raise InspectionError(f"SHA256 mismatch for {label}: expected {expected}; actual {actual}")


def safe_member_name(name: str) -> str:
    """Return a canonical ZIP-relative name, refusing portable path hazards."""
    if not name or "\\" in name or "\x00" in name or name.startswith("/"):
        raise InspectionError(f"Unsafe archive member path: {name!r}")
    candidate = name[:-1] if name.endswith("/") else name
    parts = candidate.split("/")
    if any(part in {"", ".", ".."} for part in parts) or ":" in parts[0]:
        raise InspectionError(f"Unsafe archive member path: {name!r}")
    if str(PurePosixPath(candidate)) != candidate:
        raise InspectionError(f"Unsafe archive member path: {name!r}")
    return candidate


def read_archive(path: Path, *, expected_sha256: str | None = None) -> tuple[str, dict[str, bytes], list[dict]]:
    """Validate every member before returning unmodified decompressed bytes."""
    if path.is_symlink() or not path.is_file():
        raise InspectionError("Input ZIP must be an existing regular file, not a symlink")
    archive_bytes = path.read_bytes()
    archive_sha = _digest(archive_bytes)
    _check_digest(archive_sha, expected_sha256, "input ZIP")
    try:
        with zipfile.ZipFile(BytesIO(archive_bytes)) as archive:
            infos = archive.infolist()
            names: dict[str, zipfile.ZipInfo] = {}
            total_size = 0
            for info in infos:
                name = safe_member_name(info.filename)
                if name in names:
                    raise InspectionError(f"Duplicate archive member path: {name}")
                mode = info.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if kind == stat.S_IFLNK:
                    raise InspectionError(f"Unsafe archive symlink: {name}")
                if kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise InspectionError(f"Unsafe special archive member: {name}")
                if kind != 0 and info.is_dir() != (kind == stat.S_IFDIR):
                    raise InspectionError(f"Conflicting archive member kind: {name}")
                if info.flag_bits & 1:
                    raise InspectionError(f"Encrypted archive member is not supported: {name}")
                total_size += info.file_size
                if info.file_size > MAX_MEMBER_BYTES or total_size > MAX_TOTAL_BYTES:
                    raise InspectionError("Archive exceeds the bounded uncompressed input limit")
                names[name] = info
            for name in names:
                for parent in PurePosixPath(name).parents:
                    if str(parent) in names and not names[str(parent)].is_dir():
                        raise InspectionError(f"Archive path has a file as parent: {name}")
            files: dict[str, bytes] = {}
            rows = []
            for name, info in sorted(names.items()):
                data = b"" if info.is_dir() else archive.read(info)
                if not info.is_dir():
                    files[name] = data
                rows.append({"member": name, "kind": "directory" if info.is_dir() else "file",
                             "size_bytes": len(data), "sha256": None if info.is_dir() else _digest(data)})
            return archive_sha, files, rows
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        raise InspectionError(f"Unreadable ZIP: {exc}") from exc


def select_rtl(files: dict[str, bytes], member: str | None, *, expected_sha256: str | None = None) -> tuple[str, bytes]:
    candidates = sorted(name for name in files if name.endswith((".v", ".sv")))
    if member is None:
        if len(candidates) != 1:
            raise InspectionError(f"RTL selection is ambiguous; select an exact member from {candidates}")
        member = candidates[0]
    if safe_member_name(member) != member or member not in files:
        raise InspectionError(f"Selected RTL member is absent: {member}")
    if member not in candidates:
        raise InspectionError("Selected RTL input must be an explicit .v or .sv member")
    data = files[member]
    _check_digest(_digest(data), expected_sha256, f"RTL member {member}")
    return member, data


def inspect_verilog(data: bytes, *, top: str) -> dict:
    """Collect source-text clues without pretending to elaborate preprocessor branches."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InspectionError("Selected Verilog is not UTF-8 source text") from exc
    source = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
    modules = re.findall(r"\bmodule\s+([A-Za-z_$][\w$]*)", source)
    if modules.count(top) != 1:
        raise InspectionError(f"Requested top module {top!r} must have exactly one declaration")
    match = re.search(rf"\bmodule\s+{re.escape(top)}\s*\((.*?)\)\s*;", source, flags=re.S)
    if match is None:
        raise InspectionError("Top port inspection requires an explicit ANSI header without parameter syntax")
    ports = []
    for port in re.finditer(r"\b(input|output|inout)\s*(?:(?:wire|reg|logic|signed)\s+)*(\[[^\]]+\])?\s*([A-Za-z_$][\w$]*)", match.group(1)):
        ports.append({"direction": port.group(1), "packed_range": port.group(2), "name": port.group(3)})
    lines = text.splitlines()
    clue_patterns = {
        "csr": r"\b(?:CSRFile|reg_(?:mstatus|satp|mepc|mcause|mtval|scause|pmp\w*)|csr\w*)\b",
        "mmu_tlb_ptw": r"\b(?:TLB(?:_\d+)?|PTW|sfence\w*|satp\w*|reg_satp\w*)\b",
        "trace": r"\$fwrite|\$fopen|coreMonitorBundle|auto_trace|cmt_instr|\$value\$plusargs\(\"TRACE",
        "coverage_state_instrumentation": r"\bio_covSum\b|\bmetaReset\b|\bCOV_SR\b|\bMULTICORE\b|_cov\b",
    }
    clues = {category: [{"line": i, "text": line.strip()} for i, line in enumerate(lines, 1)
                        if re.search(pattern, line)][:80] for category, pattern in clue_patterns.items()}
    interface = {
        "tilelink_port_names": sorted(port["name"] for port in ports if "auto_tl_" in port["name"]),
        "uart_port_names": sorted(port["name"] for port in ports if re.search(r"uart|serial", port["name"], re.I)),
        "trace_port_names": sorted(port["name"] for port in ports if re.search(r"trace|broadcast|cmt_instr", port["name"])),
    }
    return {"inspection_kind": "source_text_only_not_elaboration", "module_count": len(modules),
            "modules": modules, "requested_top": top, "top_ports": ports,
            "conditional_top_ports": "preprocessor directives are unelaborated; listed ports may be conditional",
            "interface_clues": interface, "source_clues": clues,
            "processor_configuration": "UNKNOWN; signal widths and module names are source clues only",
            "rtl_generation_provenance": "NOT_ESTABLISHED by archive contents alone"}


def inventory(path: Path, *, expected_zip_sha256: str | None, rtl_member: str | None,
              expected_rtl_sha256: str | None, top: str) -> tuple[dict, dict[str, bytes]]:
    archive_sha, files, members = read_archive(path, expected_sha256=expected_zip_sha256)
    selected, data = select_rtl(files, rtl_member, expected_sha256=expected_rtl_sha256)
    verilog = {name: inspect_verilog(blob, top=top) for name, blob in sorted(files.items())
               if name.endswith((".v", ".sv")) and re.search(rf"\bmodule\s+{re.escape(top)}\b", blob.decode("utf-8", errors="replace"))}
    result = {"schema_version": "rocket-rtl-input-inventory/v1", "purpose": "feasibility_diagnostics_only_not_hardware_runtime_evidence",
              "input": {"path": str(path.resolve()), "zip_sha256": archive_sha}, "members": members,
              "selected_rtl": {"member": selected, "sha256": _digest(data), "top": top},
              "verilog": verilog, "execution_observed": False}
    return result, files


def write_inventory(output: Path, result: dict, files: dict[str, bytes], *, extract_members: list[str]) -> None:
    if output.is_symlink() or output.exists():
        raise InspectionError("Output must be a new directory; existing results are never overwritten")
    selected = []
    for member in extract_members:
        if safe_member_name(member) != member or member not in files:
            raise InspectionError(f"Requested extraction member is absent: {member}")
        if member not in selected:
            selected.append(member)
    output.mkdir(parents=True)
    for member in selected:
        destination = output.joinpath(*PurePosixPath(member).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as handle:
            handle.write(files[member])
        destination.chmod(0o444)
    (output / "input-inventory.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zip", required=True, type=Path)
    parser.add_argument("--expected-zip-sha256", required=True)
    parser.add_argument("--rtl-member", required=True)
    parser.add_argument("--expected-rtl-sha256", required=True)
    parser.add_argument("--top", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--extract-member", action="append", default=[], help="Exact extra member to extract; selected RTL is included")
    args = parser.parse_args(argv)
    try:
        workspace = Path(__file__).resolve().parents[2] / "output/rtl-rocket-feasibility"
        resolved_output = args.output.resolve()
        if not resolved_output.is_relative_to(workspace.resolve()) or resolved_output == workspace.resolve():
            raise InspectionError("Output must be a new child of output/rtl-rocket-feasibility/")
        result, files = inventory(args.zip, expected_zip_sha256=args.expected_zip_sha256,
                                  rtl_member=args.rtl_member, expected_rtl_sha256=args.expected_rtl_sha256,
                                  top=args.top)
        write_inventory(resolved_output, result, files, extract_members=[args.rtl_member, *args.extract_member])
        print(f"Input inventory written: {resolved_output / 'input-inventory.json'}")
        print("RTL inspection does not establish execution or generation provenance.")
        return 0
    except (InspectionError, OSError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
