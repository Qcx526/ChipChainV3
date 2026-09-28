#!/usr/bin/env python3
"""Read-only, bounded inventory for developers adapting hardware deliveries.

This utility is not a ChipChain evidence producer or scientific analysis stage.
"""

from __future__ import annotations

import argparse
import codecs
from collections import Counter, defaultdict
import csv
from hashlib import sha256
import html
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys
import tarfile
import zipfile


CHUNK = 1024 * 1024
PREVIEW = 64 * 1024
MAX_MEMBERS = 20_000
MAX_FILE_BYTES = 2 * 1024**3
MAX_TOTAL_BYTES = 4 * 1024**3
MAX_ARCHIVE_BYTES = 4 * 1024**3
BRIEF_LIST_LIMIT = 12

SURFACES = (
    "src/chipchain/workflow/processorfuzz.py",
    "src/chipchain/runtime/processorfuzz.py",
    "src/chipchain/firmware/processorfuzz_si.py",
    "src/chipchain/firmware/elf.py",
    "tests/unit/test_processorfuzz_ingestion.py",
    "tests/integration/test_processorfuzz_real_case.py",
    "samples/processorfuzz/real_case_001/",
    "artifacts/demo/processorfuzz/real_case_001/",
)


def _safe_member_path(name: str) -> str:
    parts = PurePosixPath(name).parts
    if (not name or name.startswith("/") or "\\" in name or ".." in parts
            or re.match(r"^[A-Za-z]:", name)):
        raise ValueError(f"Unsafe archive member path: {name!r}")
    normalized = PurePosixPath(name).as_posix()
    if normalized in ("", "."):
        raise ValueError(f"Unsafe archive member path: {name!r}")
    return normalized


def _elf_header(prefix: bytes) -> dict | None:
    if not prefix.startswith(b"\x7fELF"):
        return None
    result: dict[str, object] = {"status": "truncated_or_invalid"}
    if len(prefix) < 16 or prefix[4] not in (1, 2) or prefix[5] not in (1, 2):
        return result
    bits = 32 if prefix[4] == 1 else 64
    endian = "little" if prefix[5] == 1 else "big"
    minimum = 52 if bits == 32 else 64
    if len(prefix) < minimum:
        return result
    order = "<" if endian == "little" else ">"
    elf_type_number = struct.unpack_from(order + "H", prefix, 16)[0]
    elf_type = {1: "relocatable", 2: "executable", 3: "shared_object", 4: "core"}.get(
        elf_type_number, "other")
    machine_number = struct.unpack_from(order + "H", prefix, 18)[0]
    entry = struct.unpack_from(order + ("I" if bits == 32 else "Q"), prefix, 24)[0]
    machine = {3: "x86", 20: "powerpc", 21: "powerpc64", 40: "arm",
               62: "x86_64", 183: "aarch64", 243: "riscv"}.get(machine_number, "other")
    return {"status": "header_read", "elf_type": elf_type, "elf_type_number": elf_type_number,
            "machine": machine, "machine_number": machine_number,
            "bits": bits, "endian": endian, "entry_point": f"0x{entry:x}"}


def _filename_hints(relative_path: str, *, is_directory: bool) -> list[str]:
    path = PurePosixPath(relative_path)
    name = path.name.lower()
    parts = [part.lower() for part in path.parts]
    hints: set[str] = set()
    if any(part in {"build", "obj", "verilated", "verilator"} for part in parts[:-1]) or (
            name.endswith((".o", ".a", ".d", ".so", ".cpp", ".h")) and "vtop" in name):
        hints.add("generated_build_like")
    if name.endswith(".elf"):
        hints.add("elf_extension_like")
    if name.endswith(".si"):
        hints.add("si_source_like")
    if name.endswith((".asm", ".s", ".hex", ".symbols")):
        hints.add("source_or_listing_like")
    if "rtl_sig" in name or "isa_sig" in name:
        hints.add("signature_like")
    if re.fullmatch(r"(?:rtl|isa)_\d+\.(?:log|csv)", name):
        hints.add("execution_trace_like")
    if "cfg" in name:
        hints.add("cfg_like")
    if "transition" in name:
        hints.add("transition_like")
    if name.startswith("note") or "readme" in name:
        hints.add("human_note_like")
    if any(part in {"corpus", "crashes", "mismatch", "illegal"} for part in parts):
        hints.add("corpus_or_crash_path_like")
    if is_directory and name in {"build", "obj"}:
        hints.add("generated_build_like")
    return sorted(hints)


def _bounded_text_metadata(facts: dict, preview: bytes) -> None:
    if facts["text_status"] != "utf8_text":
        return
    extension = facts["extension"]
    if extension == ".csv" and b"\n" in preview:
        try:
            header = next(csv.reader([preview.split(b"\n", 1)[0].decode("utf-8")]))
        except (UnicodeDecodeError, csv.Error, StopIteration):
            pass
        else:
            facts["csv_header"] = [value[:128] for value in header[:32]]
            facts["csv_header_truncated"] = len(header) > 32
    if extension == ".json" and facts["size_bytes"] <= PREVIEW:
        try:
            value = json.loads(preview.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
        else:
            facts["json_top_level_type"] = (
                "null" if value is None else "boolean" if isinstance(value, bool)
                else "object" if isinstance(value, dict) else "array" if isinstance(value, list)
                else "string" if isinstance(value, str) else "number"
            )


def _inspect_file(stream, expected_size: int, relative_path: str, container: str) -> dict:
    digest = sha256()
    preview = bytearray()
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    valid_utf8 = True
    has_nul = False
    newline_count = 0
    last_byte = None
    count = 0
    while chunk := stream.read(CHUNK):
        count += len(chunk)
        if count > expected_size or count > MAX_FILE_BYTES:
            raise ValueError(f"File exceeds declared or allowed size: {relative_path}")
        digest.update(chunk)
        if len(preview) < PREVIEW:
            preview.extend(chunk[:PREVIEW - len(preview)])
        has_nul |= b"\x00" in chunk
        newline_count += chunk.count(b"\n")
        last_byte = chunk[-1]
        if valid_utf8:
            try:
                decoder.decode(chunk)
            except UnicodeDecodeError:
                valid_utf8 = False
    if count != expected_size:
        raise ValueError(f"File size changed or archive entry is truncated: {relative_path}")
    if valid_utf8:
        try:
            decoder.decode(b"", final=True)
        except UnicodeDecodeError:
            valid_utf8 = False
    text_status = "utf8_text" if valid_utf8 and not has_nul else "binary"
    prefix = bytes(preview)
    elf = _elf_header(prefix)
    content_kind = ("elf" if elf is not None else "zip" if prefix.startswith(b"PK\x03\x04")
                    else "empty" if count == 0 else text_status)
    facts = {"entry_type": "regular_file", "container_type": container,
             "size_bytes": count, "sha256": digest.hexdigest(),
             "extension": PurePosixPath(relative_path).suffix.lower(),
             "detected_content_kind": content_kind, "text_status": text_status,
             "inspection_prefix_bytes": len(prefix), "inspection_prefix_truncated": count > PREVIEW}
    if text_status == "utf8_text":
        facts["lf_line_count"] = newline_count + int(count > 0 and last_byte != 10)
    if elf is not None:
        facts["elf_header"] = elf
    _bounded_text_metadata(facts, prefix)
    return {"relative_path": relative_path, "facts": facts,
            "adaptation_hints": _filename_hints(relative_path, is_directory=False)}


def _directory_entry(relative_path: str, container: str) -> dict:
    return {"relative_path": relative_path,
            "facts": {"entry_type": "directory", "container_type": container,
                      "size_bytes": 0, "sha256": None, "extension": None,
                      "detected_content_kind": "directory", "text_status": "not_applicable"},
            "adaptation_hints": _filename_hints(relative_path, is_directory=True)}


def _scan_directory(root: Path) -> tuple[list[dict], int]:
    rows: list[dict] = []
    total = 0
    pending = [root]
    seen = 0
    while pending:
        current = pending.pop()
        children = []
        with os.scandir(current) as entries:
            for entry in entries:
                seen += 1
                if seen > MAX_MEMBERS:
                    raise ValueError(f"Input exceeds {MAX_MEMBERS} members")
                children.append(entry.name)
        for name in sorted(children):
            path = current / name
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise ValueError(f"Directory input contains unsafe link or special file: {relative}")
            if stat.S_ISDIR(info.st_mode):
                rows.append(_directory_entry(relative, "directory_entry"))
                pending.append(path)
            else:
                if info.st_size > MAX_FILE_BYTES or total + info.st_size > MAX_TOTAL_BYTES:
                    raise ValueError(f"Input exceeds file or total size bound at {relative}")
                total += info.st_size
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                with os.fdopen(os.open(path, flags), "rb") as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        raise ValueError(f"Input changed to a special file: {relative}")
                    rows.append(_inspect_file(stream, info.st_size, relative, "directory_entry"))
    return rows, total


def _scan_zip(path: Path) -> tuple[list[dict], int]:
    rows: list[dict] = []
    total = 0
    seen: set[str] = set()
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_MEMBERS:
            raise ValueError(f"ZIP exceeds {MAX_MEMBERS} members")
        for info in infos:
            if info.is_dir() and info.filename in (".", "./"):
                continue
            relative = _safe_member_path(info.filename)
            if relative in seen:
                raise ValueError(f"Duplicate archive member: {relative}")
            seen.add(relative)
            mode = info.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR) or (info.is_dir() and kind == stat.S_IFREG):
                raise ValueError(f"ZIP contains unsafe link or special member: {relative}")
            if info.is_dir():
                rows.append(_directory_entry(relative, "zip_member"))
                continue
            if info.file_size > MAX_FILE_BYTES or total + info.file_size > MAX_TOTAL_BYTES:
                raise ValueError(f"ZIP exceeds file or total size bound at {relative}")
            total += info.file_size
            with archive.open(info) as stream:
                rows.append(_inspect_file(stream, info.file_size, relative, "zip_member"))
    return rows, total


def _scan_tar(path: Path) -> tuple[list[dict], int]:
    rows: list[dict] = []
    total = 0
    seen: set[str] = set()
    with tarfile.open(path, mode="r|*") as archive:
        for member in archive:
            if member.isdir() and member.name in (".", "./"):
                continue
            relative = _safe_member_path(member.name)
            if relative in seen:
                raise ValueError(f"Duplicate archive member: {relative}")
            seen.add(relative)
            if len(rows) >= MAX_MEMBERS:
                raise ValueError(f"TAR exceeds {MAX_MEMBERS} members")
            if member.isdir():
                rows.append(_directory_entry(relative, "tar_member"))
                continue
            if not member.isfile():
                raise ValueError(f"TAR contains unsafe link, device or special member: {relative}")
            if member.size > MAX_FILE_BYTES or total + member.size > MAX_TOTAL_BYTES:
                raise ValueError(f"TAR exceeds file or total size bound at {relative}")
            total += member.size
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"Cannot read TAR member: {relative}")
            with stream:
                rows.append(_inspect_file(stream, member.size, relative, "tar_member"))
    return rows, total


def inspect(input_path: Path) -> dict:
    if input_path.is_symlink():
        raise ValueError("Input must not be a symlink")
    if input_path.is_dir():
        container = "directory"
        package_sha = None
        package_bytes = None
        rows, total = _scan_directory(input_path)
    elif input_path.is_file():
        package_bytes = input_path.stat().st_size
        if package_bytes > MAX_ARCHIVE_BYTES:
            raise ValueError(f"Archive exceeds {MAX_ARCHIVE_BYTES} bytes")
        digest = sha256()
        with input_path.open("rb") as stream:
            while chunk := stream.read(CHUNK):
                digest.update(chunk)
        package_sha = digest.hexdigest()
        if zipfile.is_zipfile(input_path):
            container = "zip"
            rows, total = _scan_zip(input_path)
        elif tarfile.is_tarfile(input_path):
            container = "tar"
            rows, total = _scan_tar(input_path)
        else:
            raise ValueError("Input file is not a ZIP or TAR archive")
    else:
        raise ValueError("Input must be an existing directory, ZIP or TAR archive")
    rows.sort(key=lambda row: row["relative_path"])
    files = [row for row in rows if row["facts"]["entry_type"] == "regular_file"]
    hint_counts = Counter(hint for row in rows for hint in row["adaptation_hints"])
    return {
        "schema_version": "hardware-sample-inspection/v1",
        "purpose": "development_diagnostics_only_not_scientific_evidence",
        "input": {"name": input_path.name, "container_type": container,
                  "package_sha256": package_sha, "package_size_bytes": package_bytes},
        "limits": {"max_members": MAX_MEMBERS, "max_file_bytes": MAX_FILE_BYTES,
                   "max_total_bytes": MAX_TOTAL_BYTES, "max_archive_bytes": MAX_ARCHIVE_BYTES,
                   "inspection_prefix_bytes": PREVIEW},
        "summary": {"member_count": len(rows), "file_count": len(files),
                    "directory_count": len(rows) - len(files), "total_file_bytes": total,
                    "adaptation_hint_counts": dict(sorted(hint_counts.items()))},
        "artifacts": rows,
    }


def _display(value: str, limit: int = 160) -> str:
    safe = "".join(char if char.isprintable() else f"\\u{ord(char):04x}" for char in value[:limit])
    escaped = html.escape(safe)
    return escaped + ("…" if len(value) > limit else "")


def _file_line(row: dict) -> str:
    facts = row["facts"]
    details = [f"{facts['size_bytes']} bytes"]
    if "lf_line_count" in facts:
        details.append(f"{facts['lf_line_count']} LF-delimited lines")
    if "csv_header" in facts:
        details.append("CSV header: " + ", ".join(_display(x, 80) for x in facts["csv_header"]))
    return f"- {_display(row['relative_path'])} — {'; '.join(details)}"


def _list_section(lines: list[str], heading: str, rows: list[dict]) -> None:
    lines.extend([f"## {heading}", ""])
    if not rows:
        lines.append("No matching filename/content hints in this package. This is not proof that evidence does not exist elsewhere.")
    else:
        lines.extend(_file_line(row) for row in rows[:BRIEF_LIST_LIMIT])
        if len(rows) > BRIEF_LIST_LIMIT:
            lines.append(f"- … {len(rows) - BRIEF_LIST_LIMIT} more; see inventory.json.")
    lines.append("")


def render_brief(inventory: dict) -> str:
    info = inventory["input"]
    summary = inventory["summary"]
    files = [row for row in inventory["artifacts"] if row["facts"]["entry_type"] == "regular_file"]
    has = lambda row, hint: hint in row["adaptation_hints"]
    executables = [row for row in files if row["facts"]["detected_content_kind"] == "elf"]
    noise = [row for row in files if has(row, "generated_build_like")]
    traces = [row for row in files if has(row, "execution_trace_like")]
    signatures = [row for row in files if has(row, "signature_like")]
    stimulus = [row for row in files if has(row, "si_source_like") or has(row, "source_or_listing_like")]
    other = [row for row in files if any(has(row, hint) for hint in (
        "cfg_like", "transition_like", "human_note_like", "corpus_or_crash_path_like"))
             and row not in noise]
    source_elfs = [row for row in executables if not has(row, "generated_build_like")]
    build_elfs = [row for row in executables if has(row, "generated_build_like")]
    shown_elfs = source_elfs[:BRIEF_LIST_LIMIT]
    shown_elfs += build_elfs[:min(3, BRIEF_LIST_LIMIT - len(shown_elfs))]
    lines = ["# Hardware Sample Adaptation Brief", "",
             "> Development diagnostic only. No scientific evidence, provenance binding,",
             "> Type-II judgement or vulnerability conclusion is produced here.", "",
             "## Input", "", f"- Name: {_display(info['name'])}",
             f"- Container: {info['container_type']}",
             f"- Package SHA256: {info['package_sha256'] or 'not applicable (directory)'}",
             f"- Files: {summary['file_count']}; directories: {summary['directory_count']}",
             f"- Total member bytes: {summary['total_file_bytes']}", "",
             "## ELF files and objects", "",
             f"{len(executables)} ELF headers detected; "
             f"{sum(has(row, 'generated_build_like') for row in executables)} in generated-build-like paths. "
             "ELF type comes from the header, not the filename.", ""]
    if executables:
        for row in shown_elfs:
            elf = row["facts"].get("elf_header", {})
            lines.append(f"- {_display(row['relative_path'])} — {elf.get('elf_type', 'unknown')} ELF, "
                         f"{elf.get('machine', 'unknown')}, "
                         f"{elf.get('bits', 'unknown')}-bit, {elf.get('endian', 'unknown')}, "
                         f"entry {elf.get('entry_point', 'unknown')}; status {elf['status']}")
        if len(executables) > len(shown_elfs):
            lines.append(f"- … {len(executables) - len(shown_elfs)} more; see inventory.json.")
    else:
        lines.append("No ELF magic detected in this package.")
    lines.extend(["", "Detection of an ELF inside a hardware delivery does not make it customer firmware.", "",
                  "## Potential testcase groups (adaptation hints only)", ""])
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for row in files:
        path = PurePosixPath(row["relative_path"])
        if not has(row, "generated_build_like"):
            groups[(str(path.parent), path.stem)].append(path.suffix or "[no extension]")
    grouped = sorted(((key, extensions) for key, extensions in groups.items() if len(extensions) > 1),
                     key=lambda item: (-len(item[1]), item[0]))
    if grouped:
        for (parent, stem), extensions in grouped[:8]:
            lines.append(f"- {_display(parent)}/{_display(stem)}: {len(extensions)} files; "
                         f"extensions {', '.join(sorted(set(extensions))[:12])}")
    else:
        lines.append("No repeated same-directory stem found.")
    lines.extend(["", "Grouping by path/stem is not a build or execution provenance proof.", ""])
    _list_section(lines, "Trace-like artifacts (filename hints)", traces)
    _list_section(lines, "Signature-like artifacts (filename hints)", signatures)
    _list_section(lines, "Stimulus/source-like artifacts (filename hints)", stimulus)
    _list_section(lines, "Other potentially useful artifacts (filename hints)", other)
    lines.extend(["## Build/noise artifacts", "",
                  f"{len(noise)} generated-build-like files; "
                  f"{sum(row['facts']['size_bytes'] for row in noise)} bytes. "
                  "Individual entries remain in inventory.json.", "",
                  "## Missing relative to existing adapters", "",
                  "The current ProcessorFuzz workflow expects SI, RISC-V ELF, RTL instruction log, "
                  "ISA CSV/log and RTL/ISA signatures. The checks below are filename-shape hints only:"])
    patterns = {
        "SI (.si)": lambda n: n.endswith(".si"),
        "ELF (.elf)": lambda n: n.endswith(".elf"),
        "RTL trace (rtl_<n>.log)": lambda n: re.fullmatch(r"rtl_\d+\.log", n) is not None,
        "ISA CSV (isa_<n>.csv)": lambda n: re.fullmatch(r"isa_\d+\.csv", n) is not None,
        "ISA log (isa_<n>.log)": lambda n: re.fullmatch(r"isa_\d+\.log", n) is not None,
        "RTL signature": lambda n: "rtl_sig" in n,
        "ISA signature": lambda n: "isa_sig" in n,
    }
    names = [PurePosixPath(row["relative_path"]).name.lower() for row in files]
    for label, predicate in patterns.items():
        lines.append(f"- {label}: {'filename shape present' if any(predicate(n) for n in names) else 'no matching member in this package'}")
    lines.extend(["", "A missing shape does not prove the underlying evidence is absent outside this package; "
                  "a matching name does not establish a trusted role or common run.", "",
                  "## Existing ChipChain adaptation surfaces", ""])
    lines.extend(f"- {path}" for path in SURFACES)
    lines.extend(["", "## Adaptation rules", "",
                  "- Preserve original raw delivery bytes and keep inspection outputs separate.",
                  "- Compare with existing cases; reuse parser logic first and extend only what the new structure requires.",
                  "- Never bind SI, ELF, traces or signatures by co-location or basename alone.",
                  "- Static facts, runtime facts and simulation evidence retain distinct scopes.",
                  "- Missing or conflicting evidence may legitimately remain UNKNOWN / NOT_ESTABLISHED.",
                  "- Keep hardware-supplied trigger-test ELF separate from customer firmware.",
                  "- Add deterministic expected artifacts and regression tests, then run full validation.", ""])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Raw ZIP/TAR package or extracted directory")
    parser.add_argument("--output", required=True, type=Path, help="New or empty diagnostics directory")
    args = parser.parse_args(argv)
    try:
        input_path = args.input
        output_path = args.output
        if input_path.is_dir() and output_path.resolve().is_relative_to(input_path.resolve()):
            raise ValueError("Output directory must be outside the inspected input directory")
        if output_path.is_symlink() or (output_path.exists() and
                                        (not output_path.is_dir() or any(output_path.iterdir()))):
            raise ValueError("Output path must be a new or empty directory, not a symlink")
        inventory = inspect(input_path)
        brief = render_brief(inventory)
        output_path.mkdir(parents=True, exist_ok=True)
        (output_path / "inventory.json").write_text(
            json.dumps(inventory, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        (output_path / "adaptation-brief.md").write_text(brief, encoding="utf-8")
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError, RuntimeError) as error:
        parser.exit(2, f"inspection failed: {error}\n")
    print(f"Inspected {inventory['summary']['file_count']} files; diagnostics: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
