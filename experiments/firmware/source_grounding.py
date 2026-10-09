"""Research-only ELF/DWARF/source joins; no runtime or hardware inference."""
from __future__ import annotations

import argparse
from bisect import bisect_right
from dataclasses import asdict, dataclass
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess

from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import DWARFError, ELFError

from chipchain.firmware.elf import ElfImage
from chipchain.firmware.static_ir import FirmwareStaticAnalysis, content_id


def relative_name(name: str) -> str:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or "\\" in name:
        raise ValueError("Source file must be an explicit safe relative path")
    return path.as_posix()


@dataclass(frozen=True)
class LineInterval:
    start: int
    end: int
    file: str | None
    line: int | None
    column: int = 0
    unit: int = 0

    def __post_init__(self):
        if (type(self.start) is not int or type(self.end) is not int
                or not 0 <= self.start < self.end
                or self.line is not None and (type(self.line) is not int or self.line < 1)):
            raise ValueError("Invalid DWARF half-open line interval")
        if self.file is not None:
            relative_name(self.file)


def validated_path_maps(path_maps: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    """Explicit reverse compiler prefix maps; never infer them from basenames."""
    result = []
    for prefix, target in path_maps:
        path = PurePosixPath(prefix)
        if not path.is_absolute() or ".." in path.parts or "\\" in prefix:
            raise ValueError("DWARF prefix must be a safe absolute path")
        target = relative_name(target)
        prefix = path.as_posix()
        for other, _ in result:
            if path.is_relative_to(other) or PurePosixPath(other).is_relative_to(path):
                raise ValueError("Overlapping DWARF path maps are ambiguous")
        result.append((prefix, target))
    return tuple(sorted(result))


def source_path(declared: Path, root: Path, path_maps: tuple[tuple[str, str], ...]) -> str | None:
    if not declared.is_relative_to(root):
        for prefix, target in path_maps:
            if declared.is_relative_to(prefix):
                declared = root / target / declared.relative_to(prefix)
                break
        else:
            return None
    declared = declared.resolve()
    return declared.relative_to(root).as_posix() if declared.is_relative_to(root) else None


def dwarf_intervals(elf_bytes: bytes, source_root: Path, *,
                    path_maps: tuple[tuple[str, str], ...] = ()) -> tuple[LineInterval, ...]:
    """Read only this ELF's line programs; outside-checkout paths remain unknown."""
    path_maps = validated_path_maps(path_maps)
    elf = ELFFile(BytesIO(elf_bytes))
    if elf.get_section_by_name(".debug_line") is None:
        return ()
    root = source_root.resolve(strict=True)
    dwarf = elf.get_dwarf_info()
    result = []
    decode = lambda value: value.decode("utf-8", errors="strict") if isinstance(value, bytes) else value
    for unit, cu in enumerate(dwarf.iter_CUs()):
        program = dwarf.line_program_for_CU(cu)
        if program is None:
            continue
        comp = cu.get_top_DIE().attributes.get("DW_AT_comp_dir")
        comp_dir = Path(decode(comp.value)) if comp else root
        if not comp_dir.is_absolute():
            comp_dir = root / comp_dir
        previous = None
        for entry in program.get_entries():
            state = entry.state
            if state is None:
                continue
            if previous is not None and previous.address < state.address:
                version = int(program.header.version)
                file_index = previous.file if version >= 5 else previous.file - 1
                name = None
                files, dirs = program.header.file_entry, program.header.include_directory
                if 0 <= file_index < len(files):
                    descriptor = files[file_index]
                    directory_index = descriptor.dir_index
                    directory = comp_dir
                    if version >= 5 and directory_index < len(dirs):
                        directory = Path(decode(dirs[directory_index]))
                    elif version < 5 and 0 < directory_index <= len(dirs):
                        directory = Path(decode(dirs[directory_index - 1]))
                    if not directory.is_absolute():
                        directory = comp_dir / directory
                    declared = directory / decode(descriptor.name)
                    name = source_path(declared, root, path_maps)
                result.append(LineInterval(previous.address, state.address, name,
                                           previous.line or None, previous.column or 0, unit))
            previous = None if state.end_sequence else state
    return tuple(sorted(result, key=lambda x: (x.start, x.end, x.file or "", x.line or 0, x.column, x.unit)))


def ground_source(elf_bytes: bytes, analysis: FirmwareStaticAnalysis | bytes,
                  intervals: tuple[LineInterval, ...], source_files: dict[str, bytes], *,
                  source_commit: str, functions: tuple[str, ...] = (),
                  path_maps: tuple[tuple[str, str], ...] = ()) -> dict:
    """Pure join. Caller supplies same-ELF intervals and explicitly acquired sources."""
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("An exact source commit SHA is required")
    path_maps = validated_path_maps(path_maps)
    image = ElfImage(elf_bytes)
    static = (FirmwareStaticAnalysis.model_validate_json(analysis) if isinstance(analysis, bytes)
              else FirmwareStaticAnalysis.model_validate(analysis.model_dump(mode="json")))
    if static.artifact != image.identity:
        raise ValueError("Canonical analysis/ELF identity mismatch")
    names = {relative_name(name): value for name, value in source_files.items()}
    if len(names) != len(source_files) or any(not isinstance(value, bytes) for value in names.values()):
        raise ValueError("Source content must be exact file bytes")
    ordered = sorted(intervals, key=lambda x: (x.start, x.end, x.file or "", x.line or 0, x.column, x.unit))
    starts, maximum_ends = [], []
    for interval in ordered:
        starts.append(interval.start)
        maximum_ends.append(max(interval.end, maximum_ends[-1] if maximum_ends else 0))
    registry = {f.fact_id: f for f in static.functions}
    instructions = {i.fact_id: i for i in static.instructions}
    for instruction in static.instructions:
        if image.mapped_bytes(instruction.pc, len(instruction.raw_bytes) // 2,
                              executable=True).hex() != instruction.raw_bytes:
            raise ValueError(f"Executable instruction bytes mismatch at 0x{instruction.pc:x}")
        actual = {f.fact_id for f in static.functions
                  if any(r.start <= instruction.pc <= r.end for r in f.ranges)}
        if set(instruction.function_ids) != actual:
            raise ValueError("Canonical instruction/function ownership mismatch")
    for behavior in static.behaviors:
        if behavior.instruction_id not in instructions or instructions[behavior.instruction_id].pc != behavior.pc:
            raise ValueError("Behavior/instruction reference mismatch")
    selected = {f.fact_id for f in static.functions
                if not functions or f.name in functions or f.fact_id in functions}
    if functions and any(not any(f.name == name or f.fact_id == name for f in registry.values())
                         for name in functions):
        raise ValueError("Selected function is absent from canonical analysis")
    facts = {}
    for behavior in static.behaviors:
        facts.setdefault(behavior.instruction_id, []).append(behavior.model_dump(mode="json"))
    records = []
    for instruction in sorted(static.instructions, key=lambda x: x.pc):
        if functions and not selected.intersection(instruction.function_ids):
            continue
        candidates = []
        for interval in ordered[bisect_right(maximum_ends, instruction.pc):bisect_right(starts, instruction.pc)]:
            if interval.start <= instruction.pc < interval.end:
                candidate = asdict(interval)
                content = names.get(interval.file)
                lines = content.splitlines() if content is not None else []
                line = interval.line
                available = line is not None and 1 <= line <= len(lines)
                candidate.update(source_sha256=sha256(content).hexdigest() if content is not None else None,
                                 line_bytes_hex=lines[line - 1].hex() if available else None,
                                 line_text=lines[line - 1].decode("utf-8", errors="replace") if available else None,
                                 instruction_within_interval=instruction.pc + len(instruction.raw_bytes) // 2 <= interval.end)
                candidates.append(candidate)
        ownership = ("UNIQUE" if len(instruction.function_ids) == 1 else
                     "AMBIGUOUS" if instruction.function_ids else "UNKNOWN")
        source_status = ("AMBIGUOUS" if len(candidates) > 1 else
                         "BOUND_COMPILE_METADATA" if candidates and
                         candidates[0]["line_bytes_hex"] is not None and
                         candidates[0]["instruction_within_interval"] else "UNKNOWN")
        records.append({"instruction_id": instruction.fact_id, "pc": instruction.pc,
                        "pc_hex": hex(instruction.pc), "raw_bytes": instruction.raw_bytes,
                        "text": instruction.text, "behaviors": facts.get(instruction.fact_id, []),
                        "function_ids": list(instruction.function_ids), "ownership_status": ownership,
                        "function_names": [registry[x].name for x in instruction.function_ids],
                        "source_status": source_status, "source_candidates": candidates,
                        "grounding_status": "AMBIGUOUS" if "AMBIGUOUS" in (ownership, source_status)
                        else "SUPPORTED_STATIC" if ownership == "UNIQUE" and source_status == "BOUND_COMPILE_METADATA"
                        else "UNKNOWN"})
    calls = []
    for call in sorted(static.calls, key=lambda x: x.pc):
        if not call.direct or not selected.intersection(call.caller_function_ids):
            continue
        site = next((i for i in static.instructions if i.pc == call.pc), None)
        target = registry.get(call.target_function_id)
        valid = (site is not None and len(site.function_ids) == 1 and
                 set(call.caller_function_ids) == set(site.function_ids) and
                 target is not None and target.entry == call.target)
        calls.append({**call.model_dump(mode="json"), "status": "CONFIRMED_STATIC" if valid else "UNKNOWN"})
    payload = {"role": "research_diagnostic", "elf_sha256": image.identity.sha256,
               "analysis_id": static.analysis_id, "source_commit": source_commit,
               "explicit_dwarf_path_maps": [{"prefix": p, "checkout_relative": t} for p, t in path_maps],
               "functions": [f.model_dump(mode="json") for f in static.functions if f.fact_id in selected],
               "instructions": records, "direct_calls": calls,
               "limits": {"static_only": True, "runtime_execution": "NOT_ESTABLISHED",
                          "triggerability": "UNKNOWN", "hardware_deviation": "NOT_ESTABLISHED",
                          "source_commit_build_binding": "REQUIRES_EXTERNAL_BUILD_PROVENANCE"}}
    return {**payload, "diagnostic_id": content_id("research-source-grounding", payload)}


def render_report(result: dict) -> str:
    lines = ["# 固件源码与指令来源调查", "",
             "本调查把同一 ELF 的指令、编译器行号信息和选定源码字节连接起来。"
             "行号是编译元数据，调用关系仅为静态关系；尚未证明这些功能实际执行或满足硬件触发条件。", "",
             "源码 checkout 身份不能替代同一次构建记录；源码到 ELF 的完整来源还须核对构建日志和输入身份。", "",
             "| PC | 指令 | 所属函数 | 源码定位 |", "|---|---|---|---|"]
    for record in result["instructions"]:
        locations = "; ".join(f"{c['file'] or '未知文件'}:{c['line'] or '?'}" for c in record["source_candidates"])
        lines.append(f"| {record['pc_hex']} | {record['text'].replace('|', '/')} | "
                     f"{', '.join(record['function_names']) or 'UNKNOWN'} ({record['ownership_status']}) | "
                     f"{locations or '缺少行号信息'} ({record['source_status']}) |")
    lines += ["", "缺失源码/行号保留 UNKNOWN，重叠行号或多重函数归属保留 AMBIGUOUS。"
              "BOUND_COMPILE_METADATA 表示来源元数据和文件字节可核对，不表示运行观察、唯一因果或漏洞。", ""]
    return "\n".join(lines)


def verify_checkout(root: Path, commit: str) -> set[str]:
    """CLI-only external inspection, never used by ordinary offline unit tests."""
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("An exact source commit SHA is required")
    environment = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}
    def git(*args):
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                              check=True, timeout=15, env=environment).stdout
    if Path(git("rev-parse", "--show-toplevel").decode().strip()).resolve() != root.resolve():
        raise ValueError("Source root is not the exact checkout root")
    if git("rev-parse", "HEAD").decode().strip() != commit or git("status", "--porcelain", "--untracked-files=no"):
        raise ValueError("Source checkout commit or tracked cleanliness mismatch")
    return {name.decode() for name in git("ls-files", "-z").split(b"\0") if name}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("elf", "analysis", "source-root", "source-commit", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--function", action="append", default=[])
    parser.add_argument("--dwarf-path-map", action="append", default=[], metavar="PREFIX=RELATIVE",
                        help="Explicit reverse build prefix map to checkout-relative path; requires build provenance")
    args = parser.parse_args(argv)
    output, root = Path(args.output).resolve(), Path(args.source_root).resolve()
    if output == root or output.is_relative_to(root):
        parser.error("Output must be outside the source checkout")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        parser.error("Output must be new or empty")
    output.mkdir(parents=True, exist_ok=True)
    try:
        tracked = verify_checkout(root, args.source_commit)
        data = Path(args.elf).read_bytes()
        path_maps = validated_path_maps(tuple(tuple(value.split("=", 1)) for value in args.dwarf_path_map))
        intervals = dwarf_intervals(data, root, path_maps=path_maps)
        sources = {}
        for name in sorted({i.file for i in intervals if i.file is not None}):
            path = root / name
            if name in tracked and path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)):
                sources[name] = path.read_bytes()
        result = ground_source(data, Path(args.analysis).read_bytes(), intervals, sources,
                               source_commit=args.source_commit, functions=tuple(args.function), path_maps=path_maps)
        verify_checkout(root, args.source_commit)
        (output / "source-to-instruction-mapping.json").write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
        (output / "source-grounding.md").write_text(render_report(result))
        print(result["diagnostic_id"])
        return 0
    except (OSError, ValueError, ELFError, DWARFError, subprocess.SubprocessError) as exc:
        (output / "failure.json").write_text(json.dumps({"status": "BLOCKED", "reason": str(exc)}, ensure_ascii=False, indent=2) + "\n")
        (output / "source-grounding.md").write_text(f"# 固件源码来源调查\n\nBLOCKED：{exc}\n\n未建立运行、硬件触发或异常事实。\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
