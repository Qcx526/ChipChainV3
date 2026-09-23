"""Deterministic, human-readable renderer from canonical firmware analysis."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

from chipchain.firmware.static_ir import FirmwareStaticAnalysis, StaticBehaviorKind as K, serialize_analysis


def firmware_summary(value: FirmwareStaticAnalysis) -> dict:
    counts = Counter(b.kind for b in value.behaviors)
    return {
        "analysis_id": value.analysis_id,
        "architecture": value.artifact.architecture,
        "bit_width": value.artifact.bit_width,
        "endianness": value.artifact.endianness,
        "elf_sha256": value.artifact.sha256,
        "arm_profile": value.artifact.arm_profile or "not applicable",
        "arm_cpu_name": value.artifact.arm_cpu_name or "not established",
        "entry_address": f"0x{value.artifact.entry:x}",
        "function_count": len(value.functions),
        "basic_block_count": len(value.blocks),
        "instruction_count": len(value.instructions),
        "cfg_edge_count": len(value.edges),
        "direct_call_count": sum(c.direct for c in value.calls),
        "indirect_call_count": sum(not c.direct for c in value.calls),
        "unresolved_call_count": sum(c.target is None for c in value.calls),
        "memory_load_count": counts[K.MEMORY_LOAD],
        "memory_store_count": counts[K.MEMORY_STORE],
        "mmio_read_count": counts[K.MMIO_READ],
        "mmio_write_count": counts[K.MMIO_WRITE],
        "system_register_read_count": counts[K.SYSTEM_REGISTER_READ],
        "system_register_write_count": counts[K.SYSTEM_REGISTER_WRITE],
        "barrier_count": counts[K.MEMORY_BARRIER] + counts[K.INSTRUCTION_BARRIER],
        "atomic_count": counts[K.ATOMIC_LOAD] + counts[K.ATOMIC_STORE],
        "exception_return_count": counts[K.EXCEPTION_RETURN],
        "unsupported_count": sum(b.semantic_status == "unsupported" for b in value.behaviors),
        "unresolved_address_count": sum(b.address_status == "unknown" for b in value.behaviors),
        "ambiguous_ownership_count": sum(len(i.function_ids) > 1 for i in value.instructions),
        "ghidra_language": value.ghidra_language,
        "ghidra_version": value.ghidra_version,
    }


def render_firmware_report(value: FirmwareStaticAnalysis) -> str:
    s = firmware_summary(value)
    functions = {f.fact_id: f.name for f in value.functions}
    instructions = {i.fact_id: i for i in value.instructions}
    lines = ["# Firmware Analysis Report", "", "## 1. Analysis Summary", "",
             "本报告只说明 ELF 中的静态结构和指令语义；不证明任何指令曾实际执行。", "",
             "| 指标 | 结果 |", "|---|---:|"]
    for key, result in s.items():
        lines.append(f"| {key} | `{result}` |")
    lines += ["", "### Evidence-backed behavior examples", "",
              "| PC | Function | Instruction | Behavior Kind | Target / Address / Register | Known Value | Evidence / Provenance | Status |",
              "|---|---|---|---|---|---|---|---|"]
    examples = [b for b in value.behaviors if b.kind != K.INSTRUCTION][:12]
    for b in examples:
        i = instructions[b.instruction_id]
        function = ", ".join(functions[x] for x in i.function_ids) or "not established"
        target = (f"0x{b.address:x}" if b.address is not None else
                  f"0x{b.target:x}" if b.target is not None else
                  b.system_register or "not established")
        known = str(b.known_value) if b.known_value is not None else "not established"
        lines.append(f"| `0x{b.pc:x}` | `{function}` | `{i.text}` | {b.kind} | "
                     f"{target} | {known} | `{b.fact_id}` | {b.semantic_status} |")
    lines += ["", "## 2. Binary / Architecture Identity", "",
              f"ELF SHA256 `{value.artifact.sha256}`；{value.artifact.architecture.upper()} "
              f"{value.artifact.bit_width}-bit {value.artifact.endianness}；入口 `0x{value.artifact.entry:x}`。",
              f"PT_LOAD 段 {len(value.artifact.segments)} 个；节 {len(value.artifact.sections)} 个。", "",
              "## 3. Program Structure", "",
              f"识别 {len(value.functions)} 个函数、{len(value.blocks)} 个基本块、"
              f"{len(value.instructions)} 条指令和 {len(value.edges)} 条 CFG 边。"
              "静态 CFG 边不等于可行运行路径。", "",
              "## 4. Functions", "", "| 入口 | 名称 | 范围 | ID |", "|---|---|---|---|"]
    if value.artifact.architecture == "arm" and value.artifact.entry & 1:
        marker = lines.index("## 3. Program Structure")
        lines[marker:marker] = ["ARM ELF entry 的最低位表示 Thumb 状态；首条指令的映射 PC 去掉该状态位。", ""]
    for f in value.functions:
        ranges = ", ".join(f"0x{r.start:x}–0x{r.end:x}" for r in f.ranges)
        lines.append(f"| `0x{f.entry:x}` | `{f.name}` | {ranges} | `{f.fact_id}` |")
    lines += ["", "## 5. Basic Blocks and CFG", "", "| 基本块 | 结束 | 所属函数数 | 出边数 |",
              "|---|---:|---:|---:|"]
    for b in value.blocks:
        lines.append(f"| `0x{b.start:x}` | `0x{b.end:x}` | {len(b.function_ids)} | "
                     f"{sum(e.source_block_id == b.fact_id for e in value.edges)} |")
    lines += ["", "## 6. Call Analysis", "", "| 调用点 | 类型 | 目标 | 解析状态 |",
              "|---|---|---|---|"]
    for c in value.calls:
        lines.append(f"| `0x{c.pc:x}` | {'direct' if c.direct else 'indirect'} | "
                     f"{f'0x{c.target:x}' if c.target is not None else 'not established'} | "
                     f"{'resolved' if c.target is not None else 'unresolved'} |")
    lines += ["", "## 7. Memory Access Analysis", "",
              "普通 LOAD/STORE 保留为内存行为；没有硬件资源目录时不升级为 MMIO。", "",
              "| PC | 指令 | 行为 | 地址 | 已知值 | 状态 |",
              "|---|---|---|---|---|---|"]
    for b in value.behaviors:
        if b.kind in {K.MEMORY_LOAD, K.MEMORY_STORE, K.ATOMIC_LOAD, K.ATOMIC_STORE}:
            i = instructions[b.instruction_id]
            lines.append(f"| `0x{b.pc:x}` | `{i.text}` | {b.kind} | "
                         f"{f'0x{b.address:x}' if b.address is not None else 'unknown'} | "
                         f"{b.known_value if b.known_value is not None else 'not established'} | "
                         f"{b.semantic_status} |")
    lines += ["", "## 8. Hardware-facing Behaviors", "",
              "当前分析没有硬件资源目录，MMIO 计数为 0。已解析内存地址仍需资源绑定，"
              "才能被解释为硬件寄存器访问。", "",
              "## 9. System/Register/Barrier/Atomic Behaviors", "",
              "| PC | 所属函数 | 指令 | 行为 | 寄存器 | 证据 ID |",
              "|---|---|---|---|---|---|"]
    for b in value.behaviors:
        if b.kind in {K.SYSTEM_REGISTER_READ, K.SYSTEM_REGISTER_WRITE, K.MEMORY_BARRIER,
                      K.INSTRUCTION_BARRIER, K.ATOMIC_LOAD, K.ATOMIC_STORE, K.EXCEPTION_RETURN}:
            i = instructions[b.instruction_id]
            name = ", ".join(functions[x] for x in i.function_ids) or "unresolved"
            lines.append(f"| `0x{b.pc:x}` | `{name}` | `{i.text}` | {b.kind} | "
                         f"{b.system_register or '—'} | `{b.fact_id}` |")
    lines += ["", "## 10. Unresolved / Unsupported Facts", "",
              f"- Unsupported instructions/semantics: {s['unsupported_count']}",
              f"- Unresolved call targets: {s['unresolved_call_count']}",
              f"- Unknown memory addresses: {s['unresolved_address_count']}",
              f"- Ambiguous ownership: {s['ambiguous_ownership_count']}",
              "- Unbound hardware resources: all ordinary memory facts in this catalog-free analysis.", "",
              "Unresolved ≠ nonexistent. Unsupported ≠ safe.", ""]
    for b in value.behaviors:
        if b.semantic_status != "supported" or b.address_status == "unknown":
            i = instructions[b.instruction_id]
            lines.append(f"- `0x{b.pc:x}` `{i.raw_bytes}` `{i.text}` → {b.kind}, "
                         f"{b.semantic_status}; {b.detail or b.address_status}; `{b.fact_id}`")
    lines += ["", "## 11. Provenance and Toolchain", "",
              f"Analysis `{value.analysis_id}`。Ghidra `{value.ghidra_version}` / "
              f"`{value.ghidra_language}` 导出结构；每条指令 bytes 与 SHA256 为 "
              f"`{value.artifact.sha256}` 的 ELF PT_LOAD 可执行映射逐条比对。"
              "事实 ID 由内容计算，不含本机路径、时间或随机数。", "",
              "## 12. Scientific Limitations", "",
              "静态函数、CFG、指令和值传播不证明运行可达、运行顺序、外部控制、硬件触发、"
              "偏差或漏洞。已知写值只表示当前局部常量传播能证明的静态值；"
              "跨分支和调用的值可能未知。Ghidra 与 ELF byte 一致不构成独立语义解码。", ""]
    return "\n".join(lines)


def write_firmware_result(value: FirmwareStaticAnalysis, directory: str | Path,
                          *, export: dict | None = None) -> Path:
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    (target / "firmware-analysis.json").write_text(serialize_analysis(value))
    (target / "firmware-summary.json").write_text(
        json.dumps(firmware_summary(value), indent=2, sort_keys=True) + "\n")
    (target / "firmware-report.md").write_text(render_firmware_report(value))
    if export is not None:
        (target / "ghidra-export.json").write_text(json.dumps(export, indent=2, sort_keys=True) + "\n")
    return target
