"""Explicit runtime acquisition/persistence and fail-closed evidence replay."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

from chipchain.firmware.elf import ElfImage
from chipchain.firmware.static_ir import FirmwareStaticAnalysis
from chipchain.runtime.acquisition import acquire_raw
from chipchain.runtime.binding import materialize_runtime, validate_static_source
from chipchain.runtime.qemu_evidence import (
    AcquisitionPolicy, QemuRuntimeRunDescriptor, RuntimeCapabilities, RuntimeEvents,
    RuntimeEvidence, RuntimeProfile, RuntimeSemantics, StaticRuntimeBindings,
)
from chipchain.runtime.qemu_profile import PINNED_QEMU_VERSION, RISCV64_FW_FEASIBILITY
from chipchain.runtime.image_mapping import declared_identity_mapping
from chipchain.runtime.plugin_build import validate_header_provenance


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PROFILES = {"riscv64-fw-feasibility": RISCV64_FW_FEASIBILITY}
ARTIFACTS = {
    "runtime-run.json": ("run", QemuRuntimeRunDescriptor),
    "runtime-events.json": ("events", RuntimeEvents),
    "runtime-semantics.json": ("semantics", RuntimeSemantics),
    "static-runtime-bindings.json": ("bindings", StaticRuntimeBindings),
    "runtime-capabilities.json": ("capabilities", RuntimeCapabilities),
}


def serialize(value) -> str:
    return json.dumps(value.model_dump(mode="json"), ensure_ascii=False,
                      sort_keys=True, indent=2, allow_nan=False) + "\n"


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate canonical JSON key")
        result[key] = value
    return result


def _read_model(path: Path, cls):
    return cls.model_validate(json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object))


def _qemu_metadata(root: Path) -> tuple[str, dict[str, str]]:
    source = dict(line.split("=", 1) for line in (root / "tools/qemu/SOURCE").read_text().splitlines())
    checksums = {}
    for line in (root / "tools/qemu/SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        if name in checksums:
            raise ValueError("Duplicate QEMU manifest path")
        checksums[name] = digest
    return source["chipchain_bundle_sha256"], checksums


def validate_tool_provenance(run: QemuRuntimeRunDescriptor, directory: Path, root: Path) -> None:
    """Verify retained instrumentation and frozen QEMU release identities.

    Replay is offline and need not execute/reinstall QEMU. Compiler/acquisition
    records are local provenance, not a cryptographic proof of process execution.
    """
    validate_header_provenance(root)
    bundle, checksums = _qemu_metadata(root)
    if (run.qemu_version != PINNED_QEMU_VERSION or run.qemu_bundle_sha256 != bundle
            or checksums.get("bin/" + run.profile.executable) != run.qemu_executable_sha256):
        raise ValueError("Canonical runtime QEMU identity does not match the pinned release")
    for path, expected in (
        (directory / "trace-plugin.so", run.plugin_sha256),
        (root / "tools/qemu/plugins/chipchain_trace.c", run.plugin_source_sha256),
        (root / "tools/qemu/plugins/qemu-plugin-v7.h", run.plugin_api_header_sha256),
        (root / "tools/qemu/plugins/header-provenance.json", run.plugin_header_provenance_sha256),
    ):
        if sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("Canonical runtime plugin identity mismatch")


def write_runtime_evidence(evidence: RuntimeEvidence, directory: Path) -> None:
    """Called explicitly after successful acquisition and deterministic replay."""
    for filename, (attribute, _) in ARTIFACTS.items():
        with (directory / filename).open("x", encoding="utf-8") as handle:
            handle.write(serialize(getattr(evidence, attribute)))
    with (directory / "report.md").open("x", encoding="utf-8") as handle:
        handle.write(render_runtime_report(evidence))


def load_runtime_evidence(directory: Path, *, analysis: FirmwareStaticAnalysis) -> RuntimeEvidence:
    """Never trust saved semantic/support statuses without complete source replay."""
    directory = Path(directory)
    saved = {attribute: _read_model(directory / filename, cls)
             for filename, (attribute, cls) in ARTIFACTS.items()}
    run = saved["run"]
    validate_tool_provenance(run, directory, REPOSITORY_ROOT)
    replayed = materialize_runtime(run, (directory / "raw-events.jsonl").read_bytes(),
                                  analysis=analysis, elf_bytes=(directory / "firmware.elf").read_bytes())
    for attribute, value in saved.items():
        if value != getattr(replayed, attribute):
            raise ValueError(f"Canonical runtime {attribute} disagrees with source replay")
    return replayed


def acquire_and_write(*, elf: Path, firmware_directory: Path, profile_name: str,
                      output: Path, target_pc: int | None = None,
                      successor_events: int = 8, max_events: int = 20000) -> Path:
    if profile_name not in PROFILES:
        raise ValueError("A declared supported runtime profile must be selected explicitly")
    profile = PROFILES[profile_name]
    snapshot = RuntimeProfile.from_profile(profile)
    policy = AcquisitionPolicy(kind="target_then_successors" if target_pc is not None else "event_prefix",
                               target_pc=target_pc, successor_events=successor_events if target_pc is not None else 0,
                               max_events=max_events)
    elf = Path(elf)
    analysis = _read_model(Path(firmware_directory) / "firmware-analysis.json", FirmwareStaticAnalysis)
    image = ElfImage(elf.read_bytes())
    validate_static_source(analysis, image)
    if (image.identity.architecture, image.identity.bit_width) != (snapshot.architecture, snapshot.bit_width):
        raise ValueError("Exact ELF and declared runtime profile architecture/width mismatch")
    if target_pc is not None and target_pc not in {item.pc for item in analysis.instructions}:
        raise ValueError("Target PC is not an exact canonical static instruction")
    output = Path(output).absolute()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("Runtime output must be a new or empty directory")
    if output.resolve().is_relative_to(Path(firmware_directory).resolve()):
        raise ValueError("Runtime output must be outside the static analysis input directory")
    raw = acquire_raw(elf=elf, profile=profile, output=output, target_pc=target_pc,
                      image_mapping=declared_identity_mapping(image.identity),
                      successor_events=policy.successor_events, max_events=max_events,
                      repository_root=REPOSITORY_ROOT)
    run = raw.run
    validate_tool_provenance(run, output, REPOSITORY_ROOT)
    evidence = materialize_runtime(run, raw.raw_stream, analysis=analysis, elf_bytes=raw.elf_bytes)
    write_runtime_evidence(evidence, output)
    return output


def render_runtime_report(evidence: RuntimeEvidence) -> str:
    """Readable projection only; JSON plus raw-source replay remain authoritative."""
    run, observed = evidence.run, evidence.events
    semantic_by_event = {fact.source_event_id: fact for fact in evidence.semantics.facts}
    supported = [binding for binding in evidence.bindings.bindings if binding.status == "SUPPORTED"]
    lines = ["# 固件 QEMU 运行观测报告", "",
             "已将声明环境中的指令执行回调绑定到所给固件 ELF 的确切字节。", "",
             f"- 平台：{run.profile.architecture} / {run.profile.bit_width} bits；"
             f"QEMU {run.qemu_version}，machine `{run.profile.machine}`。",
             f"- 采集：从 ELF 入口记录 {len(observed.events)} 个连续单 vCPU 回调；"
             f"停止条件 `{observed.stop_reason}`。",
             "- 回调发生在指令执行前，表示模拟器将调度该指令；不证明指令完成或物理退休。",
             "- SUPPORTED：该静态事实具有来源绑定、解码兼容的 QEMU 指令回调观测；不表示指令或内存副作用完成。",
             "- 静态与运行时行为的对应结果：", "",
             "| ELF VA | 指令 | 共享语义 | 静态—运行绑定 |", "| --- | --- | --- | --- |"]
    for binding in supported:
        fact = semantic_by_event[binding.source_event_ids[0]]
        instruction = fact.mnemonic + " " + ",".join(fact.operands)
        lines.append(f"| `0x{binding.pc:x}` | `{instruction.strip()}` | {binding.kind.value} | SUPPORTED |")
    if not supported:
        lines.append("| — | — | — | UNKNOWN：当前窗口/解码覆盖未建立对应支持 |")
    lines += ["", "未观察到的静态操作仍为 UNKNOWN；不能据此判定不可执行或证明安全。", "",
              "运行顺序仅表示本次单 vCPU 观测的先后，不表示硬件时序或所有输入下的固定顺序。", "",
              "| 序号 | PC | 原始字节 | 已支持的解码 |", "| --- | --- | --- | --- |"]
    center = observed.target_sequence if observed.target_sequence is not None else 0
    for event in observed.events[max(0, center - 8):center + 9]:
        fact = semantic_by_event.get(event.event_id)
        text = fact.mnemonic + " " + ",".join(fact.operands) if fact else "未作语义投影"
        lines.append(f"| {event.sequence} | `0x{event.pc:x}` | `{event.instruction_bytes}` | {text} |")
    lines += ["", "目标硬件触发：NOT_ESTABLISHED。硬件异常：NOT_ESTABLISHED。"
              "完整 Type-II 链：NOT_VERIFIED。", "",
              "QEMU 观测不等同于 ProcessorFuzz RTL 证据或硅片证据，不建立外部控制权。"
              "本报告不重建函数调用栈；静态函数路径仍是静态信息。", "",
              "内部审计请查看同目录 runtime-run.json、runtime-events.json、runtime-semantics.json、"
              "static-runtime-bindings.json 与 runtime-capabilities.json。", ""]
    return "\n".join(lines)
