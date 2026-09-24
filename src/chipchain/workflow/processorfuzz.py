"""Deterministic, fail-closed ingestion of a ProcessorFuzz hardware delivery."""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Literal
from zipfile import ZipFile

from pydantic import model_validator

from chipchain.domain.common import Contract

from chipchain.firmware.elf import ElfImage
from chipchain.firmware.ghidra import analyze_headless
from chipchain.firmware.ghidra_normalize import normalize
from chipchain.firmware.processorfuzz_si import parse_si
from chipchain.firmware.report import firmware_summary, render_firmware_report
from chipchain.firmware.static_ir import content_id, serialize_analysis
from chipchain.firmware.static_ir import StaticBehaviorKind as K
from chipchain.runtime.evidence import RuntimeSource
from chipchain.runtime.processorfuzz import (
    align_traces, differential, parse_isa_csv, parse_isa_log, parse_rtl_trace, parse_signature,
)


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


class ProcessorFuzzRoleDeclaration(Contract):
    """Explicit intake classification; never inferred from package filenames or bytes."""

    package_role: Literal["hardware_trigger_validation_package", "unclassified"]
    firmware_role: Literal["hardware_supplied_trigger_test_firmware", "unclassified"]
    firmware_origin: Literal["hardware_department", "not_established"]
    customer_firmware: bool | None
    role_basis: Literal["hardware_team_delivery_intake", "not_established"]

    @model_validator(mode="after")
    def coherent(self):
        declared = ("hardware_trigger_validation_package",
                    "hardware_supplied_trigger_test_firmware",
                    "hardware_department", False, "hardware_team_delivery_intake")
        unknown = ("unclassified", "unclassified", "not_established", None, "not_established")
        fields = (self.package_role, self.firmware_role, self.firmware_origin,
                  self.customer_firmware, self.role_basis)
        if fields not in (declared, unknown):
            raise ValueError("ProcessorFuzz role declaration is inconsistent")
        return self


HARDWARE_TRIGGER_VALIDATION = ProcessorFuzzRoleDeclaration(
    package_role="hardware_trigger_validation_package",
    firmware_role="hardware_supplied_trigger_test_firmware",
    firmware_origin="hardware_department", customer_firmware=False,
    role_basis="hardware_team_delivery_intake")

UNCLASSIFIED_ROLE = ProcessorFuzzRoleDeclaration(
    package_role="unclassified", firmware_role="unclassified",
    firmware_origin="not_established", customer_firmware=None,
    role_basis="not_established")


def _json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + "\n")


def _package(path: Path) -> tuple[dict[str, bytes], str | None]:
    if path.is_dir():
        files = sorted(p for p in path.rglob("*") if p.is_file())
        if any(p.is_symlink() for p in path.rglob("*")):
            raise ValueError("Package directory contains symlink")
        if len(files) == 1 and files[0].suffix.lower() == ".zip":
            return _package(files[0])
        return {p.relative_to(path).as_posix(): p.read_bytes() for p in files}, None
    if path.suffix.lower() != ".zip":
        raise ValueError("Package must be a directory or ZIP")
    data = path.read_bytes()
    result = {}
    with ZipFile(BytesIO(data)) as archive:
        infos = archive.infolist()
        if sum(i.file_size for i in infos) > 300_000_000 or len(infos) > 10_000:
            raise ValueError("ZIP expanded size or entry count exceeds ingestion bound")
        for info in infos:
            name = info.filename
            parts = PurePosixPath(name).parts
            mode = info.external_attr >> 16
            if (not name or name.startswith("/") or "\\" in name or ".." in parts
                    or re.match(r"^[A-Za-z]:", name) or stat.S_ISLNK(mode)):
                raise ValueError("Unsafe ZIP entry path or symlink")
            if info.is_dir():
                continue
            if name in result:
                raise ValueError("Duplicate ZIP entry")
            result[name] = archive.read(info)
    return result, _sha(data)


def _role(name: str) -> str:
    base = PurePosixPath(name).name.lower()
    if base.endswith(".si"): return "si"
    if base.endswith(".elf"): return "elf"
    if base.endswith(".s"): return "assembly"
    if base == "disassembly.asm": return "disassembly"
    if base == "note.log": return "human_note"
    if re.fullmatch(r"rtl_\d+\.log", base): return "rtl_trace"
    if re.fullmatch(r"isa_\d+\.csv", base): return "isa_csv"
    if re.fullmatch(r"isa_\d+\.log", base): return "isa_log"
    if "rtl_sig" in base: return "rtl_signature"
    if "isa_sig" in base: return "isa_signature"
    if base == "rockettile": return "simulator"
    if base == "vtop__verfiles.dat": return "build_metadata"
    return "other"


def _unique(files: dict[str, bytes], role: str) -> tuple[str, bytes]:
    options = [(path, data) for path, data in files.items() if _role(path) == role]
    if not options:
        raise ValueError(f"Missing required {role} artifact")
    hashes = {_sha(data) for _, data in options}
    if len(hashes) != 1:
        raise ValueError(f"Ambiguous {role} artifacts with different contents")
    return sorted(options)[0]


_DISASM = re.compile(r"^\s*([0-9a-fA-F]{6,16}):\s+([0-9a-fA-F]{4,16})\s+", re.M)


def _disassembly_status(data: bytes, image: ElfImage) -> dict:
    text = data.decode("utf-8", errors="replace")
    checked = 0
    conflicts = []
    for match in _DISASM.finditer(text):
        pc = int(match.group(1), 16)
        number = match.group(2)
        if len(number) % 2:
            continue
        try:
            actual = image.mapped_bytes(pc, len(number) // 2, executable=True)
        except ValueError:
            continue
        checked += 1
        expected = int(number, 16).to_bytes(len(number) // 2, image.identity.endianness)
        if actual != expected:
            conflicts.append({"pc": f"0x{pc:x}", "elf_bytes": actual.hex(),
                              "disassembly_bytes": expected.hex()})
    return {"status": "CONFLICT_WITH_ELF" if conflicts else "UNBOUND",
            "mapped_instructions_checked": checked, "conflict_count": len(conflicts),
            "conflict_examples": conflicts[:12],
            "reason": "Instruction bytes disagree with authoritative ELF" if conflicts else
                      "No independent producer binding; matching bytes alone do not establish provenance"}


def _elf_trace_coverage(image: ElfImage, observations: list[dict]) -> dict:
    matching = conflicts = unmapped = 0
    for x in observations:
        enc = x["encoding"]
        try:
            data = image.mapped_bytes(x["pc"], len(enc) // 2, executable=True)
        except ValueError:
            unmapped += 1
            continue
        if data == int(enc, 16).to_bytes(len(enc) // 2, image.identity.endianness):
            matching += 1
        else:
            conflicts += 1
    return {"matching_elf_instructions": matching, "conflicting_elf_instructions": conflicts,
            "unmapped_instructions": unmapped,
            "status": "CONFLICT" if conflicts else "PARTIAL_BYTE_MATCH" if matching else "UNKNOWN"}


def _static_capabilities(analysis) -> list[dict]:
    instructions = {x.fact_id: x for x in analysis.instructions}
    kinds = {K.MEMORY_LOAD, K.MEMORY_STORE, K.SYSTEM_REGISTER_READ,
             K.SYSTEM_REGISTER_WRITE, K.MEMORY_BARRIER, K.INSTRUCTION_BARRIER,
             K.ATOMIC_LOAD, K.ATOMIC_STORE, K.TLB_INVALIDATE, K.EXCEPTION_RETURN}
    result = []
    for fact in analysis.behaviors:
        if fact.kind not in kinds:
            continue
        source = instructions[fact.instruction_id]
        resource_hint = ("CSR" if fact.kind in {K.SYSTEM_REGISTER_READ, K.SYSTEM_REGISTER_WRITE} else
                         "TLB" if fact.kind == K.TLB_INVALIDATE else
                         "EXCEPTION_STATE" if fact.kind == K.EXCEPTION_RETURN else
                         "ARCHITECTURAL_STATE" if fact.kind in {K.MEMORY_BARRIER, K.INSTRUCTION_BARRIER} else
                         "MEMORY")
        fields = {"schema_version": "general-static-capability/v1",
                  "elf_sha256": analysis.artifact.sha256, "architecture": analysis.artifact.architecture,
                  "source_analysis_id": analysis.analysis_id, "behavior_fact_id": fact.fact_id,
                  "instruction_id": source.fact_id, "pc": fact.pc, "instruction_bytes": source.raw_bytes,
                  "kind": fact.kind.value, "semantic_status": fact.semantic_status,
                  "address": fact.address, "access_width_bits": fact.access_width_bits,
                  "system_register": fact.system_register, "known_value": fact.known_value,
                  "resource_hint": resource_hint, "resource_binding_status": "UNKNOWN",
                  "execution_status": "STATIC_ONLY", "control_authority": "NOT_ESTABLISHED"}
        result.append({"capability_id": content_id("general-fwcap", fields), **fields})
    return result


def analyze_package(package: str | Path, output: str | Path, *, ghidra_home: str | Path | None = None,
                    role_declaration: ProcessorFuzzRoleDeclaration | None = None) -> Path:
    role_declaration = role_declaration or UNCLASSIFIED_ROLE
    role_declaration = ProcessorFuzzRoleDeclaration.model_validate(role_declaration.model_dump(mode="json"))
    files, archive_sha = _package(Path(package))
    if not files:
        raise ValueError("Empty ProcessorFuzz package")
    si_path, si_bytes = _unique(files, "si")
    elf_path, elf_bytes = _unique(files, "elf")
    rtl_path, rtl_bytes = _unique(files, "rtl_trace")
    isa_csv_path, isa_csv_bytes = _unique(files, "isa_csv")
    isa_log_path, isa_log_bytes = _unique(files, "isa_log")
    rtl_sig_path, rtl_sig_bytes = _unique(files, "rtl_signature")
    isa_sig_path, isa_sig_bytes = _unique(files, "isa_signature")
    si = parse_si(si_bytes)
    image = ElfImage(elf_bytes)
    if image.identity.architecture != "riscv":
        raise ValueError("ProcessorFuzz package requires RISC-V ELF")
    target = Path(output)
    target.mkdir(parents=True, exist_ok=True)
    # Ghidra imports a private snapshot of the bytes held by ElfImage.
    exported = analyze_headless(elf_path, image, ghidra_home=ghidra_home)
    analysis = normalize(image, exported)
    simulator = next((data for name, data in files.items() if _role(name) == "simulator"), None)
    build = next((data for name, data in files.items() if _role(name) == "build_metadata"), None)
    source_common = dict(case_id=si.case_id, elf_sha256=image.identity.sha256,
                         si_sha256=si.raw_sha256, rtl_trace_sha256=_sha(rtl_bytes),
                         isa_trace_sha256=_sha(isa_csv_bytes),
                         simulator_sha256=_sha(simulator) if simulator else None,
                         build_metadata_sha256=_sha(build) if build else None,
                         rtl_source_revision="not_established")
    rtl = parse_rtl_trace(rtl_bytes, RuntimeSource(trace_sha256=_sha(rtl_bytes), **source_common))
    isa = parse_isa_csv(isa_csv_bytes, RuntimeSource(trace_sha256=_sha(isa_csv_bytes), **source_common))
    isa_log = parse_isa_log(isa_log_bytes, RuntimeSource(trace_sha256=_sha(isa_log_bytes), **source_common))
    rtl_sig = parse_signature(rtl_sig_bytes, RuntimeSource(trace_sha256=_sha(rtl_sig_bytes), **source_common), "rtl")
    isa_sig = parse_signature(isa_sig_bytes, RuntimeSource(trace_sha256=_sha(isa_sig_bytes), **source_common), "isa_reference")
    coverage_rtl = _elf_trace_coverage(image, rtl["instruction_observations"])
    coverage_isa = _elf_trace_coverage(image, isa["instruction_observations"])
    # Byte agreement can bind sampled trace instructions to ELF, but not the SI,
    # simulator source revision, or signature production context.
    diff = differential(rtl_sig, isa_sig, testcase_binding="UNKNOWN",
                        firmware_binding="UNKNOWN", execution_context_binding="UNKNOWN")
    alignment = align_traces(rtl, isa)
    disassembly = next(((name, data) for name, data in files.items() if _role(name) == "disassembly"), None)
    disassembly_result = _disassembly_status(disassembly[1], image) if disassembly else None
    inventory = [{"path": name, "role": _role(name), "sha256": _sha(data),
                  "artifact_id": "sha256:" + _sha(data), "size_bytes": len(data)}
                 for name, data in sorted(files.items())]
    conflicts = ([{"path": disassembly[0], **disassembly_result}] if disassembly_result and
                 disassembly_result["status"] == "CONFLICT_WITH_ELF" else [])
    unbound = [{"path": name, "role": _role(name), "reason": "Human note is not runtime evidence"}
               for name in sorted(files) if _role(name) == "human_note"]
    if disassembly and not conflicts:
        unbound.append({"path": disassembly[0], "role": "disassembly", "reason": "No producer binding"})
    manifest_fields = {"schema_version": "processorfuzz-case-manifest/v2", "case_id": si.case_id,
                       **role_declaration.model_dump(mode="json"),
                       "archive_sha256": archive_sha, "si_sha256": si.raw_sha256,
                       "elf_sha256": image.identity.sha256, "rtl_trace_sha256": _sha(rtl_bytes),
                       "isa_trace_sha256": _sha(isa_csv_bytes), "isa_log_sha256": _sha(isa_log_bytes),
                       "rtl_signature_sha256": _sha(rtl_sig_bytes), "isa_signature_sha256": _sha(isa_sig_bytes),
                       "simulator_sha256": source_common["simulator_sha256"],
                       "build_metadata_sha256": source_common["build_metadata_sha256"],
                       "rtl_source_revision": "not_established",
                       "bindings": {"si_to_elf": "UNKNOWN", "rtl_trace_to_elf": coverage_rtl["status"],
                                    "isa_trace_to_elf": coverage_isa["status"],
                                    "signatures_same_execution": "UNKNOWN"},
                       "conflicting_artifact_hashes": sorted(_sha(files[x["path"]]) for x in conflicts)}
    manifest = {"manifest_id": content_id("processorfuzz-manifest", manifest_fields), **manifest_fields,
                "inventory": inventory, "selected_paths": {"si": si_path, "elf": elf_path,
                "rtl_trace": rtl_path, "isa_csv": isa_csv_path, "isa_log": isa_log_path,
                "rtl_signature": rtl_sig_path, "isa_signature": isa_sig_path},
                "unbound_artifacts": unbound, "conflicting_artifacts": conflicts}
    summary = firmware_summary(analysis)
    summary.update({"case_id": si.case_id, "manifest_id": manifest["manifest_id"],
                    "rtl_instruction_count": len(rtl["instruction_observations"]),
                    "isa_instruction_count": len(isa["instruction_observations"]),
                    "isa_log_instruction_count": len(isa_log["instruction_observations"]),
                    "signature_different_word_count": len(diff["different_fields"]),
                    "architectural_differential_status": diff["status"],
                    "type2_verification_status": "NOT_ESTABLISHED"})
    _json(target / "processorfuzz-case-manifest.json", manifest)
    _json(target / "processorfuzz-si.json", si.model_dump(mode="json"))
    (target / "firmware-analysis.json").write_text(serialize_analysis(analysis))
    _json(target / "firmware-summary.json", firmware_summary(analysis))
    firmware_report = render_firmware_report(analysis)
    scope_note = ("> 输入角色：硬件团队提供的 trigger-test firmware；不是客户固件、生产固件或真实目标镜像。"
                  if role_declaration == HARDWARE_TRIGGER_VALIDATION else
                  "> 输入固件角色未分类；静态分析不证明客户固件具有相同指令行为。")
    (target / "firmware-report.md").write_text(
        firmware_report.replace("# Firmware Analysis Report\n",
                                f"# Firmware Analysis Report\n\n{scope_note}\n", 1))
    _json(target / "ghidra-export.json", exported.model_dump(mode="json", by_alias=True))
    _json(target / "rtl-runtime-evidence.json", {**rtl, "elf_byte_coverage": coverage_rtl,
                                                  "alignment": alignment})
    _json(target / "isa-reference-evidence.json", {**isa, "elf_byte_coverage": coverage_isa,
                                                    "isa_log_summary": {"source": isa_log["source"],
                                                    "instruction_count": len(isa_log["instruction_observations"]),
                                                    "unparsed_rows": isa_log["unparsed_rows"]}})
    _json(target / "architectural-differential.json", diff)
    static_caps = _static_capabilities(analysis)
    _json(target / "static-capabilities.json", {"schema_version": "general-static-capability-set/v1",
          "source_analysis_id": analysis.analysis_id, "capabilities": static_caps,
          "limitation": "General static model; frozen CAP0 has no real Ghidra source kind"})
    _json(target / "resource-bindings.json", {"status": "UNKNOWN",
          "reason": "No independently bound hardware resource catalog",
          "resource_hints": dict(Counter(x["resource_hint"] for x in static_caps))})
    _json(target / "capability-continuity.json", {"status": "UNKNOWN", "reason": "No runtime CAP0 capability for this real package"})
    _json(target / "cross-layer-candidates.json", {"status": "INCOMPLETE", "verification_status": "NOT_ESTABLISHED",
          "missing_requirements": ["authoritative_hardware_behavior_contract", "si_elf_build_binding",
                                   "signature_execution_context_binding", "rtl_source_revision",
                                   "generic_type2_runtime_evaluator"]})
    _json(target / "summary.json", summary)
    (target / "processorfuzz-report.md").write_text(_render_report(manifest, si, summary, rtl, isa,
                                                                     coverage_rtl, coverage_isa, diff, alignment))
    return target


def _render_report(manifest, si, summary, rtl, isa, cov_rtl, cov_isa, diff, alignment) -> str:
    selected = manifest["selected_paths"]
    roles = Counter(row["role"] for row in manifest["inventory"])
    role_statement = (
        "该 ZIP 是硬件团队真实交付的触发验证包；包内 ELF 是硬件团队制作的触发测试程序，"
        "不是客户固件、生产固件或真实目标固件镜像。它可以帮助理解硬件 trigger reference 并检查证据绑定，"
        "但不能证明客户固件包含该触发行为。"
        if manifest["package_role"] == "hardware_trigger_validation_package" else
        "包与 ELF 的角色尚未由调用方声明；不能据此推断客户固件行为。")
    lines = ["# ProcessorFuzz 真实交付包验收报告", "", "## 1. Case Summary", "",
             f"Case ID `{si.case_id}`；ELF SHA256 `{summary['elf_sha256']}`。",
             role_statement, "",
             "| 角色字段 | 值 |", "|---|---|",
             f"| package_role | `{manifest['package_role']}` |",
             f"| firmware_role | `{manifest['firmware_role']}` |",
             f"| firmware_origin | `{manifest['firmware_origin']}` |",
             f"| customer_firmware | `{str(manifest['customer_firmware']).lower() if manifest['customer_firmware'] is not None else 'not_established'}` |",
             f"| role_basis | `{manifest['role_basis']}` |", "",
             "包内签名的原始数值确实不同；当前缺少同一执行上下文和完整硬件来源绑定，因此不声称已验证漏洞或 Type-II 链。", "",
             "## 2. Input Artifact Inventory", "",
             f"归档共 {len(manifest['inventory'])} 个文件：" + "、".join(f"{role} {count}" for role, count in sorted(roles.items())) + "。",
             "完整逐文件 SHA256 见 `processorfuzz-case-manifest.json`。以下列出直接用于本轮分析的输入。", "",
             "| 文件 | 角色 | SHA256 |", "|---|---|---|"]
    for row in manifest["inventory"]:
        if row["role"] != "other":
            lines.append(f"| `{row['path']}` | {row['role']} | `{row['sha256']}` |")
    lines += ["", "## 3. Provenance / Binding Status", "",
              f"接受 SI `{selected['si']}`；ELF `{selected['elf']}`；RTL `{selected['rtl_trace']}`；"
              f"ISA CSV `{selected['isa_csv']}`；ISA log `{selected['isa_log']}`；"
              f"RTL/ISA signatures `{selected['rtl_signature']}` / `{selected['isa_signature']}`。", "",
              f"SI→ELF `{manifest['bindings']['si_to_elf']}`；RTL→ELF `{cov_rtl['status']}`；"
              f"ISA→ELF `{cov_isa['status']}`；signature 同次执行 `UNKNOWN`；RTL source revision `not_established`。", "",
              "### 拒绝或待绑定的文件", ""]
    for x in manifest["unbound_artifacts"]:
        lines.append(f"- `{x['path']}`：UNBOUND。{x['reason']}。")
    for x in manifest["conflicting_artifacts"]:
        lines.append(f"- `{x['path']}`：CONFLICT_WITH_ELF。{x['conflict_count']} 个映射字节冲突；不能作为 ELF 的权威反汇编。")
    lines += ["", "## 4. ProcessorFuzz SI Testcase", "",
              f"原始 SI SHA256 `{si.raw_sha256}`；模式 `{si.execution_mode or 'not established'}`；"
              f"解析 {len(si.instructions)} 条源指令，{len(si.labels)} 个标签；这些是测试描述，不是执行记录。", "",
              "## 5. Firmware Static Analysis Summary", "",
              f"Ghidra+ELF 分析 `{summary['instruction_count']}` 条指令、`{summary['function_count']}` 个函数、"
              f"`{summary['basic_block_count']}` 个基本块。CSR 读/写 "
              f"`{summary['system_register_read_count']}`/`{summary['system_register_write_count']}`；"
              f"barrier `{summary['barrier_count']}`；sfence.vma/TLB invalidate `{summary['tlb_invalidate_count']}`；"
              f"atomic behaviors `{summary['atomic_count']}`；"
              f"exception return `{summary['exception_return_count']}`。详见 `firmware-report.md`。", "",
              "## 6. RTL Runtime Trace Summary", "",
              f"解析 `{len(rtl['instruction_observations'])}` 条有表头约束的前六列记录；"
              f"ELF 匹配 `{cov_rtl['matching_elf_instructions']}`，冲突 `{cov_rtl['conflicting_elf_instructions']}`，"
              f"未映射 `{cov_rtl['unmapped_instructions']}`。其余列未声称完整解码。", "",
              "## 7. ISA Reference Trace Summary", "",
              f"CSV 解析 `{len(isa['instruction_observations'])}` 条 reference 记录；"
              f"ELF 匹配 `{cov_isa['matching_elf_instructions']}`，冲突 `{cov_isa['conflicting_elf_instructions']}`，"
              f"未映射 `{cov_isa['unmapped_instructions']}`。ISA 不是 DUT RTL。", "",
              "## 8. Exception / Privilege / CSR Observations", "",
              "静态 ELF 的 CSR/异常返回语义见固件报告；RTL 和 ISA 仅已解析明确的 PC、指令编码与 mode 列。"
              "没有建立完整 CSR 状态或异常事件 schema binding，不能归因 signature word。", "",
              "## 9. Architectural Differential", "",
              f"原始 128-bit 签名差异 `{len(diff['different_fields'])}` 个 word；"
              f"正式状态 `{diff['status']}`；trace 对齐 `{alignment['status']}`。", "",
              "| word index | RTL raw | ISA raw |", "|---:|---|---|"]
    for x in diff["different_fields"]:
        lines.append(f"| {x['index']} | `{x['rtl_raw']}` | `{x['isa_raw']}` |")
    lines += ["", "## 10. Cross-Layer Candidate", "",
              "固件静态事实与运行片段可供后续建立 Type-II candidate；当前没有可信 HBC，"
              "也没有对该非 MMIO 样本适用的冻结 verifier 输入，因此候选状态 INCOMPLETE。"
              "Candidate 不等于已验证 Type-II 链。", "",
              "## 11. Missing Verification Requirements", "",
              "- SI、ELF、trace、signature 的明确构建和运行来源绑定。",
              "- 完整 RTL source revision 或可信硬件构建 manifest。",
              "- 独立撰写并核验的硬件行为契约，以及适用非 MMIO 资源的运行评估器。", "",
              "## 12. Scientific Limitations", "",
              "`note.log` 只作人类笔记；`disassembly.asm` 若冲突则拒绝；签名差异不是漏洞证明。"
              "未运行 LLM，未根据包名、文件名或人工 bug 标签推断因果。", "",
              "General firmware-analysis 的验证依据是独立编写的项目固件样本，不是这个硬件触发测试 ELF。"
              "未来客户固件必须作为单独证据来源进入，并通过同一个 generic firmware frontend 分析。", ""]
    return "\n".join(lines)
