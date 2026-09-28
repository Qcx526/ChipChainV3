"""Prepare an evidence-bounded Type-II case from two existing CLI outputs.

This is a deterministic assembly stage, not the frozen Type-II verifier. In
particular, ProcessorFuzz runtime observations belong to its selected test ELF.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re

from chipchain.cross_layer.type2_verifier import RULE as FROZEN_VERIFIER_RULE
from chipchain.firmware.processorfuzz_si import ProcessorFuzzSiTestcase
from chipchain.firmware.ghidra_models import GhidraExport
from chipchain.firmware.report import firmware_summary
from chipchain.firmware.static_ir import (FirmwareStaticAnalysis, StaticBehaviorKind,
                                           content_id)
from chipchain.workflow.processorfuzz import (ProcessorFuzzRoleDeclaration,
                                               _static_capabilities)


SCHEMA = "type2-customer-case-assembly/v1"
MAX_JSON_BYTES = 64 * 1024 * 1024
HASH = re.compile(r"^[0-9a-f]{64}$")
# These kinds have a useful architecture-neutral semantic meaning without
# pretending that a shared generic load/store is a resource or run binding.
CANDIDATE_KINDS = frozenset({
    StaticBehaviorKind.TLB_INVALIDATE, StaticBehaviorKind.MEMORY_BARRIER,
    StaticBehaviorKind.INSTRUCTION_BARRIER, StaticBehaviorKind.EXCEPTION_RETURN,
    StaticBehaviorKind.ATOMIC_LOAD, StaticBehaviorKind.ATOMIC_STORE,
})
MANIFEST_NON_IDENTITY = frozenset({"manifest_id", "inventory", "selected_paths",
                                   "unbound_artifacts", "conflicting_artifacts"})
MANIFEST_REQUIRED = frozenset({
    "schema_version", "manifest_id", "case_id", "package_role", "firmware_role",
    "firmware_origin", "customer_firmware", "role_basis", "archive_sha256",
    "si_sha256", "elf_sha256", "rtl_trace_sha256", "isa_trace_sha256",
    "isa_log_sha256", "rtl_signature_sha256", "isa_signature_sha256",
    "simulator_sha256", "build_metadata_sha256", "rtl_source_revision",
    "bindings", "inventory", "selected_paths", "unbound_artifacts",
    "conflicting_artifacts", "conflicting_artifact_hashes",
})
SELECTED_HASHES = {
    "si": ("si_sha256", "si"), "elf": ("elf_sha256", "elf"),
    "rtl_trace": ("rtl_trace_sha256", "rtl_trace"),
    "isa_csv": ("isa_trace_sha256", "isa_csv"),
    "isa_log": ("isa_log_sha256", "isa_log"),
    "rtl_signature": ("rtl_signature_sha256", "rtl_signature"),
    "isa_signature": ("isa_signature_sha256", "isa_signature"),
}


@dataclass(frozen=True)
class PreparedCase:
    case_manifest: dict
    association: dict
    readiness: dict
    report: str


def _object_no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Duplicate JSON key: {key}")
        value[key] = item
    return value


def _json(directory: Path, name: str) -> object:
    path = directory / name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Missing or unsafe canonical artifact: {name}")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"Canonical artifact exceeds size bound: {name}")
    try:
        return json.loads(path.read_text(encoding="utf-8"),
                          object_pairs_hook=_object_no_duplicates,
                          parse_constant=lambda token: (_ for _ in ()).throw(
                              ValueError(f"Non-finite JSON value: {token}")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid canonical JSON: {name}") from exc


def _dict(value: object, name: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return value


def _sha(value: object, name: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or HASH.fullmatch(value) is None:
        raise ValueError(f"Invalid SHA256 in {name}")
    return value


def _analysis(directory: Path) -> FirmwareStaticAnalysis:
    analysis = FirmwareStaticAnalysis.model_validate(
        _dict(_json(directory, "firmware-analysis.json"), "firmware-analysis.json"))
    summary = _dict(_json(directory, "firmware-summary.json"), "firmware-summary.json")
    if summary != firmware_summary(analysis):
        raise ValueError("firmware-analysis.json and firmware-summary.json disagree")
    exported = GhidraExport.model_validate(
        _dict(_json(directory, "ghidra-export.json"), "ghidra-export.json"))
    if (exported.language != analysis.ghidra_language
            or len(exported.instructions) != len(analysis.instructions)):
        raise ValueError("Ghidra export and firmware analysis disagree")
    for raw, fact in zip(sorted(exported.instructions, key=lambda item: item.pc),
                         analysis.instructions, strict=True):
        if (raw.pc, raw.bytes, raw.mnemonic, tuple(raw.operands), raw.text) != (
                fact.pc, fact.raw_bytes, fact.mnemonic, fact.operands, fact.text):
            raise ValueError("Ghidra instruction and firmware analysis disagree")
    return analysis


def _manifest(directory: Path, si: ProcessorFuzzSiTestcase, analysis: FirmwareStaticAnalysis) -> dict:
    manifest = _dict(_json(directory, "processorfuzz-case-manifest.json"),
                     "processorfuzz-case-manifest.json")
    if (manifest.get("schema_version") != "processorfuzz-case-manifest/v2"
            or not MANIFEST_REQUIRED.issubset(manifest)):
        raise ValueError("Unsupported ProcessorFuzz manifest schema")
    declared = {key: value for key, value in manifest.items()
                if key not in MANIFEST_NON_IDENTITY}
    if manifest.get("manifest_id") != content_id("processorfuzz-manifest", declared):
        raise ValueError("ProcessorFuzz manifest identity mismatch")
    ProcessorFuzzRoleDeclaration.model_validate({key: manifest.get(key) for key in (
        "package_role", "firmware_role", "firmware_origin", "customer_firmware", "role_basis")})
    if manifest.get("case_id") != si.case_id or manifest.get("si_sha256") != si.raw_sha256:
        raise ValueError("ProcessorFuzz SI and manifest disagree")
    if manifest.get("elf_sha256") != analysis.artifact.sha256:
        raise ValueError("ProcessorFuzz selected ELF and static analysis disagree")
    _sha(manifest.get("archive_sha256"), "archive_sha256", nullable=True)
    bindings = manifest.get("bindings")
    if (not isinstance(bindings, dict) or set(bindings) != {
            "si_to_elf", "rtl_trace_to_elf", "isa_trace_to_elf", "signatures_same_execution"}
            or not all(isinstance(value, str) for value in bindings.values())):
        raise ValueError("ProcessorFuzz binding status has invalid shape")

    inventory = manifest.get("inventory")
    selected = manifest.get("selected_paths")
    if not isinstance(inventory, list) or not isinstance(selected, dict) or set(selected) != set(SELECTED_HASHES):
        raise ValueError("ProcessorFuzz selected paths or inventory have invalid shape")
    by_path: dict[str, dict] = {}
    for entry in inventory:
        if not isinstance(entry, dict) or set(entry) != {"path", "role", "sha256", "artifact_id", "size_bytes"}:
            raise ValueError("Invalid ProcessorFuzz inventory row")
        path = entry["path"]
        digest = _sha(entry["sha256"], "inventory.sha256")
        if (not isinstance(path, str) or not path or path in by_path
                or entry["artifact_id"] != f"sha256:{digest}"
                or type(entry["size_bytes"]) is not int or entry["size_bytes"] < 0):
            raise ValueError("Invalid ProcessorFuzz inventory identity")
        by_path[path] = entry
    for key, (hash_key, role) in SELECTED_HASHES.items():
        path, digest = selected[key], manifest.get(hash_key)
        if path is None and digest is None and key in {"rtl_trace", "isa_csv", "isa_log"}:
            continue
        if (not isinstance(path, str) or path not in by_path
                or by_path[path]["role"] != role
                or by_path[path]["sha256"] != _sha(digest, hash_key)):
            raise ValueError(f"ProcessorFuzz selected {key} and manifest disagree")
    return manifest


def _hardware(directory: Path) -> tuple[dict, FirmwareStaticAnalysis, dict, dict, dict, dict]:
    si = ProcessorFuzzSiTestcase.model_validate(
        _dict(_json(directory, "processorfuzz-si.json"), "processorfuzz-si.json"))
    analysis = _analysis(directory)
    manifest = _manifest(directory, si, analysis)
    summary = _dict(_json(directory, "summary.json"), "summary.json")
    for key, value in firmware_summary(analysis).items():
        if summary.get(key) != value:
            raise ValueError(f"ProcessorFuzz summary disagrees on {key}")
    if (summary.get("manifest_id") != manifest["manifest_id"]
            or summary.get("case_id") != manifest["case_id"]):
        raise ValueError("ProcessorFuzz summary identity mismatch")
    if summary.get("ingestion_profile") != manifest.get("ingestion_profile"):
        raise ValueError("ProcessorFuzz ingestion profiles disagree")

    caps = _dict(_json(directory, "static-capabilities.json"), "static-capabilities.json")
    if (caps.get("schema_version") != "general-static-capability-set/v1"
            or caps.get("source_analysis_id") != analysis.analysis_id
            or caps.get("capabilities") != _static_capabilities(analysis)):
        raise ValueError("ProcessorFuzz static capabilities disagree with analysis")
    resource = _dict(_json(directory, "resource-bindings.json"), "resource-bindings.json")
    continuity = _dict(_json(directory, "capability-continuity.json"), "capability-continuity.json")
    candidates = _dict(_json(directory, "cross-layer-candidates.json"),
                       "cross-layer-candidates.json")
    if (resource.get("status") != "UNKNOWN" or continuity.get("status") != "UNKNOWN"
            or candidates.get("status") != "INCOMPLETE"
            or candidates.get("verification_status") != "NOT_ESTABLISHED"
            or summary.get("type2_verification_status") != candidates["verification_status"]
            or not isinstance(candidates.get("missing_requirements"), list)
            or not all(isinstance(x, str) for x in candidates["missing_requirements"])):
        raise ValueError("Unsupported or inconsistent ProcessorFuzz readiness artifacts")
    expected_hints = dict(Counter(cap["resource_hint"] for cap in caps["capabilities"]))
    if resource.get("resource_hints") != expected_hints:
        raise ValueError("ProcessorFuzz resource hints disagree with static capabilities")

    diff = _dict(_json(directory, "architectural-differential.json"),
                 "architectural-differential.json")
    diff_fields = {key: value for key, value in diff.items() if key != "differential_id"}
    if (diff.get("differential_id") != content_id("architectural-differential", diff_fields)
            or diff.get("rtl_artifact_id") != "sha256:" + manifest["rtl_signature_sha256"]
            or diff.get("reference_artifact_id") != "sha256:" + manifest["isa_signature_sha256"]
            or summary.get("architectural_differential_status") != diff.get("status")
            or diff.get("same_execution_context_binding") != manifest["bindings"]["signatures_same_execution"]
            or not isinstance(diff.get("different_fields"), list)
            or summary.get("signature_different_word_count") != len(diff["different_fields"])):
        raise ValueError("ProcessorFuzz differential identity mismatch")

    has_trace = manifest["selected_paths"]["rtl_trace"] is not None
    if not has_trace and (manifest["bindings"]["rtl_trace_to_elf"] != "UNKNOWN"
                          or manifest["bindings"]["isa_trace_to_elf"] != "UNKNOWN"):
        raise ValueError("Absent ProcessorFuzz traces cannot have ELF binding")
    for name, trace_key, count_key, binding_key in (
        ("rtl-runtime-evidence.json", "rtl_trace_sha256", "rtl_instruction_count", "rtl_trace_to_elf"),
        ("isa-reference-evidence.json", "isa_trace_sha256", "isa_instruction_count", "isa_trace_to_elf"),
    ):
        if not has_trace:
            if (directory / name).exists() or summary.get(count_key) is not None:
                raise ValueError("ProcessorFuzz trace profile disagrees with runtime output")
            continue
        trace = _dict(_json(directory, name), name)
        source = _dict(trace.get("source"), f"{name}.source")
        for field in ("case_id", "elf_sha256", "si_sha256", "rtl_trace_sha256",
                      "isa_trace_sha256", "simulator_sha256", "build_metadata_sha256",
                      "rtl_source_revision"):
            if source.get(field) != manifest.get(field):
                raise ValueError(f"ProcessorFuzz runtime source disagrees on {field}")
        if (source.get("trace_sha256") != manifest[trace_key]
                or not isinstance(trace.get("instruction_observations"), list)
                or len(trace["instruction_observations"]) != summary.get(count_key)
                or not isinstance(trace.get("elf_byte_coverage"), dict)
                or trace["elf_byte_coverage"].get("status") != manifest["bindings"].get(binding_key)):
            raise ValueError(f"ProcessorFuzz runtime evidence disagrees: {name}")
    return manifest, analysis, summary, caps, resource, candidates


def _candidate_relations(firmware: FirmwareStaticAnalysis, hardware_caps: list[dict]) -> list[dict]:
    by_kind: dict[str, list[dict]] = {}
    for cap in hardware_caps:
        if cap["semantic_status"] == "supported" and cap["kind"] in CANDIDATE_KINDS:
            by_kind.setdefault(cap["kind"], []).append(cap)
    relations = []
    for kind, caps in sorted(by_kind.items()):
        facts = sorted(b.fact_id for b in firmware.behaviors
                       if b.kind == kind and b.semantic_status == "supported")
        relations.append({
            "kind": kind,
            "status": "SUPPORTED_CANDIDATE" if facts else "NO_STATIC_KIND_MATCH",
            "scope": "static_semantic_kind_only",
            "hardware_reference_source": "selected_processorfuzz_test_elf_static_analysis",
            "firmware_behavior_fact_ids": facts,
            "hardware_test_static_capability_ids": sorted(cap["capability_id"] for cap in caps),
        })
    return relations


def prepare_case(firmware_directory: str | Path, hardware_directory: str | Path) -> PreparedCase:
    """Validate two independent canonical analyses and assemble without writing."""
    firmware_dir, hardware_dir = Path(firmware_directory), Path(hardware_directory)
    if not firmware_dir.is_dir() or not hardware_dir.is_dir():
        raise ValueError("Firmware and hardware inputs must be existing analysis directories")
    firmware = _analysis(firmware_dir)
    hw_manifest, hardware, hw_summary, caps, resource, candidates = _hardware(hardware_dir)
    same_bytes = firmware.artifact.sha256 == hardware.artifact.sha256
    identity_status = "SAME_ELF_BYTES" if same_bytes else "DISTINCT_FIRMWARE"
    compatible = all((firmware.artifact.architecture == hardware.artifact.architecture,
                      firmware.artifact.bit_width == hardware.artifact.bit_width,
                      firmware.artifact.endianness == hardware.artifact.endianness))
    identity = {
        "firmware_analysis_id": firmware.analysis_id,
        "firmware_elf_sha256": firmware.artifact.sha256,
        "hardware_manifest_id": hw_manifest["manifest_id"],
        "hardware_case_id": hw_manifest["case_id"],
        "hardware_test_elf_sha256": hardware.artifact.sha256,
    }
    case_id = content_id("type2-case-assembly", {"schema_version": SCHEMA, **identity})
    relation = {"status": identity_status,
                "basis": "selected_elf_sha256_equality_only",
                "same_execution_established": False}
    case_manifest = {
        "schema_version": SCHEMA, "case_id": case_id,
        "input_validation_scope": "canonical_output_internal_consistency_no_raw_elf_or_zip_replay",
        "firmware_side": {
            "analysis_id": firmware.analysis_id, "elf_sha256": firmware.artifact.sha256,
            "architecture": firmware.artifact.architecture,
            "bit_width": firmware.artifact.bit_width, "endianness": firmware.artifact.endianness,
            "role": "not_established_by_static_analysis",
        },
        "hardware_side": {
            "manifest_id": hw_manifest["manifest_id"], "case_id": hw_manifest["case_id"],
            "archive_sha256": hw_manifest["archive_sha256"],
            "selected_test_elf_sha256": hardware.artifact.sha256,
            "analysis_id": hardware.analysis_id,
            "architecture": hardware.artifact.architecture,
            "bit_width": hardware.artifact.bit_width, "endianness": hardware.artifact.endianness,
            "package_role": hw_manifest["package_role"],
            "firmware_role": hw_manifest["firmware_role"],
            "firmware_origin": hw_manifest["firmware_origin"],
            "role_basis": hw_manifest["role_basis"],
            "customer_firmware": hw_manifest["customer_firmware"],
        },
        "identity_relation": relation,
    }
    relations = _candidate_relations(firmware, caps["capabilities"])
    association = {
        "schema_version": "type2-case-association/v1", "case_id": case_id,
        "firmware_identity_relation": relation,
        "architecture_compatibility": {
            "status": "SUPPORTED" if compatible else "INCOMPATIBLE",
            "basis": "architecture_bit_width_endianness",
            "scope": "ELF_architecture_tuple_only_not_platform_compatibility",
        },
        "semantic_candidate_relations": relations,
        "resource_binding_status": resource["status"],
        "runtime_binding_status": "UNKNOWN",
        "hardware_trigger_status": "NOT_ESTABLISHED",
        "hardware_trigger_basis": "no_authoritative_contract_or_firmware_specific_runtime_binding",
        "hardware_differential_status": hw_summary["architectural_differential_status"],
        "hardware_package_candidate_status": candidates["status"],
        "hardware_package_verification_status": candidates["verification_status"],
    }
    # workflow/type2.py requires an HBC, target/reference RunEvidence with
    # static/runtime/bridge/CAP0 and raw bytes, plus controlled source/state/
    # observation bindings. The two accepted public CLI outputs provide none
    # of that firmware-specific chain. This is a baseline gap inventory, not
    # an exhaustive or generic proof that a future verifier could be invoked.
    # The existing verifier is additionally pinned to controlled Ibex MMIO.
    missing = [
        "authoritative_hardware_behavior_contract",
        "firmware_specific_runtime_execution_and_source_binding",
        "firmware_specific_reference_variant_run_evidence",
        "controlled_source_state_and_observation_bindings",
    ]
    package_gaps = []
    if resource["status"] != "SUPPORTED":
        package_gaps.append("independently_bound_hardware_resource_catalog")
    if hw_manifest["bindings"]["si_to_elf"] != "BOUND":
        package_gaps.append("hardware_si_to_test_elf_build_binding")
    if hw_manifest["bindings"]["signatures_same_execution"] != "BOUND":
        package_gaps.append("hardware_signature_execution_context_binding")
    readiness = {
        "schema_version": "type2-verification-readiness/v1", "case_id": case_id,
        "assembly_status": "COMPLETE", "ready": False, "status": "NOT_READY",
        "verifier_rule_version": FROZEN_VERIFIER_RULE,
        "verifier_applicability_status": "NOT_APPLICABLE",
        "verifier_applicability_reason": "current_processorfuzz_output_is_not_controlled_ibex_mmio_evidence",
        "requirements_scope": "baseline_gaps_for_current_public_cli_outputs_not_exhaustive",
        "available_evidence": [
            {"kind": "firmware_static_analysis", "id": firmware.analysis_id},
            {"kind": "hardware_test_static_analysis", "id": hardware.analysis_id},
            {"kind": "hardware_package_manifest", "id": hw_manifest["manifest_id"]},
            {"kind": "hardware_signature_comparison", "id": _dict(
                _json(hardware_dir, "architectural-differential.json"),
                "architectural-differential.json")["differential_id"]},
        ] + ([{"kind": "hardware_test_rtl_trace", "id": "sha256:" + hw_manifest["rtl_trace_sha256"]},
              {"kind": "hardware_test_isa_trace", "id": "sha256:" + hw_manifest["isa_trace_sha256"]}]
             if hw_manifest["rtl_trace_sha256"] is not None else []),
        "missing_requirements": missing,
        "hardware_package_evidence_gaps": package_gaps,
        "blocking_conflicts": ([] if compatible else ["architecture_bit_width_or_endianness_mismatch"]),
        "verifier_invoked": False,
        "frozen_verifier_manifest_emitted": False,
    }
    return PreparedCase(case_manifest, association, readiness,
                        _report(case_manifest, association, readiness))


def _report(manifest: dict, association: dict, readiness: dict) -> str:
    firmware, hardware = manifest["firmware_side"], manifest["hardware_side"]
    relation = association["firmware_identity_relation"]["status"]
    distinct = relation == "DISTINCT_FIRMWARE"
    lines = [
        "# ChipChain Type-II 案例装配报告", "",
        "**案例装配完成；Type-II 验证尚未就绪，也没有运行冻结 verifier。**", "",
        "## 1. 案例概要", "",
        f"- 案例 ID：`{manifest['case_id']}`",
        f"- 架构兼容：`{association['architecture_compatibility']['status']}`",
        "- 装配成功不等于 Type-II 验证成功。", "",
        "- 本阶段核对规范输出之间的一致性；没有在装配时重新读取原始 ELF 或 ZIP。", "",
        "## 2. 固件侧身份", "",
        f"- 静态分析：`{firmware['analysis_id']}`",
        f"- ELF SHA256：`{firmware['elf_sha256']}`",
        f"- 架构：{firmware['architecture']} / {firmware['bit_width']}-bit / {firmware['endianness']}",
        "- 静态分析不证明固件来源或运行情况。本项目的 FW-POS/FW-NEG 基准是现实风格合成固件，不是客户生产固件；不能仅凭输入目录名为任意 ELF 指派该身份。", "",
        "## 3. 硬件侧身份", "",
        f"- ProcessorFuzz manifest：`{hardware['manifest_id']}`",
        f"- 包 SHA256：`{hardware['archive_sha256'] or '未提供（目录输入）'}`",
        f"- 选定测试 ELF SHA256：`{hardware['selected_test_elf_sha256']}`",
        f"- 包角色：`{hardware['package_role']}`；包内 ELF 角色：`{hardware['firmware_role']}`。", "",
        "## 4. 身份分离", "",
        f"- 固件 ELF 与硬件测试 ELF：`{relation}`。",
        ("- 两份 ELF 的 SHA256 不同；ProcessorFuzz trace、ISA trace 和签名不能转绑到所给固件。"
         if distinct else "- ELF 字节相同也不自动证明同次执行或来源绑定。"), "",
        "## 5. 静态语义候选", "",
        "硬件侧的参考事实来自 ProcessorFuzz 所选测试 ELF 的静态分析及其 general-static-capability 投影，"
        "不是 SI、RTL/ISA trace、签名、HardwareBehaviorContract 或已验证的硬件行为。", "",
        "下表只比较经过规范静态分析的行为种类；未匹配具体操作数、资源实例、执行顺序、"
        "有效上下文或 RTL 修订。共同种类不是资源绑定、触发或运行证据。", "",
        "| 行为种类 | 静态关联 | 固件事实数 | 测试 ELF 静态 capability 数 |",
        "| --- | --- | ---: | ---: |",
    ]
    for item in association["semantic_candidate_relations"]:
        lines.append(f"| `{item['kind']}` | `{item['status']}` | "
                     f"{len(item['firmware_behavior_fact_ids'])} | "
                     f"{len(item['hardware_test_static_capability_ids'])} |")
    if not association["semantic_candidate_relations"]:
        lines.append("| 无可比较的已支持种类 | `UNKNOWN` | 0 | 0 |")
    tlb = next((item for item in association["semantic_candidate_relations"]
                if item["kind"] == "TLB_INVALIDATE"), None)
    if tlb is not None:
        lines += ["", ("所给固件与包内测试 ELF 有 `TLB_INVALIDATE` 种类的静态候选；"
                        "这不证明操作数相同或指令曾执行。"
                        if tlb["status"] == "SUPPORTED_CANDIDATE" else
                        "相对于包内测试 ELF 的 `TLB_INVALIDATE` 静态参考种类，所给固件没有"
                        "同种类的规范静态事实；这不构成触发反证或硬件安全证明。")]
    lines += ["", "## 6. 运行与硬件证据", "",
              f"- 固件运行来源绑定：`{association['runtime_binding_status']}`。",
              f"- 硬件资源绑定：`{association['resource_binding_status']}`。",
              f"- 所给固件的硬件触发：`{association['hardware_trigger_status']}`。",
              f"- 原硬件包的 Type-II 候选/验证状态：`{association['hardware_package_candidate_status']}` / "
              f"`{association['hardware_package_verification_status']}`。",
              f"- 硬件包原始签名差异的正式状态：`{association['hardware_differential_status']}`。",
              ("- 硬件包 trace 的 source 字段指向所选测试 ELF，但来源和执行绑定仍不完整；"
               "它们不是所给固件的运行证据。" if any(
                   item["kind"] == "hardware_test_rtl_trace" for item in readiness["available_evidence"])
               else "- 硬件包没有指令级运行 trace；签名比较不能补足所给固件的运行证据。"), "",
              "## 7. 缺失的验证条件", "",
              "按当前冻结 verifier 的证据输入契约，现有两种公开分析输出缺少以下基础材料；"
              "这不是穷尽的通用 verifier 检查清单：", ""]
    lines.extend(f"- `{item}`" for item in readiness["missing_requirements"])
    lines += ["", "硬件包自身另有以下来源/资源证据缺口，不能把它们等同于 verifier 的输入字段：", ""]
    lines.extend(f"- `{item}`" for item in readiness["hardware_package_evidence_gaps"])
    if readiness["blocking_conflicts"]:
        lines += ["", "架构冲突：" + ", ".join(readiness["blocking_conflicts"])]
    lines += ["", "## 8. 验证准备度", "",
              f"- `ready={str(readiness['ready']).lower()}`；状态 `{readiness['status']}`。",
              f"- 当前冻结规则 `{readiness['verifier_rule_version']}` 对本案例："
              f"`{readiness['verifier_applicability_status']}`。它只适用于固定的受控 Ibex MMIO "
              "Reference/Variant 证据；补齐上述缺口也不能直接用它验证 ProcessorFuzz/TLB 案例。",
              "- 没有构造冻结 verifier 的输入 manifest，也没有产生 VERIFIED 结论。", "",
              "## 9. 科学边界", "",
              "静态事实不等于运行事实；静态语义相似不等于相同固件或同次执行。",
              "硬件测试包不能证明客户固件满足触发条件、发生偏差或存在漏洞。",
              "模拟/分析结果不代表物理硅片适用性。", ""]
    return "\n".join(lines)


def write_case(prepared: PreparedCase, output_directory: str | Path) -> Path:
    """Persist only on explicit request, into a new or empty directory."""
    target = Path(output_directory)
    if target.is_symlink() or (target.exists() and (not target.is_dir() or any(target.iterdir()))):
        raise ValueError("Output directory must be new or empty")
    target.mkdir(parents=True, exist_ok=True)
    for name, value in (("case-manifest.json", prepared.case_manifest),
                        ("association.json", prepared.association),
                        ("verification-readiness.json", prepared.readiness)):
        (target / name).write_text(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                             indent=2, allow_nan=False) + "\n", encoding="utf-8")
    (target / "report.md").write_text(prepared.report, encoding="utf-8")
    return target
