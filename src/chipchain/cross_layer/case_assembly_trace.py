"""Explanatory projection of an already computed Type-II case assembly.

This module does not produce evidence, assign scientific IDs, or decide an
association. Every reported status is copied from the validated V1 assembly.
"""
from __future__ import annotations

from chipchain.firmware.static_ir import FirmwareStaticAnalysis


SCHEMA = "type2-analysis-chain/v1"
HARDWARE_REFERENCE = "selected_processorfuzz_test_elf_static_analysis"
BASE_REQUIREMENTS = {
    "authoritative_hardware_behavior_contract": (
        "current Type-II evidence contract", "无权威 HardwareBehaviorContract；测试 ELF 的静态事实不能替代合同"),
    "firmware_specific_runtime_execution_and_source_binding": (
        "current Type-II RunEvidence contract", "没有所给固件的运行及来源绑定；包内 trace 若存在也只关联测试 ELF"),
    "firmware_specific_reference_variant_run_evidence": (
        "current Type-II target/reference RunEvidence contract", "缺少适用于所给固件的 Reference/Variant 运行证据"),
    "controlled_source_state_and_observation_bindings": (
        "controlled-ibex-type2-runtime/v1", "缺少受控来源、内部状态及观测值的显式绑定"),
}
PACKAGE_GAPS = {
    "independently_bound_hardware_resource_catalog": (
        "ProcessorFuzz resource provenance", "资源提示不是已绑定的硬件资源实例"),
    "hardware_si_to_test_elf_build_binding": (
        "ProcessorFuzz SI/ELF provenance", "SI 与所选测试 ELF 的构建关系未建立"),
    "hardware_signature_execution_context_binding": (
        "ProcessorFuzz signature provenance", "签名之间的同次执行上下文未建立"),
}


def _stage(number: int, operation: str, implementation_function: str,
           inputs: list[str], checks_or_rule: list[str], outputs: dict,
           result: object, scientific_boundary: str) -> dict:
    return {
        "stage_id": f"S{number}", "operation": operation,
        "implementation_function": implementation_function, "inputs": inputs,
        "checks_or_rule": checks_or_rule, "outputs": outputs, "result": result,
        "scientific_boundary": scientific_boundary,
    }


def _instruction(analysis: FirmwareStaticAnalysis, instruction_id: str) -> dict | None:
    source = next((item for item in analysis.instructions if item.fact_id == instruction_id), None)
    if source is None:
        return None
    return {"instruction_id": source.fact_id, "pc": source.pc,
            "mnemonic": source.mnemonic, "operands": list(source.operands)}


def _supported_facts(analysis: FirmwareStaticAnalysis, kinds: tuple[str, ...]) -> list[dict]:
    rows = []
    for kind in kinds:
        ids = sorted(item.fact_id for item in analysis.behaviors
                     if item.kind == kind and item.semantic_status == "supported")
        rows.append({"kind": kind, "count": len(ids), "fact_ids": ids})
    return rows


def _supported_capabilities(capabilities: list[dict], kinds: tuple[str, ...]) -> list[dict]:
    rows = []
    for kind in kinds:
        ids = sorted(item["capability_id"] for item in capabilities
                     if item["kind"] == kind and item["semantic_status"] == "supported")
        rows.append({"kind": kind, "count": len(ids), "capability_ids": ids,
                     "origin": HARDWARE_REFERENCE})
    return rows


def _relations(firmware: FirmwareStaticAnalysis, hardware: FirmwareStaticAnalysis,
               capabilities: list[dict], association: dict) -> list[dict]:
    fw_facts = {item.fact_id: item for item in firmware.behaviors}
    hw_facts = {item.fact_id: item for item in hardware.behaviors}
    hw_caps = {item["capability_id"]: item for item in capabilities}
    result = []
    for relation in association["semantic_candidate_relations"]:
        firmware_rows = []
        for fact_id in relation["firmware_behavior_fact_ids"]:
            fact = fw_facts[fact_id]
            firmware_rows.append({"fact_id": fact.fact_id,
                                  "source_instruction": _instruction(firmware, fact.instruction_id)})
        hardware_rows = []
        for capability_id in relation["hardware_test_static_capability_ids"]:
            cap = hw_caps[capability_id]
            fact = hw_facts[cap["behavior_fact_id"]]
            hardware_rows.append({"capability_id": capability_id,
                                  "behavior_fact_id": fact.fact_id,
                                  "source_instruction": _instruction(hardware, fact.instruction_id),
                                  "execution_status": cap["execution_status"]})
        result.append({
            "kind": relation["kind"], "firmware_fact_count": len(firmware_rows),
            "firmware_facts": firmware_rows,
            "hardware_reference_source": relation["hardware_reference_source"],
            "hardware_capability_count": len(hardware_rows),
            "hardware_capabilities": hardware_rows,
            "rule": "compare_supported_architecture_neutral_static_semantic_kind_only",
            "scope": relation["scope"], "status": relation["status"],
        })
    return result


def _requirements(readiness: dict, hardware_manifest: dict, association: dict,
                  runtime_material: list[dict]) -> list[dict]:
    rows = []
    available = {
        "authoritative_hardware_behavior_contract": [],
        "firmware_specific_runtime_execution_and_source_binding": (
            ["ProcessorFuzz hardware-test runtime material only"] if runtime_material else []),
        "firmware_specific_reference_variant_run_evidence": [],
        "controlled_source_state_and_observation_bindings": [],
        "independently_bound_hardware_resource_catalog": [
            f"resource_binding_status={association['resource_binding_status']}"],
        "hardware_si_to_test_elf_build_binding": [
            f"manifest.bindings.si_to_elf={hardware_manifest['bindings']['si_to_elf']}"],
        "hardware_signature_execution_context_binding": [
            "manifest.bindings.signatures_same_execution="
            + hardware_manifest["bindings"]["signatures_same_execution"]],
    }
    for group, names, descriptions in (
        ("frozen_verifier_baseline", readiness["missing_requirements"], BASE_REQUIREMENTS),
        ("hardware_package_provenance", readiness["hardware_package_evidence_gaps"], PACKAGE_GAPS),
    ):
        for name in names:
            required_by, reason = descriptions.get(
                name, ("existing verification-readiness.json", "原准备度对象列出的未满足条件"))
            rows.append({"requirement": name, "group": group,
                         "required_by": required_by,
                         "available_evidence": available.get(name, []),
                         "evaluation": "MISSING", "reason": reason,
                         "effect": "verification_not_ready"})
    return rows


def build_analysis_chain(*, firmware: FirmwareStaticAnalysis,
                         hardware: FirmwareStaticAnalysis, hardware_manifest: dict,
                         hardware_caps: dict, differential: dict, runtime_material: list[dict],
                         case_manifest: dict, association: dict, readiness: dict,
                         candidate_kinds: tuple[str, ...]) -> dict:
    """Project validated inputs and already-computed outcomes; do not re-decide them."""
    fw_side, hw_side = case_manifest["firmware_side"], case_manifest["hardware_side"]
    fw_tuple = {key: fw_side[key] for key in ("architecture", "bit_width", "endianness")}
    hw_tuple = {key: hw_side[key] for key in ("architecture", "bit_width", "endianness")}
    candidate_rows = _relations(firmware, hardware, hardware_caps["capabilities"], association)
    requirement_rows = _requirements(readiness, hardware_manifest, association,
                                     runtime_material)
    stages = [
        _stage(1, "validate_firmware_canonical_analysis", "chipchain.cross_layer.case_assembly._analysis",
               ["firmware-analysis.json", "firmware-summary.json", "ghidra-export.json"],
               ["summary equals firmware_summary(analysis)", "Ghidra language and instruction count match",
                "each sorted Ghidra instruction tuple matches the normalized instruction"],
               {"analysis_id": fw_side["analysis_id"], "elf_sha256": fw_side["elf_sha256"],
                "architecture_tuple": fw_tuple,
                "supported_candidate_kind_facts": _supported_facts(firmware, candidate_kinds)},
               "canonical_outputs_consistent", "Does not re-attest original ELF bytes or establish runtime execution."),
        _stage(2, "validate_hardware_package_canonical_analysis",
               "chipchain.cross_layer.case_assembly._hardware",
               ["processorfuzz-si.json", "firmware-analysis.json", "firmware-summary.json",
                "ghidra-export.json", "processorfuzz-case-manifest.json", "summary.json",
                "static-capabilities.json", "resource-bindings.json",
                "capability-continuity.json", "cross-layer-candidates.json",
                "architectural-differential.json"]
               + [item["artifact"] for item in runtime_material],
               ["_analysis validates the selected test ELF analysis",
                "_manifest validates SI, role declaration, inventory and selected artifact hashes",
                "static capabilities equal the deterministic projection of test ELF analysis",
                "runtime source fields agree with the manifest when trace outputs exist",
                "architectural differential identity and signature references agree"],
               {"manifest_id": hw_side["manifest_id"], "archive_sha256": hw_side["archive_sha256"],
                "selected_test_elf_sha256": hw_side["selected_test_elf_sha256"],
                "static_analysis_id": hw_side["analysis_id"],
                "package_role": hw_side["package_role"], "firmware_role": hw_side["firmware_role"],
                "supported_candidate_kind_capabilities": _supported_capabilities(
                    hardware_caps["capabilities"], candidate_kinds)},
               "canonical_outputs_consistent",
               "Static facts come from the hardware team's selected test ELF, not an HBC or verified hardware behavior."),
        _stage(3, "compare_elf_identity", "chipchain.cross_layer.case_assembly.prepare_case",
               ["case-manifest.json.firmware_side.elf_sha256",
                "case-manifest.json.hardware_side.selected_test_elf_sha256"],
               ["selected ELF SHA256 equality only"],
               {"firmware_elf_sha256": fw_side["elf_sha256"],
                "hardware_test_elf_sha256": hw_side["selected_test_elf_sha256"],
                "same_execution_established": case_manifest["identity_relation"]["same_execution_established"]},
               case_manifest["identity_relation"]["status"],
               "Distinct firmware cannot inherit ProcessorFuzz runtime material; equal bytes alone also do not prove same execution."),
        _stage(4, "compare_architecture_tuple", "chipchain.cross_layer.case_assembly.prepare_case",
               ["firmware-analysis.json.artifact", "hardware firmware-analysis.json.artifact"],
               ["architecture, bit width and endianness equality"],
               {"firmware": fw_tuple, "hardware_test_elf": hw_tuple},
               association["architecture_compatibility"]["status"],
               "Architecture tuple compatibility does not establish platform compatibility."),
        _stage(5, "associate_static_semantic_kinds",
               "chipchain.cross_layer.case_assembly._candidate_relations",
               ["firmware-analysis.json.behaviors", "hardware static-capabilities.json.capabilities"],
               ["supported candidate kinds only", "compare architecture-neutral semantic kind only",
                "copy statuses and IDs from association.json"],
               {"relations": candidate_rows},
               [{"kind": item["kind"], "status": item["status"]} for item in candidate_rows],
               "A candidate is not matching operands, resource, run, order or trigger; no static kind match is not a trigger contradiction or hardware safety finding."),
        _stage(6, "isolate_hardware_runtime_provenance",
               "chipchain.cross_layer.case_assembly._hardware / prepare_case",
               [item["artifact"] for item in runtime_material] + ["processorfuzz-case-manifest.json"],
               ["recorded RuntimeSource fields must agree with the selected test ELF manifest",
                "assembly does not rebind hardware-test traces or signatures to supplied firmware"],
               {"runtime_material": runtime_material,
                "rtl_trace_sha256": hardware_manifest["rtl_trace_sha256"],
                "isa_trace_sha256": hardware_manifest["isa_trace_sha256"],
                "rtl_signature_artifact_id": "sha256:" + hardware_manifest["rtl_signature_sha256"],
                "isa_signature_artifact_id": "sha256:" + hardware_manifest["isa_signature_sha256"],
                "hardware_test_elf_sha256": hw_side["selected_test_elf_sha256"],
                "supplied_firmware_elf_sha256": fw_side["elf_sha256"]},
               association["runtime_binding_status"],
               "Recorded source and partial byte coverage are not full SI/build/run provenance or supplied-firmware runtime binding."),
        _stage(7, "evaluate_hardware_signature_differential",
               "chipchain.cross_layer.case_assembly._hardware",
               ["architectural-differential.json", "processorfuzz-case-manifest.json"],
               ["differential ID and selected signature references agree",
                "raw differing words do not prove same testcase, firmware or execution context"],
               {"differential_id": differential["differential_id"],
                "comparison_scope": differential["comparison_scope"],
                "raw_values_differ": differential["raw_values_differ"],
                "raw_differing_word_count": len(differential["different_fields"]),
                "same_testcase_binding": differential["same_testcase_binding"],
                "same_firmware_binding": differential["same_firmware_binding"],
                "same_execution_context_binding": differential["same_execution_context_binding"],
                "rtl_signature_artifact_id": differential["rtl_artifact_id"],
                "isa_signature_artifact_id": differential["reference_artifact_id"]},
               association["hardware_differential_status"],
               "Raw signature differences are observations; unresolved bindings keep the formal differential unknown."),
        _stage(8, "derive_verification_readiness",
               "chipchain.cross_layer.case_assembly.prepare_case",
               ["case-manifest.json", "association.json", "verification-readiness.json"],
               ["inventory baseline gaps against current Type-II evidence contract",
                "keep hardware-package provenance gaps separate",
                "check frozen verifier applicability independently of missing evidence"],
               {"requirements": requirement_rows,
                "requirements_scope": readiness["requirements_scope"],
                "frozen_verifier_rule": readiness["verifier_rule_version"],
                "verifier_applicability_status": readiness["verifier_applicability_status"],
                "verifier_applicability_reason": readiness["verifier_applicability_reason"],
                "verifier_invoked": readiness["verifier_invoked"]},
               {"assembly_status": readiness["assembly_status"],
                "readiness_status": readiness["status"], "verification_ready": readiness["ready"]},
               "The current controlled-Ibex MMIO verifier is not applicable to this ProcessorFuzz hardware-test evidence; the gap list is not exhaustive and does not imply that filling it invokes verification."),
    ]
    return {
        "schema_version": SCHEMA, "case_id": case_manifest["case_id"],
        "artifact_role": "explanatory_derivation_projection", "scientific_evidence": False,
        "stages": stages,
        "final_result": {
            "assembly_status": readiness["assembly_status"],
            "semantic_candidate_statuses": stages[4]["result"],
            "runtime_binding_status": association["runtime_binding_status"],
            "hardware_differential_status": association["hardware_differential_status"],
            "frozen_verifier_applicability": readiness["verifier_applicability_status"],
            "verification_ready": readiness["ready"], "readiness_status": readiness["status"],
            "verifier_invoked": readiness["verifier_invoked"],
            "hardware_package_type2_status": association["hardware_package_verification_status"],
        },
    }


def render_analysis_report(chain: dict) -> str:
    """Render only the derived chain, with no independent status decisions."""
    stages = chain["stages"]
    fw, hw, identity, architecture, semantic, runtime, differential, readiness = stages
    final = chain["final_result"]
    hbc_requirement = next((row for row in readiness["outputs"]["requirements"]
                            if row["requirement"] == "authoritative_hardware_behavior_contract"), None)
    lines = [
        "# ChipChain Type-II 跨层分析链报告", "",
        "## 0. 最终链路结论", "",
        f"- 案例：`{chain['case_id']}`；装配 `{final['assembly_status']}`。",
        f"- 静态语义候选已计算；运行绑定 `{final['runtime_binding_status']}`；"
        f"验证准备度 `{final['readiness_status']}`。",
        f"- 冻结 verifier 适用性 `{final['frozen_verifier_applicability']}`；"
        f"本次未运行 verifier。原硬件包 Type-II 状态 `{final['hardware_package_type2_status']}`。",
        "- 本报告及 `analysis-chain.json` 是确定性解释投影，不是新增科学证据。", "",
        "## 1. 输入与处理流程", "",
        "`firmware-analysis.json` / `firmware-summary.json` / `ghidra-export.json` → `_analysis()`；"
        "ProcessorFuzz 规范输出 → `_hardware()`；两侧验证后由 `prepare_case()` 比较身份与架构，"
        "由 `_candidate_relations()` 建立静态种类关联，再汇总运行来源、差异和验证准备度。", "",
        "## 2. Stage 1：固件静态分析输入验证", "",
        "- 输入：" + "、".join(f"`{name}`" for name in fw["inputs"]) + "。",
        "- `_analysis()` 检查摘要、Ghidra language、指令数量及逐条规范指令元组。",
        f"- 分析 ID：`{fw['outputs']['analysis_id']}`；ELF SHA256：`{fw['outputs']['elf_sha256']}`。",
        "- 架构：" + _arch(fw["outputs"]["architecture_tuple"]) + "。",
        "- 候选相关的受支持静态事实："
        + "；".join(f"`{row['kind']}` ×{row['count']}" for row in
                   fw["outputs"]["supported_candidate_kind_facts"]) + "。",
        "- 该核对不重新认证原始 ELF 字节，也不证明指令已执行。", "",
        "## 3. Stage 2：硬件侧分析输入验证", "",
        "- 输入：" + "、".join(f"`{name}`" for name in hw["inputs"]) + "。",
        "- `_hardware()` 依次核对测试 ELF 的静态分析、SI/manifest、能力投影、"
        "运行来源字段及签名差异对象。",
        f"- Manifest：`{hw['outputs']['manifest_id']}`；原包 SHA256："
        f"`{hw['outputs']['archive_sha256'] or 'not_provided'}`。",
        f"- 测试 ELF SHA256：`{hw['outputs']['selected_test_elf_sha256']}`；"
        f"静态分析 ID：`{hw['outputs']['static_analysis_id']}`。",
        f"- 包角色：`{hw['outputs']['package_role']}`；"
        f"ELF 角色：`{hw['outputs']['firmware_role']}`。",
        "- 受支持的测试 ELF 静态能力："
        + "；".join(f"`{row['kind']}` ×{row['count']}" for row in
                   hw["outputs"]["supported_candidate_kind_capabilities"]) + "。",
        "- 这些是硬件团队所选测试 ELF 的静态事实，不是 HardwareBehaviorContract 或已验证的硬件行为。", "",
        "## 4. Stage 3：固件身份关系判定", "",
        f"- 所给固件：`{identity['outputs']['firmware_elf_sha256']}`。",
        f"- 硬件测试 ELF：`{identity['outputs']['hardware_test_elf_sha256']}`。",
        f"- 规则：只比较 SHA256；结果 `{identity['result']}`。",
        "- `DISTINCT_FIRMWARE` 时，硬件包的 RuntimeSource 元数据仍记录测试 ELF；"
        "trace 与签名不能被所给固件继承。即使字节相同，也不自动证明同次执行。", "",
        "## 5. Stage 4：架构兼容性判定", "",
        "- 所给固件：" + _arch(architecture["outputs"]["firmware"]) + "。",
        "- 测试 ELF：" + _arch(architecture["outputs"]["hardware_test_elf"]) + "。",
        f"- 架构 / 位宽 / 字节序元组比较：`{architecture['result']}`。"
        "这不证明平台兼容。", "",
        "## 6. Stage 5：跨层静态语义候选推导", "",
        "`_candidate_relations()` 仅比较两侧受支持、可跨架构解释的静态行为种类；"
        "下列状态直接复制自 `association.json`。", "",
        "| 行为种类 | 固件事实 | 测试 ELF 能力 | 静态关联 |",
        "| --- | ---: | ---: | --- |",
        *[f"| `{item['kind']}` | {item['firmware_fact_count']} | "
          f"{item['hardware_capability_count']} | `{item['status']}` |"
          for item in semantic["outputs"]["relations"]], "",
    ]
    for index, relation in enumerate(semantic["outputs"]["relations"], 1):
        lines += [f"### 候选 C{index} — `{relation['kind']}` → `{relation['status']}`", "",
                  f"- 固件事实：{relation['firmware_fact_count']} 个。"]
        if relation["firmware_facts"]:
            for fact in relation["firmware_facts"]:
                lines.append(f"  - `{fact['fact_id']}`；{_instruction_text(fact['source_instruction'])}。")
        else:
            lines.append("  - 无该种类的受支持规范静态事实。")
        lines.append(f"- 硬件参考：`{relation['hardware_reference_source']}`；"
                     f"测试 ELF 静态 capability {relation['hardware_capability_count']} 个。")
        for cap in relation["hardware_capabilities"]:
            lines.append(f"  - `{cap['capability_id']}` → `{cap['behavior_fact_id']}`；"
                         f"{_instruction_text(cap['source_instruction'])}；"
                         f"`{cap['execution_status']}`。")
        lines += [f"- 规则：受支持的静态语义种类相同才给出候选；结果 `{relation['status']}`。",
                  ("- 边界：同种类不等于同操作数、同资源、同次执行、规定顺序或硬件触发。"
                   if relation["status"] == "SUPPORTED_CANDIDATE" else
                   "- 边界：缺少同种类的规范静态事实，不等于触发反证、运行反证或硬件安全。"), ""]
    lines += [
        "## 7. Stage 6：运行证据来源隔离", "",
        f"- 所给固件 ELF：`{runtime['outputs']['supplied_firmware_elf_sha256']}`；"
        f"硬件测试 ELF：`{runtime['outputs']['hardware_test_elf_sha256']}`。",
    ]
    if runtime["outputs"]["runtime_material"]:
        for item in runtime["outputs"]["runtime_material"]:
            lines.append(f"- `{item['artifact']}`：trace SHA256 `{item['trace_sha256']}`；"
                         f"记录的 source ELF SHA256 `{item['source_elf_sha256']}`；"
                         f"ELF 字节覆盖 `{item['elf_byte_coverage_status']}`。")
    else:
        lines.append("- 本包未提供规范指令级 RTL/ISA trace 输出。")
    lines += [f"- RTL/ISA 签名引用：`{runtime['outputs']['rtl_signature_artifact_id']}` / "
              f"`{runtime['outputs']['isa_signature_artifact_id']}`。",
              f"- 本案例的固件运行绑定：`{runtime['result']}`。"
              "记录的 source 和局部字节匹配不构成所给固件的运行或完整构建绑定。", "",
              "## 8. Stage 7：硬件差异证据判定", "",
              f"- `architectural-differential.json`：`{differential['outputs']['differential_id']}`。",
              f"- 原始签名差异字数：{differential['outputs']['raw_differing_word_count']}；"
              f"仅表示 `{differential['outputs']['comparison_scope']}`。",
              f"- 同 testcase / 固件 / 执行上下文绑定："
              f"`{differential['outputs']['same_testcase_binding']}` / "
              f"`{differential['outputs']['same_firmware_binding']}` / "
              f"`{differential['outputs']['same_execution_context_binding']}`。",
              f"- 正式 architectural differential：`{differential['result']}`；"
              "原始不同不能越过未解决的绑定。", "",
              "## 9. Stage 8：Type-II 验证准备度推导", "",
              "以下是当前公开输出的基础缺口及硬件包自身来源缺口，非穷尽清单。", "",
              "| 要求 | 要求来源 | 已有材料 | 评估 | 原因 |",
              "| --- | --- | --- | --- | --- |"]
    for row in readiness["outputs"]["requirements"]:
        available = "、".join(f"`{item}`" for item in row["available_evidence"]) or "无"
        lines.append(f"| `{row['requirement']}` | {row['required_by']} | {available} | "
                     f"`{row['evaluation']}` | {row['reason']} |")
    lines += ["",
              f"- 冻结规则：`{readiness['outputs']['frozen_verifier_rule']}`；"
              f"适用性：`{readiness['outputs']['verifier_applicability_status']}`。",
              "- 当前 ProcessorFuzz 硬件测试材料不是受控 Ibex MMIO 证据模型；"
              "补齐上述缺口也不能直接用该冻结 verifier 验证。",
              f"- 结果：装配 `{final['assembly_status']}`；"
              f"`verification_ready={str(final['verification_ready']).lower()}`；"
              f"准备度 `{final['readiness_status']}`。", "",
              "## 10. 完整推导链", "", "```text",
              "firmware-analysis.json → _analysis() → FirmwareStaticAnalysis",
              *[f"  {row['kind']} ×{row['count']}" for row in
                fw["outputs"]["supported_candidate_kind_facts"]],
              "ProcessorFuzz canonical outputs → _hardware() → selected test ELF static capabilities",
              *[f"  {row['kind']} ×{row['count']}" for row in
                hw["outputs"]["supported_candidate_kind_capabilities"]],
              "_candidate_relations() →",
              *[f"  {item['kind']} → {item['status']}" for item in semantic["outputs"]["relations"]],
              f"ELF SHA comparison → {identity['result']}",
              f"architecture tuple comparison → {architecture['result']}",
              f"supplied firmware runtime binding → {runtime['result']}",
              *( [f"authoritative HBC → {hbc_requirement['evaluation']}"]
                 if hbc_requirement else []),
              f"hardware differential → {differential['result']}",
              f"frozen verifier applicability → {final['frozen_verifier_applicability']}",
              f"verification readiness → {final['readiness_status']}",
              f"verification_ready → {str(final['verification_ready']).lower()}",
              f"original hardware package Type-II → {final['hardware_package_type2_status']}",
              "this assembly → no verifier invocation", "```", "",
              "## 11. 科学边界", "",
              "`analysis-chain.json` 与本报告只解释现有规范输入和 V1 装配结果；"
              "不增加证据、不重算静态关联、不产生新的 Type-II 科学身份。",
              "`type2 prepare` 检查规范输出之间的一致性，不重新认证原始 ELF 或 ZIP 字节。",
              "测试 ELF 不是客户固件；架构兼容与静态语义相似均不证明资源、触发、偏差或漏洞。",
              "冻结 verifier 未运行，本案例没有 VERIFIED 结论。", ""]
    return "\n".join(lines)


def _arch(value: dict) -> str:
    return f"`{value['architecture']}` / {value['bit_width']}-bit / `{value['endianness']}`"


def _instruction_text(value: dict | None) -> str:
    if value is None:
        return "来源指令无法从规范静态分析回溯"
    operands = ", ".join(value["operands"])
    mnemonic = f"{value['mnemonic']} {operands}" if operands else value["mnemonic"]
    return f"PC `0x{value['pc']:x}`，`{mnemonic}`，指令 `{value['instruction_id']}`"
