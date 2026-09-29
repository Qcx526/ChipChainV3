"""Offline public-CLI coverage for evidence-bounded Type-II case preparation."""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
import shutil

import pytest

from chipchain.cli import main
from chipchain.cross_layer.type2_verifier import RULE as FROZEN_VERIFIER_RULE
from chipchain.firmware.static_ir import content_id


ROOT = Path(__file__).resolve().parents[2]
FIRMWARE = ROOT / "samples/firmware/riscv/processorfuzz_real_case_001/expected"
HARDWARE = ROOT / "samples/processorfuzz/real_case_001/expected"
OUTPUT_NAMES = {
    "case-manifest.json", "association.json", "verification-readiness.json",
    "analysis-chain.json", "report.md",
}
FIRMWARE_SHA = {
    "positive": "35f9fff9c00e6a93bb9e6884b8604cd3d36dd35f7fdea408412633c5b7ae9fe4",
    "negative_trigger": "2b6275ffb203f5ffc5411bb9200f5eafaab61fe6615a403697ecabace469e7cd",
}
# Frozen V1 output bytes: these three scientific projections must not change
# when the explanatory chain or report changes. No ignored output is required.
V1_JSON_SHA = {
    "positive": {
        "case-manifest.json": "28a612691390f4000b90ad0f53fff3fe8203905d033fe2cc86d5ebe5020c3d4e",
        "association.json": "94a17e7f676ce6ea6b8b3f476decee8f42143f5727643f6968eb2f626d74ec2d",
        "verification-readiness.json": "2715691884d894cdfd1e4773a70b73ba4adcba7978e87f1bbc42c12f337a23d7",
    },
    "negative_trigger": {
        "case-manifest.json": "e9f137edecf75948cba5109b077ff6da3bd5faf438312c7c9b5b0684da21f1ce",
        "association.json": "13455b0e080eca42e1ea5e9ebd7d363487b8caf9f076041ee88af76524a55ae8",
        "verification-readiness.json": "329a94bbf9aa50b76b4b98ee2123a14ffe2c6417743fe37fa72a04b11af19318",
    },
}


def prepare(firmware: Path, hardware: Path, output: Path) -> int:
    return main(["type2", "prepare", "--firmware", str(firmware), "--hardware", str(hardware),
                 "--output", str(output)])


def read_json(directory: Path, name: str) -> dict:
    return json.loads((directory / name).read_text())


@pytest.mark.parametrize("variant,tlb_status", [
    ("positive", "SUPPORTED_CANDIDATE"),
    ("negative_trigger", "NO_STATIC_KIND_MATCH"),
])
def test_prepare_realistic_firmware_and_hardware_outputs(
    variant: str, tlb_status: str, tmp_path: Path,
) -> None:
    """Independent static analyses may assemble even when verification cannot proceed."""
    firmware = FIRMWARE / variant
    first = tmp_path / "first"
    second = tmp_path / "second"
    assert prepare(firmware, HARDWARE, first) == 0
    assert prepare(firmware, HARDWARE, second) == 0
    assert {path.name for path in first.iterdir()} == OUTPUT_NAMES
    assert {path.name for path in second.iterdir()} == OUTPUT_NAMES
    for name in OUTPUT_NAMES:
        assert (first / name).read_bytes() == (second / name).read_bytes(), name
        assert str(tmp_path).encode() not in (first / name).read_bytes()
    for name, digest in V1_JSON_SHA[variant].items():
        assert sha256((first / name).read_bytes()).hexdigest() == digest

    manifest = read_json(first, "case-manifest.json")
    association = read_json(first, "association.json")
    readiness = read_json(first, "verification-readiness.json")
    fw_analysis = read_json(firmware, "firmware-analysis.json")
    hw_manifest = read_json(HARDWARE, "processorfuzz-case-manifest.json")
    hw_caps = read_json(HARDWARE, "static-capabilities.json")
    hw_analysis = read_json(HARDWARE, "firmware-analysis.json")
    differential = read_json(HARDWARE, "architectural-differential.json")
    chain = read_json(first, "analysis-chain.json")

    assert manifest["case_id"]
    assert manifest["firmware_side"]["analysis_id"] == fw_analysis["analysis_id"]
    assert manifest["firmware_side"]["elf_sha256"] == FIRMWARE_SHA[variant]
    assert manifest["hardware_side"]["manifest_id"] == hw_manifest["manifest_id"]
    assert manifest["hardware_side"]["archive_sha256"] == hw_manifest["archive_sha256"]
    assert manifest["hardware_side"]["selected_test_elf_sha256"] == hw_manifest["elf_sha256"]
    assert manifest["hardware_side"]["package_role"] == "hardware_trigger_validation_package"
    assert manifest["hardware_side"]["firmware_role"] == "hardware_supplied_trigger_test_firmware"
    assert manifest["firmware_side"]["elf_sha256"] != manifest["hardware_side"]["selected_test_elf_sha256"]
    assert manifest["identity_relation"]["status"] == "DISTINCT_FIRMWARE"
    assert manifest["identity_relation"]["same_execution_established"] is False

    assert association["architecture_compatibility"]["status"] == "SUPPORTED"
    assert association["firmware_identity_relation"]["status"] == "DISTINCT_FIRMWARE"
    assert association["firmware_identity_relation"]["same_execution_established"] is False
    relations = {relation["kind"]: relation
                 for relation in association["semantic_candidate_relations"]}
    assert relations["TLB_INVALIDATE"]["status"] == tlb_status
    assert relations["TLB_INVALIDATE"]["scope"] == "static_semantic_kind_only"
    assert relations["TLB_INVALIDATE"]["hardware_reference_source"] == (
        "selected_processorfuzz_test_elf_static_analysis")
    tlb_firmware_facts = {behavior["fact_id"] for behavior in fw_analysis["behaviors"]
                          if behavior["kind"] == "TLB_INVALIDATE"}
    tlb_hardware_caps = {cap["capability_id"] for cap in hw_caps["capabilities"]
                         if cap["kind"] == "TLB_INVALIDATE"}
    assert set(relations["TLB_INVALIDATE"]["firmware_behavior_fact_ids"]) == tlb_firmware_facts
    assert set(relations["TLB_INVALIDATE"]["hardware_test_static_capability_ids"]) <= tlb_hardware_caps
    if variant == "positive":
        assert relations["TLB_INVALIDATE"]["hardware_test_static_capability_ids"]
    else:
        assert not relations["TLB_INVALIDATE"]["firmware_behavior_fact_ids"]

    assert association["resource_binding_status"] == "UNKNOWN"
    assert association["runtime_binding_status"] == "UNKNOWN"
    assert association["hardware_trigger_status"] == "NOT_ESTABLISHED"
    assert association["hardware_differential_status"] == "UNKNOWN"
    assert association["hardware_package_verification_status"] == "NOT_ESTABLISHED"
    assert readiness["assembly_status"] == "COMPLETE"
    assert readiness["ready"] is False
    assert readiness["verifier_rule_version"] == FROZEN_VERIFIER_RULE
    assert readiness["verifier_applicability_status"] == "NOT_APPLICABLE"
    assert readiness["requirements_scope"] == (
        "baseline_gaps_for_current_public_cli_outputs_not_exhaustive")
    assert readiness["missing_requirements"]
    assert "authoritative_hardware_behavior_contract" in readiness["missing_requirements"]
    assert "firmware_specific_runtime_execution_and_source_binding" in readiness["missing_requirements"]
    assert "firmware_specific_reference_variant_run_evidence" in readiness["missing_requirements"]
    assert "controlled_source_state_and_observation_bindings" in readiness["missing_requirements"]
    assert "hardware_si_to_test_elf_build_binding" in readiness["hardware_package_evidence_gaps"]
    assert readiness["available_evidence"]
    assert {item["kind"] for item in readiness["available_evidence"]} <= {
        "firmware_static_analysis", "hardware_test_static_analysis", "hardware_package_manifest",
        "hardware_signature_comparison", "hardware_test_rtl_trace", "hardware_test_isa_trace",
    }
    assert readiness["verifier_invoked"] is False
    assert readiness["frozen_verifier_manifest_emitted"] is False
    assert not (first / "verification.json").exists()
    assert not (first / "verified-attack-chain.json").exists()
    assert chain["schema_version"] == "type2-analysis-chain/v1"
    assert chain["case_id"] == manifest["case_id"]
    assert chain["artifact_role"] == "explanatory_derivation_projection"
    assert chain["scientific_evidence"] is False
    stages = chain["stages"]
    assert [stage["stage_id"] for stage in stages] == [f"S{number}" for number in range(1, 9)]
    assert all({"operation", "implementation_function", "inputs", "checks_or_rule",
                "outputs", "result", "scientific_boundary"} <= stage.keys() for stage in stages)
    fw_tlb = next(row for row in stages[0]["outputs"]["supported_candidate_kind_facts"]
                  if row["kind"] == "TLB_INVALIDATE")
    assert fw_tlb["fact_ids"] == sorted(tlb_firmware_facts)
    assert fw_tlb["count"] == len(tlb_firmware_facts)
    hw_tlb = next(row for row in stages[1]["outputs"]["supported_candidate_kind_capabilities"]
                  if row["kind"] == "TLB_INVALIDATE")
    assert hw_tlb["capability_ids"] == sorted(tlb_hardware_caps)
    assert hw_tlb["count"] == len(tlb_hardware_caps)
    for row in stages[0]["outputs"]["supported_candidate_kind_facts"]:
        ids = sorted(b["fact_id"] for b in fw_analysis["behaviors"]
                     if b["kind"] == row["kind"] and b["semantic_status"] == "supported")
        assert row["fact_ids"] == ids
        assert row["count"] == len(ids)
    for row in stages[1]["outputs"]["supported_candidate_kind_capabilities"]:
        ids = sorted(c["capability_id"] for c in hw_caps["capabilities"]
                     if c["kind"] == row["kind"] and c["semantic_status"] == "supported")
        assert row["capability_ids"] == ids
        assert row["count"] == len(ids)
    assert stages[2]["result"] == manifest["identity_relation"]["status"]
    assert stages[3]["result"] == association["architecture_compatibility"]["status"]
    assert len(stages[4]["outputs"]["relations"]) == len(relations)
    for item in stages[4]["outputs"]["relations"]:
        source = relations[item["kind"]]
        assert item["status"] == source["status"]
        assert [row["fact_id"] for row in item["firmware_facts"]] == source[
            "firmware_behavior_fact_ids"]
        assert [row["capability_id"] for row in item["hardware_capabilities"]] == source[
            "hardware_test_static_capability_ids"]
        for row in item["firmware_facts"]:
            fact = next(b for b in fw_analysis["behaviors"] if b["fact_id"] == row["fact_id"])
            instruction = next(i for i in fw_analysis["instructions"]
                               if i["fact_id"] == fact["instruction_id"])
            assert row["source_instruction"] == {
                "instruction_id": instruction["fact_id"], "pc": instruction["pc"],
                "mnemonic": instruction["mnemonic"], "operands": instruction["operands"]}
        for row in item["hardware_capabilities"]:
            cap = next(c for c in hw_caps["capabilities"]
                       if c["capability_id"] == row["capability_id"])
            fact = next(b for b in hw_analysis["behaviors"]
                        if b["fact_id"] == cap["behavior_fact_id"])
            instruction = next(i for i in hw_analysis["instructions"]
                               if i["fact_id"] == fact["instruction_id"])
            assert row["behavior_fact_id"] == fact["fact_id"]
            assert row["source_instruction"] == {
                "instruction_id": instruction["fact_id"], "pc": instruction["pc"],
                "mnemonic": instruction["mnemonic"], "operands": instruction["operands"]}
            assert row["execution_status"] == "STATIC_ONLY"
    tlb_chain = next(item for item in stages[4]["outputs"]["relations"]
                     if item["kind"] == "TLB_INVALIDATE")
    assert tlb_chain["status"] == tlb_status
    assert tlb_chain["firmware_fact_count"] == (1 if variant == "positive" else 0)
    assert tlb_chain["hardware_capability_count"] == 2
    assert tlb_chain["hardware_reference_source"] == (
        "selected_processorfuzz_test_elf_static_analysis")
    assert {item["artifact"] for item in stages[5]["outputs"]["runtime_material"]} == {
        "rtl-runtime-evidence.json", "isa-reference-evidence.json"}
    for item in stages[5]["outputs"]["runtime_material"]:
        trace = read_json(HARDWARE, item["artifact"])
        assert item["source_elf_sha256"] == trace["source"]["elf_sha256"] == hw_manifest[
            "elf_sha256"]
        assert item["source_elf_sha256"] != manifest["firmware_side"]["elf_sha256"]
        assert item["trace_sha256"] == trace["source"]["trace_sha256"]
    assert stages[5]["result"] == association["runtime_binding_status"] == "UNKNOWN"
    assert stages[6]["outputs"]["differential_id"] == differential["differential_id"]
    assert stages[6]["outputs"]["raw_differing_word_count"] == len(
        differential["different_fields"])
    assert stages[6]["outputs"]["raw_values_differ"] == differential["raw_values_differ"]
    for field in ("same_testcase_binding", "same_firmware_binding",
                  "same_execution_context_binding"):
        assert stages[6]["outputs"][field] == differential[field]
    assert stages[6]["result"] == differential["status"] == "UNKNOWN"
    assert {row["requirement"] for row in stages[7]["outputs"]["requirements"]} == (
        set(readiness["missing_requirements"]) |
        set(readiness["hardware_package_evidence_gaps"]))
    assert stages[7]["outputs"]["verifier_applicability_status"] == "NOT_APPLICABLE"
    requirement_rows = stages[7]["outputs"]["requirements"]
    assert {row["requirement"] for row in requirement_rows
            if row["group"] == "frozen_verifier_baseline"} == set(readiness["missing_requirements"])
    assert {row["requirement"] for row in requirement_rows
            if row["group"] == "hardware_package_provenance"} == set(
                readiness["hardware_package_evidence_gaps"])
    assert all(row["evaluation"] == "MISSING" and row["required_by"] and row["reason"]
               for row in requirement_rows)
    assert stages[7]["result"]["verification_ready"] == readiness["ready"] is False
    assert chain["final_result"]["semantic_candidate_statuses"] == stages[4]["result"]
    assert chain["final_result"]["hardware_package_type2_status"] == "NOT_ESTABLISHED"
    report = (first / "report.md").read_text()
    assert "# ChipChain Type-II 跨层分析链报告" in report
    assert "## 10. 完整推导链" in report
    assert "NOT_ESTABLISHED" in report
    assert "硬件团队所选测试 ELF 的静态事实" in report
    assert "补齐上述缺口也不能直接用该冻结 verifier 验证" in report
    assert f"TLB_INVALIDATE → {tlb_status}" in report
    assert "authoritative HBC → MISSING" in report
    assert "verification_ready → false" in report
    if variant == "negative_trigger":
        assert "不等于触发反证、运行反证或硬件安全" in report
        assert "TLB_INVALIDATE ×0" in report


@pytest.mark.parametrize("variant,alias", [
    ("positive", "negative_trigger"),
    ("negative_trigger", "positive"),
])
def test_case_meaning_does_not_come_from_input_directory_name(
    variant: str, alias: str, tmp_path: Path,
) -> None:
    copied_firmware = tmp_path / alias
    shutil.copytree(FIRMWARE / variant, copied_firmware)
    copied_hardware = tmp_path / "renamed-hardware-input"
    shutil.copytree(HARDWARE, copied_hardware)
    original_output = tmp_path / "original-output"
    renamed_output = tmp_path / "renamed-output"
    assert prepare(FIRMWARE / variant, HARDWARE, original_output) == 0
    assert prepare(copied_firmware, copied_hardware, renamed_output) == 0
    for name in OUTPUT_NAMES:
        assert (original_output / name).read_bytes() == (renamed_output / name).read_bytes()


def test_signature_only_hardware_chain_does_not_invent_runtime(tmp_path: Path) -> None:
    hardware = ROOT / "samples/processorfuzz/real_case_002/expected"
    output = tmp_path / "signature-only"
    assert prepare(FIRMWARE / "positive", hardware, output) == 0
    chain = read_json(output, "analysis-chain.json")
    assert chain["stages"][5]["outputs"]["runtime_material"] == []
    assert chain["stages"][5]["outputs"]["rtl_trace_sha256"] is None
    assert chain["stages"][5]["result"] == "UNKNOWN"
    assert "本包未提供规范指令级 RTL/ISA trace 输出" in (output / "report.md").read_text()


def test_firmware_summary_elf_disagreement_is_rejected(tmp_path: Path) -> None:
    firmware = tmp_path / "firmware"
    shutil.copytree(FIRMWARE / "positive", firmware)
    summary = read_json(firmware, "firmware-summary.json")
    summary["elf_sha256"] = "0" * 64
    (firmware / "firmware-summary.json").write_text(json.dumps(summary))
    with pytest.raises(SystemExit) as error:
        prepare(firmware, HARDWARE, tmp_path / "case")
    assert error.value.code == 2


@pytest.mark.parametrize("filename,field", [
    ("summary.json", "manifest_id"),
    ("processorfuzz-case-manifest.json", "elf_sha256"),
])
def test_hardware_identity_disagreement_is_rejected(
    filename: str, field: str, tmp_path: Path,
) -> None:
    hardware = tmp_path / "hardware"
    shutil.copytree(HARDWARE, hardware)
    payload = read_json(hardware, filename)
    payload[field] = "0" * 64
    (hardware / filename).write_text(json.dumps(payload))
    with pytest.raises(SystemExit) as error:
        prepare(FIRMWARE / "positive", hardware, tmp_path / "case")
    assert error.value.code == 2


def test_missing_canonical_firmware_analysis_is_rejected(tmp_path: Path) -> None:
    firmware = tmp_path / "firmware"
    shutil.copytree(FIRMWARE / "positive", firmware)
    (firmware / "firmware-analysis.json").unlink()
    with pytest.raises(SystemExit) as error:
        prepare(firmware, HARDWARE, tmp_path / "case")
    assert error.value.code == 2


def test_missing_hardware_manifest_is_rejected(tmp_path: Path) -> None:
    hardware = tmp_path / "hardware"
    shutil.copytree(HARDWARE, hardware)
    (hardware / "processorfuzz-case-manifest.json").unlink()
    with pytest.raises(SystemExit) as error:
        prepare(FIRMWARE / "positive", hardware, tmp_path / "case")
    assert error.value.code == 2


def test_nonempty_output_directory_is_rejected_without_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "case"
    output.mkdir()
    sentinel = output / "leave-untouched.txt"
    sentinel.write_text("existing customer data\n")
    with pytest.raises(SystemExit) as error:
        prepare(FIRMWARE / "positive", HARDWARE, output)
    assert error.value.code == 2
    assert sentinel.read_text() == "existing customer data\n"
    assert {path.name for path in output.iterdir()} == {sentinel.name}


def test_ghidra_export_disagreement_is_rejected(tmp_path: Path) -> None:
    firmware = tmp_path / "firmware"
    shutil.copytree(FIRMWARE / "positive", firmware)
    exported = read_json(firmware, "ghidra-export.json")
    exported["instructions"][0]["bytes"] = "00000000"
    (firmware / "ghidra-export.json").write_text(json.dumps(exported))
    with pytest.raises(SystemExit) as error:
        prepare(firmware, HARDWARE, tmp_path / "case")
    assert error.value.code == 2


def test_hardware_selected_path_disagreement_is_rejected(tmp_path: Path) -> None:
    hardware = tmp_path / "hardware"
    shutil.copytree(HARDWARE, hardware)
    manifest = read_json(hardware, "processorfuzz-case-manifest.json")
    # Selected paths are intentionally outside the manifest ID payload.
    manifest["selected_paths"]["elf"] = manifest["selected_paths"]["si"]
    (hardware / "processorfuzz-case-manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(SystemExit) as error:
        prepare(FIRMWARE / "positive", hardware, tmp_path / "case")
    assert error.value.code == 2


def test_hardware_runtime_source_disagreement_is_rejected(tmp_path: Path) -> None:
    hardware = tmp_path / "hardware"
    shutil.copytree(HARDWARE, hardware)
    trace = read_json(hardware, "rtl-runtime-evidence.json")
    trace["source"]["elf_sha256"] = FIRMWARE_SHA["positive"]
    (hardware / "rtl-runtime-evidence.json").write_text(json.dumps(trace))
    with pytest.raises(SystemExit) as error:
        prepare(FIRMWARE / "positive", hardware, tmp_path / "case")
    assert error.value.code == 2


def test_signature_binding_disagreement_is_rejected(tmp_path: Path) -> None:
    hardware = tmp_path / "hardware"
    shutil.copytree(HARDWARE, hardware)
    differential = read_json(hardware, "architectural-differential.json")
    differential["same_execution_context_binding"] = "BOUND"
    fields = {key: value for key, value in differential.items() if key != "differential_id"}
    differential["differential_id"] = content_id("architectural-differential", fields)
    (hardware / "architectural-differential.json").write_text(json.dumps(differential))
    with pytest.raises(SystemExit) as error:
        prepare(FIRMWARE / "positive", hardware, tmp_path / "case")
    assert error.value.code == 2


def test_benchmark_expectation_does_not_enter_assembly(tmp_path: Path) -> None:
    benchmark = read_json(FIRMWARE.parent, "benchmark-contract.json")
    assert benchmark["contract_kind"] == "SyntheticBenchmarkContract"
    assert benchmark["positive_expectation"] == "SATISFIES_SYNTHETIC_BENCHMARK_CONTRACT"
    assert benchmark["negative_expectation"] == "CONTRADICTS_SYNTHETIC_BENCHMARK_CONTRACT"
    for variant in ("positive", "negative_trigger"):
        original = tmp_path / f"original-{variant}"
        assert prepare(FIRMWARE / variant, HARDWARE, original) == 0
        renamed_parent = tmp_path / f"mutated-benchmark-{variant}"
        shutil.copytree(FIRMWARE.parent, renamed_parent)
        modified = read_json(renamed_parent, "benchmark-contract.json")
        modified["positive_expectation"] = "ARBITRARY_CHANGED_EXPECTATION"
        modified["negative_expectation"] = "ANOTHER_CHANGED_EXPECTATION"
        (renamed_parent / "benchmark-contract.json").write_text(json.dumps(modified))
        changed = tmp_path / f"changed-{variant}"
        assert prepare(renamed_parent / "expected" / variant, HARDWARE, changed) == 0
        for name in OUTPUT_NAMES:
            assert (original / name).read_bytes() == (changed / name).read_bytes(), name
        combined = b"".join((original / name).read_bytes() for name in OUTPUT_NAMES)
        assert b"SYNTHETIC_BENCHMARK_CONTRACT" not in combined
        assert b"positive_expectation" not in combined
        assert b"negative_expectation" not in combined
