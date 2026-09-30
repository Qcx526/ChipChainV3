"""Additive case policy using explicit synthetic runtime bundle inputs.

Acquisition/parser/source replay are tested in the runtime layer. These tests
isolate how already-validated per-instruction support affects a case display.
"""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from chipchain.cross_layer.case_assembly import prepare_case, write_case
from chipchain.cross_layer.case_assembly_customer import render_customer_report
from chipchain.cross_layer.case_assembly_runtime import (
    FIRMWARE_RUNTIME_REQUIREMENT, build_runtime_projection)
from chipchain.firmware.static_ir import FirmwareStaticAnalysis, content_id
from chipchain.runtime.image_mapping import declared_identity_mapping


ROOT = Path(__file__).resolve().parents[2]
FIRMWARE = ROOT / "samples/firmware/riscv/processorfuzz_real_case_001/expected"
HARDWARE = ROOT / "samples/processorfuzz/real_case_001/expected"
CUSTOMER_SHA = {
    "positive": "f4c436196438da97bd5dacf9820702ece6412372082051d7f2977cdac8678017",
    "negative_trigger": "3ea547d9d09183dab0e9a84cc548506df6644d0836555a583dc5ba5a0a5226c3",
}


def inputs(variant: str, *, absent_pc: int | None = None):
    analysis = FirmwareStaticAnalysis.model_validate_json(
        (FIRMWARE / variant / "firmware-analysis.json").read_text())
    base = prepare_case(FIRMWARE / variant, HARDWARE)
    selected_ids = {fact_id for relation in base.association["semantic_candidate_relations"]
                    for fact_id in relation["firmware_behavior_fact_ids"]}
    instructions = {item.fact_id: item for item in analysis.instructions}
    events, bindings = [], []
    for index, fact in enumerate(fact for fact in analysis.behaviors if fact.fact_id in selected_ids):
        instruction = instructions[fact.instruction_id]
        event = SimpleNamespace(event_id=f"synthetic-runtime-event:{index}",
                                sequence=index, vcpu=0, pc=fact.pc,
                                instruction_bytes=instruction.raw_bytes)
        observed = fact.pc != absent_pc
        if observed:
            events.append(event)
        bindings.append(SimpleNamespace(
            static_behavior_id=fact.fact_id, static_instruction_id=instruction.fact_id,
            pc=fact.pc, kind=fact.kind, status="SUPPORTED" if observed else "UNKNOWN",
            reason="EXACT_SOURCE_INSTRUCTION_OBSERVED" if observed else "NOT_OBSERVED_IN_THIS_RUN",
            source_event_ids=(event.event_id,) if observed else (),
            semantic_fact_ids=(f"synthetic-runtime-semantic:{index}",) if observed else (),
        ))
    evidence = SimpleNamespace(
        run=SimpleNamespace(run_id="synthetic-runtime-run:1", firmware=analysis.artifact,
                            image_mapping=declared_identity_mapping(analysis.artifact)),
        events=SimpleNamespace(artifact_id="synthetic-runtime-events:1", events=tuple(events)),
        semantics=SimpleNamespace(artifact_id="synthetic-runtime-semantics:1"),
        bindings=SimpleNamespace(artifact_id="synthetic-runtime-bindings:1", bindings=tuple(bindings)),
        capabilities=SimpleNamespace(artifact_id="synthetic-runtime-capabilities:1"),
    )
    return analysis, base, evidence


def project(analysis, base, evidence):
    return build_runtime_projection(firmware=analysis, evidence=evidence,
                                    case_manifest=base.case_manifest,
                                    association=base.association, readiness=base.readiness)


@pytest.mark.parametrize("variant,kind", [("positive", "TLB_INVALIDATE"),
                                          ("negative_trigger", "MEMORY_BARRIER")])
def test_firmware_runtime_projection_keeps_base_case_and_hardware_gaps(
    variant: str, kind: str, tmp_path: Path,
) -> None:
    analysis, base, evidence = inputs(variant)
    snapshot = json.dumps([base.case_manifest, base.association, base.readiness, base.analysis_chain],
                          sort_keys=True)
    projection = project(analysis, base, evidence)
    assert projection == project(analysis, base, evidence)
    assert projection["projection_id"] == content_id("type2-firmware-runtime-projection", {
        key: value for key, value in projection.items() if key != "projection_id"})
    assert projection["runtime_binding_status"] == "SUPPORTED"
    assert projection["base_case_id"] == base.case_manifest["case_id"]
    assert projection["firmware_runtime_requirement"]["status"] == "SATISFIED_FOR_DECLARED_SCOPE"
    assert FIRMWARE_RUNTIME_REQUIREMENT not in projection["effective_missing_requirements"]
    assert projection["effective_missing_requirements"] == [
        item for item in base.readiness["missing_requirements"] if item != FIRMWARE_RUNTIME_REQUIREMENT]
    assert projection["hardware_package_evidence_gaps"] == base.readiness["hardware_package_evidence_gaps"]
    assert projection["hardware_trigger_status"] == "NOT_ESTABLISHED"
    assert projection["hardware_deviation_status"] == "NOT_ESTABLISHED"
    assert projection["silicon_applicability_status"] == "NOT_ESTABLISHED"
    assert projection["hardware_differential_status"] == "UNKNOWN"
    assert projection["hardware_package_verification_status"] == "NOT_ESTABLISHED"
    assert projection["verification_ready"] is False
    assert projection["verifier_invoked"] is False
    assert projection["verifier_applicability_status"] == "NOT_APPLICABLE"
    assert projection["full_type2_chain_status"] == "NOT_VERIFIED"
    target = next(row for row in projection["firmware_facts"] if row["pc"] == 0x80000064)
    assert target["kind"] == kind
    assert target["status"] == "SUPPORTED"
    assert target["observations"][0]["instruction_bytes"] == (
        "73000012" if variant == "positive" else "0f003003")
    assert snapshot == json.dumps([base.case_manifest, base.association, base.readiness,
                                   base.analysis_chain], sort_keys=True)
    assert base.association["runtime_binding_status"] == "UNKNOWN"
    assert FIRMWARE_RUNTIME_REQUIREMENT in base.readiness["missing_requirements"]
    customer = render_customer_report(firmware=analysis, chain=base.analysis_chain,
                                     association=base.association, readiness=base.readiness,
                                     runtime_projection=projection)
    enhanced = replace(base, customer_report=customer, runtime_projection=projection)
    original_output, enhanced_output = tmp_path / "original", tmp_path / "enhanced"
    write_case(base, original_output)
    write_case(enhanced, enhanced_output)
    for name in ("case-manifest.json", "association.json", "verification-readiness.json",
                 "analysis-chain.json", "report.md"):
        assert (original_output / name).read_bytes() == (enhanced_output / name).read_bytes()
    assert json.loads((enhanced_output / "runtime-projection.json").read_text()) == projection
    assert not (original_output / "runtime-projection.json").exists()
    assert "软件侧静态候选得到 QEMU 运行时执行支持" in customer
    assert "来源绑定 QEMU 环境中观察到指令执行回调" in customer
    assert "完整 Type-II 攻击链尚未验证" in customer
    assert "真实硬件触发 | 当前材料尚未建立" in customer
    assert "权威硬件触发条件：未建立" in customer
    assert "没有据此重建完整函数调用栈" in customer
    assert "firmware-static:" not in customer
    assert analysis.artifact.sha256 not in customer
    if variant == "negative_trigger":
        assert "TLB_INVALIDATE`：尚未建立该固件运行中对应行为的执行支持" in customer
        assert "也不证明硬件安全" in customer


def test_partial_candidate_runtime_coverage_remains_unknown() -> None:
    analysis, base, evidence = inputs("positive", absent_pc=0x80000064)
    projection = project(analysis, base, evidence)
    assert projection["runtime_binding_status"] == "UNKNOWN"
    assert FIRMWARE_RUNTIME_REQUIREMENT in projection["effective_missing_requirements"]
    target = next(row for row in projection["firmware_facts"] if row["pc"] == 0x80000064)
    assert target["status"] == "UNKNOWN"
    assert target["source_event_ids"] == []
    assert "CONTRADICTED" not in json.dumps(projection)
    customer = render_customer_report(firmware=analysis, chain=base.analysis_chain,
                                     association=base.association, readiness=base.readiness,
                                     runtime_projection=projection)
    assert "此有界运行中未观察到；不能推断不可执行" in customer
    assert "软件侧静态候选得到 QEMU 运行时执行支持" not in customer


def test_runtime_projection_defends_against_wrong_firmware() -> None:
    analysis, base, evidence = inputs("positive")
    other, _, _ = inputs("negative_trigger")
    evidence.run.firmware = other.artifact
    with pytest.raises(ValueError, match="firmware identity disagree"):
        project(analysis, base, evidence)


@pytest.mark.parametrize("field,value", [("pc", 0x80000068),
                                         ("instruction_bytes", "00000000")])
def test_runtime_projection_defends_exact_instruction_reference(field: str, value) -> None:
    analysis, base, evidence = inputs("positive")
    setattr(evidence.events.events[-1], field, value)
    with pytest.raises(ValueError, match="static candidate instruction disagree"):
        project(analysis, base, evidence)


@pytest.mark.parametrize("variant", ["positive", "negative_trigger"])
def test_no_runtime_customer_report_retains_frozen_bytes(variant: str) -> None:
    base = prepare_case(FIRMWARE / variant, HARDWARE)
    assert base.runtime_projection is None
    assert sha256(base.customer_report.encode()).hexdigest() == CUSTOMER_SHA[variant]


@pytest.mark.parametrize("variant", ["positive", "negative_trigger"])
def test_public_case_cli_replays_runtime_sources_and_keeps_frozen_base(variant, tmp_path):
    from chipchain.cli import main
    from tests.runtime_fixtures import write_synthetic_runtime

    runtime = tmp_path / "runtime"
    write_synthetic_runtime(runtime, variant)
    output = tmp_path / "case"
    assert main(["type2", "prepare", "--firmware", str(FIRMWARE / variant),
                 "--hardware", str(HARDWARE), "--runtime", str(runtime),
                 "--output", str(output)]) == 0
    projection = json.loads((output / "runtime-projection.json").read_text())
    assert projection["runtime_binding_status"] == "SUPPORTED"
    assert projection["verification_ready"] is False
    base = tmp_path / "base"
    write_case(prepare_case(FIRMWARE / variant, HARDWARE), base)
    for name in ("case-manifest.json", "association.json", "verification-readiness.json",
                 "analysis-chain.json", "report.md"):
        assert (base / name).read_bytes() == (output / name).read_bytes()


def test_public_case_cli_rejects_other_firmware_runtime_before_writing(tmp_path):
    from chipchain.cli import main
    from tests.runtime_fixtures import write_synthetic_runtime

    runtime, output = tmp_path / "runtime", tmp_path / "case"
    write_synthetic_runtime(runtime, "positive")
    with pytest.raises(SystemExit) as failure:
        main(["type2", "prepare", "--firmware", str(FIRMWARE / "negative_trigger"),
              "--hardware", str(HARDWARE), "--runtime", str(runtime),
              "--output", str(output)])
    assert failure.value.code == 2
    assert not output.exists()
