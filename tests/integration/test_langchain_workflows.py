"""Real LangGraph + LangChain structured parsing, with three independent fake models."""

from collections.abc import Callable

import pytest

from chipchain.agents.cross_layer import CrossLayerSecurityAgent
from chipchain.agents.firmware import FirmwareSecurityAgent
from chipchain.agents.hardware import HardwareSecurityAgent
from chipchain.domain.case import CaseBundle
from chipchain.domain.cross_layer import CrossLayerAnalysisReport
from chipchain.agents.model_outputs.firmware import ModelFirmwareAnalysisReport
from chipchain.domain.firmware import FirmwareAnalysisReport
from chipchain.domain.hardware import HardwareAnalysisReport
from chipchain.workflows import (
    build_case_workflow, build_cross_layer_workflow, build_firmware_workflow, build_hardware_workflow,
)
from chipchain.workflows.state import AnalysisStatus, CaseWorkflowState
from tests.fakes import fake_model


@pytest.mark.parametrize("name,calls", [
    ("hardware_only", (1, 0, 0)), ("firmware_only", (0, 1, 0)), ("paired", (1, 1, 1)),
])
def test_case_routing_invokes_only_applicable_models(
    load_case: Callable[[str], CaseBundle], monkeypatch: pytest.MonkeyPatch,
    name: str, calls: tuple[int, int, int],
) -> None:
    # Deliberately restore inert keys after the suite guard removes ambient keys.
    # No injected fake or production agent should discover/use them.
    for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "QWEN_API_KEY"):
        monkeypatch.setenv(key, "synthetic-unused-key")
    case = load_case(name)
    hw = fake_model(HardwareAnalysisReport, HardwareAnalysisReport(case_id=case.case_id))
    fw = fake_model(ModelFirmwareAnalysisReport, FirmwareAnalysisReport(case_id=case.case_id))
    cross = fake_model(CrossLayerAnalysisReport, CrossLayerAnalysisReport(case_id=case.case_id))
    result = CaseWorkflowState.model_validate(build_case_workflow(
        hardware_agent=HardwareSecurityAgent(model=hw), firmware_agent=FirmwareSecurityAgent(model=fw),
        cross_layer_agent=CrossLayerSecurityAgent(model=cross),
    ).invoke({"case": case}))
    assert tuple(len(model.seen_messages) for model in (hw, fw, cross)) == calls
    assert result.errors == []
    for report, status, invoked in zip(
        (result.hardware_report, result.firmware_report, result.cross_layer_report),
        (result.hardware_status, result.firmware_status, result.cross_layer_status), calls, strict=True,
    ):
        assert (report is not None) == bool(invoked)
        assert status == (AnalysisStatus.COMPLETED if invoked else AnalysisStatus.NOT_APPLICABLE)
    if result.hardware_report is not None:
        assert result.hardware_report.findings == []
    if result.firmware_report is not None:
        assert result.firmware_report.findings == []
    if result.cross_layer_report is not None:
        assert result.cross_layer_report.candidates == result.cross_layer_report.attack_chain_candidates == []


@pytest.mark.parametrize("failure_kind", ["invocation", "structured"])
def test_model_failures_become_failed_state_and_block_cross_layer(
    load_case: Callable[[str], CaseBundle], failure_kind: str,
) -> None:
    case = load_case("paired")
    hw = fake_model(
        HardwareAnalysisReport, {},
        failure=RuntimeError("synthetic-secret") if failure_kind == "invocation" else None,
    )
    fw = fake_model(ModelFirmwareAnalysisReport, FirmwareAnalysisReport(case_id=case.case_id))
    cross = fake_model(CrossLayerAnalysisReport, CrossLayerAnalysisReport(case_id=case.case_id))
    result = CaseWorkflowState.model_validate(build_case_workflow(
        hardware_agent=HardwareSecurityAgent(model=hw), firmware_agent=FirmwareSecurityAgent(model=fw),
        cross_layer_agent=CrossLayerSecurityAgent(model=cross),
    ).invoke({"case": case}))
    assert result.hardware_status == AnalysisStatus.FAILED and result.hardware_report is None
    assert result.firmware_status == AnalysisStatus.COMPLETED
    assert result.cross_layer_status == AnalysisStatus.BLOCKED
    assert len(hw.seen_messages) == len(fw.seen_messages) == 1
    assert not cross.seen_messages
    assert result.errors[0].error_type == (
        "AgentExecutionError" if failure_kind == "invocation" else "AgentStructuredOutputError"
    )
    assert "synthetic-secret" not in result.model_dump_json()


@pytest.mark.parametrize("layer", ["firmware", "cross_layer"])
def test_other_domains_reject_invalid_model_output_in_workflow(
    load_case: Callable[[str], CaseBundle], layer: str,
) -> None:
    case = load_case("paired")
    hw = fake_model(HardwareAnalysisReport, HardwareAnalysisReport(case_id=case.case_id))
    fw = fake_model(ModelFirmwareAnalysisReport, {} if layer == "firmware" else FirmwareAnalysisReport(case_id=case.case_id))
    cross = fake_model(CrossLayerAnalysisReport, {})
    result = CaseWorkflowState.model_validate(build_case_workflow(
        hardware_agent=HardwareSecurityAgent(model=hw), firmware_agent=FirmwareSecurityAgent(model=fw),
        cross_layer_agent=CrossLayerSecurityAgent(model=cross),
    ).invoke({"case": case}))
    assert getattr(result, f"{layer}_status") == AnalysisStatus.FAILED
    assert getattr(result, f"{layer}_report") is None
    assert result.errors[0].error_type == "AgentStructuredOutputError"
    if layer == "firmware":
        assert result.cross_layer_status == AnalysisStatus.BLOCKED and not cross.seen_messages


def test_each_standalone_workflow_accepts_model_backed_agent(load_case: Callable[[str], CaseBundle]) -> None:
    case = load_case("paired")
    hw = fake_model(HardwareAnalysisReport, HardwareAnalysisReport(case_id=case.case_id))
    fw = fake_model(ModelFirmwareAnalysisReport, FirmwareAnalysisReport(case_id=case.case_id))
    cross = fake_model(CrossLayerAnalysisReport, CrossLayerAnalysisReport(case_id=case.case_id))
    hardware = build_hardware_workflow(agent=HardwareSecurityAgent(model=hw)).invoke({"case": case})
    firmware = build_firmware_workflow(agent=FirmwareSecurityAgent(model=fw)).invoke({"case": case})
    result = CaseWorkflowState.model_validate(build_cross_layer_workflow(
        agent=CrossLayerSecurityAgent(model=cross),
    ).invoke({
        "case": case, "hardware_report": hardware["hardware_report"],
        "firmware_report": firmware["firmware_report"],
        "processor_behavior_ir": hardware["processor_behavior_ir"],
        "hardware_status": hardware["hardware_status"], "firmware_status": firmware["firmware_status"],
    }))
    assert result.cross_layer_status == AnalysisStatus.COMPLETED
    assert tuple(len(model.seen_messages) for model in (hw, fw, cross)) == (1, 1, 1)
