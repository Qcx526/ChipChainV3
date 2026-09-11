from collections.abc import Callable

import pytest
from langgraph.graph.state import CompiledStateGraph

from chipchain.agents.contracts import (
    CrossLayerAgentInput, CrossLayerAgentOutput, FirmwareAgentInput, FirmwareAgentOutput,
    HardwareAgentInput, HardwareAgentOutput,
)
from chipchain.agents.cross_layer import CrossLayerSecurityAgent
from chipchain.agents.firmware import FirmwareSecurityAgent
from chipchain.agents.hardware import HardwareSecurityAgent
from chipchain.domain.behavior import BehaviorKind, ProcessorBehavior, ProcessorBehaviorIR
from chipchain.domain.case import CaseBundle, CaseLabel
from chipchain.domain.common import AnalysisLayer, Architecture
from chipchain.domain.firmware import FirmwareAnalysisReport
from chipchain.domain.hardware import HardwareAnalysisReport
from chipchain.workflows import (
    build_case_workflow, build_cross_layer_workflow, build_firmware_workflow,
    build_hardware_workflow,
)
from chipchain.workflows.state import AnalysisStatus, CaseWorkflowState, WorkflowStage


class RecordingHardware(HardwareSecurityAgent):
    def __init__(self, *, fail: bool = False, emit_behavior: bool = False,
                 behavior_id: str = "synthetic:hardware:behavior") -> None:
        self.calls = 0
        self.fail = fail
        self.emit_behavior = emit_behavior
        self.behavior_id = behavior_id

    def invoke(self, inputs: HardwareAgentInput) -> HardwareAgentOutput:
        self.calls += 1
        if self.fail:
            raise RuntimeError("Synthetic hardware failure")
        if self.emit_behavior:
            return HardwareAgentOutput(
                report=HardwareAnalysisReport(case_id=inputs.case.case_id, processor_behavior_ids=[self.behavior_id]),
                processor_behavior_ir=ProcessorBehaviorIR(case_id=inputs.case.case_id, behaviors=[
                    ProcessorBehavior(behavior_id=self.behavior_id, kind=BehaviorKind.INSTRUCTION,
                                      architecture=Architecture.UNKNOWN, origin=AnalysisLayer.HARDWARE,
                                      summary="Synthetic test-only behavior"),
                ]),
            )
        return super().invoke(inputs)


class RecordingFirmware(FirmwareSecurityAgent):
    def __init__(self, *, fail: bool = False, emit_behavior: bool = False,
                 behavior_id: str = "synthetic:firmware:behavior") -> None:
        self.calls = 0
        self.fail = fail
        self.emit_behavior = emit_behavior
        self.behavior_id = behavior_id

    def invoke(self, inputs: FirmwareAgentInput) -> FirmwareAgentOutput:
        self.calls += 1
        if self.fail:
            raise RuntimeError("Synthetic firmware failure")
        if self.emit_behavior:
            return FirmwareAgentOutput(
                report=FirmwareAnalysisReport(case_id=inputs.case.case_id, processor_behavior_ids=[self.behavior_id]),
                processor_behavior_ir=ProcessorBehaviorIR(case_id=inputs.case.case_id, behaviors=[
                    ProcessorBehavior(behavior_id=self.behavior_id, kind=BehaviorKind.INSTRUCTION,
                                      architecture=Architecture.UNKNOWN, origin=AnalysisLayer.FIRMWARE,
                                      summary="Synthetic test-only behavior"),
                ]),
            )
        return super().invoke(inputs)


class RecordingCrossLayer(CrossLayerSecurityAgent):
    def __init__(self, *, fail: bool = False) -> None:
        self.calls = 0
        self.fail = fail

    def invoke(self, inputs: CrossLayerAgentInput) -> CrossLayerAgentOutput:
        self.calls += 1
        if self.fail:
            raise RuntimeError("Synthetic cross-layer failure")
        return super().invoke(inputs)


@pytest.mark.parametrize("name,expected", [
    ("hardware_only", (1, 0, 0)), ("firmware_only", (0, 1, 0)), ("paired", (1, 1, 1)),
])
def test_case_routing(
    load_case: Callable[[str], CaseBundle], name: str, expected: tuple[int, int, int],
) -> None:
    hw, fw, cross = RecordingHardware(), RecordingFirmware(), RecordingCrossLayer()
    graph = build_case_workflow(hardware_agent=hw, firmware_agent=fw, cross_layer_agent=cross)
    assert isinstance(graph, CompiledStateGraph)
    result = CaseWorkflowState.model_validate(graph.invoke({"case": load_case(name)}))
    assert (hw.calls, fw.calls, cross.calls) == expected
    for status, count, report in zip(
        (result.hardware_status, result.firmware_status, result.cross_layer_status), expected,
        (result.hardware_report, result.firmware_report, result.cross_layer_report), strict=True,
    ):
        assert status == (AnalysisStatus.COMPLETED if count else AnalysisStatus.NOT_APPLICABLE)
        assert (report is not None) is bool(count)
    assert result.errors == []
    assert result.processor_behavior_ir is not None
    assert result.processor_behavior_ir.behaviors == []
    if result.cross_layer_report is not None:
        report = result.cross_layer_report
        assert report.candidates == report.attack_chain_candidates == []
        assert report.trigger_features == report.root_location_candidates == []
        assert report.unresolved_questions and report.missing_constraints
    assert CaseWorkflowState.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize("architecture", [Architecture.ARM, Architecture.RISCV, Architecture.POWERPC])
def test_paired_routing_eligibility_is_architecture_neutral(
    load_case: Callable[[str], CaseBundle], architecture: Architecture,
) -> None:
    case = load_case("paired")
    case.target.architecture = architecture
    hw, fw, cross = RecordingHardware(), RecordingFirmware(), RecordingCrossLayer()
    graph = build_case_workflow(hardware_agent=hw, firmware_agent=fw, cross_layer_agent=cross)
    updates = list(graph.stream({"case": case}, stream_mode="updates"))
    assert [name for update in updates for name in update] == [
        "initialize", "hardware", "firmware", "aggregate_ir", "eligibility", "cross_layer",
    ]
    assert (hw.calls, fw.calls, cross.calls) == (1, 1, 1)
    assert updates[1]["hardware"]["hardware_status"] == AnalysisStatus.COMPLETED
    assert updates[2]["firmware"]["firmware_status"] == AnalysisStatus.COMPLETED
    ir = updates[3]["aggregate_ir"]["processor_behavior_ir"]
    assert type(ir) is ProcessorBehaviorIR
    assert ir.case_id == case.case_id
    assert ir.behaviors == []
    # Empty reports/IR permit routing, not evidence sufficiency or verified triggers.
    final = updates[-1]["cross_layer"]
    assert final["cross_layer_status"] == AnalysisStatus.COMPLETED
    assert final["cross_layer_report"].candidates == []
    assert final["cross_layer_report"].missing_constraints
    assert final["errors"] == []


@pytest.mark.parametrize("builder,name,field", [
    (build_hardware_workflow, "hardware_only", "hardware_status"),
    (build_firmware_workflow, "firmware_only", "firmware_status"),
])
def test_standalone_workflows(
    load_case: Callable[[str], CaseBundle], builder: Callable[[], CompiledStateGraph],
    name: str, field: str,
) -> None:
    result = CaseWorkflowState.model_validate(builder().invoke({"case": load_case(name)}))
    assert getattr(result, field) == AnalysisStatus.COMPLETED
    assert result.cross_layer_status == AnalysisStatus.NOT_APPLICABLE
    assert result.processor_behavior_ir is not None
    assert not result.errors


@pytest.mark.parametrize("builder,name", [
    (build_hardware_workflow, "firmware_only"), (build_firmware_workflow, "hardware_only"),
])
def test_standalone_workflow_rejects_missing_side(
    load_case: Callable[[str], CaseBundle], builder: Callable[[], CompiledStateGraph], name: str,
) -> None:
    with pytest.raises(ValueError, match="requires"):
        builder().invoke({"case": load_case(name)})


@pytest.mark.parametrize("failed_side", ["hardware", "firmware"])
def test_single_side_failure_does_not_stop_other_side(
    load_case: Callable[[str], CaseBundle], failed_side: str,
) -> None:
    hw = RecordingHardware(fail=failed_side == "hardware")
    fw = RecordingFirmware(fail=failed_side == "firmware")
    cross = RecordingCrossLayer()
    result = CaseWorkflowState.model_validate(build_case_workflow(
        hardware_agent=hw, firmware_agent=fw, cross_layer_agent=cross,
    ).invoke({"case": load_case("paired")}))
    assert hw.calls == fw.calls == 1
    assert cross.calls == 0
    assert getattr(result, f"{failed_side}_status") == AnalysisStatus.FAILED
    assert getattr(result, f"{failed_side}_report") is None
    other = "firmware" if failed_side == "hardware" else "hardware"
    assert getattr(result, f"{other}_status") == AnalysisStatus.COMPLETED
    assert result.cross_layer_status == AnalysisStatus.BLOCKED
    assert result.cross_layer_report is None
    assert [error.stage.value for error in result.errors] == [failed_side, "cross_layer"]
    assert result.errors[0].error_type == "RuntimeError"


def test_ir_collision_blocks_cross_layer(load_case: Callable[[str], CaseBundle]) -> None:
    cross = RecordingCrossLayer()
    result = CaseWorkflowState.model_validate(build_case_workflow(
        hardware_agent=RecordingHardware(emit_behavior=True, behavior_id="synthetic:shared-id"),
        firmware_agent=RecordingFirmware(emit_behavior=True, behavior_id="synthetic:shared-id"),
        cross_layer_agent=cross,
    ).invoke({"case": load_case("paired")}))
    assert result.hardware_status == result.firmware_status == AnalysisStatus.COMPLETED
    assert result.processor_behavior_ir is None
    assert result.errors[0].stage == WorkflowStage.IR_AGGREGATION
    assert result.cross_layer_status == AnalysisStatus.BLOCKED
    assert cross.calls == 0


def test_cross_layer_failure_is_explicit(load_case: Callable[[str], CaseBundle]) -> None:
    result = CaseWorkflowState.model_validate(build_case_workflow(
        cross_layer_agent=RecordingCrossLayer(fail=True),
    ).invoke({"case": load_case("paired")}))
    assert result.cross_layer_status == AnalysisStatus.FAILED
    assert result.cross_layer_report is None
    assert result.errors[0].stage == WorkflowStage.CROSS_LAYER


def test_nonempty_ir_aggregation_keeps_both_layers(load_case: Callable[[str], CaseBundle]) -> None:
    result = CaseWorkflowState.model_validate(build_case_workflow(
        hardware_agent=RecordingHardware(emit_behavior=True),
        firmware_agent=RecordingFirmware(emit_behavior=True),
    ).invoke({"case": load_case("paired")}))
    assert result.processor_behavior_ir is not None
    assert [b.behavior_id for b in result.processor_behavior_ir.behaviors] == [
        "synthetic:hardware:behavior", "synthetic:firmware:behavior",
    ]
    assert [b.origin for b in result.processor_behavior_ir.behaviors] == [
        AnalysisLayer.HARDWARE, AnalysisLayer.FIRMWARE,
    ]
    assert result.cross_layer_status == AnalysisStatus.COMPLETED
    assert not result.errors


def test_partial_ir_preserves_successful_side(load_case: Callable[[str], CaseBundle]) -> None:
    result = CaseWorkflowState.model_validate(build_case_workflow(
        hardware_agent=RecordingHardware(fail=True),
        firmware_agent=RecordingFirmware(emit_behavior=True),
    ).invoke({"case": load_case("paired")}))
    assert result.processor_behavior_ir is not None
    assert [b.origin for b in result.processor_behavior_ir.behaviors] == [AnalysisLayer.FIRMWARE]
    assert result.cross_layer_status == AnalysisStatus.BLOCKED


def test_wrong_case_agent_output_fails_without_blocking_firmware(
    load_case: Callable[[str], CaseBundle],
) -> None:
    class WrongCaseHardware(HardwareSecurityAgent):
        def invoke(self, inputs: HardwareAgentInput) -> HardwareAgentOutput:
            return HardwareAgentOutput(
                report=HardwareAnalysisReport(case_id="different"),
                processor_behavior_ir=ProcessorBehaviorIR(case_id="different"),
            )

    result = CaseWorkflowState.model_validate(build_case_workflow(
        hardware_agent=WrongCaseHardware(),
    ).invoke({"case": load_case("paired")}))
    assert result.hardware_status == AnalysisStatus.FAILED
    assert result.firmware_status == AnalysisStatus.COMPLETED
    assert result.cross_layer_status == AnalysisStatus.BLOCKED
    assert "different case" in result.errors[0].message


@pytest.mark.parametrize("defect", ["hardware_report", "firmware_report", "ir", "case_id", "status", "single_side", "dangling_id"])
def test_cross_layer_gate_rejects_ineligible_state(
    load_case: Callable[[str], CaseBundle], defect: str,
) -> None:
    case = load_case("paired")
    state = CaseWorkflowState(
        case=case, hardware_report=HardwareAnalysisReport(case_id=case.case_id),
        firmware_report=FirmwareAnalysisReport(case_id=case.case_id),
        processor_behavior_ir=ProcessorBehaviorIR(case_id=case.case_id),
        hardware_status=AnalysisStatus.COMPLETED, firmware_status=AnalysisStatus.COMPLETED,
    )
    match defect:
        case "hardware_report": state.hardware_report = None
        case "firmware_report": state.firmware_report = None
        case "ir": state.processor_behavior_ir = None
        case "case_id": state.hardware_report = HardwareAnalysisReport(case_id="different")
        case "status": state.hardware_status = AnalysisStatus.FAILED
        case "single_side": state.case = load_case("hardware_only")
        case "dangling_id": state.hardware_report = HardwareAnalysisReport(case_id=case.case_id, processor_behavior_ids=["missing"])
    agent = RecordingCrossLayer()
    with pytest.raises(ValueError):
        build_cross_layer_workflow(agent).invoke(state)
    assert agent.calls == 0


def test_standalone_cross_layer_workflow(load_case: Callable[[str], CaseBundle]) -> None:
    case = load_case("paired")
    result = CaseWorkflowState.model_validate(build_cross_layer_workflow().invoke({
        "case": case, "hardware_report": HardwareAnalysisReport(case_id=case.case_id),
        "firmware_report": FirmwareAnalysisReport(case_id=case.case_id),
        "processor_behavior_ir": ProcessorBehaviorIR(case_id=case.case_id),
        "hardware_status": AnalysisStatus.COMPLETED, "firmware_status": AnalysisStatus.COMPLETED,
    }))
    assert result.cross_layer_status == AnalysisStatus.COMPLETED
    assert result.cross_layer_report is not None
    assert result.cross_layer_report.candidates == []


def test_ground_truth_and_previous_run_do_not_drive_results(load_case: Callable[[str], CaseBundle]) -> None:
    case = load_case("paired")
    graph = build_case_workflow()
    initial = graph.invoke({"case": case})
    again = graph.invoke(initial)
    assert initial == again
    case.ground_truth_label = CaseLabel.CONFIRMED_CROSS_LAYER
    labeled = graph.invoke({"case": case})
    for name in ("hardware_report", "firmware_report", "processor_behavior_ir", "cross_layer_report"):
        assert initial[name] == labeled[name]


def test_compiled_workflow_can_run_different_cases(load_case: Callable[[str], CaseBundle]) -> None:
    graph = build_case_workflow()
    for name in ("paired", "hardware_only", "firmware_only"):
        state = CaseWorkflowState.model_validate(graph.invoke({"case": load_case(name)}))
        assert state.processor_behavior_ir is not None
        assert state.processor_behavior_ir.case_id == state.case.case_id
        if name != "paired":
            assert state.cross_layer_report is None
            assert state.cross_layer_status == AnalysisStatus.NOT_APPLICABLE
