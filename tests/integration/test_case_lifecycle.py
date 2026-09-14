from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

import pytest
from langgraph.graph import END, START, StateGraph

from chipchain.agents.contracts import HardwareAgentInput, HardwareAgentOutput
from chipchain.agents.hardware import HardwareSecurityAgent
from chipchain.agents.firmware import FirmwareSecurityAgent
from chipchain.agents.cross_layer import CrossLayerSecurityAgent
from chipchain.agents.prompts.hardware import PROMPT_DESCRIPTOR as HARDWARE_PROMPT
from chipchain.agents.prompts.firmware import PROMPT_DESCRIPTOR as FIRMWARE_PROMPT
from chipchain.agents.prompts.cross_layer import PROMPT_DESCRIPTOR as CROSS_PROMPT
from chipchain.domain.case import CaseBundle, CaseLabel
from chipchain.domain.common import AnalysisStatus, Architecture, WorkflowStage
from chipchain.domain.provenance import AgentRole, ModelDescriptor
from chipchain.domain.run import AnalysisRun, FailureCategory
from chipchain.domain.hardware import HardwareAnalysisReport
from chipchain.agents.model_outputs.firmware import ModelFirmwareAnalysisReport
from chipchain.domain.firmware import FirmwareAnalysisReport
from chipchain.domain.cross_layer import CrossLayerAnalysisReport
from chipchain.execution import analysis_run_from_state, run_case, run_cases
from chipchain.execution.provenance import capture_provenance
from chipchain.workflows import build_case_workflow
from chipchain.workflows.state import CaseWorkflowState
from tests.fakes import fake_model

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.mark.parametrize("architecture", [Architecture.ARM, Architecture.RISCV, Architecture.POWERPC])
def test_case_repeated_runs_and_architecture_neutrality(
    load_case: Callable[[str], CaseBundle], architecture: Architecture,
) -> None:
    case = load_case("paired")
    case.target.architecture = architecture
    before = case.model_dump_json()
    first, second = run_case(case), run_case(case)
    assert first.run_id != second.run_id
    assert first.case_id == second.case_id == case.case_id
    assert first.started_at.utcoffset() == timedelta(0)
    assert first.finished_at >= first.started_at
    assert first.status == second.status == AnalysisStatus.COMPLETED
    assert case.model_dump_json() == before
    assert AnalysisRun.model_validate_json(first.model_dump_json()) == first
    first.hardware_report.unresolved_questions.append("test mutation")
    assert first.hardware_report != second.hardware_report


def test_explicit_state_projection_and_snapshot_isolation(load_case: Callable[[str], CaseBundle]) -> None:
    case = load_case("hardware_only")
    case.hardware_artifacts[0].sha256 = "a" * 64
    case.hardware_artifacts[0].size_bytes = 3
    state = CaseWorkflowState.model_validate(build_case_workflow().invoke({"case": case}))
    provenance = capture_provenance()
    run = analysis_run_from_state(state, run_id=UUID(int=1), started_at=NOW, finished_at=NOW, provenance=provenance)
    assert {item.stage: item.status for item in run.stages} == {
        WorkflowStage.HARDWARE: AnalysisStatus.COMPLETED,
        WorkflowStage.FIRMWARE: AnalysisStatus.NOT_APPLICABLE,
        WorkflowStage.IR_AGGREGATION: AnalysisStatus.COMPLETED,
        WorkflowStage.CROSS_LAYER: AnalysisStatus.NOT_APPLICABLE,
    }
    assert all(s.started_at is None and s.finished_at is None for s in run.stages)
    assert run.artifacts[0].sha256 == "a" * 64
    assert not {"case", "hardware_observations", "hardware_behaviors", "errors"} & run.model_dump().keys()
    state.hardware_report.unresolved_questions.append("state mutation")
    provenance.runtime_packages.clear()
    assert "state mutation" not in run.hardware_report.unresolved_questions
    assert run.provenance.runtime_packages


def test_model_provenance_ground_truth_and_runtime_outcome(load_case: Callable[[str], CaseBundle]) -> None:
    case = load_case("paired")
    hw = fake_model(HardwareAnalysisReport, HardwareAnalysisReport(case_id=case.case_id))
    fw = fake_model(ModelFirmwareAnalysisReport, FirmwareAnalysisReport(case_id=case.case_id))
    cross = fake_model(CrossLayerAnalysisReport, CrossLayerAnalysisReport(case_id=case.case_id))
    graph = build_case_workflow(hardware_agent=HardwareSecurityAgent(model=hw),
                               firmware_agent=FirmwareSecurityAgent(model=fw), cross_layer_agent=CrossLayerSecurityAgent(model=cross))
    provenance = capture_provenance(
        prompts=[HARDWARE_PROMPT, FIRMWARE_PROMPT, CROSS_PROMPT],
        models=[ModelDescriptor(agent_role=role, model_identifier=f"synthetic-{role}", mode="fake") for role in AgentRole],
    )
    first = run_case(case, workflow=graph, provenance=provenance, run_id_factory=lambda: UUID(int=1), clock=lambda: NOW)
    case.ground_truth_label = CaseLabel.CONFIRMED_CROSS_LAYER
    second = run_case(case, workflow=graph, provenance=provenance, run_id_factory=lambda: UUID(int=1), clock=lambda: NOW)
    assert first == second
    assert first.provenance.models[0].mode == "fake"
    for model in (hw, fw, cross):
        assert model.seen_messages[0] == model.seen_messages[1]
        assert "ground_truth_label" not in model.seen_messages[0][1].content


def test_small_set_sequential_order_and_failure_isolation(load_case: Callable[[str], CaseBundle]) -> None:
    visits = []

    class SelectiveFailure(HardwareSecurityAgent):
        def invoke(self, inputs: HardwareAgentInput) -> HardwareAgentOutput:
            visits.append(inputs.case.case_id)
            if inputs.case.case_id == "synthetic:failure":
                raise RuntimeError("synthetic-secret raw response must not persist")
            return super().invoke(inputs)

    cases = [load_case("paired") for _ in range(3)]
    for case, name, architecture in zip(cases, ["first", "failure", "last"],
                                       [Architecture.ARM, Architecture.RISCV, Architecture.POWERPC], strict=True):
        case.case_id = f"synthetic:{name}"
        case.target.architecture = architecture
    ids = iter([UUID(int=1), UUID(int=2), UUID(int=3)])
    ticks = iter(NOW + timedelta(seconds=i) for i in range(6))
    runs = run_cases(cases, workflow=build_case_workflow(hardware_agent=SelectiveFailure()),
                     run_id_factory=lambda: next(ids), clock=lambda: next(ticks))
    assert visits == [case.case_id for case in cases]
    assert [run.status for run in runs] == [AnalysisStatus.COMPLETED, AnalysisStatus.FAILED, AnalysisStatus.COMPLETED]
    assert runs[0].finished_at < runs[1].started_at < runs[1].finished_at < runs[2].started_at
    failed = runs[1]
    assert failed.stages[0].status == AnalysisStatus.FAILED
    assert failed.stages[1].status == AnalysisStatus.COMPLETED
    assert failed.stages[3].status == AnalysisStatus.BLOCKED
    assert failed.failures[0].exception_type == "RuntimeError"
    assert "synthetic-secret" not in failed.model_dump_json()
    assert failed.provenance.models[0].mode == "unknown"


@pytest.mark.parametrize("invalid", [False, True])
def test_model_failure_categories(load_case: Callable[[str], CaseBundle], invalid: bool) -> None:
    case = load_case("hardware_only")
    model = fake_model(HardwareAnalysisReport, {}, failure=None if invalid else RuntimeError("synthetic secret"))
    run = run_case(case, workflow=build_case_workflow(hardware_agent=HardwareSecurityAgent(model=model)))
    assert run.status == AnalysisStatus.FAILED
    assert run.failures[0].category == (FailureCategory.STRUCTURED_OUTPUT if invalid else FailureCategory.AGENT_EXECUTION)


def test_escaping_workflow_failure_does_not_stop_small_set(load_case: Callable[[str], CaseBundle]) -> None:
    graph = StateGraph(CaseWorkflowState)

    def broken(state: CaseWorkflowState) -> dict[str, object]:
        raise RuntimeError("synthetic-secret")

    graph.add_node("broken", broken)
    graph.add_edge(START, "broken")
    graph.add_edge("broken", END)
    runs = run_cases([load_case("hardware_only"), load_case("firmware_only")], workflow=graph.compile())
    assert len(runs) == 2 and runs[0].run_id != runs[1].run_id
    assert all(r.status == AnalysisStatus.FAILED for r in runs)
    assert all(r.failures[0].stage is None for r in runs)
    assert all("synthetic-secret" not in r.model_dump_json() for r in runs)


def test_case_input_validation_failure_and_empty_sequence(load_case: Callable[[str], CaseBundle]) -> None:
    invalid = load_case("hardware_only")
    invalid.hardware_artifacts.clear()
    runs = run_cases([invalid, load_case("firmware_only")])
    assert runs[0].status == AnalysisStatus.FAILED
    assert runs[0].failures[0].category == FailureCategory.INPUT_VALIDATION
    assert runs[1].status == AnalysisStatus.COMPLETED
    assert run_cases([]) == []


def test_case_count_above_typical_workload_is_allowed(load_case: Callable[[str], CaseBundle]) -> None:
    cases = [load_case("hardware_only") for _ in range(11)]
    for index, case in enumerate(cases):
        case.case_id = f"synthetic:case-{index}"
    runs = run_cases(cases)
    assert len(runs) == 11
    assert [run.case_id for run in runs] == [case.case_id for case in cases]
    assert len({run.run_id for run in runs}) == 11
    assert all(run.status == AnalysisStatus.COMPLETED for run in runs)


def test_run_execution_does_not_write_workspace_files(
    load_case: Callable[[str], CaseBundle], monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    case = load_case("paired")
    monkeypatch.chdir(tmp_path)
    run = run_case(case)
    assert run.status == AnalysisStatus.COMPLETED
    assert list(tmp_path.iterdir()) == []


def test_invalid_final_state_is_a_failure_not_a_success(load_case: Callable[[str], CaseBundle]) -> None:
    graph = StateGraph(CaseWorkflowState)
    graph.add_node("incomplete", lambda state: {"hardware_status": AnalysisStatus.COMPLETED})
    graph.add_edge(START, "incomplete")
    graph.add_edge("incomplete", END)
    runs = run_cases([load_case("hardware_only"), load_case("firmware_only")], workflow=graph.compile())
    assert len(runs) == 2
    assert all(run.status == AnalysisStatus.FAILED for run in runs)
    assert all(run.failures[0].category == FailureCategory.WORKFLOW_INTERNAL for run in runs)
    assert all(run.artifacts for run in runs)
