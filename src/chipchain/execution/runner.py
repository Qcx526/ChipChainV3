"""Fresh run identities around existing workflows; no automatic file persistence."""

from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from uuid import UUID, uuid4

from langgraph.graph.state import CompiledStateGraph
from pydantic import ValidationError

from chipchain.domain.case import CaseBundle
from chipchain.domain.common import AnalysisStatus, WorkflowStage
from chipchain.domain.provenance import RunProvenance
from chipchain.domain.run import AnalysisRun, ArtifactIdentity, FailureCategory, RunFailure, RunStageRecord
from chipchain.execution.provenance import capture_provenance, stub_provenance
from chipchain.workflows.case import build_case_workflow
from chipchain.workflows.state import CaseWorkflowState


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _failure(
    exception_type: str | None, stage: WorkflowStage | None,
    category: FailureCategory | None = None,
) -> RunFailure:
    if category is None:
        category = {
            "AgentStructuredOutputError": FailureCategory.STRUCTURED_OUTPUT,
            "AgentExecutionError": FailureCategory.AGENT_EXECUTION,
            "ValidationError": FailureCategory.INPUT_VALIDATION,
        }.get(exception_type, FailureCategory.WORKFLOW_INTERNAL)
    messages = {
        FailureCategory.INPUT_VALIDATION: "Analysis input validation failed.",
        FailureCategory.DETERMINISTIC_ANALYSIS: "Deterministic analysis failed.",
        FailureCategory.AGENT_EXECUTION: "Agent execution failed.",
        FailureCategory.STRUCTURED_OUTPUT: "Agent structured output validation failed.",
        FailureCategory.WORKFLOW_INTERNAL: "Workflow failed or prerequisite analysis is unavailable.",
    }
    return RunFailure(category=category, stage=stage, public_message=messages[category], exception_type=exception_type)


def _artifact_identities(case: CaseBundle) -> list[ArtifactIdentity]:
    return [ArtifactIdentity(artifact_id=a.artifact_id, sha256=a.sha256, size_bytes=a.size_bytes)
            for a in (*case.hardware_artifacts, *case.firmware_artifacts)]


def analysis_run_from_state(
    state: CaseWorkflowState, *, run_id: UUID, started_at: datetime, finished_at: datetime,
    provenance: RunProvenance,
) -> AnalysisRun:
    """Project a final state. Per-stage times stay unknown: state has no timing events."""
    failures = [_failure(error.error_type, error.stage) for error in state.errors]
    aggregation_status = (
        AnalysisStatus.FAILED if any(e.stage == WorkflowStage.IR_AGGREGATION for e in state.errors)
        else AnalysisStatus.COMPLETED if state.processor_behavior_ir is not None else AnalysisStatus.BLOCKED
    )
    statuses = (
        (WorkflowStage.HARDWARE, state.hardware_status),
        (WorkflowStage.FIRMWARE, state.firmware_status),
        (WorkflowStage.IR_AGGREGATION, aggregation_status),
        (WorkflowStage.CROSS_LAYER, state.cross_layer_status),
    )
    if any(status == AnalysisStatus.PENDING for _, status in statuses):
        raise ValueError("AnalysisRun projection requires a final workflow state")
    records = []
    for stage, status in statuses:
        failure = next((item for item in failures if item.stage == stage), None)
        if status == AnalysisStatus.FAILED and failure is None:
            failure = _failure(None, stage)
            failures.append(failure)
        records.append(RunStageRecord(stage=stage, status=status, failure=failure))
    status = (
        AnalysisStatus.FAILED if failures or any(s == AnalysisStatus.FAILED for _, s in statuses)
        else AnalysisStatus.BLOCKED if any(s == AnalysisStatus.BLOCKED for _, s in statuses)
        else AnalysisStatus.COMPLETED
    )
    return AnalysisRun(
        run_id=run_id, case_id=state.case.case_id, case_schema_version=state.case.schema_version,
        started_at=started_at, finished_at=finished_at, status=status, stages=records, failures=failures,
        provenance=provenance, artifacts=_artifact_identities(state.case),
        hardware_report=state.hardware_report, firmware_report=state.firmware_report,
        processor_behavior_ir=state.processor_behavior_ir, cross_layer_report=state.cross_layer_report,
    ).model_copy(deep=True)


def _failed_run(
    case: CaseBundle, *, run_id: UUID, started_at: datetime, finished_at: datetime,
    provenance: RunProvenance, failure: RunFailure, include_artifacts: bool = True,
) -> AnalysisRun:
    # An escaping failure has no trustworthy final stage result. Do not invent one.
    applicable = (case.has_hardware_inputs, case.has_firmware_inputs, True, case.is_paired)
    return AnalysisRun(
        run_id=run_id, case_id=case.case_id, case_schema_version=case.schema_version,
        started_at=started_at, finished_at=finished_at, status=AnalysisStatus.FAILED,
        stages=[RunStageRecord(stage=stage, status=(AnalysisStatus.BLOCKED if applies else AnalysisStatus.NOT_APPLICABLE))
                for stage, applies in zip(WorkflowStage, applicable, strict=True)],
        failures=[failure], provenance=provenance,
        artifacts=_artifact_identities(case) if include_artifacts else [],
    ).model_copy(deep=True)


def run_case(
    case: CaseBundle, *, workflow: CompiledStateGraph | None = None,
    provenance: RunProvenance | None = None, run_id_factory: Callable[[], UUID] = uuid4,
    clock: Callable[[], datetime] = utc_now,
) -> AnalysisRun:
    """Execute one case. Caller-owned clock/ID factories must supply valid values."""
    run_id, started_at = run_id_factory(), clock()
    snapshot = (provenance if provenance is not None else (
        stub_provenance() if workflow is None else capture_provenance()
    )).model_copy(deep=True)
    try:
        isolated_case = CaseBundle.model_validate(case.model_dump())
    except ValidationError as exc:
        return _failed_run(
            case, run_id=run_id, started_at=started_at, finished_at=clock(), provenance=snapshot,
            failure=_failure(type(exc).__name__, None, FailureCategory.INPUT_VALIDATION),
            include_artifacts=False,
        )
    try:
        graph = workflow if workflow is not None else build_case_workflow()
        state = CaseWorkflowState.model_validate(graph.invoke({"case": isolated_case}))
        if state.case.case_id != isolated_case.case_id:
            raise ValueError("Workflow returned a different case")
    except Exception as exc:
        return _failed_run(
            isolated_case, run_id=run_id, started_at=started_at, finished_at=clock(), provenance=snapshot,
            failure=_failure(type(exc).__name__, None),
        )
    finished_at = clock()
    try:
        return analysis_run_from_state(
            state, run_id=run_id, started_at=started_at, finished_at=finished_at, provenance=snapshot,
        )
    except ValueError as exc:
        return _failed_run(
            isolated_case, run_id=run_id, started_at=started_at, finished_at=finished_at,
            provenance=snapshot,
            failure=_failure(type(exc).__name__, None, FailureCategory.WORKFLOW_INTERNAL),
        )


def run_cases(
    cases: Sequence[CaseBundle], *, workflow: CompiledStateGraph | None = None,
    provenance: RunProvenance | None = None, run_id_factory: Callable[[], UUID] = uuid4,
    clock: Callable[[], datetime] = utc_now,
) -> list[AnalysisRun]:
    """Small-set sequential convenience; typical 1–10 case workloads are not a hard limit."""
    graph = workflow if workflow is not None else build_case_workflow()
    snapshot = provenance if provenance is not None else (
        stub_provenance() if workflow is None else capture_provenance()
    )
    return [run_case(case, workflow=graph, provenance=snapshot, run_id_factory=run_id_factory, clock=clock)
            for case in cases]
