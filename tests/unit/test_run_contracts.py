from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from chipchain.agents.prompts.hardware import PROMPT_DESCRIPTOR as HARDWARE_PROMPT
from chipchain.agents.prompts.firmware import PROMPT_DESCRIPTOR as FIRMWARE_PROMPT
from chipchain.agents.prompts.cross_layer import PROMPT_DESCRIPTOR as CROSS_PROMPT
from chipchain.domain.common import AnalysisStatus, WorkflowStage
from chipchain.domain.provenance import AgentRole, ModelDescriptor, ToolDescriptor
from chipchain.domain.run import AnalysisRun, FailureCategory, RunFailure, RunStageRecord, RunStatus
from chipchain.execution.provenance import RUNTIME_PACKAGES, capture_provenance
from chipchain.workflows.state import AnalysisStatus as WorkflowStatus

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_provenance_descriptors_dependency_snapshot_and_round_trip() -> None:
    provenance = capture_provenance(
        prompts=[HARDWARE_PROMPT, FIRMWARE_PROMPT, CROSS_PROMPT],
        models=[ModelDescriptor(agent_role=AgentRole.HARDWARE, model_identifier="synthetic-model", mode="fake")],
        tools=[ToolDescriptor(tool_name="synthetic-tool", tool_version="v1", tool_role="hardware", configuration_sha256="a" * 64)],
    )
    assert provenance.package_identifier == "chipchain" and provenance.package_version
    assert provenance.python_version and provenance.platform
    assert set(provenance.runtime_packages) == set(RUNTIME_PACKAGES)
    assert all(provenance.runtime_packages.values())
    assert len(provenance.models) == 3
    assert provenance.models[0].mode == "fake"
    assert provenance.models[1].mode == "unknown"
    assert {p.agent_role: p.prompt_version for p in provenance.prompts} == {
        AgentRole.HARDWARE: "v2", AgentRole.FIRMWARE: "v1", AgentRole.CROSS_LAYER: "v1",
    }
    assert provenance.tools[0].configuration_sha256 == "a" * 64
    assert "SYSTEM_PROMPT" not in provenance.model_dump_json()
    run = AnalysisRun(
        run_id=UUID(int=1), case_id="case", case_schema_version="1.0", started_at=NOW,
        finished_at=NOW, status=RunStatus.COMPLETED, provenance=provenance,
    )
    assert AnalysisRun.model_validate(run.model_dump(mode="json")) == run
    assert AnalysisRun.model_validate_json(run.model_dump_json()) == run
    assert WorkflowStatus is AnalysisStatus is RunStatus


def test_missing_runtime_package_does_not_block_provenance(monkeypatch: pytest.MonkeyPatch) -> None:
    from chipchain.execution import provenance as module
    original = module.metadata.version

    def version(name: str) -> str:
        if name == "langgraph-prebuilt":
            raise module.metadata.PackageNotFoundError(name)
        return original(name)

    monkeypatch.setattr(module.metadata, "version", version)
    provenance = capture_provenance()
    assert provenance.runtime_packages["langgraph-prebuilt"] is None
    assert provenance.runtime_packages["pydantic"]


def test_utc_normalization_and_naive_time_rejection() -> None:
    local = NOW.astimezone(timezone(timedelta(hours=8)))
    run = AnalysisRun(case_id="c", case_schema_version="1.0", started_at=local, provenance=capture_provenance())
    assert run.started_at == NOW and run.started_at.utcoffset() == timedelta(0)
    with pytest.raises(ValidationError):
        AnalysisRun(case_id="c", case_schema_version="1.0", started_at=NOW.replace(tzinfo=None), provenance=capture_provenance())
    with pytest.raises(ValidationError):
        RunStageRecord(stage=WorkflowStage.HARDWARE, status=AnalysisStatus.PENDING, started_at=NOW.replace(tzinfo=None))


def test_run_time_and_stage_failure_invariants() -> None:
    with pytest.raises(ValidationError, match="finish"):
        AnalysisRun(case_id="c", case_schema_version="1.0", started_at=NOW,
                    finished_at=NOW - timedelta(seconds=1), status=RunStatus.COMPLETED, provenance=capture_provenance())
    failure = RunFailure(category=FailureCategory.DETERMINISTIC_ANALYSIS, stage=WorkflowStage.HARDWARE,
                         public_message="Deterministic analysis failed.")
    stage = RunStageRecord(stage=WorkflowStage.HARDWARE, status=AnalysisStatus.FAILED,
                           started_at=NOW, finished_at=NOW, failure=failure)
    assert RunStageRecord.model_validate_json(stage.model_dump_json()) == stage
    with pytest.raises(ValidationError, match="match"):
        RunStageRecord(stage=WorkflowStage.FIRMWARE, status=AnalysisStatus.FAILED, failure=failure)
    with pytest.raises(ValidationError, match="requires"):
        RunStageRecord(stage=WorkflowStage.HARDWARE, status=AnalysisStatus.FAILED)


def test_descriptor_contracts_exclude_credentials() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        ModelDescriptor.model_validate({"agent_role": "hardware", "api_key": "synthetic-secret"})
    with pytest.raises(ValidationError, match="Extra inputs"):
        ToolDescriptor.model_validate({"tool_name": "synthetic", "tool_role": "hardware", "configuration": {"token": "synthetic"}})
