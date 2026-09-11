"""Durable execution records, separate from samples and transient workflow state."""

from datetime import timezone
from enum import StrEnum
from typing import Annotated, Self, TypeAlias
from uuid import UUID, uuid4

from pydantic import AfterValidator, AwareDatetime, Field, model_validator

from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.common import AnalysisStatus, Contract, FileSize, Identifier, Sha256, WorkflowStage
from chipchain.domain.cross_layer import CrossLayerAnalysisReport
from chipchain.domain.firmware import FirmwareAnalysisReport
from chipchain.domain.hardware import HardwareAnalysisReport
from chipchain.domain.provenance import RunProvenance

UTCDateTime: TypeAlias = Annotated[AwareDatetime, AfterValidator(lambda value: value.astimezone(timezone.utc))]
RunStatus = AnalysisStatus


class FailureCategory(StrEnum):
    INPUT_VALIDATION = "input_validation"
    DETERMINISTIC_ANALYSIS = "deterministic_analysis"
    AGENT_EXECUTION = "agent_execution"
    STRUCTURED_OUTPUT = "structured_output"
    WORKFLOW_INTERNAL = "workflow_internal"


class RunFailure(Contract):
    category: FailureCategory
    stage: WorkflowStage | None = None
    public_message: Identifier
    exception_type: Identifier | None = None


class RunStageRecord(Contract):
    stage: WorkflowStage
    status: AnalysisStatus
    started_at: UTCDateTime | None = None
    finished_at: UTCDateTime | None = None
    failure: RunFailure | None = None

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        if self.finished_at is not None and (
            self.started_at is None or self.finished_at < self.started_at
        ):
            raise ValueError("Stage finish must follow its start")
        if self.failure is not None and (
            self.failure.stage != self.stage
            or self.status not in (AnalysisStatus.FAILED, AnalysisStatus.BLOCKED)
        ):
            raise ValueError("Stage failure must match its stage and failed/blocked status")
        if self.status == AnalysisStatus.FAILED and self.failure is None:
            raise ValueError("Failed stage requires a failure record")
        return self


class ArtifactIdentity(Contract):
    artifact_id: Identifier
    sha256: Sha256 | None = None
    size_bytes: FileSize | None = None


class AnalysisRun(Contract):
    run_id: UUID = Field(default_factory=uuid4)
    case_id: Identifier
    case_schema_version: Identifier
    started_at: UTCDateTime
    finished_at: UTCDateTime | None = None
    status: RunStatus = RunStatus.PENDING
    stages: list[RunStageRecord] = Field(default_factory=list)
    failures: list[RunFailure] = Field(default_factory=list)
    provenance: RunProvenance
    artifacts: list[ArtifactIdentity] = Field(default_factory=list)
    hardware_report: HardwareAnalysisReport | None = None
    firmware_report: FirmwareAnalysisReport | None = None
    processor_behavior_ir: ProcessorBehaviorIR | None = None
    cross_layer_report: CrossLayerAnalysisReport | None = None

    @model_validator(mode="after")
    def validate_run(self) -> Self:
        if self.finished_at is not None and self.finished_at < self.started_at:
            raise ValueError("Run finish must follow its start")
        if self.status != RunStatus.PENDING and self.finished_at is None:
            raise ValueError("A terminal run requires finished_at")
        if self.status == RunStatus.PENDING and self.finished_at is not None:
            raise ValueError("A pending run cannot have finished_at")
        if self.status == RunStatus.FAILED and not self.failures:
            raise ValueError("A failed run requires a failure record")
        stages = [item.stage for item in self.stages]
        if len(stages) != len(set(stages)):
            raise ValueError("Run stages must be unique")
        ids = [item.artifact_id for item in self.artifacts]
        if len(ids) != len(set(ids)):
            raise ValueError("Run artifact identities must be unique")
        if self.status == RunStatus.COMPLETED and (
            self.failures or any(item.status not in (AnalysisStatus.COMPLETED, AnalysisStatus.NOT_APPLICABLE)
                                 for item in self.stages)
        ):
            raise ValueError("Completed run cannot contain incomplete or failed stages")
        for report in (self.hardware_report, self.firmware_report,
                       self.processor_behavior_ir, self.cross_layer_report):
            if report is not None and report.case_id != self.case_id:
                raise ValueError("Run results must belong to the run case_id")
        for item in self.stages:
            result = {
                WorkflowStage.HARDWARE: self.hardware_report,
                WorkflowStage.FIRMWARE: self.firmware_report,
                WorkflowStage.IR_AGGREGATION: self.processor_behavior_ir,
                WorkflowStage.CROSS_LAYER: self.cross_layer_report,
            }[item.stage]
            if item.status == AnalysisStatus.COMPLETED and result is None:
                raise ValueError("Completed stage requires its result")
            if item.status in (AnalysisStatus.FAILED, AnalysisStatus.BLOCKED, AnalysisStatus.NOT_APPLICABLE) and result is not None:
                raise ValueError("Failed, blocked or inapplicable stage cannot have a successful result")
            for time in (item.started_at, item.finished_at):
                if time is not None and (time < self.started_at or (
                    self.finished_at is not None and time > self.finished_at
                )):
                    raise ValueError("Stage timestamps must lie within run timestamps")
        return self
