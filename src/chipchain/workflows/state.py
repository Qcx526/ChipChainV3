"""Explicit lifecycle status distinguishes absence, failure and blocked analysis."""

from pydantic import Field

from chipchain.agents.contracts import CrossLayerAgentInput
from chipchain.domain.behavior import ProcessorBehavior, ProcessorBehaviorIR
from chipchain.domain.case import CaseBundle
from chipchain.domain.common import AnalysisStatus, Contract, Identifier, WorkflowStage
from chipchain.domain.cross_layer import CrossLayerAnalysisReport
from chipchain.domain.firmware import FirmwareAnalysisReport
from chipchain.domain.hardware import HardwareAnalysisReport
from chipchain.tools.contracts import FirmwareObservations, HardwareObservations


class WorkflowError(Contract):
    stage: WorkflowStage
    error_type: Identifier
    message: str


class CaseWorkflowState(Contract):
    case: CaseBundle
    hardware_report: HardwareAnalysisReport | None = None
    firmware_report: FirmwareAnalysisReport | None = None
    processor_behavior_ir: ProcessorBehaviorIR | None = None
    cross_layer_report: CrossLayerAnalysisReport | None = None
    hardware_status: AnalysisStatus = Field(default_factory=lambda data: (
        AnalysisStatus.PENDING if data["case"].has_hardware_inputs
        else AnalysisStatus.NOT_APPLICABLE
    ))
    firmware_status: AnalysisStatus = Field(default_factory=lambda data: (
        AnalysisStatus.PENDING if data["case"].has_firmware_inputs
        else AnalysisStatus.NOT_APPLICABLE
    ))
    cross_layer_status: AnalysisStatus = Field(default_factory=lambda data: (
        AnalysisStatus.PENDING if data["case"].is_paired else AnalysisStatus.NOT_APPLICABLE
    ))
    errors: list[WorkflowError] = Field(default_factory=list)
    hardware_observations: HardwareObservations | None = None
    firmware_observations: FirmwareObservations | None = None
    hardware_behaviors: list[ProcessorBehavior] = Field(default_factory=list)
    firmware_behaviors: list[ProcessorBehavior] = Field(default_factory=list)


def cross_layer_input(state: CaseWorkflowState) -> CrossLayerAgentInput:
    """Check routing eligibility shared by case and standalone workflows.

    Structural consistency permits execution, including empty reports/IR. It does
    not establish evidence sufficiency, reachability, triggers or attack chains.
    """
    if (state.hardware_status != AnalysisStatus.COMPLETED
            or state.firmware_status != AnalysisStatus.COMPLETED):
        raise ValueError("Cross-layer workflow requires both analyses to be completed")
    if state.hardware_report is None or state.firmware_report is None:
        raise ValueError("Cross-layer workflow requires both analysis reports")
    if state.processor_behavior_ir is None:
        raise ValueError("Cross-layer workflow requires an aggregated processor behavior IR")
    return CrossLayerAgentInput(
        case=state.case,
        hardware_report=state.hardware_report,
        firmware_report=state.firmware_report,
        processor_behavior_ir=state.processor_behavior_ir,
    )


def workflow_error(stage: WorkflowStage, error: Exception) -> WorkflowError:
    return WorkflowError(stage=stage, error_type=type(error).__name__, message=str(error))
