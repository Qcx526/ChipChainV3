"""Case-first routing composed from independently compiled LangGraph workflows."""

from collections.abc import Callable

from chipchain.domain.case import CaseBundle
from chipchain.tools.contracts import HardwareObservations, FirmwareObservations

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from chipchain.agents.cross_layer import CrossLayerSecurityAgent
from chipchain.agents.firmware import FirmwareSecurityAgent
from chipchain.agents.hardware import HardwareSecurityAgent
from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.workflows.cross_layer import build_cross_layer_workflow
from chipchain.workflows.firmware import build_firmware_workflow
from chipchain.workflows.hardware import build_hardware_workflow
from chipchain.workflows.state import (
    AnalysisStatus, CaseWorkflowState, WorkflowStage, cross_layer_input, workflow_error,
)


def build_case_workflow(
    *,
    hardware_agent: HardwareSecurityAgent | None = None,
    firmware_agent: FirmwareSecurityAgent | None = None,
    cross_layer_agent: CrossLayerSecurityAgent | None = None,
    hardware_observer: Callable[[CaseBundle], HardwareObservations] | None = None,
    firmware_observer: Callable[[CaseBundle], FirmwareObservations] | None = None,
) -> CompiledStateGraph:
    hardware = build_hardware_workflow(hardware_agent, observer=hardware_observer)
    firmware = build_firmware_workflow(firmware_agent, observer=firmware_observer)
    cross_layer = build_cross_layer_workflow(cross_layer_agent)

    def initialize(state: CaseWorkflowState) -> dict[str, object]:
        # Each invocation is a fresh run; caller-supplied reports cannot bypass routing.
        fresh = CaseWorkflowState(
            case=state.case,
            hardware_status=(AnalysisStatus.PENDING if state.case.has_hardware_inputs
                             else AnalysisStatus.NOT_APPLICABLE),
            firmware_status=(AnalysisStatus.PENDING if state.case.has_firmware_inputs
                             else AnalysisStatus.NOT_APPLICABLE),
            cross_layer_status=(AnalysisStatus.PENDING if state.case.is_paired
                                else AnalysisStatus.NOT_APPLICABLE),
        )
        return {name: getattr(fresh, name) for name in CaseWorkflowState.model_fields}

    def run_hardware(state: CaseWorkflowState) -> dict[str, object]:
        result = CaseWorkflowState.model_validate(hardware.invoke({"case": state.case}))
        return {
            "hardware_report": result.hardware_report,
            "hardware_behaviors": result.hardware_behaviors,
            "hardware_observations": result.hardware_observations,
            "hardware_status": result.hardware_status,
            "errors": [*state.errors, *result.errors],
        }

    def run_firmware(state: CaseWorkflowState) -> dict[str, object]:
        result = CaseWorkflowState.model_validate(firmware.invoke({"case": state.case}))
        return {
            "firmware_report": result.firmware_report,
            "firmware_behaviors": result.firmware_behaviors,
            "firmware_observations": result.firmware_observations,
            "firmware_status": result.firmware_status,
            "errors": [*state.errors, *result.errors],
        }

    def aggregate(state: CaseWorkflowState) -> dict[str, object]:
        try:
            return {"processor_behavior_ir": ProcessorBehaviorIR(
                case_id=state.case.case_id,
                behaviors=[*state.hardware_behaviors, *state.firmware_behaviors],
            )}
        except ValueError as error:
            return {"processor_behavior_ir": None, "errors": [
                *state.errors, workflow_error(WorkflowStage.IR_AGGREGATION, error),
            ]}

    def eligibility(state: CaseWorkflowState) -> dict[str, object]:
        if not state.case.is_paired:
            return {"cross_layer_status": AnalysisStatus.NOT_APPLICABLE}
        try:
            cross_layer_input(state)
            return {"cross_layer_status": AnalysisStatus.PENDING}
        except ValueError as error:
            return {"cross_layer_status": AnalysisStatus.BLOCKED, "errors": [
                *state.errors, workflow_error(WorkflowStage.CROSS_LAYER, error),
            ]}

    def run_cross_layer(state: CaseWorkflowState) -> dict[str, object]:
        result = CaseWorkflowState.model_validate(cross_layer.invoke(state))
        return {"cross_layer_report": result.cross_layer_report,
                "cross_layer_status": result.cross_layer_status, "errors": result.errors}

    def first_route(state: CaseWorkflowState) -> str:
        return "hardware" if state.case.has_hardware_inputs else "firmware"

    def after_hardware(state: CaseWorkflowState) -> str:
        return "firmware" if state.case.has_firmware_inputs else "aggregate_ir"

    def after_eligibility(state: CaseWorkflowState) -> str:
        return "cross_layer" if state.cross_layer_status == AnalysisStatus.PENDING else END

    graph = StateGraph(CaseWorkflowState)
    graph.add_node("initialize", initialize)
    graph.add_node("hardware", run_hardware)
    graph.add_node("firmware", run_firmware)
    graph.add_node("aggregate_ir", aggregate)
    graph.add_node("eligibility", eligibility)
    graph.add_node("cross_layer", run_cross_layer)
    graph.add_edge(START, "initialize")
    graph.add_conditional_edges("initialize", first_route, ["hardware", "firmware"])
    graph.add_conditional_edges("hardware", after_hardware, ["firmware", "aggregate_ir"])
    graph.add_edge("firmware", "aggregate_ir")
    graph.add_edge("aggregate_ir", "eligibility")
    graph.add_conditional_edges("eligibility", after_eligibility, ["cross_layer", END])
    graph.add_edge("cross_layer", END)
    return graph.compile()
