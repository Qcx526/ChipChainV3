"""Two-node firmware lifecycle; artifact paths are never opened."""

from collections.abc import Callable

from chipchain.domain.case import CaseBundle

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from chipchain.agents.contracts import FirmwareAgentInput, FirmwareAgentOutput
from chipchain.agents.firmware import FirmwareSecurityAgent
from chipchain.tools.contracts import FirmwareObservations
from chipchain.workflows.state import (
    AnalysisStatus, CaseWorkflowState, WorkflowStage, workflow_error,
)


def build_firmware_workflow(
    agent: FirmwareSecurityAgent | None = None,
    *, observer: Callable[[CaseBundle], FirmwareObservations] | None = None,
) -> CompiledStateGraph:
    security_agent = agent if agent is not None else FirmwareSecurityAgent()

    def observe(state: CaseWorkflowState) -> dict[str, object]:
        if not state.case.has_firmware_inputs:
            raise ValueError("Firmware workflow requires firmware artifacts")
        if observer is not None:
            try:
                observations = FirmwareObservations.model_validate(observer(state.case).model_dump())
                FirmwareAgentInput(case=state.case, deterministic_observations=observations)
                return {"firmware_observations": observations}
            except Exception:
                return {"firmware_observations": None, "firmware_status": AnalysisStatus.FAILED,
                        "errors": [*state.errors, workflow_error(WorkflowStage.FIRMWARE,
                            ValueError("Deterministic firmware observation failed"))]}
        return {"firmware_observations": FirmwareObservations(
            case_id=state.case.case_id,
            unresolved_questions=["R0 observation stub: no firmware artifacts were analyzed."],
        )}

    def analyze(state: CaseWorkflowState) -> dict[str, object]:
        if state.firmware_status == AnalysisStatus.FAILED:
            return {}
        try:
            if state.firmware_observations is None:
                raise ValueError("Firmware observations are missing")
            output = FirmwareAgentOutput.model_validate(security_agent.invoke(FirmwareAgentInput(
                case=state.case, deterministic_observations=state.firmware_observations,
            )))
            if output.report.case_id != state.case.case_id:
                raise ValueError("Firmware agent returned a report for a different case")
            return {
                "firmware_report": output.report,
                "firmware_behaviors": output.processor_behavior_ir.behaviors,
                "processor_behavior_ir": output.processor_behavior_ir,
                "firmware_status": AnalysisStatus.COMPLETED,
            }
        except Exception as error:
            return {
                "firmware_report": None, "firmware_behaviors": [],
                "processor_behavior_ir": None, "firmware_status": AnalysisStatus.FAILED,
                "errors": [*state.errors, workflow_error(WorkflowStage.FIRMWARE, error)],
            }

    graph = StateGraph(CaseWorkflowState)
    graph.add_node("observe_firmware", observe)
    graph.add_node("analyze_firmware", analyze)
    graph.add_edge(START, "observe_firmware")
    graph.add_edge("observe_firmware", "analyze_firmware")
    graph.add_edge("analyze_firmware", END)
    return graph.compile()
