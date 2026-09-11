"""Two-node hardware lifecycle: empty observation stub -> independent agent."""

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from chipchain.agents.contracts import HardwareAgentInput, HardwareAgentOutput
from chipchain.agents.hardware import HardwareSecurityAgent
from chipchain.tools.contracts import HardwareObservations
from chipchain.workflows.state import (
    AnalysisStatus, CaseWorkflowState, WorkflowStage, workflow_error,
)


def build_hardware_workflow(
    agent: HardwareSecurityAgent | None = None,
) -> CompiledStateGraph:
    security_agent = agent if agent is not None else HardwareSecurityAgent()

    def observe(state: CaseWorkflowState) -> dict[str, object]:
        if not state.case.has_hardware_inputs:
            raise ValueError("Hardware workflow requires hardware artifacts")
        return {"hardware_observations": HardwareObservations(
            case_id=state.case.case_id,
            unresolved_questions=["R0 observation stub: no hardware artifacts were analyzed."],
        )}

    def analyze(state: CaseWorkflowState) -> dict[str, object]:
        try:
            if state.hardware_observations is None:
                raise ValueError("Hardware observations are missing")
            output = HardwareAgentOutput.model_validate(security_agent.invoke(HardwareAgentInput(
                case=state.case, deterministic_observations=state.hardware_observations,
            )))
            if output.report.case_id != state.case.case_id:
                raise ValueError("Hardware agent returned a report for a different case")
            return {
                "hardware_report": output.report,
                "hardware_behaviors": output.processor_behavior_ir.behaviors,
                "processor_behavior_ir": output.processor_behavior_ir,
                "hardware_status": AnalysisStatus.COMPLETED,
            }
        except Exception as error:
            return {
                "hardware_report": None, "hardware_behaviors": [],
                "processor_behavior_ir": None, "hardware_status": AnalysisStatus.FAILED,
                "errors": [*state.errors, workflow_error(WorkflowStage.HARDWARE, error)],
            }

    graph = StateGraph(CaseWorkflowState)
    graph.add_node("observe_hardware", observe)
    graph.add_node("analyze_hardware", analyze)
    graph.add_edge(START, "observe_hardware")
    graph.add_edge("observe_hardware", "analyze_hardware")
    graph.add_edge("analyze_hardware", END)
    return graph.compile()
