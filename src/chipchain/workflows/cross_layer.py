"""R0 eligibility permits workflow routing, not analytical confirmation.

It establishes neither sufficient vulnerability evidence, verified reachability,
hardware trigger satisfaction nor attack-chain confirmation.
"""

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from chipchain.agents.contracts import CrossLayerAgentOutput
from chipchain.agents.cross_layer import CrossLayerSecurityAgent
from chipchain.workflows.state import (
    AnalysisStatus, CaseWorkflowState, WorkflowStage, cross_layer_input, workflow_error,
)


def build_cross_layer_workflow(
    agent: CrossLayerSecurityAgent | None = None,
) -> CompiledStateGraph:
    security_agent = agent if agent is not None else CrossLayerSecurityAgent()

    def validate(state: CaseWorkflowState) -> dict[str, object]:
        cross_layer_input(state)
        return {"cross_layer_status": AnalysisStatus.PENDING, "cross_layer_report": None}

    def analyze(state: CaseWorkflowState) -> dict[str, object]:
        try:
            output = CrossLayerAgentOutput.model_validate(
                security_agent.invoke(cross_layer_input(state))
            )
            if output.report.case_id != state.case.case_id:
                raise ValueError("Cross-layer agent returned a report for a different case")
            return {"cross_layer_report": output.report,
                    "cross_layer_status": AnalysisStatus.COMPLETED}
        except Exception as error:
            return {
                "cross_layer_report": None, "cross_layer_status": AnalysisStatus.FAILED,
                "errors": [*state.errors, workflow_error(WorkflowStage.CROSS_LAYER, error)],
            }

    graph = StateGraph(CaseWorkflowState)
    graph.add_node("validate_eligibility", validate)
    graph.add_node("analyze_cross_layer", analyze)
    graph.add_edge(START, "validate_eligibility")
    graph.add_edge("validate_eligibility", "analyze_cross_layer")
    graph.add_edge("analyze_cross_layer", END)
    return graph.compile()
