"""Cross-layer domain agent with optional model; default stub invents no candidates."""

from langchain_core.language_models import BaseChatModel

from chipchain.agents.contracts import CrossLayerAgentInput, CrossLayerAgentOutput
from chipchain.agents.context import cross_layer_context
from chipchain.agents.prompts.cross_layer import SYSTEM_PROMPT
from chipchain.agents.runtime import (
    AgentStructuredOutputError, StructuredReportRuntime, validate_agent_output,
)
from chipchain.domain.cross_layer import CrossLayerAnalysisReport, MissingConstraint


class CrossLayerSecurityAgent:
    _runtime: StructuredReportRuntime[CrossLayerAnalysisReport] | None = None

    def __init__(self, *, model: BaseChatModel | None = None) -> None:
        self._runtime = (
            StructuredReportRuntime(model, CrossLayerAnalysisReport, SYSTEM_PROMPT)
            if model is not None else None
        )

    def invoke(self, inputs: CrossLayerAgentInput) -> CrossLayerAgentOutput:
        if self._runtime is not None:
            report = self._runtime.invoke(cross_layer_context(inputs))
            if report.case_id != inputs.case.case_id:
                exc = ValueError("Report case_id differs from input case_id")
                raise AgentStructuredOutputError("Model response belongs to a different case") from exc
            return validate_agent_output(CrossLayerAgentOutput, report=report)
        return CrossLayerAgentOutput(
            report=CrossLayerAnalysisReport(
                case_id=inputs.case.case_id,
                missing_constraints=[MissingConstraint(
                    constraint_id=f"{inputs.case.case_id}:missing:cross-layer-analysis",
                    description="R0 has no cross-layer causal or trigger analysis.",
                    required_evidence=[
                        "Hardware trigger conditions",
                        "Existing firmware behavior and reachability evidence",
                        "Validated firmware/hardware interaction evidence",
                    ],
                )],
                unresolved_questions=[
                    "R0 stub: eligibility permits orchestration only; no vulnerability is established.",
                    "Behavior graph and retrieved knowledge context are not analyzed in R0.",
                ],
            )
        )
