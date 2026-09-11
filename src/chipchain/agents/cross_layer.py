"""Cross-layer stub deliberately produces no invented candidates."""

from chipchain.agents.contracts import CrossLayerAgentInput, CrossLayerAgentOutput
from chipchain.domain.cross_layer import CrossLayerAnalysisReport, MissingConstraint


class CrossLayerSecurityAgent:
    def invoke(self, inputs: CrossLayerAgentInput) -> CrossLayerAgentOutput:
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
