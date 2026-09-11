"""Offline lifecycle stub, not a hardware vulnerability analyzer."""

from chipchain.agents.contracts import HardwareAgentInput, HardwareAgentOutput
from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.hardware import HardwareAnalysisReport


class HardwareSecurityAgent:
    def invoke(self, inputs: HardwareAgentInput) -> HardwareAgentOutput:
        observations = inputs.deterministic_observations
        ir = ProcessorBehaviorIR(
            case_id=inputs.case.case_id,
            behaviors=[b for item in observations.observations for b in item.behaviors],
        )
        return HardwareAgentOutput(
            report=HardwareAnalysisReport(
                case_id=inputs.case.case_id,
                processor_behavior_ids=[b.behavior_id for b in ir.behaviors],
                unresolved_questions=[
                    *observations.unresolved_questions,
                    "R0 stub: hardware security reasoning and trigger analysis are not implemented.",
                ],
            ),
            processor_behavior_ir=ir,
        )
