"""Offline lifecycle stub; never modifies firmware to construct paths."""

from chipchain.agents.contracts import FirmwareAgentInput, FirmwareAgentOutput
from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.firmware import FirmwareAnalysisReport


class FirmwareSecurityAgent:
    def invoke(self, inputs: FirmwareAgentInput) -> FirmwareAgentOutput:
        observations = inputs.deterministic_observations
        ir = ProcessorBehaviorIR(
            case_id=inputs.case.case_id,
            behaviors=[b for item in observations.observations for b in item.behaviors],
        )
        return FirmwareAgentOutput(
            report=FirmwareAnalysisReport(
                case_id=inputs.case.case_id,
                processor_behavior_ids=[b.behavior_id for b in ir.behaviors],
                unresolved_questions=[
                    *observations.unresolved_questions,
                    "R0 stub: firmware security reasoning and reachability analysis are not implemented.",
                ],
            ),
            processor_behavior_ir=ir,
        )
