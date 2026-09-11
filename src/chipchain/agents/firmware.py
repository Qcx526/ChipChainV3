"""Firmware domain agent; never modifies firmware to construct paths."""

from langchain_core.language_models import BaseChatModel

from chipchain.agents.contracts import FirmwareAgentInput, FirmwareAgentOutput
from chipchain.agents.context import firmware_context
from chipchain.agents.prompts.firmware import SYSTEM_PROMPT
from chipchain.agents.runtime import StructuredReportRuntime, validate_agent_output
from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.firmware import FirmwareAnalysisReport


class FirmwareSecurityAgent:
    _runtime: StructuredReportRuntime[FirmwareAnalysisReport] | None = None

    def __init__(self, *, model: BaseChatModel | None = None) -> None:
        self._runtime = (
            StructuredReportRuntime(model, FirmwareAnalysisReport, SYSTEM_PROMPT)
            if model is not None else None
        )

    def invoke(self, inputs: FirmwareAgentInput) -> FirmwareAgentOutput:
        observations = inputs.deterministic_observations
        ir = ProcessorBehaviorIR(
            case_id=inputs.case.case_id,
            behaviors=[b for item in observations.observations for b in item.behaviors],
        )
        if self._runtime is not None:
            report = self._runtime.invoke(firmware_context(inputs))
            return validate_agent_output(
                FirmwareAgentOutput, report=report, processor_behavior_ir=ir,
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
