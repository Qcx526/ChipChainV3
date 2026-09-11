"""Hardware domain agent with optional injected LangChain model; no analyzer."""

from langchain_core.language_models import BaseChatModel

from chipchain.agents.contracts import HardwareAgentInput, HardwareAgentOutput
from chipchain.agents.context import hardware_context
from chipchain.agents.prompts.hardware import SYSTEM_PROMPT
from chipchain.agents.runtime import StructuredReportRuntime, validate_agent_output
from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.hardware import HardwareAnalysisReport


class HardwareSecurityAgent:
    _runtime: StructuredReportRuntime[HardwareAnalysisReport] | None = None

    def __init__(self, *, model: BaseChatModel | None = None) -> None:
        self._runtime = (
            StructuredReportRuntime(model, HardwareAnalysisReport, SYSTEM_PROMPT)
            if model is not None else None
        )

    def invoke(self, inputs: HardwareAgentInput) -> HardwareAgentOutput:
        observations = inputs.deterministic_observations
        ir = ProcessorBehaviorIR(
            case_id=inputs.case.case_id,
            behaviors=[b for item in observations.observations for b in item.behaviors],
        )
        if self._runtime is not None:
            report = self._runtime.invoke(hardware_context(inputs))
            return validate_agent_output(
                HardwareAgentOutput, report=report, processor_behavior_ir=ir,
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
