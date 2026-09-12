"""Hardware domain agent with optional injected LangChain model; no analyzer."""

from langchain_core.language_models import BaseChatModel

from chipchain.agents.contracts import HardwareAgentInput, HardwareAgentOutput
from chipchain.agents.context import hardware_context
from chipchain.agents.prompts.hardware import SYSTEM_PROMPT
from chipchain.agents.runtime import AgentStructuredOutputError, StructuredReportRuntime, validate_agent_output
from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.hardware import HardwareAnalysisReport


class HardwareSecurityAgent:
    _runtime: StructuredReportRuntime[HardwareAnalysisReport] | None = None

    def __init__(self, *, model: BaseChatModel | None = None,
                 structured_output_method: str | None = None) -> None:
        self._runtime = (
            StructuredReportRuntime(model, HardwareAnalysisReport, SYSTEM_PROMPT,
                                    structured_output_method=structured_output_method)
            if model is not None else None
        )

    @property
    def last_usage(self) -> dict[str, int]:
        return dict(self._runtime.last_usage) if self._runtime is not None else {}

    @property
    def last_response_metadata(self) -> dict[str, str]:
        return dict(self._runtime.last_response_metadata) if self._runtime is not None else {}

    def invoke(self, inputs: HardwareAgentInput) -> HardwareAgentOutput:
        observations = inputs.deterministic_observations
        ir = ProcessorBehaviorIR(
            case_id=inputs.case.case_id,
            behaviors=[b for item in observations.observations for b in item.behaviors],
        )
        if self._runtime is not None:
            report = self._runtime.invoke(hardware_context(inputs))
            validate_hardware_evidence(report, inputs)
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


def validate_hardware_evidence(report: HardwareAnalysisReport, inputs: HardwareAgentInput) -> None:
    """Reject invented/rewritten evidence; this does not prove prose entailment."""
    evidence = {}
    for observation in inputs.deterministic_observations.observations:
        refs = [*observation.evidence, *(e for b in observation.behaviors for e in b.evidence)]
        for behavior in observation.behaviors:
            if behavior.decoded_instruction is not None:
                refs.extend(behavior.decoded_instruction.evidence)
        for ref in refs:
            if ref.evidence_id in evidence and evidence[ref.evidence_id] != ref:
                raise AgentStructuredOutputError("Input contains conflicting evidence identities")
            evidence[ref.evidence_id] = ref
    findings = {finding.finding_id for finding in report.findings}
    for item in [*report.findings, *report.trigger_hypotheses, *report.abnormal_states]:
        if any(evidence.get(ref.evidence_id) != ref for ref in item.evidence):
            raise AgentStructuredOutputError("Model response contains unknown or altered evidence references")
        if not set(getattr(item, "hardware_finding_ids", [])).issubset(findings):
            raise AgentStructuredOutputError("Model response contains unknown finding references")
