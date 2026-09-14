"""Firmware domain agent; never modifies firmware to construct paths."""

from langchain_core.language_models import BaseChatModel

from chipchain.agents.contracts import FirmwareAgentInput, FirmwareAgentOutput
from chipchain.agents.context import firmware_context
from chipchain.agents.firmware_evidence import collect_firmware_evidence
from chipchain.agents.model_outputs.firmware import (
    ModelFirmwareAnalysisReport, hydrate_firmware_report, validate_firmware_report_references,
)
from chipchain.agents.prompts.firmware import SYSTEM_PROMPT
from chipchain.agents.runtime import AgentStructuredOutputError, StructuredReportRuntime, validate_agent_output
from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.firmware import FirmwareAnalysisReport


class FirmwareSecurityAgent:
    _runtime: StructuredReportRuntime[ModelFirmwareAnalysisReport] | None = None

    def __init__(self, *, model: BaseChatModel | None = None,
                 structured_output_method: str | None = None) -> None:
        self._runtime = (
            StructuredReportRuntime(model, ModelFirmwareAnalysisReport, SYSTEM_PROMPT,
                                    structured_output_method=structured_output_method)
            if model is not None else None
        )

    @property
    def last_usage(self) -> dict[str, int]:
        return dict(self._runtime.last_usage) if self._runtime is not None else {}

    @property
    def last_response_metadata(self) -> dict[str, str]:
        return dict(self._runtime.last_response_metadata) if self._runtime is not None else {}

    def invoke(self, inputs: FirmwareAgentInput) -> FirmwareAgentOutput:
        collect_firmware_evidence(inputs)  # Reject conflicting/undeclared input evidence before any invocation.
        observations = inputs.deterministic_observations
        ir = ProcessorBehaviorIR(
            case_id=inputs.case.case_id,
            behaviors=[b for item in observations.observations for b in item.behaviors],
        )
        if self._runtime is not None:
            model_report = self._runtime.invoke(firmware_context(inputs))
            report = hydrate_firmware_report(model_report, inputs)
            validate_firmware_evidence(report, inputs)
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


def validate_firmware_evidence(report: FirmwareAnalysisReport, inputs: FirmwareAgentInput) -> None:
    """Exact evidence/finding grounding, not proof that report prose is entailed."""
    validate_firmware_report_references(report)
    evidence = collect_firmware_evidence(inputs)
    for item in [*report.findings, *report.external_input_paths, *report.reachable_behaviors, *report.issue_anchors]:
        if any(evidence.get(ref.evidence_id) != ref for ref in item.evidence):
            raise AgentStructuredOutputError("Model response contains unknown or altered firmware evidence references")
