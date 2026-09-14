"""Firmware domain agent; never modifies firmware to construct paths."""

from langchain_core.language_models import BaseChatModel

from chipchain.agents.contracts import FirmwareAgentInput, FirmwareAgentOutput
from chipchain.agents.context import firmware_context
from chipchain.agents.firmware_evidence import collect_firmware_reasoning_evidence
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
        self._model = model
        self._structured_output_method = structured_output_method
        self._supported_runtime = None
        self._active_runtime = self._runtime

    @property
    def last_usage(self) -> dict[str, int]:
        return dict(self._active_runtime.last_usage) if self._active_runtime is not None else {}

    @property
    def last_response_metadata(self) -> dict[str, str]:
        return dict(self._active_runtime.last_response_metadata) if self._active_runtime is not None else {}

    @property
    def last_parse_stage(self) -> str | None:
        return self._active_runtime.last_parse_stage if self._active_runtime is not None else None

    def invoke(self, inputs: FirmwareAgentInput, *, relevant_static_structure=None, static_source=None) -> FirmwareAgentOutput:
        self._active_runtime = self._runtime
        collect_firmware_reasoning_evidence(inputs, relevant_static_structure)  # Reject conflicting/undeclared input evidence before any invocation.
        context = None
        if relevant_static_structure is not None:
            from chipchain.agents.projections.firmware_envelope import firmware_enriched_context
            context = firmware_enriched_context(inputs, relevant_static_structure, static_source=static_source)
        observations = inputs.deterministic_observations
        ir = ProcessorBehaviorIR(
            case_id=inputs.case.case_id,
            behaviors=[b for item in observations.observations for b in item.behaviors],
        )
        if self._runtime is not None:
            model_report = self._runtime.invoke(context if context is not None else firmware_context(inputs))
            report = hydrate_firmware_report(model_report, inputs, relevant_static_structure=relevant_static_structure)
            validate_firmware_evidence(report, inputs, relevant_static_structure=relevant_static_structure)
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

    def invoke_supported(self, inputs: FirmwareAgentInput, *, static_relation_catalog,
                         relation_projection, relevant_static_structure):
        """Explicit B3 path; deterministic preparation and ELF IO belong to caller."""
        from chipchain.agents.model_outputs.firmware_v2 import ModelFirmwareAnalysisReportV2
        from chipchain.agents.prompts.firmware_v2 import SYSTEM_PROMPT as SUPPORTED_PROMPT
        from chipchain.agents.projections.firmware_envelope_v3 import (
            build_firmware_envelope_v3, serialize_firmware_envelope_v3, envelope_v3_components,
        )
        from chipchain.agents.relation_support import validate_relation_support, strip_support_fields
        from chipchain.tools.firmware.structure_projection import relevant_structure_sha256
        registry = collect_firmware_reasoning_evidence(inputs,relevant_static_structure)
        if relevant_structure_sha256(relevant_static_structure) != static_relation_catalog.source_identities.a3_sha256:
            raise ValueError('B3 A3/A4 identity mismatch')
        envelope = build_firmware_envelope_v3(inputs,relation_projection,static_relation_catalog=static_relation_catalog)
        if envelope_v3_components(envelope)[2] != registry:
            raise ValueError('B3 exact reasoning registry mismatch')
        context = serialize_firmware_envelope_v3(envelope)
        if self._model is None:
            raise ValueError('B3 supported invocation requires explicit model')
        if self._supported_runtime is None:
            self._supported_runtime = StructuredReportRuntime(self._model,ModelFirmwareAnalysisReportV2,SUPPORTED_PROMPT,
                structured_output_method=self._structured_output_method)
        self._active_runtime = self._supported_runtime
        model_report = self._supported_runtime.invoke(context)
        support = validate_relation_support(model_report,static_relation_catalog)
        report = hydrate_firmware_report(strip_support_fields(model_report),inputs,
            relevant_static_structure=relevant_static_structure)
        validate_firmware_evidence(report,inputs,relevant_static_structure=relevant_static_structure)
        ir = ProcessorBehaviorIR(case_id=inputs.case.case_id,
            behaviors=[b for o in inputs.deterministic_observations.observations for b in o.behaviors])
        return validate_agent_output(FirmwareAgentOutput,report=report,processor_behavior_ir=ir),support


def validate_firmware_evidence(report: FirmwareAnalysisReport, inputs: FirmwareAgentInput, *, relevant_static_structure=None) -> None:
    """Exact evidence/finding grounding, not proof that report prose is entailed."""
    validate_firmware_report_references(report)
    evidence = collect_firmware_reasoning_evidence(inputs, relevant_static_structure)
    for item in [*report.findings, *report.external_input_paths, *report.reachable_behaviors, *report.issue_anchors]:
        if any(evidence.get(ref.evidence_id) != ref for ref in item.evidence):
            raise AgentStructuredOutputError("Model response contains unknown or altered firmware evidence references")
