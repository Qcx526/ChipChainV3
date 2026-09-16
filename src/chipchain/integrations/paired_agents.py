"""Pilot-only ID binding for legacy hardware/cross-layer report shapes.

Canonical domain schemas and existing supported agents remain unchanged. All
transport fields are required, including empty lists, to reject incomplete output.
"""

from copy import deepcopy

from pydantic import Field, create_model

from chipchain.agents.contracts import HardwareAgentOutput, CrossLayerAgentOutput
from chipchain.agents.context import hardware_context, cross_layer_context
from chipchain.agents.hardware import HardwareSecurityAgent, validate_hardware_evidence
from chipchain.agents.cross_layer import CrossLayerSecurityAgent
from chipchain.agents.runtime import StructuredReportRuntime, AgentStructuredOutputError, validate_agent_output
from chipchain.agents.prompts import hardware, cross_layer
from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.common import Contract, Identifier
from chipchain.domain.hardware import HardwareAnalysisReport, HardwareFinding, HardwareTriggerHypothesis, AbnormalState
from chipchain.domain.cross_layer import (CrossLayerAnalysisReport, CrossLayerCandidate, AttackChainCandidate,
                                        TriggerFeature, RootLocationCandidate)


def binding_schema(canonical, items):
    """Derive a transport schema from explicit canonical item types, not model data."""
    fields = {}
    for name, field in canonical.model_fields.items():
        annotation = field.annotation
        if name in items:
            annotation = list[binding_schema(items[name], {})]
        if name == 'evidence':
            fields['evidence_ids'] = (list[Identifier], Field(..., min_length=1))
        else:
            # Canonical validation remains authoritative after hydration.
            fields[name] = (annotation, Field(..., description=field.description))
    return create_model('Bound' + canonical.__name__, __base__=Contract, **fields)


HARDWARE_ITEMS = {'findings': HardwareFinding, 'trigger_hypotheses': HardwareTriggerHypothesis,
                  'abnormal_states': AbnormalState}
CROSS_ITEMS = {'candidates': CrossLayerCandidate, 'attack_chain_candidates': AttackChainCandidate,
               'trigger_features': TriggerFeature, 'root_location_candidates': RootLocationCandidate}
HardwareBinding = binding_schema(HardwareAnalysisReport, HARDWARE_ITEMS)
CrossLayerBinding = binding_schema(CrossLayerAnalysisReport, CROSS_ITEMS)
BINDING_PROMPT = '''
For this explicit paired baseline pilot, use the Bound report schema. All schema
fields must be present, using empty lists where no evidence supports an item.
Select evidence_ids only from the supplied evidence_id values. The program binds
these IDs to canonical EvidenceRefs; never emit evidence objects in this response.
Write all human-facing summaries, descriptions and unresolved questions in Chinese.
Keep IDs and technical identifiers unchanged. Baseline success is not proof of
security. Function names alone prove neither behavior nor external input paths.
Do not invent abnormality, exposure, exploitability or causality to fill a list.
'''
HW_PROMPT = hardware.SYSTEM_PROMPT.replace(
    'Copy each cited EvidenceRef exactly; do not rewrite',
    'Select the ID of each cited EvidenceRef; do not rewrite') + BINDING_PROMPT
CROSS_PROMPT = cross_layer.SYSTEM_PROMPT + BINDING_PROMPT


def hydrate(model_report, registry, canonical, groups):
    data = model_report.model_dump()
    for group in groups:
        for item in data[group]:
            ids = item.pop('evidence_ids')
            if len(ids) != len(set(ids)) or any(identifier not in registry for identifier in ids):
                raise AgentStructuredOutputError('Unknown or duplicate evidence ID')
            item['evidence'] = [registry[i].model_copy(deep=True) for i in ids]
    return canonical.model_validate(data)


def register(registry, refs):
    for ref in refs:
        if ref.evidence_id in registry and registry[ref.evidence_id] != ref:
            raise AgentStructuredOutputError('Conflicting canonical evidence')
        registry[ref.evidence_id] = deepcopy(ref)


class BoundHardwareAgent(HardwareSecurityAgent):
    def __init__(self, *, model, structured_output_method='function_calling'):
        super().__init__()
        self._runtime = StructuredReportRuntime(model, HardwareBinding, HW_PROMPT,
            structured_output_method=structured_output_method)
        self._active_runtime = self._runtime

    def invoke(self, inputs):
        registry = {}
        behaviors = [b for o in inputs.deterministic_observations.observations for b in o.behaviors]
        for o in inputs.deterministic_observations.observations:
            register(registry, o.evidence)
        for b in behaviors:
            register(registry, b.evidence)
            if b.decoded_instruction:
                register(registry, b.decoded_instruction.evidence)
        report = hydrate(self._runtime.invoke(hardware_context(inputs)), registry,
                         HardwareAnalysisReport, HARDWARE_ITEMS)
        validate_hardware_evidence(report, inputs)
        return validate_agent_output(HardwareAgentOutput, report=report,
            processor_behavior_ir=ProcessorBehaviorIR(case_id=inputs.case.case_id, behaviors=behaviors))


class BoundCrossLayerAgent(CrossLayerSecurityAgent):
    def __init__(self, *, model, structured_output_method='function_calling'):
        super().__init__()
        self._runtime = StructuredReportRuntime(model, CrossLayerBinding, CROSS_PROMPT,
            structured_output_method=structured_output_method)

    def invoke(self, inputs):
        registry = {}
        for behavior in inputs.processor_behavior_ir.behaviors:
            register(registry, behavior.evidence)
        for report in [inputs.hardware_report, inputs.firmware_report]:
            for field in type(report).model_fields:
                items = getattr(report, field)
                if isinstance(items, list):
                    for item in items:
                        register(registry, getattr(item, 'evidence', []))
        report = hydrate(self._runtime.invoke(cross_layer_context(inputs)), registry,
                         CrossLayerAnalysisReport, CROSS_ITEMS)
        if report.case_id != inputs.case.case_id:
            raise AgentStructuredOutputError('Cross-layer report belongs to a different case')
        return validate_agent_output(CrossLayerAgentOutput, report=report)
