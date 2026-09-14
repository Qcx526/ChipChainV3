"""Canonical supplied evidence registry shared by projection and output grounding."""

from chipchain.agents.contracts import FirmwareAgentInput
from chipchain.agents.runtime import AgentStructuredOutputError
from chipchain.domain.evidence import EvidenceRef
from chipchain.tools.contracts import FirmwareObservation, ObservationRole


def collect_firmware_evidence(inputs: FirmwareAgentInput) -> dict[str, EvidenceRef]:
    """All three nesting levels, including generic observations; never select a winner."""
    result: dict[str, EvidenceRef] = {}
    artifact_ids = {a.artifact_id for a in inputs.case.firmware_artifacts}
    for observation in inputs.deterministic_observations.observations:
        if isinstance(observation, FirmwareObservation) and observation.role != ObservationRole.ANALYSIS_INPUT:
            raise AgentStructuredOutputError("Benchmark oracle cannot enter firmware analysis")
        refs = list(observation.evidence)
        for behavior in observation.behaviors:
            refs.extend(behavior.evidence)
            if behavior.decoded_instruction is not None:
                refs.extend(behavior.decoded_instruction.evidence)
        for ref in refs:
            if ref.artifact_id not in artifact_ids:
                raise AgentStructuredOutputError("Firmware evidence references an undeclared artifact")
            if ref.evidence_id in result and result[ref.evidence_id] != ref:
                raise AgentStructuredOutputError("Conflicting firmware evidence identities")
            result[ref.evidence_id] = ref.model_copy(deep=True)
    return dict(sorted(result.items()))


# Model-context safety budget, not a domain cardinality invariant. v1's 128 stays unchanged.
MAX_REASONING_EVIDENCE = 256


def merge_reasoning_evidence(base, relevant_static_structure, *, case_id, artifact_ids):
    from chipchain.tools.firmware.structure_projection import (
        FirmwareRelevantStaticStructure, parse_relevant_static_structure, serialize_relevant_static_structure,
    )
    if not isinstance(relevant_static_structure, FirmwareRelevantStaticStructure):
        raise AgentStructuredOutputError('Supplemental evidence requires a typed static structure')
    relevant=parse_relevant_static_structure(serialize_relevant_static_structure(relevant_static_structure))
    if relevant.case_id != case_id:
        raise AgentStructuredOutputError('Reasoning evidence case mismatch')
    result={key:value.model_copy(deep=True) for key,value in base.items()}
    for ref in relevant.evidence_catalog:
        if ref.artifact_id not in artifact_ids:
            raise AgentStructuredOutputError('Reasoning evidence references undeclared artifact')
        if ref.evidence_id in result and result[ref.evidence_id] != ref:
            raise AgentStructuredOutputError('Conflicting reasoning evidence identities')
        result[ref.evidence_id]=ref.model_copy(deep=True)
    if len(result)>MAX_REASONING_EVIDENCE:
        raise AgentStructuredOutputError('Reasoning evidence exceeds model-context safety limit')
    return dict(sorted(result.items()))


def collect_firmware_reasoning_evidence(inputs, relevant_static_structure=None):
    base=collect_firmware_evidence(inputs)
    if relevant_static_structure is None:
        return base
    return merge_reasoning_evidence(base,relevant_static_structure,case_id=inputs.case.case_id,
                                   artifact_ids={a.artifact_id for a in inputs.case.firmware_artifacts})
