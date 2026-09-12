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
