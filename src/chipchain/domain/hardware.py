"""Hardware findings remain separate from proposed triggers."""

from pydantic import Field

from chipchain.domain.common import (
    CandidateStatus, Contract, EpistemicStatus, Identifier, Scalar,
)
from chipchain.domain.evidence import EvidenceRef


class HardwareFinding(Contract):
    finding_id: Identifier
    summary: Identifier
    evidence: list[EvidenceRef] = Field(default_factory=list)
    processor_behavior_ids: list[Identifier] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.UNKNOWN


class TriggerConstraint(Contract):
    """Descriptive constraint only; no solver semantics in R0."""

    subject: Identifier
    relation: Identifier
    value: Scalar


class HardwareTriggerHypothesis(Contract):
    hypothesis_id: Identifier
    summary: Identifier
    hardware_finding_ids: list[Identifier] = Field(default_factory=list)
    processor_behavior_ids: list[Identifier] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    constraints: list[TriggerConstraint] = Field(default_factory=list)
    epistemic_status: CandidateStatus = EpistemicStatus.HYPOTHESIZED


class AbnormalState(Contract):
    state_id: Identifier
    summary: Identifier
    hardware_finding_ids: list[Identifier] = Field(default_factory=list)
    processor_behavior_ids: list[Identifier] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.UNKNOWN


class HardwareAnalysisReport(Contract):
    case_id: Identifier
    findings: list[HardwareFinding] = Field(default_factory=list)
    trigger_hypotheses: list[HardwareTriggerHypothesis] = Field(default_factory=list)
    abnormal_states: list[AbnormalState] = Field(default_factory=list)
    processor_behavior_ids: list[Identifier] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
