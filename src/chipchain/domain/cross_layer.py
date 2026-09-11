"""Cross-layer candidate contracts; no vulnerability or chain inference."""

from enum import StrEnum

from pydantic import Field

from chipchain.domain.common import CandidateStatus, Contract, EpistemicStatus, Identifier
from chipchain.domain.evidence import EvidenceRef


class CrossLayerType(StrEnum):
    TYPE_I = "TYPE_I"
    TYPE_II = "TYPE_II"
    TYPE_III = "TYPE_III"


class MissingConstraint(Contract):
    constraint_id: Identifier
    description: Identifier
    required_evidence: list[str] = Field(default_factory=list)


class CrossLayerCandidate(Contract):
    candidate_id: Identifier
    candidate_type: CrossLayerType
    summary: Identifier
    hardware_finding_ids: list[Identifier] = Field(default_factory=list)
    firmware_finding_ids: list[Identifier] = Field(default_factory=list)
    processor_behavior_ids: list[Identifier] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    missing_constraints: list[MissingConstraint] = Field(default_factory=list)
    epistemic_status: CandidateStatus = EpistemicStatus.HYPOTHESIZED


class AttackChainCandidate(Contract):
    candidate_id: Identifier
    candidate_type: CrossLayerType
    summary: Identifier
    cross_layer_candidate_ids: list[Identifier] = Field(default_factory=list)
    ordered_processor_behavior_ids: list[Identifier] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    missing_constraints: list[MissingConstraint] = Field(default_factory=list)
    epistemic_status: CandidateStatus = EpistemicStatus.HYPOTHESIZED


class TriggerFeature(Contract):
    """A proposed trigger feature, never a verified trigger."""

    feature_id: Identifier
    candidate_ids: list[Identifier] = Field(default_factory=list)
    processor_behavior_ids: list[Identifier] = Field(default_factory=list)
    description: Identifier
    evidence: list[EvidenceRef] = Field(default_factory=list)
    epistemic_status: CandidateStatus = EpistemicStatus.HYPOTHESIZED


class RootLocationCandidate(Contract):
    candidate_id: Identifier
    summary: Identifier
    processor_behavior_ids: list[Identifier] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    epistemic_status: CandidateStatus = EpistemicStatus.HYPOTHESIZED


class CrossLayerAnalysisReport(Contract):
    case_id: Identifier
    candidates: list[CrossLayerCandidate] = Field(default_factory=list)
    attack_chain_candidates: list[AttackChainCandidate] = Field(default_factory=list)
    trigger_features: list[TriggerFeature] = Field(default_factory=list)
    root_location_candidates: list[RootLocationCandidate] = Field(default_factory=list)
    missing_constraints: list[MissingConstraint] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
