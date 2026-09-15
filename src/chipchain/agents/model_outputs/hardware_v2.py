"""Model-only Hardware B2 schema. Canonical hardware domain remains unchanged."""
from typing import Annotated, Literal

from pydantic import Field

from chipchain.domain.common import Contract, EpistemicStatus
from chipchain.domain.evidence import EvidenceTime
from chipchain.domain.hardware import TriggerConstraint
from chipchain.tools.hardware.relation_claims import HardwareClaimKind
from chipchain.tools.hardware.relations import HardwareRelationKind, canonical_json, sha256_text
from chipchain.agents.projections.hardware_relations import CompactAttributes

SafeID = Annotated[str, Field(pattern=r'^[A-Za-z0-9_.:-]{1,200}$')]
MAX_SUPPORTS = 128


class ModelHardwareRelationFactSupport(Contract):
    support_claim_id: SafeID
    claim_type: Literal['relation_fact'] = 'relation_fact'
    relation_id: SafeID
    expected_kind: HardwareRelationKind
    expected_status: Literal['observed', 'derived']
    expected_attributes: CompactAttributes


class ModelHardwareSemanticSupport(Contract):
    support_claim_id: SafeID
    claim_type: Literal['semantic_claim'] = 'semantic_claim'
    semantic_kind: HardwareClaimKind
    relation_ids: list[SafeID] = Field(max_length=128)
    expected_attributes: CompactAttributes | None
    expected_status: Literal['observed', 'derived']
    start: EvidenceTime | None = None
    end: EvidenceTime | None = None


ModelHardwareSupport = Annotated[
    ModelHardwareRelationFactSupport | ModelHardwareSemanticSupport, Field(discriminator='claim_type'),
]


class ModelHardwareFindingV2(Contract):
    finding_id: SafeID
    summary: str = Field(min_length=1, max_length=4096)
    evidence_ids: list[SafeID] = Field(min_length=1, max_length=128)
    processor_behavior_ids: list[SafeID] = Field(max_length=128)
    epistemic_status: EpistemicStatus
    support_claim_ids: list[SafeID] = Field(min_length=1, max_length=MAX_SUPPORTS)


class ModelHardwareTriggerHypothesisV2(Contract):
    hypothesis_id: SafeID
    summary: str = Field(min_length=1, max_length=4096)
    hardware_finding_ids: list[SafeID] = Field(max_length=128)
    processor_behavior_ids: list[SafeID] = Field(max_length=128)
    evidence_ids: list[SafeID] = Field(min_length=1, max_length=128)
    constraints: list[TriggerConstraint] = Field(max_length=32)
    # VERIFIED is representable so the explicit epistemic post-gate can reject it.
    epistemic_status: EpistemicStatus
    support_claim_ids: list[SafeID] = Field(min_length=1, max_length=MAX_SUPPORTS)


class ModelAbnormalStateV2(Contract):
    state_id: SafeID
    summary: str = Field(min_length=1, max_length=4096)
    hardware_finding_ids: list[SafeID] = Field(max_length=128)
    processor_behavior_ids: list[SafeID] = Field(max_length=128)
    evidence_ids: list[SafeID] = Field(min_length=1, max_length=128)
    epistemic_status: EpistemicStatus
    support_claim_ids: list[SafeID] = Field(min_length=1, max_length=MAX_SUPPORTS)


class ModelHardwareAnalysisReportV2(Contract):
    case_id: SafeID
    findings: list[ModelHardwareFindingV2] = Field(max_length=64)
    trigger_hypotheses: list[ModelHardwareTriggerHypothesisV2] = Field(max_length=64)
    abnormal_states: list[ModelAbnormalStateV2] = Field(max_length=64)
    processor_behavior_ids: list[SafeID] = Field(max_length=128)
    unresolved_questions: list[str] = Field(max_length=64)
    support_claims: list[ModelHardwareSupport] = Field(max_length=MAX_SUPPORTS)


def hardware_model_schema_sha256() -> str:
    return sha256_text(canonical_json(ModelHardwareAnalysisReportV2.model_json_schema()))
