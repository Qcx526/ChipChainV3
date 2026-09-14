"""B3 model-only support schema; canonical domain reports remain unchanged."""
from typing import Annotated, Literal
from pydantic import Field
from chipchain.domain.common import Contract
from chipchain.agents.model_outputs.firmware import (
    ModelFirmwareFinding, ModelExternalInputPath, ModelReachableBehavior,
    ModelFirmwareIssueAnchor, ModelFirmwareAnalysisReport,
)
from chipchain.tools.firmware.relations import RelationKind, RelationStatus, TransferKind

SafeID = Annotated[str,Field(pattern=r'^[A-Za-z0-9_.:-]{1,160}$')]


class ModelRelationFactClaim(Contract):
    support_claim_id: SafeID
    claim_type: Literal['relation_fact'] = 'relation_fact'
    relation_id: SafeID
    expected_kind: RelationKind
    expected_status: RelationStatus
    expected_source_entity_id: SafeID
    expected_target_entity_id: SafeID | None
    expected_direction: Literal['read','write','unknown'] | None = None
    expected_transfer_kind: TransferKind | None = None
    expected_vector_index: int | None = Field(default=None,ge=1,strict=True)
    expected_binding_status: Literal['function_entry','inside_function','non_thumb','outside_executable','ambiguous','no_function'] | None = None


class ModelStaticCallPathClaim(Contract):
    support_claim_id: SafeID
    claim_type: Literal['static_call_path'] = 'static_call_path'
    source_function_id: SafeID
    target_function_id: SafeID
    edge_relation_ids: list[SafeID] = Field(min_length=1)


class ModelUnsupportedSemanticClaim(Contract):
    support_claim_id: SafeID
    claim_type: Literal['runtime_reachability','physical_input_path','trigger_to_handler']
    source_entity_id: SafeID
    target_entity_id: SafeID
    relation_ids: list[SafeID]


ModelRelationSupportClaim = Annotated[
    ModelRelationFactClaim | ModelStaticCallPathClaim | ModelUnsupportedSemanticClaim,
    Field(discriminator='claim_type'),
]


class SupportedFinding(ModelFirmwareFinding):
    support_claim_ids: list[SafeID] = Field(min_length=1)


class SupportedExternalInputPath(ModelExternalInputPath):
    support_claim_ids: list[SafeID] = Field(min_length=1)


class SupportedReachableBehavior(ModelReachableBehavior):
    support_claim_ids: list[SafeID] = Field(min_length=1)


class SupportedIssueAnchor(ModelFirmwareIssueAnchor):
    support_claim_ids: list[SafeID] = Field(min_length=1)


class ModelFirmwareAnalysisReportV2(ModelFirmwareAnalysisReport):
    findings: list[SupportedFinding] = Field(default_factory=list)
    external_input_paths: list[SupportedExternalInputPath] = Field(default_factory=list)
    reachable_behaviors: list[SupportedReachableBehavior] = Field(default_factory=list)
    issue_anchors: list[SupportedIssueAnchor] = Field(default_factory=list)
    support_claims: list[ModelRelationSupportClaim] = Field(default_factory=list)
