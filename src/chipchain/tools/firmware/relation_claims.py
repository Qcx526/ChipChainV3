"""Compatibility of explicitly cited typed facts; no NLP, graph search or LLM."""
from enum import StrEnum
from typing import Literal

from pydantic import Field

from chipchain.domain.common import Contract
from chipchain.tools.firmware.relations import (
    DirectionDetails, FirmwareStaticRelationCatalog, Identifier, RelationEndpoint,
    RelationKind as K, RelationStatus as S,
)


class ClaimKind(StrEnum):
    DIRECT_CALL = 'direct_call'
    DIRECT_BRANCH = 'direct_branch'
    VECTOR_DISPATCH = 'vector_dispatch'
    MMIO_CONTAINMENT = 'mmio_containment'
    MMIO_READ = 'mmio_read'
    MMIO_WRITE = 'mmio_write'
    STATIC_CALL_PATH = 'static_call_path'
    RUNTIME_REACHABILITY = 'runtime_reachability'
    PHYSICAL_INPUT_PATH = 'physical_input_path'
    TRIGGER_TO_HANDLER = 'trigger_to_handler'


class StaticRelationClaim(Contract):
    claim_id: Identifier
    claim_kind: ClaimKind
    source: RelationEndpoint
    target: RelationEndpoint | None = None
    relation_ids: list[Identifier] = Field(default_factory=list)


class StaticCallPathClaim(Contract):
    claim_id: Identifier
    claim_kind: Literal[ClaimKind.STATIC_CALL_PATH] = ClaimKind.STATIC_CALL_PATH
    source_function_id: Identifier
    target_function_id: Identifier
    edge_relation_ids: list[Identifier] = Field(default_factory=list)


class ClaimSupportStatus(StrEnum):
    SUPPORTED = 'supported'
    UNSUPPORTED = 'unsupported'
    INCOMPATIBLE = 'incompatible'


class ClaimSupportResult(Contract):
    claim_id: Identifier
    status: ClaimSupportStatus
    reason: Literal['exact_static_relation', 'exact_static_call_path', 'no_supplied_relations',
        'unknown_relation_id', 'relation_type_or_status_mismatch', 'endpoint_mismatch',
        'direction_mismatch', 'static_facts_do_not_establish_claim', 'missing_static_fact',
        'broken_explicit_path']
    relation_ids: list[str]


def _same_endpoint(actual, claimed):
    # Address may be omitted by a claim; identity/type must still match exactly.
    if actual is None or claimed is None:
        return actual is claimed
    return (actual.entity_type, actual.entity_id) == (claimed.entity_type, claimed.entity_id) and (
        claimed.address is None or actual.address == claimed.address)


def check_claim_support(catalog: FirmwareStaticRelationCatalog,
                        claim: StaticRelationClaim | StaticCallPathClaim) -> ClaimSupportResult:
    catalog = FirmwareStaticRelationCatalog.model_validate(catalog.model_dump())
    claim = type(claim).model_validate(claim.model_dump())
    ids = claim.edge_relation_ids if isinstance(claim, StaticCallPathClaim) else claim.relation_ids

    def result(status, reason):
        return ClaimSupportResult(claim_id=claim.claim_id, status=status, reason=reason, relation_ids=ids)

    # Unsupported is not refuted: no A4 capability connects triggers, runtime or physical inputs.
    if claim.claim_kind in (ClaimKind.RUNTIME_REACHABILITY, ClaimKind.PHYSICAL_INPUT_PATH, ClaimKind.TRIGGER_TO_HANDLER):
        return result('unsupported', 'static_facts_do_not_establish_claim')
    if not ids:
        return result('unsupported', 'no_supplied_relations')
    lookup = {r.relation_id: r for r in catalog.relations}
    if any(rid not in lookup for rid in ids):
        return result('incompatible', 'unknown_relation_id')
    relations = [lookup[rid] for rid in ids]
    if claim.claim_kind == ClaimKind.STATIC_CALL_PATH:
        if isinstance(claim, StaticCallPathClaim):
            source_id, target_id = claim.source_function_id, claim.target_function_id
        else:
            if claim.source.entity_type != 'function' or claim.target is None or claim.target.entity_type != 'function':
                return result('incompatible', 'endpoint_mismatch')
            source_id, target_id = claim.source.entity_id, claim.target.entity_id
            if not _same_endpoint(relations[0].source, claim.source) or not _same_endpoint(relations[-1].target, claim.target):
                return result('incompatible', 'endpoint_mismatch')
        if any(r.kind != K.DIRECT_CALL or r.status != S.CONFIRMED_STATIC for r in relations):
            return result('incompatible', 'relation_type_or_status_mismatch')
        if (relations[0].source.entity_id != source_id or relations[-1].target.entity_id != target_id
                or any(a.target != b.source for a, b in zip(relations, relations[1:]))):
            return result('incompatible', 'broken_explicit_path')
        return result('supported', 'exact_static_call_path')
    kind = {ClaimKind.DIRECT_CALL: K.DIRECT_CALL, ClaimKind.DIRECT_BRANCH: K.DIRECT_BRANCH,
            ClaimKind.VECTOR_DISPATCH: K.VECTOR_DISPATCH, ClaimKind.MMIO_CONTAINMENT: K.MMIO_FUNCTION_CONTAINMENT,
            ClaimKind.MMIO_READ: K.MMIO_ACCESS_DIRECTION, ClaimKind.MMIO_WRITE: K.MMIO_ACCESS_DIRECTION}[claim.claim_kind]
    missing = False
    for relation in relations:
        if relation.kind != kind:
            return result('incompatible', 'relation_type_or_status_mismatch')
        if not _same_endpoint(relation.source, claim.source):
            return result('incompatible', 'endpoint_mismatch')
        if relation.status == S.MISSING or (isinstance(relation.attributes, DirectionDetails) and relation.attributes.direction == 'unknown'):
            missing = True
            continue
        if relation.status != S.CONFIRMED_STATIC:
            return result('incompatible', 'relation_type_or_status_mismatch')
        if not _same_endpoint(relation.target, claim.target):
            return result('incompatible', 'endpoint_mismatch')
        if claim.claim_kind in (ClaimKind.MMIO_READ, ClaimKind.MMIO_WRITE):
            wanted = 'read' if claim.claim_kind == ClaimKind.MMIO_READ else 'write'
            if relation.attributes.direction != wanted:
                return result('incompatible', 'direction_mismatch')
    return result('unsupported', 'missing_static_fact') if missing else result('supported', 'exact_static_relation')
