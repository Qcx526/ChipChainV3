"""Exact typed support, never interpretation of Firmware claim prose."""
from typing import Literal
from pydantic import Field
from chipchain.domain.common import Contract
from chipchain.agents.runtime import AgentStructuredOutputError
from chipchain.agents.model_outputs.firmware import ModelFirmwareAnalysisReport, validate_firmware_report_references
from chipchain.agents.model_outputs.firmware_v2 import (
    ModelFirmwareAnalysisReportV2, ModelRelationFactClaim, ModelStaticCallPathClaim, ModelRelationSupportClaim, SafeID,
)
from chipchain.tools.firmware.relations import FirmwareStaticRelationCatalog, RelationEndpoint, DirectionDetails, TransferDetails, VectorDetails
from chipchain.tools.firmware.relation_claims import StaticRelationClaim, StaticCallPathClaim, check_claim_support

COLLECTIONS = {'findings':'finding_id','external_input_paths':'path_id','reachable_behaviors':'reachability_id','issue_anchors':'anchor_id'}


class RelationSupportError(AgentStructuredOutputError):
    def __init__(self, reason_code):
        super().__init__('Model relation support validation failed',failure_category='relation_support_validation')
        self.reason_code = reason_code


class FirmwareClaimReference(Contract):
    collection: Literal['findings','external_input_paths','reachable_behaviors','issue_anchors']
    claim_id: SafeID


class SupportAuditEntry(Contract):
    support_claim: ModelRelationSupportClaim
    result: Literal['supported','unsupported','incompatible']
    reason_code: Literal['exact_relation_fact','exact_static_relation','exact_static_call_path','relation_fact_mismatch',
        'unknown_relation_id','no_supplied_relations','relation_type_or_status_mismatch','endpoint_mismatch',
        'direction_mismatch','static_facts_do_not_establish_claim','missing_static_fact','broken_explicit_path']
    relation_ids: list[str]
    referencing_firmware_claims: list[FirmwareClaimReference] = Field(min_length=1)


class FirmwareRelationSupportReport(Contract):
    schema_version: Literal['firmware-relation-support/v1'] = 'firmware-relation-support/v1'
    support_claims: list[SupportAuditEntry]


def exact_relation_fact_match(claim, relation):
    if relation is None:
        return False
    if (claim.expected_kind,claim.expected_status,claim.expected_source_entity_id,claim.expected_target_entity_id) != (
            relation.kind,relation.status,relation.source.entity_id,relation.target.entity_id if relation.target else None):
        return False
    d = relation.attributes
    expected = (d.direction if isinstance(d,DirectionDetails) else None,
                d.transfer_kind if isinstance(d,TransferDetails) else None,
                d.vector_index if isinstance(d,VectorDetails) else None,
                d.binding_status if isinstance(d,VectorDetails) else None)
    return expected == (claim.expected_direction,claim.expected_transfer_kind,claim.expected_vector_index,claim.expected_binding_status)


def evaluate_support(claim, catalog):
    if isinstance(claim,ModelRelationFactClaim):
        relation = next((r for r in catalog.relations if r.relation_id == claim.relation_id),None)
        ids = [claim.relation_id]
        if relation is None:
            return 'incompatible','unknown_relation_id',ids
        if not exact_relation_fact_match(claim,relation):
            return 'incompatible','relation_fact_mismatch',ids
        # Unresolved/missing facts can themselves be correctly stated. This does not
        # promote them to confirmed transfer/containment proof.
        if relation.status != 'confirmed_static':
            return 'supported','exact_relation_fact',ids
        kind = {'direct_call':'direct_call','direct_branch':'direct_branch','vector_dispatch':'vector_dispatch',
                'mmio_function_containment':'mmio_containment',
                'mmio_access_direction':'mmio_'+claim.expected_direction if claim.expected_direction else None}[relation.kind]
        typed = StaticRelationClaim(claim_id=claim.support_claim_id,claim_kind=kind,source=relation.source,
            target=relation.target,relation_ids=ids)
    elif isinstance(claim,ModelStaticCallPathClaim):
        ids = claim.edge_relation_ids
        typed = StaticCallPathClaim(claim_id=claim.support_claim_id,source_function_id=claim.source_function_id,
            target_function_id=claim.target_function_id,edge_relation_ids=ids)
    else:
        ids = claim.relation_ids
        typed = StaticRelationClaim(claim_id=claim.support_claim_id,claim_kind=claim.claim_type,
            source=RelationEndpoint(entity_type='address',entity_id=claim.source_entity_id),
            target=RelationEndpoint(entity_type='address',entity_id=claim.target_entity_id),relation_ids=ids)
    result = check_claim_support(catalog,typed)
    return result.status.value,result.reason,ids


def validate_relation_support(model_report, catalog):
    model_report = ModelFirmwareAnalysisReportV2.model_validate(model_report.model_dump())
    catalog = FirmwareStaticRelationCatalog.model_validate(catalog.model_dump())
    validate_firmware_report_references(model_report)
    claims = {c.support_claim_id:c for c in model_report.support_claims}
    if len(claims) != len(model_report.support_claims):
        raise RelationSupportError('duplicate_support_claim_id')
    refs = {key:[] for key in claims}
    for collection,key in COLLECTIONS.items():
        for item in getattr(model_report,collection):
            if not item.support_claim_ids or len(item.support_claim_ids) != len(set(item.support_claim_ids)):
                raise RelationSupportError('missing_or_duplicate_support_reference')
            for sid in item.support_claim_ids:
                if sid not in claims:
                    raise RelationSupportError('unknown_support_claim_id')
                refs[sid].append(FirmwareClaimReference(collection=collection,claim_id=getattr(item,key)))
    if any(not references for references in refs.values()):
        raise RelationSupportError('unused_support_claim')
    entries = []
    for sid,claim in claims.items():
        status,reason,ids = evaluate_support(claim,catalog)
        if status != 'supported':
            raise RelationSupportError('unsupported_relation_claim' if status == 'unsupported' else 'incompatible_relation_claim')
        entries.append(SupportAuditEntry(support_claim=claim,result=status,reason_code=reason,relation_ids=ids,
            referencing_firmware_claims=refs[sid]))
    return FirmwareRelationSupportReport(support_claims=entries)


def strip_support_fields(report):
    data = report.model_dump()
    data.pop('support_claims')
    for collection in COLLECTIONS:
        for item in data[collection]:
            item.pop('support_claim_ids')
    return ModelFirmwareAnalysisReport.model_validate(data)


def validate_support_artifact(audit, report, catalog):
    """Recreate only typed support wiring from canonical report, then rerun all gates."""
    audit = FirmwareRelationSupportReport.model_validate(audit.model_dump())
    data = report.model_dump()
    index = {}
    for collection,key in COLLECTIONS.items():
        for item in data[collection]:
            item['evidence_ids'] = [e['evidence_id'] for e in item.pop('evidence')]
            item['support_claim_ids'] = []
            identity = (collection,item[key])
            if identity in index:
                raise RelationSupportError('duplicate_firmware_claim_id')
            index[identity] = item
    data['support_claims'] = [e.support_claim.model_dump() for e in audit.support_claims]
    for entry in audit.support_claims:
        for ref in entry.referencing_firmware_claims:
            item = index.get((ref.collection,ref.claim_id))
            if item is None:
                raise RelationSupportError('unknown_firmware_claim_reference')
            item['support_claim_ids'].append(entry.support_claim.support_claim_id)
    rebuilt = validate_relation_support(ModelFirmwareAnalysisReportV2.model_validate(data),catalog)
    if rebuilt != audit:
        raise RelationSupportError('support_artifact_mismatch')
    return rebuilt
