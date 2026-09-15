"""Referenced support is mandatory; orphan support is evaluated diagnostic data.

The v1 contract and evaluator retain their original semantics. This policy only
changes which evaluated supports may reject the canonical Firmware report.
"""
from typing import Literal

from pydantic import Field, model_validator

from chipchain.domain.common import Contract
from chipchain.agents.model_outputs.firmware import validate_firmware_report_references
from chipchain.agents.model_outputs.firmware_v2 import ModelFirmwareAnalysisReportV2
from chipchain.agents.relation_support import (
    COLLECTIONS, FirmwareClaimReference, RelationSupportError, SupportAuditEntry,
    evaluate_support,
)
from chipchain.tools.firmware.relations import FirmwareStaticRelationCatalog


class SupportAuditEntryV2(SupportAuditEntry):
    usage_status: Literal['referenced', 'orphaned']
    referencing_firmware_claims: list[FirmwareClaimReference] = Field(default_factory=list)

    @model_validator(mode='after')
    def validate_usage(self):
        if self.usage_status == 'referenced':
            if not self.referencing_firmware_claims or self.result != 'supported':
                raise ValueError('Referenced support requires references and a supported result')
        elif self.referencing_firmware_claims:
            raise ValueError('Orphan support cannot reference Firmware claims')
        return self


class SupportAuditCounts(Contract):
    generated_support_claim_count: int = Field(ge=0, strict=True)
    referenced_support_claim_count: int = Field(ge=0, strict=True)
    orphan_support_claim_count: int = Field(ge=0, strict=True)
    referenced_supported_count: int = Field(ge=0, strict=True)
    orphan_supported_count: int = Field(ge=0, strict=True)
    orphan_unsupported_count: int = Field(ge=0, strict=True)
    orphan_incompatible_count: int = Field(ge=0, strict=True)


def support_audit_counts(entries):
    referenced = [e for e in entries if e.usage_status == 'referenced']
    orphaned = [e for e in entries if e.usage_status == 'orphaned']
    return dict(
        generated_support_claim_count=len(entries),
        referenced_support_claim_count=len(referenced),
        orphan_support_claim_count=len(orphaned),
        referenced_supported_count=sum(e.result == 'supported' for e in referenced),
        orphan_supported_count=sum(e.result == 'supported' for e in orphaned),
        orphan_unsupported_count=sum(e.result == 'unsupported' for e in orphaned),
        orphan_incompatible_count=sum(e.result == 'incompatible' for e in orphaned),
    )


class FirmwareRelationSupportReportV2(SupportAuditCounts):
    schema_version: Literal['firmware-relation-support/v2'] = 'firmware-relation-support/v2'
    support_claims: list[SupportAuditEntryV2]

    @model_validator(mode='after')
    def validate_counts(self):
        if any(getattr(self, key) != value for key, value in support_audit_counts(self.support_claims).items()):
            raise ValueError('Support audit counts mismatch')
        return self


def validate_relation_support_v2(model_report, catalog):
    model_report = ModelFirmwareAnalysisReportV2.model_validate(model_report.model_dump())
    catalog = FirmwareStaticRelationCatalog.model_validate(catalog.model_dump())
    validate_firmware_report_references(model_report)
    claims = {c.support_claim_id: c for c in model_report.support_claims}
    if len(claims) != len(model_report.support_claims):
        raise RelationSupportError('duplicate_support_claim_id')
    refs = {key: [] for key in claims}
    for collection, key in COLLECTIONS.items():
        for item in getattr(model_report, collection):
            if not item.support_claim_ids or len(item.support_claim_ids) != len(set(item.support_claim_ids)):
                raise RelationSupportError('missing_or_duplicate_support_reference')
            for sid in item.support_claim_ids:
                if sid not in claims:
                    raise RelationSupportError('unknown_support_claim_id')
                refs[sid].append(FirmwareClaimReference(collection=collection, claim_id=getattr(item, key)))
    # Complete every deterministic evaluation BEFORE enforcing referenced results.
    evaluated = [(sid, claim, evaluate_support(claim, catalog)) for sid, claim in claims.items()]
    entries = []
    for sid, claim, (status, reason, ids) in evaluated:
        if refs[sid] and status != 'supported':
            raise RelationSupportError('unsupported_relation_claim' if status == 'unsupported' else 'incompatible_relation_claim')
        entries.append(SupportAuditEntryV2(
            support_claim=claim, usage_status='referenced' if refs[sid] else 'orphaned',
            result=status, reason_code=reason, relation_ids=ids, referencing_firmware_claims=refs[sid],
        ))
    return FirmwareRelationSupportReportV2(support_claims=entries, **support_audit_counts(entries))


def validate_support_artifact_v2(audit, report, catalog):
    """Rebuild explicit wiring and reevaluate, including orphan diagnostics.

    Canonical reports strip support fields; the audit supplies the wiring. This
    checks internal consistency, not authenticity of a separately signed source.
    """
    audit = FirmwareRelationSupportReportV2.model_validate(audit.model_dump())
    data = report.model_dump()
    index = {}
    for collection, key in COLLECTIONS.items():
        for item in data[collection]:
            item['evidence_ids'] = [e['evidence_id'] for e in item.pop('evidence')]
            item['support_claim_ids'] = []
            identity = (collection, item[key])
            if identity in index:
                raise RelationSupportError('duplicate_firmware_claim_id')
            index[identity] = item
    data['support_claims'] = [e.support_claim.model_dump() for e in audit.support_claims]
    for entry in audit.support_claims:
        for ref in entry.referencing_firmware_claims:
            item = index.get((ref.collection, ref.claim_id))
            if item is None:
                raise RelationSupportError('unknown_firmware_claim_reference')
            item['support_claim_ids'].append(entry.support_claim.support_claim_id)
    rebuilt = validate_relation_support_v2(ModelFirmwareAnalysisReportV2.model_validate(data), catalog)
    if rebuilt != audit:
        raise RelationSupportError('support_artifact_mismatch')
    return rebuilt
