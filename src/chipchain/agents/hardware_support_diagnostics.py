"""Typed referenced-support diagnostics, with no rejected item or provider prose."""
from typing import Literal

from pydantic import Field, model_validator

from chipchain.domain.common import Contract, Sha256
from chipchain.domain.evidence import EvidenceTime
from chipchain.agents.model_outputs.hardware_v2 import SafeID, ModelHardwareRelationFactSupport
from chipchain.agents.hardware_support import (
    HardwareClaimReference, HardwareSupportCounts, HardwareSupportEntry, evaluation_counts,
)
from chipchain.agents.projections.hardware_relations import HardwareRelationRow, build_hardware_relation_projection
from chipchain.tools.hardware.relations import HardwareRelationKind, canonical_json, sha256_text
from chipchain.tools.hardware.relation_claims import HardwareClaimKind

MAX_HARDWARE_SUPPORT_FAILURE_BYTES = 256 * 1024


class SafeExpectedField(Contract):
    path: SafeID
    # Only numeric/bool/null or exact deterministic catalog vocabulary is copied.
    value: str | int | bool | None
    unrecognized_text_sha256: Sha256 | None = None
    unrecognized_text_characters: int | None = Field(default=None, ge=0, strict=True)

    @model_validator(mode='after')
    def redaction(self):
        if (self.unrecognized_text_sha256 is None) != (self.unrecognized_text_characters is None):
            raise ValueError('Incomplete typed string redaction')
        if self.unrecognized_text_sha256 is not None and self.value is not None:
            raise ValueError('Unrecognized model text must not be copied')
        return self


class SafeExpectedSemantics(Contract):
    expected_kind: HardwareRelationKind | None
    expected_status: Literal['observed', 'derived']
    semantic_kind: HardwareClaimKind | None
    start: EvidenceTime | None
    end: EvidenceTime | None
    attributes_fields: list[SafeExpectedField]


class HardwareRelationSnapshot(Contract):
    relation_id: SafeID
    actual: HardwareRelationRow | None


class FailedHardwareReferencedSupport(Contract):
    support_claim_id: SafeID
    claim_type: Literal['relation_fact', 'semantic_claim']
    usage_status: Literal['referenced'] = 'referenced'
    result: Literal['unsupported', 'incompatible']
    reason: HardwareSupportEntry.model_fields['reason'].annotation
    relation_ids: list[SafeID]
    referencing_hardware_claims: list[HardwareClaimReference] = Field(min_length=1)
    expected: SafeExpectedSemantics
    actual_relations: list[HardwareRelationSnapshot]

    @model_validator(mode='after')
    def snapshot_identity(self):
        if [s.relation_id for s in self.actual_relations] != sorted(set(self.relation_ids)):
            raise ValueError('Failure must include every referenced relation snapshot')
        if any(s.actual is not None and s.actual.relation_id != s.relation_id for s in self.actual_relations):
            raise ValueError('Failure snapshot identity mismatch')
        refs = [(r.collection, r.claim_id) for r in self.referencing_hardware_claims]
        if refs != sorted(set(refs)):
            raise ValueError('Failure references must be unique and sorted')
        return self


class HardwareRelationSupportFailureV1(HardwareSupportCounts):
    schema_version: Literal['hardware-relation-support-failure/v1'] = 'hardware-relation-support-failure/v1'
    failed_referenced_supports: list[FailedHardwareReferencedSupport] = Field(min_length=1)

    @model_validator(mode='after')
    def counts(self):
        failures = self.failed_referenced_supports
        ids = [e.support_claim_id for e in failures]
        if ids != sorted(set(ids)):
            raise ValueError('Failure entries must be unique and sorted')
        if (self.generated_support_count != self.referenced_support_count + self.orphan_support_count
            or self.referenced_support_count != self.referenced_supported_count + self.referenced_unsupported_count + self.referenced_incompatible_count
            or self.orphan_support_count != self.orphan_supported_count + self.orphan_unsupported_count + self.orphan_incompatible_count
            or self.referenced_unsupported_count != sum(e.result == 'unsupported' for e in failures)
            or self.referenced_incompatible_count != sum(e.result == 'incompatible' for e in failures)):
            raise ValueError('Failure counts mismatch')
        return self


def _leaves(value, path='attributes'):
    if isinstance(value, dict):
        for k in sorted(value):
            yield from _leaves(value[k], path + '.' + k)
    elif isinstance(value, list):
        for i, child in enumerate(value):
            yield from _leaves(child, path + '.' + str(i))
    else:
        yield path, value


def build_hardware_support_failure(entries, catalog):
    projection = build_hardware_relation_projection(catalog)
    rows = {r.relation_id: r for r in projection.relations}
    vocabulary = {v for r in projection.relations for _, v in _leaves(r.attributes.model_dump(mode='json')) if isinstance(v, str)}
    failures = []
    for entry in entries:
        if entry.usage_status != 'referenced' or entry.result == 'supported':
            continue
        claim = entry.support_claim
        fields = []
        attrs = claim.expected_attributes.model_dump(mode='json') if claim.expected_attributes is not None else None
        for path, value in _leaves(attrs):
            if isinstance(value, str) and value not in vocabulary:
                fields.append(SafeExpectedField(path=path, value=None,
                    unrecognized_text_sha256=sha256_text(value), unrecognized_text_characters=len(value)))
            else:
                fields.append(SafeExpectedField(path=path, value=value))
        fact = isinstance(claim, ModelHardwareRelationFactSupport)
        failures.append(FailedHardwareReferencedSupport(
            support_claim_id=claim.support_claim_id, claim_type=claim.claim_type,
            result=entry.result, reason=entry.reason, relation_ids=entry.relation_ids,
            referencing_hardware_claims=entry.referencing_hardware_claims,
            expected=SafeExpectedSemantics(expected_kind=claim.expected_kind if fact else None,
                expected_status=claim.expected_status, semantic_kind=None if fact else claim.semantic_kind,
                start=None if fact else claim.start, end=None if fact else claim.end, attributes_fields=fields),
            actual_relations=[HardwareRelationSnapshot(relation_id=rid, actual=rows.get(rid)) for rid in sorted(set(entry.relation_ids))],
        ))
    diagnostic = HardwareRelationSupportFailureV1(**evaluation_counts(entries),
        failed_referenced_supports=sorted(failures, key=lambda e: e.support_claim_id))
    serialize_hardware_support_failure(diagnostic)
    return diagnostic


def serialize_hardware_support_failure(diagnostic):
    checked = HardwareRelationSupportFailureV1.model_validate_json(diagnostic.model_dump_json())
    text = canonical_json(checked.model_dump(mode='json'))
    if len(text.encode('utf-8')) > MAX_HARDWARE_SUPPORT_FAILURE_BYTES:
        raise ValueError('Hardware support diagnostic exceeds byte cap')
    return text
