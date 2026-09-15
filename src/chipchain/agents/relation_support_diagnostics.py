"""Bounded typed diagnostics, never rejected Firmware prose or provider content."""
from typing import Annotated, Literal

from pydantic import Field, model_validator

from chipchain.domain.common import Contract
from chipchain.agents.model_outputs.firmware_v2 import (
    SafeID, ModelRelationFactClaim,
)
from chipchain.agents.relation_support import FirmwareClaimReference, RelationSupportError, SupportAuditEntry
from chipchain.tools.firmware.relations import RelationKind, RelationStatus, TransferKind

MAX_RELATION_SUPPORT_FAILURE_BYTES = 256 * 1024
MAX_ITEMS = 4096
Count = Annotated[int, Field(strict=True, ge=0, le=2**32-1)]
VectorIndex = Annotated[int, Field(strict=True, ge=1, le=2**32-1)]
Reason = SupportAuditEntry.model_fields['reason_code'].annotation
Binding = Literal['function_entry', 'inside_function', 'non_thumb', 'outside_executable', 'ambiguous', 'no_function']
Direction = Literal['read', 'write', 'unknown']
Mnemonic = Literal['bl', 'blx', 'bx', 'b', 'b.w', 'b.n', 'tbb', 'tbh', 'ldr', 'ldr.w', 'ldr.n',
    'ldrb', 'ldrb.w', 'ldrh', 'ldrh.w', 'ldrsb', 'ldrsb.w', 'ldrsh', 'ldrsh.w', 'ldrd', 'ldrex',
    'str', 'str.w', 'str.n', 'strb', 'strb.w', 'strh', 'strh.w', 'strd', 'strex',
    'ldm', 'ldm.w', 'stm', 'stm.w', 'pop', 'pop.w', 'mov', 'mov.w', 'add', 'add.w', 'not_allowlisted']


class ExpectedFact(Contract):
    claim_type: Literal['relation_fact']
    relation_id: SafeID
    expected_kind: RelationKind
    expected_status: RelationStatus
    expected_source_entity_id: SafeID
    expected_target_entity_id: SafeID | None
    expected_direction: Direction | None
    expected_transfer_kind: TransferKind | None
    expected_vector_index: VectorIndex | None
    expected_binding_status: Binding | None


class ExpectedPath(Contract):
    claim_type: Literal['static_call_path']
    source_function_id: SafeID
    target_function_id: SafeID
    edge_relation_ids: list[SafeID] = Field(min_length=1, max_length=MAX_ITEMS)


class ExpectedSemantic(Contract):
    claim_type: Literal['runtime_reachability', 'physical_input_path', 'trigger_to_handler']
    source_entity_id: SafeID
    target_entity_id: SafeID
    relation_ids: list[SafeID] = Field(max_length=MAX_ITEMS)


Expected = Annotated[ExpectedFact | ExpectedPath | ExpectedSemantic, Field(discriminator='claim_type')]


class SafeEndpoint(Contract):
    entity_type: Literal['function', 'instruction_site', 'mmio_site', 'vector_entry', 'handler', 'address']
    entity_id: SafeID


class SafeTransfer(Contract):
    detail_type: Literal['control_transfer']
    transfer_kind: TransferKind
    call_semantics: Literal[True, False]
    original_reason: Literal['computed_or_ambiguous', 'missing_caller', 'missing_callee', 'callee_entry_conflict',
        'caller_containment_conflict', 'instruction_boundary_unconfirmed', 'decoder_disagreement'] | None
    mnemonic: Mnemonic | None


class SafeDirection(Contract):
    detail_type: Literal['mmio_direction']
    direction: Direction
    mnemonic: Mnemonic | None


class SafeVector(Contract):
    detail_type: Literal['vector_dispatch']
    vector_index: VectorIndex
    binding_status: Binding


class SafeContainment(Contract):
    detail_type: Literal['mmio_containment']


class ActualRelation(Contract):
    relation_id: SafeID
    kind: RelationKind
    status: RelationStatus
    source: SafeEndpoint
    target: SafeEndpoint | None
    attributes: Annotated[SafeTransfer | SafeDirection | SafeVector | SafeContainment, Field(discriminator='detail_type')]


class RelationSnapshot(Contract):
    relation_id: SafeID
    actual: ActualRelation | None


class FailedReferencedSupport(Contract):
    support_claim_id: SafeID
    claim_type: Literal['relation_fact', 'static_call_path', 'runtime_reachability', 'physical_input_path', 'trigger_to_handler']
    usage_status: Literal['referenced'] = 'referenced'
    result: Literal['unsupported', 'incompatible']
    reason_code: Reason
    # Additional diagnostic detail; never replaces the frozen evaluator reason.
    mismatch_detail: Literal['direction_mismatch'] | None = None
    relation_ids: list[SafeID] = Field(max_length=MAX_ITEMS)
    referencing_firmware_claims: list[FirmwareClaimReference] = Field(min_length=1, max_length=MAX_ITEMS)
    expected: Expected
    actual_relations: list[RelationSnapshot] = Field(max_length=MAX_ITEMS)

    @model_validator(mode='after')
    def identities_and_order(self):
        if self.claim_type != self.expected.claim_type:
            raise ValueError('Diagnostic claim type mismatch')
        expected_ids = ([self.expected.relation_id] if isinstance(self.expected, ExpectedFact)
            else self.expected.edge_relation_ids if isinstance(self.expected, ExpectedPath) else self.expected.relation_ids)
        if self.relation_ids != expected_ids:
            raise ValueError('Diagnostic relation IDs mismatch')
        refs = [(r.collection, r.claim_id) for r in self.referencing_firmware_claims]
        if refs != sorted(set(refs)):
            raise ValueError('Diagnostic references must be unique and sorted')
        if [r.relation_id for r in self.actual_relations] != sorted(set(self.relation_ids)):
            raise ValueError('Diagnostic snapshots must cover exact sorted relation IDs')
        if any(r.actual is not None and r.actual.relation_id != r.relation_id for r in self.actual_relations):
            raise ValueError('Diagnostic snapshot identity mismatch')
        return self


class FirmwareRelationSupportFailureReportV1(Contract):
    schema_version: Literal['firmware-relation-support-failure/v1'] = 'firmware-relation-support-failure/v1'
    failure_reason_code: Literal['incompatible_relation_claim', 'unsupported_relation_claim']
    generated_support_claim_count: Count
    referenced_support_claim_count: Count
    orphan_support_claim_count: Count
    referenced_supported_count: Count
    referenced_unsupported_count: Count
    referenced_incompatible_count: Count
    orphan_supported_count: Count
    orphan_unsupported_count: Count
    orphan_incompatible_count: Count
    failed_referenced_supports: list[FailedReferencedSupport] = Field(min_length=1, max_length=MAX_ITEMS)

    @model_validator(mode='after')
    def consistency(self):
        failures = self.failed_referenced_supports
        keys = [(e.result, e.support_claim_id, e.claim_type) for e in failures]
        if keys != sorted(keys) or len({e.support_claim_id for e in failures}) != len(failures):
            raise ValueError('Diagnostic failures must be unique and sorted')
        if (self.generated_support_claim_count != self.referenced_support_claim_count + self.orphan_support_claim_count
            or self.referenced_support_claim_count != self.referenced_supported_count + self.referenced_unsupported_count + self.referenced_incompatible_count
            or self.orphan_support_claim_count != self.orphan_supported_count + self.orphan_unsupported_count + self.orphan_incompatible_count
            or self.referenced_unsupported_count != sum(e.result == 'unsupported' for e in failures)
            or self.referenced_incompatible_count != sum(e.result == 'incompatible' for e in failures)):
            raise ValueError('Diagnostic counts mismatch')
        if not any(e.result + '_relation_claim' == self.failure_reason_code for e in failures):
            raise ValueError('Diagnostic failure reason mismatch')
        return self


class RelationSupportValidationErrorV2(RelationSupportError):
    def __init__(self, reason_code, failure_diagnostic):
        super().__init__(reason_code)
        self.failure_diagnostic = failure_diagnostic


def evaluation_counts(evaluation):
    entries = evaluation.support_claims
    counts = dict(generated_support_claim_count=len(entries),
        referenced_support_claim_count=sum(e.usage_status == 'referenced' for e in entries),
        orphan_support_claim_count=sum(e.usage_status == 'orphaned' for e in entries))
    for usage, prefix in [('referenced', 'referenced'), ('orphaned', 'orphan')]:
        for status in ('supported', 'unsupported', 'incompatible'):
            counts[f'{prefix}_{status}_count'] = sum(e.usage_status == usage and e.result == status for e in entries)
    return counts


def actual_snapshot(relation):
    if relation is None:
        return None
    attrs = relation.attributes.model_dump()
    schema = {'control_transfer': SafeTransfer, 'mmio_direction': SafeDirection,
              'vector_dispatch': SafeVector, 'mmio_containment': SafeContainment}[attrs['detail_type']]
    attrs = {k: v for k, v in attrs.items() if k in schema.model_fields}
    if 'mnemonic' in attrs and attrs['mnemonic'] is not None:
        from typing import get_args
        if attrs['mnemonic'] not in get_args(Mnemonic):
            attrs['mnemonic'] = 'not_allowlisted'
    def endpoint(value):
        return dict(entity_type=value.entity_type, entity_id=value.entity_id) if value else None
    return ActualRelation(relation_id=relation.relation_id, kind=relation.kind, status=relation.status,
        source=endpoint(relation.source), target=endpoint(relation.target), attributes=attrs)


def build_failure_diagnostic(evaluation, catalog):
    """Derive only allowed typed fields, from ALL completed evaluations."""
    failures = [e for e in evaluation.support_claims if e.usage_status == 'referenced' and e.result != 'supported']
    if not failures:
        return None
    relations = {r.relation_id: r for r in catalog.relations}
    entries = []
    for e in failures:
        claim = e.support_claim
        expected = claim.model_dump(exclude={'support_claim_id'})
        detail = None
        if isinstance(claim, ModelRelationFactClaim):
            actual = relations.get(claim.relation_id)
            if actual is not None and actual.kind == claim.expected_kind == 'mmio_access_direction' and actual.attributes.direction != claim.expected_direction:
                detail = 'direction_mismatch'
        entries.append(FailedReferencedSupport(support_claim_id=claim.support_claim_id, claim_type=claim.claim_type,
            result=e.result, reason_code=e.reason_code, mismatch_detail=detail, relation_ids=e.relation_ids,
            referencing_firmware_claims=sorted(e.referencing_firmware_claims, key=lambda r: (r.collection, r.claim_id)),
            expected=expected, actual_relations=[RelationSnapshot(relation_id=rid, actual=actual_snapshot(relations.get(rid)))
                for rid in sorted(set(e.relation_ids))]))
    # Preserve R2's first-in-model-order top-level reason, not sorted order.
    return FirmwareRelationSupportFailureReportV1(
        failure_reason_code=failures[0].result + '_relation_claim', **evaluation_counts(evaluation),
        failed_referenced_supports=sorted(entries, key=lambda e: (e.result, e.support_claim_id, e.claim_type)))


def validate_failure_diagnostic(diagnostic, evaluation, catalog):
    """Recompute all nine counts and exact typed content using complete evaluation.

    Standalone JSON parsing can check only internal arithmetic: non-failed entries
    intentionally are not copied into the failure artifact. This context validator
    is mandatory at creation; it does not infer omitted counts from failed entries.
    """
    checked = FirmwareRelationSupportFailureReportV1.model_validate(diagnostic.model_dump())
    if checked != build_failure_diagnostic(evaluation, catalog):
        raise ValueError('Diagnostic differs from complete evaluation')
    return checked
