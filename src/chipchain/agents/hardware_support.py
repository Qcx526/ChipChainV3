"""Hardware B2 support evaluation, exact hydration and canonical report gates."""
from typing import Literal

from pydantic import Field, model_validator

from chipchain.agents.contracts import HardwareAgentInput, HardwareAgentOutput
from chipchain.agents.model_outputs.hardware_v2 import (
    SafeID, ModelHardwareAnalysisReportV2, ModelHardwareRelationFactSupport, ModelHardwareSupport,
)
from chipchain.agents.projections.hardware_relations import CompactInstruction
from chipchain.agents.runtime import AgentStructuredOutputError
from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.common import Contract
from chipchain.domain.hardware import HardwareAnalysisReport
from chipchain.tools.hardware.relation_claims import (
    CAPABILITY_FOR_CLAIM, HardwareRelationFactClaim, HardwareSemanticClaim, HardwareClaimSupport,
    check_hardware_claim,
)
from chipchain.tools.hardware.relations import (
    HardwareRelation, HardwareRelationCatalog, parse_hardware_relation_catalog, serialize_hardware_relation_catalog,
)

COLLECTIONS = {'findings': 'finding_id', 'trigger_hypotheses': 'hypothesis_id', 'abnormal_states': 'state_id'}


class HardwareSupportError(AgentStructuredOutputError):
    def __init__(self, reason_code, *, diagnostic=None, failed_count=0):
        super().__init__('Hardware supported report rejected', failure_category='hardware_support_validation')
        self.reason_code = reason_code
        self.failure_diagnostic = diagnostic
        self.failed_count = failed_count


class HardwareClaimReference(Contract):
    collection: Literal['findings', 'trigger_hypotheses', 'abnormal_states']
    claim_id: SafeID


class HardwareSupportEntry(Contract):
    support_claim: ModelHardwareSupport
    usage_status: Literal['referenced', 'orphaned']
    result: Literal['supported', 'unsupported', 'incompatible']
    reason: HardwareClaimSupport.model_fields['reason'].annotation
    relation_ids: list[SafeID]
    referencing_hardware_claims: list[HardwareClaimReference]

    @model_validator(mode='after')
    def wiring(self):
        refs = [(r.collection, r.claim_id) for r in self.referencing_hardware_claims]
        if bool(refs) != (self.usage_status == 'referenced') or refs != sorted(set(refs)):
            raise ValueError('Support usage/reference mismatch')
        if self.relation_ids != support_relation_ids(self.support_claim):
            raise ValueError('Support relation identity mismatch')
        return self


def support_relation_ids(claim):
    return [claim.relation_id] if isinstance(claim, ModelHardwareRelationFactSupport) else claim.relation_ids


def evaluation_counts(entries):
    counts = dict(generated_support_count=len(entries),
        referenced_support_count=sum(e.usage_status == 'referenced' for e in entries),
        orphan_support_count=sum(e.usage_status == 'orphaned' for e in entries))
    for usage, prefix in [('referenced', 'referenced'), ('orphaned', 'orphan')]:
        for status in ('supported', 'unsupported', 'incompatible'):
            counts[f'{prefix}_{status}_count'] = sum(e.usage_status == usage and e.result == status for e in entries)
    return counts


class HardwareSupportCounts(Contract):
    generated_support_count: int = Field(ge=0, strict=True)
    referenced_support_count: int = Field(ge=0, strict=True)
    orphan_support_count: int = Field(ge=0, strict=True)
    referenced_supported_count: int = Field(ge=0, strict=True)
    referenced_unsupported_count: int = Field(ge=0, strict=True)
    referenced_incompatible_count: int = Field(ge=0, strict=True)
    orphan_supported_count: int = Field(ge=0, strict=True)
    orphan_unsupported_count: int = Field(ge=0, strict=True)
    orphan_incompatible_count: int = Field(ge=0, strict=True)


class HardwareRelationSupportReportV1(HardwareSupportCounts):
    schema_version: Literal['hardware-relation-support/v1'] = 'hardware-relation-support/v1'
    support_claims: list[HardwareSupportEntry]

    @model_validator(mode='after')
    def success_invariants(self):
        ids = [e.support_claim.support_claim_id for e in self.support_claims]
        if len(ids) != len(set(ids)):
            raise ValueError('Duplicate audit support identity')
        if any(e.usage_status == 'referenced' and e.result != 'supported' for e in self.support_claims):
            raise ValueError('Successful audit cannot contain failed referenced support')
        if any(getattr(self, k) != v for k, v in evaluation_counts(self.support_claims).items()):
            raise ValueError('Support audit counts mismatch')
        return self


def collect_hardware_evidence(inputs: HardwareAgentInput):
    inputs = HardwareAgentInput.model_validate_json(inputs.model_dump_json())
    registry = {}
    for o in inputs.deterministic_observations.observations:
        refs = [*o.evidence, *(e for b in o.behaviors for e in b.evidence)]
        refs += [e for b in o.behaviors if b.decoded_instruction for e in b.decoded_instruction.evidence]
        for e in refs:
            if e.evidence_id in registry and registry[e.evidence_id] != e:
                raise HardwareSupportError('conflicting_evidence_identity')
            registry[e.evidence_id] = e
    return registry


def deterministic_hardware_ir(inputs):
    return ProcessorBehaviorIR(case_id=inputs.case.case_id,
        behaviors=[b.model_copy(deep=True) for o in inputs.deterministic_observations.observations for b in o.behaviors])


def validate_model_references(report, inputs):
    if report.case_id != inputs.case.case_id:
        raise HardwareSupportError('case_id_mismatch')
    behavior_ids = {b.behavior_id for b in deterministic_hardware_ir(inputs).behaviors}
    finding_ids = {f.finding_id for f in report.findings}
    if not set(report.processor_behavior_ids) <= behavior_ids:
        raise HardwareSupportError('unknown_behavior_id')
    if len(report.processor_behavior_ids) != len(set(report.processor_behavior_ids)):
        raise HardwareSupportError('duplicate_behavior_reference')
    for collection, key in COLLECTIONS.items():
        items = getattr(report, collection)
        ids = [getattr(i, key) for i in items]
        if len(ids) != len(set(ids)):
            raise HardwareSupportError('duplicate_hardware_claim_id')
        for item in items:
            if not set(item.processor_behavior_ids) <= behavior_ids:
                raise HardwareSupportError('unknown_behavior_id')
            if not set(getattr(item, 'hardware_finding_ids', [])) <= finding_ids:
                raise HardwareSupportError('unknown_finding_id')
            for field in ('processor_behavior_ids', 'evidence_ids', 'hardware_finding_ids'):
                values = getattr(item, field, [])
                if len(values) != len(set(values)):
                    raise HardwareSupportError('duplicate_item_reference')


def expand_expected_attributes(compact, actual: HardwareRelation):
    """Restore ONLY non-model fields from the bound relation, never repair assertions.

    Raw log text, decode evidence/operand AST/backend spelling/reason/mode are omitted
    from model supports. Every exposed compact field overwrites the template and is
    then compared by the frozen A3 checker. No signal/time/value guess or inference.
    """
    if compact is None:
        return None
    data = actual.attributes.model_dump(mode='json')
    supplied = compact.model_dump(mode='json')
    if supplied['kind'] != data['kind']:
        raise ValueError('Expected attribute kind mismatch')
    if isinstance(compact, CompactInstruction) and supplied['decoded_instruction'] is not None:
        if data['decoded_instruction'] is None:
            raise ValueError('Expected decode absent from relation')
        nested = {**data['decoded_instruction'], **supplied.pop('decoded_instruction')}
        data.update(supplied)
        data['decoded_instruction'] = nested
    else:
        data.update(supplied)
    return type(actual.attributes).model_validate(data)


def evaluate_model_support(claim, catalog):
    ids = support_relation_ids(claim)
    actual = next((r for r in catalog.relations if r.relation_id == (ids[0] if ids else None)), None)
    common = dict(claim_id=claim.support_claim_id)
    fact = isinstance(claim, ModelHardwareRelationFactSupport)
    if fact and actual is None:
        return HardwareClaimSupport(**common, status='incompatible', reason='unknown_relation', relation_ids=ids)
    try:
        # Unsupported semantic kinds are independent of expected fact attributes in A3.
        attrs = (expand_expected_attributes(claim.expected_attributes, actual)
                 if actual is not None and (fact or claim.semantic_kind in CAPABILITY_FOR_CLAIM) else None)
        typed = (HardwareRelationFactClaim(**common, relation_id=claim.relation_id,
                    expected_kind=claim.expected_kind, expected_status=claim.expected_status, expected_attributes=attrs)
                 if fact else HardwareSemanticClaim(**common, kind=claim.semantic_kind, relation_ids=ids,
                    expected_attributes=attrs, expected_status=claim.expected_status, start=claim.start, end=claim.end))
    except ValueError:
        # Structurally contradictory compact expectations are factual mismatch;
        # A3 classes/checker stay frozen and are never weakened to accept them.
        return HardwareClaimSupport(**common, status='incompatible', reason='exact_fact_mismatch', relation_ids=ids)
    return check_hardware_claim(catalog, typed)


def evaluate_all_supports(report, catalog):
    claims = {c.support_claim_id: c for c in report.support_claims}
    if len(claims) != len(report.support_claims):
        raise HardwareSupportError('duplicate_support_claim_id')
    wiring = {sid: [] for sid in claims}
    for collection, key in COLLECTIONS.items():
        for item in getattr(report, collection):
            ids = item.support_claim_ids
            if not ids or len(ids) != len(set(ids)):
                raise HardwareSupportError('missing_or_duplicate_support_reference')
            for sid in ids:
                if sid not in claims:
                    raise HardwareSupportError('unknown_support_claim_id')
                wiring[sid].append(HardwareClaimReference(collection=collection, claim_id=getattr(item, key)))
    entries = []
    for sid, claim in claims.items():
        result = evaluate_model_support(claim, catalog)
        refs = sorted(wiring[sid], key=lambda r: (r.collection, r.claim_id))
        entries.append(HardwareSupportEntry(support_claim=claim, usage_status='referenced' if refs else 'orphaned',
            result=result.status, reason=result.reason, relation_ids=result.relation_ids, referencing_hardware_claims=refs))
    return entries


def validate_supported_hardware_report(model_report, inputs, catalog):
    from chipchain.tools.hardware.relation_builder import build_hardware_relation_catalog
    from chipchain.tools.hardware.relations import hardware_relation_catalog_sha256
    rebuilt_input = build_hardware_relation_catalog(inputs, projection_descriptor=catalog.source.operational_projection)
    if hardware_relation_catalog_sha256(rebuilt_input) != hardware_relation_catalog_sha256(catalog):
        raise HardwareSupportError('input_catalog_mismatch')
    model_report = ModelHardwareAnalysisReportV2.model_validate_json(model_report.model_dump_json())
    catalog = parse_hardware_relation_catalog(serialize_hardware_relation_catalog(catalog))
    validate_model_references(model_report, inputs)
    entries = evaluate_all_supports(model_report, catalog)
    failed = [e for e in entries if e.usage_status == 'referenced' and e.result != 'supported']
    if failed:
        from chipchain.agents.hardware_support_diagnostics import build_hardware_support_failure
        diagnostic = None
        try:
            diagnostic = build_hardware_support_failure(entries, catalog)
        except ValueError:
            pass  # Diagnostic safety must never change rejection semantics.
        raise HardwareSupportError('referenced_support_failed', diagnostic=diagnostic, failed_count=len(failed))
    audit = HardwareRelationSupportReportV1(support_claims=entries, **evaluation_counts(entries))
    registry = collect_hardware_evidence(inputs)
    relations = {r.relation_id: r for r in catalog.relations}
    supports = {e.support_claim.support_claim_id: e for e in entries}
    data = model_report.model_dump(mode='json', exclude={'support_claims'})
    for collection in COLLECTIONS:
        for item in data[collection]:
            ids = item.pop('evidence_ids')
            if not set(ids) <= registry.keys():
                raise HardwareSupportError('unknown_evidence_id')
            support_ids = item.pop('support_claim_ids')
            covered = set()
            for sid in support_ids:
                available = {eid for rid in supports[sid].relation_ids if rid in relations for eid in relations[rid].evidence_ids}
                if not available.intersection(ids):
                    raise HardwareSupportError('unrelated_support_evidence')
                covered.update(available)
            if not set(ids) <= covered:
                raise HardwareSupportError('uncovered_item_evidence')
            item['evidence'] = [registry[eid].model_dump(mode='json') for eid in ids]
    # Explicit post-schema epistemic gate also catches VERIFIED trigger before
    # the narrower canonical CandidateStatus rejects it during construction.
    for collection in COLLECTIONS:
        for item in data[collection]:
            if item['epistemic_status'] == 'verified':
                raise HardwareSupportError('unsupported_verified_status')
            if collection == 'trigger_hypotheses' and item['epistemic_status'] not in ('hypothesized', 'inferred'):
                raise HardwareSupportError('hypothesis_status')
    try:
        report = HardwareAnalysisReport.model_validate(data)
        output = HardwareAgentOutput(report=report, processor_behavior_ir=deterministic_hardware_ir(inputs))
        from chipchain.agents.hardware import validate_hardware_evidence
        from chipchain.integrations.deepseek_hardware import validate_real_report
        validate_hardware_evidence(report, inputs)
        validate_real_report(output)
    except ValueError:
        raise HardwareSupportError('canonical_grounding_failure') from None
    return output, audit


def revalidate_hardware_support_artifact(audit, report, inputs, catalog):
    """Future export boundary: rebuild wiring, rerun A3, hydrate and compare canonical data."""
    audit = HardwareRelationSupportReportV1.model_validate_json(audit.model_dump_json())
    data = report.model_dump(mode='json')
    index = {}
    for collection, key in COLLECTIONS.items():
        for item in data[collection]:
            item['evidence_ids'] = [e['evidence_id'] for e in item.pop('evidence')]
            item['support_claim_ids'] = []
            index[(collection, item[key])] = item
    data['support_claims'] = [e.support_claim.model_dump(mode='json') for e in audit.support_claims]
    for entry in audit.support_claims:
        for ref in entry.referencing_hardware_claims:
            item = index.get((ref.collection, ref.claim_id))
            if item is None:
                raise HardwareSupportError('unknown_audit_item_reference')
            item['support_claim_ids'].append(entry.support_claim.support_claim_id)
    checked, rebuilt = validate_supported_hardware_report(ModelHardwareAnalysisReportV2.model_validate(data), inputs, catalog)
    if rebuilt != audit or checked.report != report:
        raise HardwareSupportError('support_artifact_mismatch')
    return rebuilt
