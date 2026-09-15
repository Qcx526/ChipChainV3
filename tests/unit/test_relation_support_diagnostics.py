"""R3 safe complete failure diagnostics; all inputs here are synthetic."""
import hashlib
import json
from copy import deepcopy

import pytest
from pydantic import ValidationError

from chipchain.agents.model_outputs.firmware_v2 import ModelFirmwareAnalysisReportV2
from chipchain.agents.relation_support import RelationSupportError
from chipchain.agents.relation_support_v2 import (
    evaluate_relation_support_v2, enforce_referenced_support, validate_relation_support_v2,
    FirmwareRelationSupportReportV2,
)
from chipchain.agents import relation_support_diagnostics as diag
from chipchain.tools.firmware.relations import FirmwareStaticRelationCatalog, capabilities_for
from chipchain.integrations import deepseek_firmware as real
from chipchain.agents.runtime import AgentExecutionError
from tests.unit.test_firmware_relations import components, payload_for, fact_claim, patch_run, persisted
from tests.unit.test_firmware_orphan_support import with_orphans, orphan_persisted
from tests.unit.test_deepseek_firmware import config


@pytest.fixture
def diagnostic_case(components):
    # Synthetic analogues with familiar regression IDs; not imported real fixtures.
    value = components[1].model_dump(mode='json')
    value = json.loads(json.dumps(value).replace('f80000', 'f80f34').replace('f80008', 'f80eac'))
    for r in value['relations']:
        if r['relation_id'] == 'call-80004':
            r.update(relation_id='call-80f88', kind='control_transfer_unresolved', status='unresolved')
            r['target'] = dict(entity_type='address', entity_id='addr:816cc', address=0x816cc)
            r['attributes'].update(transfer_kind='indirect_call', call_semantics=False,
                original_reason='computed_or_ambiguous', mnemonic='blx')
        elif r['relation_id'] == 'edge-80000':
            r.update(relation_id='call-80abe', kind='direct_branch')
            r['attributes'].update(transfer_kind='direct_branch', call_semantics=False, mnemonic='b.w')
        elif r['relation_id'] == 'mmio-direction-80002':
            r['relation_id'] = 'mmio-direction-80eba'
            r['attributes'].update(direction='read', mnemonic='ldr')
        elif r['relation_id'] == 'vector-1':
            r['target'] = next(f for f in value['function_endpoints'] if f['entity_id'] == 'f80f34')
        r['capabilities'] = capabilities_for(r['kind'], r['status']).model_dump()
    catalog = FirmwareStaticRelationCatalog.model_validate(value)
    return payload_for(components), catalog


def invalid_claim(catalog, kind, sid=None):
    rid = {'reset':'call-80f88', 'uart':'call-80abe', 'direction':'mmio-direction-80eba',
           'vector':'vector-1'}.get(kind, 'call-80abe')
    c = fact_claim(next(r for r in catalog.relations if r.relation_id == rid), sid or kind)
    if kind in ('reset', 'uart', 'vector'):
        c.update(expected_kind='direct_call', expected_status='confirmed_static', expected_transfer_kind='direct_call')
        if kind == 'reset': c['expected_target_entity_id'] = 'f80eac'
    elif kind == 'direction': c['expected_direction'] = 'write'
    elif kind == 'unknown': c['relation_id'] = 'invented'
    elif kind == 'path':
        c = dict(support_claim_id=sid or kind, claim_type='static_call_path', source_function_id='f80f34',
                 target_function_id='f80eac', edge_relation_ids=['call-80abe','call-80f88'])
    else:
        c = dict(support_claim_id=sid or kind, claim_type='trigger_to_handler', source_entity_id='f80f34',
                 target_entity_id='f80eac', relation_ids=['call-80abe'])
    return c


def evaluation_for(case, kinds):
    p, catalog = case
    p = deepcopy(p)
    p['support_claims'] = [invalid_claim(catalog, k) for k in kinds]
    p['findings'][0]['support_claim_ids'] = [c['support_claim_id'] for c in p['support_claims']]
    return evaluate_relation_support_v2(ModelFirmwareAnalysisReportV2.model_validate(p), catalog)


@pytest.mark.parametrize('kind', ['reset','uart','direction','vector','trigger','unknown','path'])
def test_expected_actual_diagnostic_and_rejection(diagnostic_case, kind):
    evaluation = evaluation_for(diagnostic_case, [kind])
    with pytest.raises(diag.RelationSupportValidationErrorV2) as error:
        enforce_referenced_support(evaluation, diagnostic_case[1])
    assert str(error.value) == 'Model relation support validation failed'
    assert error.value.failure_category == 'relation_support_validation'
    report = error.value.failure_diagnostic
    assert diag.validate_failure_diagnostic(report, evaluation, diagnostic_case[1]) == report
    e = report.failed_referenced_supports[0]
    actual = e.actual_relations[0].actual
    assert e.referencing_firmware_claims[0].claim_id == 'finding-1'
    if kind == 'reset':
        assert e.expected.expected_kind == 'direct_call' and e.expected.expected_target_entity_id == 'f80eac'
        assert actual.kind == 'control_transfer_unresolved' and actual.status == 'unresolved'
        assert actual.attributes.transfer_kind == 'indirect_call' and actual.attributes.mnemonic == 'blx'
    elif kind == 'uart':
        assert actual.kind == 'direct_branch' and actual.attributes.mnemonic == 'b.w'
    elif kind == 'direction':
        assert e.expected.expected_direction == 'write'
        assert actual.attributes.direction == 'read' and actual.attributes.mnemonic == 'ldr'
        assert e.reason_code == 'relation_fact_mismatch' and e.mismatch_detail == 'direction_mismatch'
    elif kind == 'vector':
        assert actual.kind == 'vector_dispatch' and actual.target.entity_id == 'f80f34'
    elif kind == 'unknown':
        assert actual is None and e.reason_code == 'unknown_relation_id'
    elif kind == 'trigger':
        assert e.result == 'unsupported' and e.reason_code == 'static_facts_do_not_establish_claim'
    else:
        assert e.expected.edge_relation_ids == ['call-80abe','call-80f88']
        assert [s.relation_id for s in e.actual_relations] == sorted(e.expected.edge_relation_ids)


def test_complete_failures_and_determinism(diagnostic_case):
    evaluation = evaluation_for(diagnostic_case, ['reset','uart','trigger'])
    # Bad orphans participate in counts, never in failed_referenced_supports.
    orphan = evaluation.support_claims[0].model_dump()
    orphan['support_claim']['support_claim_id'] = 'orphan-bad'
    orphan.update(usage_status='orphaned', referencing_firmware_claims=[])
    from chipchain.agents.relation_support_v2 import SupportEvaluationEntry
    evaluation.support_claims.append(SupportEvaluationEntry.model_validate(orphan))
    d = diag.build_failure_diagnostic(evaluation, diagnostic_case[1])
    assert (d.generated_support_claim_count, d.referenced_support_claim_count, d.orphan_support_claim_count) == (4,3,1)
    assert d.referenced_incompatible_count == 2 and d.referenced_unsupported_count == 1
    assert d.orphan_incompatible_count == 1 and len(d.failed_referenced_supports) == 3
    assert [e.support_claim_id for e in d.failed_referenced_supports] == ['reset','uart','trigger']
    assert all(e.usage_status == 'referenced' for e in d.failed_referenced_supports)
    # Swapping same-result model entries leaves both R2 reason and sorted bytes identical.
    evaluation.support_claims[:2] = reversed(evaluation.support_claims[:2])
    assert diag.build_failure_diagnostic(evaluation, diagnostic_case[1]).model_dump_json() == d.model_dump_json()
    with pytest.raises(ValidationError):
        FirmwareRelationSupportReportV2.model_validate(dict(schema_version='firmware-relation-support/v2',
            support_claims=[e.model_dump() for e in evaluation.support_claims],
            **{k:v for k,v in d.model_dump().items() if k.endswith('_count') and k not in ('referenced_unsupported_count','referenced_incompatible_count')}))


@pytest.mark.parametrize('key', [k for k in diag.FirmwareRelationSupportFailureReportV1.model_fields if k.endswith('_count')])
def test_complete_evaluation_count_revalidation(diagnostic_case, key):
    evaluation = evaluation_for(diagnostic_case, ['reset','uart','trigger'])
    d = diag.build_failure_diagnostic(evaluation, diagnostic_case[1])
    # model_copy bypasses Pydantic to simulate a tampered in-memory object.
    altered = d.model_copy(update={key:getattr(d,key)+1})
    with pytest.raises(ValueError): diag.validate_failure_diagnostic(altered, evaluation, diagnostic_case[1])


def test_coordinated_count_and_snapshot_forgery_refused(diagnostic_case):
    evaluation = evaluation_for(diagnostic_case, ['reset'])
    d = diag.build_failure_diagnostic(evaluation, diagnostic_case[1])
    value = d.model_dump()
    value.update(generated_support_claim_count=2, orphan_support_claim_count=1, orphan_supported_count=1)
    structurally_valid = diag.FirmwareRelationSupportFailureReportV1.model_validate(value)
    with pytest.raises(ValueError): diag.validate_failure_diagnostic(structurally_valid, evaluation, diagnostic_case[1])
    value = d.model_dump()
    value['failed_referenced_supports'][0]['actual_relations'][0]['actual']['attributes']['mnemonic'] = 'b.w'
    with pytest.raises(ValueError):
        diag.validate_failure_diagnostic(diag.FirmwareRelationSupportFailureReportV1.model_validate(value), evaluation, diagnostic_case[1])


def failure_run(components, config, monkeypatch, tmp_path, *, secret_id=None):
    p = with_orphans(components)
    p['findings'][0]['summary'] = 'PRIVATE SECRET RAW PROVIDER TEXT'
    p['findings'][0]['support_claim_ids'].append('orphan-wrong')
    if secret_id:
        p['support_claims'][2]['support_claim_id'] = secret_id
        p['findings'][0]['support_claim_ids'][-1] = secret_id
    seen, _ = patch_run(components, monkeypatch, p)
    with pytest.raises(AgentExecutionError):
        real.run_real_firmware(tmp_path, config=config, enabled=True, output_root=tmp_path/'out',
                              context_mode='relation_v3', ghidra_home=tmp_path)
    assert len(seen) == 1
    return next((tmp_path/'out').glob('*/*'))


def test_safe_persistence_and_hash(components, config, monkeypatch, tmp_path):
    path = failure_run(components, config, monkeypatch, tmp_path)
    assert {p.name for p in path.iterdir()} == {'failure.json','invocation_attempts.jsonl','firmware_relation_support_failure.json'}
    blob = (path/'firmware_relation_support_failure.json').read_bytes()
    failure = json.loads((path/'failure.json').read_text())
    assert failure['diagnostic_persisted'] is True and failure['failed_referenced_support_count'] == 1
    assert failure['relation_support_failure_sha256'] == hashlib.sha256(blob).hexdigest()
    assert failure['relation_support_failure_schema'] == 'firmware-relation-support-failure/v1'
    for p in path.iterdir():
        text = p.read_text()
        assert 'PRIVATE SECRET RAW PROVIDER TEXT' not in text and 'RAW PROVIDER BODY' not in text
        assert all(key not in text for key in ['tool_calls','raw_encoding','evidence_ids','unresolved_questions','summary'])
    diag.FirmwareRelationSupportFailureReportV1.model_validate_json(blob)


@pytest.mark.parametrize('secret', ['configured', 'recognizable'])
def test_secret_scanners_prevent_diagnostic(components, config, monkeypatch, tmp_path, secret):
    sid = config.api_key.get_secret_value() if secret == 'configured' else 'sk-abcdefghijklmnop'
    path = failure_run(components, config, monkeypatch, tmp_path, secret_id=sid)
    assert {p.name for p in path.iterdir()} == {'failure.json','invocation_attempts.jsonl'}
    assert json.loads((path/'failure.json').read_text())['diagnostic_persisted'] is False
    assert all(sid not in p.read_text() for p in path.iterdir())


def test_oversize_still_rejects_with_basic_logs(components, config, monkeypatch, tmp_path):
    monkeypatch.setattr(diag, 'MAX_RELATION_SUPPORT_FAILURE_BYTES', 1)
    path = failure_run(components, config, monkeypatch, tmp_path)
    assert {p.name for p in path.iterdir()} == {'failure.json','invocation_attempts.jsonl'}
    assert json.loads((path/'failure.json').read_text())['diagnostic_persisted'] is False


@pytest.mark.parametrize('mutation', ['prose','identifier','mnemonic','vector_bound'])
def test_diagnostic_has_no_unbounded_text(diagnostic_case, mutation):
    evaluation = evaluation_for(diagnostic_case, ['reset'])
    value = diag.build_failure_diagnostic(evaluation, diagnostic_case[1]).model_dump()
    entry = value['failed_referenced_supports'][0]
    if mutation == 'prose': entry['summary'] = 'PRIVATE'
    elif mutation == 'identifier': entry['support_claim_id'] = 'PRIVATE SECRET RAW PROVIDER TEXT'
    elif mutation == 'mnemonic': entry['actual_relations'][0]['actual']['attributes']['mnemonic'] = 'PRIVATE'
    else: entry['expected']['expected_vector_index'] = 2**32
    with pytest.raises(ValidationError): diag.FirmwareRelationSupportFailureReportV1.model_validate(value)


def test_success_has_no_failure_diagnostic(persisted, orphan_persisted):
    for path in (persisted, orphan_persisted):
        assert len(list(path.iterdir())) == 6
        assert not (path/'firmware_relation_support_failure.json').exists()
        audit = json.loads((path/'firmware_relation_support.json').read_text())
        assert audit['schema_version'] == 'firmware-relation-support/v2'


def test_wiring_failure_has_no_evaluation_diagnostic(components):
    p = payload_for(components)
    p['findings'][0]['support_claim_ids'] = ['unknown-support']
    with pytest.raises(RelationSupportError) as error:
        validate_relation_support_v2(ModelFirmwareAnalysisReportV2.model_validate(p), components[1])
    assert not hasattr(error.value, 'failure_diagnostic')


def test_default_256_kib_budget_drops_whole_diagnostic(diagnostic_case, config, tmp_path):
    evaluation = evaluation_for(diagnostic_case, ['reset'])
    base = evaluation.support_claims[0]
    evaluation.support_claims = [base.model_copy(update={
        'support_claim':base.support_claim.model_copy(update={'support_claim_id':f'failure-{n:04d}'})
    }) for n in range(300)]
    diagnostic = diag.build_failure_diagnostic(evaluation, diagnostic_case[1])
    blob = json.dumps(diagnostic.model_dump(mode='json'), sort_keys=True, indent=2).encode()
    assert len(diagnostic.failed_referenced_supports) == 300
    assert len(blob) > diag.MAX_RELATION_SUPPORT_FAILURE_BYTES == 256 * 1024
    assert real.persist_relation_support_failure(diagnostic, tmp_path, config) == {'diagnostic_persisted':False}
    assert not (tmp_path/'firmware_relation_support_failure.json').exists()


def test_reference_and_snapshot_order_is_canonical(diagnostic_case):
    evaluation = evaluation_for(diagnostic_case, ['path'])
    from chipchain.agents.relation_support import FirmwareClaimReference
    evaluation.support_claims[0].referencing_firmware_claims = [
        FirmwareClaimReference(collection='issue_anchors',claim_id='anchor-z'),
        FirmwareClaimReference(collection='findings',claim_id='finding-z'),
        FirmwareClaimReference(collection='findings',claim_id='finding-a'),
    ]
    d = diag.build_failure_diagnostic(evaluation, diagnostic_case[1])
    refs = d.failed_referenced_supports[0].referencing_firmware_claims
    assert [(r.collection,r.claim_id) for r in refs] == [
        ('findings','finding-a'),('findings','finding-z'),('issue_anchors','anchor-z')]
    evaluation.support_claims[0].referencing_firmware_claims.reverse()
    assert diag.build_failure_diagnostic(evaluation, diagnostic_case[1]).model_dump_json() == d.model_dump_json()


def test_success_bytes_equal_frozen_r2_baseline(components):
    p = ModelFirmwareAnalysisReportV2.model_validate(with_orphans(components))
    evaluation = evaluate_relation_support_v2(p, components[1])
    assert diag.build_failure_diagnostic(evaluation, components[1]) is None
    # Computed using pristine 5754d155 relation_support_v2.py, before the R3 split.
    blob = validate_relation_support_v2(p, components[1]).model_dump_json().encode()
    assert hashlib.sha256(blob).hexdigest() == '701135ba9c7727ca069c1f6767f6e7a831bbba8cab823c6db2cc2324aabbc60b'
