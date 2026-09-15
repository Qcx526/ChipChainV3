"""R2 support usage policy, audit reconstruction, and historical v1 compatibility."""
import json

import pytest
from pydantic import ValidationError

from chipchain.agents import relation_support_v2 as policy
from chipchain.agents.model_outputs.firmware_v2 import ModelFirmwareAnalysisReportV2
from chipchain.agents.relation_support import (
    COLLECTIONS, FirmwareRelationSupportReport, RelationSupportError,
    validate_relation_support, validate_support_artifact,
)
from chipchain.execution.reviewed_output import _validate, export_reviewed_output
from chipchain.integrations import deepseek_firmware as real
from tests.unit.test_deepseek_firmware import config
from tests.unit.test_firmware_relations import components, payload_for, invoke, patch_run, persisted


def with_orphans(components):
    p = payload_for(components)
    good = p['support_claims'][0]
    p['support_claims'] += [
        dict(good, support_claim_id='orphan-good'),
        dict(good, support_claim_id='orphan-wrong', expected_target_entity_id='invented'),
        dict(good, support_claim_id='orphan-unknown', relation_id='unknown-relation'),
        dict(support_claim_id='orphan-trigger', claim_type='trigger_to_handler',
             source_entity_id='f80008', target_entity_id='f80010', relation_ids=['edge-80000']),
    ]
    return p


def test_all_orphan_results_preserved_without_canonical_effect(components):
    baseline, _, _ = invoke(components, payload_for(components))
    output, audit, _ = invoke(components, with_orphans(components))
    assert output == baseline
    assert audit.schema_version == 'firmware-relation-support/v2'
    assert [(e.usage_status, e.result) for e in audit.support_claims] == [
        ('referenced', 'supported'), ('orphaned', 'supported'),
        ('orphaned', 'incompatible'), ('orphaned', 'incompatible'), ('orphaned', 'unsupported'),
    ]
    assert audit.support_claims[3].reason_code == 'unknown_relation_id'
    assert audit.support_claims[3].relation_ids == ['unknown-relation']
    assert policy.support_audit_counts(audit.support_claims) == dict(
        generated_support_claim_count=5, referenced_support_claim_count=1, orphan_support_claim_count=4,
        referenced_supported_count=1, orphan_supported_count=1, orphan_unsupported_count=1, orphan_incompatible_count=2,
    )
    restored = policy.FirmwareRelationSupportReportV2.model_validate_json(audit.model_dump_json())
    assert policy.validate_support_artifact_v2(restored, output.report, components[1]) == audit
    assert 'support_claim' not in output.report.model_dump_json()


def test_all_orphan_empty_report(components):
    p = with_orphans(components)
    p['findings'] = []
    output, audit, _ = invoke(components, p)
    assert all(not getattr(output.report, name) for name in COLLECTIONS)
    assert audit.generated_support_claim_count == audit.orphan_support_claim_count == 5
    assert audit.referenced_supported_count == audit.referenced_support_claim_count == 0
    assert all(e.usage_status == 'orphaned' and not e.referencing_firmware_claims for e in audit.support_claims)
    policy.validate_support_artifact_v2(audit, output.report, components[1])


def test_evaluate_every_support_before_referenced_rejection(components, monkeypatch):
    p = with_orphans(components)
    p['support_claims'][0]['expected_target_entity_id'] = 'invented'
    evaluate = policy.evaluate_support
    seen = []
    def spy(claim, catalog):
        seen.append(claim.support_claim_id)
        return evaluate(claim, catalog)
    monkeypatch.setattr(policy, 'evaluate_support', spy)
    with pytest.raises(RelationSupportError) as error:
        policy.validate_relation_support_v2(ModelFirmwareAnalysisReportV2.model_validate(p), components[1])
    assert error.value.reason_code == 'incompatible_relation_claim'
    assert seen == [c['support_claim_id'] for c in p['support_claims']]


@pytest.mark.parametrize('defect', ['orphan_with_ref', 'referenced_empty', 'referenced_incompatible', 'referenced_unsupported'])
def test_entry_usage_invariants(components, defect):
    _, audit, _ = invoke(components, with_orphans(components))
    entry = audit.support_claims[0].model_dump()
    if defect == 'orphan_with_ref': entry['usage_status'] = 'orphaned'
    elif defect == 'referenced_empty': entry['referencing_firmware_claims'] = []
    else: entry['result'] = defect.removeprefix('referenced_')
    with pytest.raises(ValidationError): policy.SupportAuditEntryV2.model_validate(entry)


@pytest.mark.parametrize('key', list(policy.SupportAuditCounts.model_fields))
def test_audit_counts_are_recomputed(components, key):
    _, audit, _ = invoke(components, with_orphans(components))
    data = audit.model_dump()
    data[key] += 1
    with pytest.raises(ValidationError): policy.FirmwareRelationSupportReportV2.model_validate(data)


@pytest.fixture
def orphan_persisted(components, config, monkeypatch, tmp_path):
    seen, _ = patch_run(components, monkeypatch, with_orphans(components))
    path = real.run_real_firmware(tmp_path, config=config, enabled=True, output_root=tmp_path/'out',
                                 context_mode='relation_v3', ghidra_home=tmp_path)
    assert len(seen) == 1
    return path


def test_orphan_diagnostics_persistence_export_and_reevaluation(orphan_persisted, config, tmp_path, monkeypatch):
    files = {p.name: p.read_bytes() for p in orphan_persisted.iterdir()}
    seen = []
    evaluate = policy.evaluate_support
    def spy(claim, catalog):
        seen.append(claim.support_claim_id)
        return evaluate(claim, catalog)
    monkeypatch.setattr(policy, 'evaluate_support', spy)
    _, invocation, _ = _validate(files, config.api_key.get_secret_value())
    assert seen == ['support-1', 'orphan-good', 'orphan-wrong', 'orphan-unknown', 'orphan-trigger']
    assert invocation.structured_support_claim_count == invocation.generated_support_claim_count == 5
    assert invocation.supported_support_claim_count == 2
    assert invocation.referenced_supported_count == 1 and invocation.orphan_incompatible_count == 2
    dest = export_reviewed_output(orphan_persisted, phase='synthetic-r2', accepted=True, reviewed_root=tmp_path/'reviewed')
    assert all((dest/name).read_bytes() == content for name, content in files.items())


@pytest.mark.parametrize('defect', ['orphan_result', 'reason', 'relation_ids', 'orphan_ref', 'duplicate_id',
    'duplicate_ref', 'remove_only_reference', *policy.SupportAuditCounts.model_fields])
def test_v2_exporter_rejects_fabricated_audit(orphan_persisted, config, defect):
    files = {p.name: p.read_bytes() for p in orphan_persisted.iterdir()}
    audit = json.loads(files['firmware_relation_support.json'])
    entries = audit['support_claims']
    if defect in policy.SupportAuditCounts.model_fields:
        invocation = json.loads(files['invocation.json'])
        invocation[defect] += 1
        files['invocation.json'] = json.dumps(invocation).encode()
    elif defect == 'orphan_result':
        entries[2]['result'] = 'supported'
        audit['orphan_supported_count'] += 1
        audit['orphan_incompatible_count'] -= 1
    elif defect == 'reason': entries[3]['reason_code'] = 'relation_fact_mismatch'
    elif defect == 'relation_ids': entries[3]['relation_ids'] = ['edge-80000']
    elif defect == 'orphan_ref': entries[2]['referencing_firmware_claims'] = entries[0]['referencing_firmware_claims']
    elif defect == 'duplicate_id': entries[1]['support_claim']['support_claim_id'] = 'support-1'
    elif defect == 'duplicate_ref': entries[0]['referencing_firmware_claims'] *= 2
    elif defect == 'remove_only_reference':
        entries[0].update(usage_status='orphaned', referencing_firmware_claims=[])
        audit.update(referenced_support_claim_count=0, referenced_supported_count=0,
                     orphan_support_claim_count=5, orphan_supported_count=2)
    files['firmware_relation_support.json'] = json.dumps(audit).encode()
    with pytest.raises((ValueError, RelationSupportError)): _validate(files, config.api_key.get_secret_value())


def test_v1_policy_and_artifact_compatibility(components, persisted, config, tmp_path):
    output, _, _ = invoke(components, payload_for(components))
    audit = validate_relation_support(ModelFirmwareAnalysisReportV2.model_validate(payload_for(components)), components[1])
    assert isinstance(audit, FirmwareRelationSupportReport)
    assert audit.schema_version == 'firmware-relation-support/v1'
    assert validate_support_artifact(audit, output.report, components[1]) == audit
    with pytest.raises(RelationSupportError) as error:
        validate_relation_support(ModelFirmwareAnalysisReportV2.model_validate(with_orphans(components)), components[1])
    assert error.value.reason_code == 'unused_support_claim'
    # Exercise the same exporter with historical v1 artifact/invocation shapes.
    files = {p.name: p.read_bytes() for p in persisted.iterdir()}
    files['firmware_relation_support.json'] = audit.model_dump_json().encode()
    invocation = json.loads(files['invocation.json'])
    for key in policy.SupportAuditCounts.model_fields: invocation.pop(key)
    files['invocation.json'] = json.dumps(invocation).encode()
    _validate(files, config.api_key.get_secret_value())
    for name, content in files.items(): (persisted/name).write_bytes(content)
    export_reviewed_output(persisted, phase='synthetic-v1', accepted=True, reviewed_root=tmp_path/'reviewed')


def test_prompt_schema_identities_unchanged():
    import hashlib
    from chipchain.agents.prompts.firmware_v2 import SYSTEM_PROMPT
    assert hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest() == '10573f3efba97bed7a44d491e4915197f57d771e90b4143248bf19842b685bff'
    schema = json.dumps(ModelFirmwareAnalysisReportV2.model_json_schema(), sort_keys=True, separators=(',', ':'))
    assert hashlib.sha256(schema.encode()).hexdigest() == '512974761886482b973ed4230e02f6aa56be9812b3a62be1588e0aa0bb516248'


def test_referenced_failure_precedes_hydration(components, monkeypatch):
    from chipchain.agents import firmware
    def forbidden(*args, **kwargs):
        pytest.fail('Hydration must not execute after failed support validation')
    monkeypatch.setattr(firmware, 'hydrate_firmware_report', forbidden)
    p = with_orphans(components)
    p['findings'][0]['support_claim_ids'].append('orphan-wrong')
    with pytest.raises(RelationSupportError): invoke(components, p)
