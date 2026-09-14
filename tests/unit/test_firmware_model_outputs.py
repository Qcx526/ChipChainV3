"""ID-only transport, exact hydration and safe error categories; no real provider."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.agents.firmware import FirmwareSecurityAgent, validate_firmware_evidence
from chipchain.agents.firmware_evidence import collect_firmware_evidence
from chipchain.agents.model_outputs.firmware import (
    FirmwareBindingError, ModelFirmwareAnalysisReport, hydrate_firmware_report,
)
from chipchain.agents.runtime import AgentExecutionError, AgentStructuredOutputError
from chipchain.domain.provenance import AgentRole
from chipchain.integrations import deepseek, deepseek_firmware as real
from tests.fakes import fake_model
from tests.firmware_fakes import model_report_fixture
from tests.unit.test_deepseek_firmware import config, inputs, patch_inputs, script_provider
from tests.unit.test_firmware_grounding import report_with_all_objects

COLLECTIONS = ['findings', 'external_input_paths', 'reachable_behaviors', 'issue_anchors']


def test_hydration_exact_objects_order_isolation_and_no_mutation(inputs):
    expected = report_with_all_objects(inputs)
    model_report = model_report_fixture(expected)
    registry = collect_firmware_evidence(inputs)
    ids = list(registry)[-2:][::-1]
    model_report.findings[0].evidence_ids = ids
    before = inputs.model_dump_json()
    model_before = model_report.model_dump_json()
    report = hydrate_firmware_report(model_report, inputs)
    assert report.findings[0].evidence == [registry[eid] for eid in ids]
    assert [r.evidence_id for r in report.findings[0].evidence] == ids
    assert inputs.model_dump_json() == before and model_report.model_dump_json() == model_before
    assert report == hydrate_firmware_report(model_report, inputs)
    for name in COLLECTIONS:
        for item in getattr(report, name):
            assert all(ref == registry[ref.evidence_id] for ref in item.evidence)
            assert all(ref is not registry[ref.evidence_id] for ref in item.evidence)
    validate_firmware_evidence(report, inputs)
    report.findings[0].evidence[0].summary = 'Mutate only hydrated copy'
    assert inputs.model_dump_json() == before
    assert model_report.model_dump_json() == model_before


@pytest.mark.parametrize('collection', COLLECTIONS)
@pytest.mark.parametrize('defect', ['unknown', 'duplicate'])
def test_invalid_evidence_ids_fail_without_repair(inputs, collection, defect):
    report = model_report_fixture(report_with_all_objects(inputs))
    item = getattr(report, collection)[0]
    item.evidence_ids = ['not-supplied'] if defect == 'unknown' else item.evidence_ids * 2
    before = report.model_dump_json()
    with pytest.raises(FirmwareBindingError) as caught:
        hydrate_firmware_report(report, inputs)
    assert caught.value.reason_code == f'{defect}_evidence_id'
    assert report.model_dump_json() == before


@pytest.mark.parametrize('collection', COLLECTIONS)
@pytest.mark.parametrize('representation', ['evidence_field', 'object_in_ids'])
def test_model_cannot_supply_full_evidence_object(inputs, collection, representation):
    canonical = report_with_all_objects(inputs)
    payload = model_report_fixture(canonical).model_dump(mode='json')
    ref = getattr(canonical, collection)[0].evidence[0].model_dump(mode='json')
    if representation == 'evidence_field':
        payload[collection][0]['evidence'] = [ref]
    else:
        payload[collection][0]['evidence_ids'] = [ref]
    with pytest.raises(ValidationError):
        ModelFirmwareAnalysisReport.model_validate(payload)
    model = fake_model(ModelFirmwareAnalysisReport, payload)
    with pytest.raises(AgentStructuredOutputError) as caught:
        FirmwareSecurityAgent(model=model).invoke(inputs)
    assert caught.value.failure_category == 'structured_output_parsing'


@pytest.mark.parametrize('collection', COLLECTIONS)
def test_duplicate_claim_ids_rejected(inputs, collection):
    report = model_report_fixture(report_with_all_objects(inputs))
    item = getattr(report, collection)[0].model_copy(deep=True)
    getattr(report, collection).append(item)
    with pytest.raises(FirmwareBindingError) as caught:
        FirmwareSecurityAgent(model=fake_model(ModelFirmwareAnalysisReport, report)).invoke(inputs)
    assert caught.value.reason_code == 'duplicate_claim_id'


def test_unknown_external_path_reference_and_valid_cross_references(inputs):
    report = model_report_fixture(report_with_all_objects(inputs))
    report.reachable_behaviors[0].external_input_path_ids = ['p']
    output = FirmwareSecurityAgent(model=fake_model(ModelFirmwareAnalysisReport, report)).invoke(inputs)
    assert output.report.reachable_behaviors[0].external_input_path_ids == ['p']
    report.reachable_behaviors[0].external_input_path_ids = ['unknown-path']
    with pytest.raises(FirmwareBindingError) as caught:
        FirmwareSecurityAgent(model=fake_model(ModelFirmwareAnalysisReport, report)).invoke(inputs)
    assert caught.value.reason_code == 'unknown_external_input_path_id'


def test_schema_has_no_evidence_ref_and_only_id_lists():
    schema = ModelFirmwareAnalysisReport.model_json_schema()
    assert 'EvidenceRef' not in schema['$defs']
    assert '#/$defs/EvidenceRef' not in json.dumps(schema)
    for name in ('ModelFirmwareFinding', 'ModelExternalInputPath', 'ModelReachableBehavior', 'ModelFirmwareIssueAnchor'):
        claim = schema['$defs'][name]
        assert claim['additionalProperties'] is False
        assert 'evidence' not in claim['properties']
        assert claim['properties']['evidence_ids']['items']['type'] == 'string'


def test_empty_report_and_stub_do_not_need_hydration(inputs, monkeypatch):
    empty = ModelFirmwareAnalysisReport(case_id=inputs.case.case_id)
    assert not hydrate_firmware_report(empty, inputs).findings
    import chipchain.agents.firmware as firmware
    monkeypatch.setattr(firmware, 'hydrate_firmware_report', lambda *a: pytest.fail('Stub must not hydrate'))
    assert not FirmwareSecurityAgent().invoke(inputs).report.findings


@pytest.mark.parametrize('reason', [
    'unknown_evidence_id', 'duplicate_evidence_id', 'unknown_behavior_id', 'unknown_finding_id',
    'unknown_external_input_path_id', 'duplicate_claim_id', 'runtime_without_runtime_evidence',
    'verified_model_claim', 'missing_claim_evidence',
])
def test_reason_codes_in_sanitized_real_runner_failure(inputs, config, monkeypatch, tmp_path, reason):
    patch_inputs(monkeypatch, inputs)
    report = report_with_all_objects(inputs)
    if reason == 'unknown_evidence_id': report.findings[0].evidence[0].evidence_id = 'unknown'
    elif reason == 'duplicate_evidence_id': report.findings[0].evidence *= 2
    elif reason == 'unknown_behavior_id': report.processor_behavior_ids = ['unknown']
    elif reason == 'unknown_finding_id': report.issue_anchors[0].firmware_finding_ids = ['unknown']
    elif reason == 'unknown_external_input_path_id': report.reachable_behaviors[0].external_input_path_ids = ['unknown']
    elif reason == 'duplicate_claim_id': report.issue_anchors *= 2
    elif reason == 'runtime_without_runtime_evidence': report.reachable_behaviors[0].reachability_kind = 'runtime'
    elif reason == 'verified_model_claim': report.findings[0].epistemic_status = 'verified'
    elif reason == 'missing_claim_evidence': report.findings[0].evidence = []
    report.unresolved_questions = ['MODEL_PROSE_MUST_NOT_BE_SAVED']
    seen = script_provider(monkeypatch, report)
    with pytest.raises(AgentExecutionError):
        real.run_real_firmware(tmp_path, config=config, enabled=True, output_root=tmp_path / 'out')
    assert len(seen) == 1
    failure = next((tmp_path / 'out').rglob('failure.json'))
    assert json.loads(failure.read_text())['reason_code'] == reason
    assert {p.name for p in failure.parent.iterdir()} == {'failure.json', 'invocation_attempts.jsonl'}
    for p in failure.parent.iterdir():
        assert 'MODEL_PROSE_MUST_NOT_BE_SAVED' not in p.read_text()
        assert config.api_key.get_secret_value() not in p.read_text()


def test_flash_default_and_firmware_resolution(config, tmp_path):
    assert deepseek.DeepSeekConfig(api_key=config.api_key).model == 'deepseek-flash'
    env = tmp_path / 'selected.env'
    env.write_text('DEEPSEEK_API_KEY=synthetic-key\nCHIPCHAIN_HARDWARE_MODEL=deepseek-v4-pro\n')
    for environment in ({}, {'CHIPCHAIN_HARDWARE_MODEL': 'deepseek-v4-pro'}, {'CHIPCHAIN_FIRMWARE_MODEL':'deepseek-flash'}):
        c = deepseek.load_deepseek_config(environment, agent_role=AgentRole.FIRMWARE, env_file=env)
        assert c.model == 'deepseek-flash'
        assert c.descriptor(AgentRole.FIRMWARE).agent_role == 'firmware'
    assert deepseek.load_deepseek_config({}, agent_role=AgentRole.HARDWARE, env_file=env).model == 'deepseek-v4-pro'
    env.write_text(env.read_text()+'CHIPCHAIN_FIRMWARE_MODEL=deepseek-v4-pro\n')
    assert deepseek.load_deepseek_config({'CHIPCHAIN_FIRMWARE_MODEL':'deepseek-flash'},
                                       agent_role=AgentRole.FIRMWARE, env_file=env).model == 'deepseek-flash'


def test_corrected_runner_refuses_non_flash_before_io_or_api(config, tmp_path, monkeypatch):
    wrong = deepseek.DeepSeekConfig(api_key=config.api_key, model='deepseek-v4-pro')
    monkeypatch.setattr(real, 'prepare_firmware_input', lambda *a: pytest.fail('Must refuse before IO'))
    with pytest.raises(deepseek.DeepSeekConfigurationError, match='requires deepseek-flash'):
        real.run_real_firmware(tmp_path, config=wrong, enabled=True, output_root=tmp_path / 'out')
    assert not (tmp_path / 'out').exists()
