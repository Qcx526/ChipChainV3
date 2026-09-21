"""Small synthetic declarations only; no model outputs or runtime execution."""
import copy
import json

import pytest

from chipchain.cross_layer import capability_compatibility as xl2
from chipchain.firmware.capability import FirmwareCapabilityInput, NumericDomain, build_firmware_capability
from chipchain.hardware.behavior_contract import HardwareBehaviorContractInput, build_hardware_behavior_contract
from tests.unit.test_firmware_capability import synthetic_input
from tests.unit.test_hardware_behavior_contract import complete_input


def inputs(kind='CSR_WRITE'):
    fw, hw = synthetic_input(), complete_input()
    fw['architecture'] = fw['scope']['target']['architecture'] = 'riscv'
    fw['scope']['target']['word_size_bits'] = 32
    fw['scope']['platform_id'] = 'synthetic-platform'
    fw['scope']['assumptions'] = []
    fw['conditions'] = []
    p = fw['primitives'][0]
    p.update(architecture='riscv', kind=kind, condition_ids=[], constraint_ids=['resource', 'csr', 'value', 'width'])
    p['control'].update(status='not_established', dimensions=[], support_basis='not_established')
    common = {k: fw[k] for k in ('source_artifact_ids', 'evidence_ids', 'provenance')}
    fw['constraints'] = [dict(constraint_id='resource', kind='target_resource', resource_kind='csr', identity='synthetic-csr-bank', **common),
        dict(constraint_id='csr', kind='CSR', identity='synthetic-status', **common),
        dict(constraint_id='value', kind='value', domain=dict(minimum=0, maximum=255), **common),
        dict(constraint_id='width', kind='access_width', domain=dict(exact=32), **common)]
    common_hw = {k: hw[k] for k in ('source_artifact_ids', 'evidence_ids', 'provenance')}
    hw['preconditions'] = []
    hw['trigger'] = [dict(condition_id='hw:csr', condition_kind='CSR_access', description='合成 CSR 写入要求',
        formalization_status='formalized', access=dict(atom_id='hw:atom', kind='csr_access', csr_identity='synthetic-status',
            access='write', value_constraint=dict(operator='eq', value=0)), **common_hw)]
    return fw, hw


def build_pair(fw, hw):
    return (build_firmware_capability(FirmwareCapabilityInput.model_validate(fw)),
            build_hardware_behavior_contract(HardwareBehaviorContractInput.model_validate(hw)))


def compare(fw=None, hw=None):
    if fw is None:
        fw, hw = inputs()
    return xl2.compare_capability_contract(*build_pair(fw, hw))


def trigger_result(result, name='hw:csr'):
    return next(r for r in result.requirement_results if r.requirement_id == name)


def mmio_inputs():
    fw, hw = inputs('MMIO_WRITE')
    fw['constraints'][0].update(resource_kind='mmio', identity='synthetic-peripheral')
    common = {k: fw[k] for k in ('source_artifact_ids', 'evidence_ids', 'provenance')}
    fw['constraints'][1] = dict(constraint_id='address', kind='address', domain=dict(minimum=0x1000, maximum=0x10ff), **common)
    fw['primitives'][0]['constraint_ids'] = ['resource', 'address', 'value', 'width']
    hw['trigger'][0].update(condition_kind='MMIO_access', access=dict(atom_id='hw:mmio-atom', kind='mmio_access',
        address=0x1000, access='write', width_bits=32, value_constraint=dict(operator='eq', value=0)))
    return fw, hw


def add_precondition(fw, hw, kind='privilege', subject='privilege', value='M'):
    common = {k: hw[k] for k in ('source_artifact_ids', 'evidence_ids', 'provenance')}
    hw['preconditions'].append(dict(condition_id='hw:pre', condition_kind=kind, formalization_status='formalized',
        description='合成前置条件', required_relation=dict(subject=subject, operator='eq', operands=[value]), **common))
    return fw, hw


def ordered_inputs():
    fw, hw = inputs()
    second = copy.deepcopy(fw['primitives'][0]); second['primitive_id'] = 'fw:second'
    second['constraint_ids'] = ['resource', 'csr:second', 'value', 'width']
    fw['primitives'].append(second)
    c = copy.deepcopy(fw['constraints'][1]); c.update(constraint_id='csr:second', identity='synthetic-second')
    fw['constraints'].append(c)
    common = {k:fw[k] for k in ('source_artifact_ids', 'evidence_ids', 'provenance')}
    fw['constraints'].append(dict(constraint_id='fw:order', kind='ordering', before_primitive_id='primitive:write',
        after_primitive_id='fw:second', max_gap_events=5, **common))
    second = copy.deepcopy(hw['trigger'][0]); second['condition_id'] = 'hw:second'
    second['access'].update(atom_id='hw:second-atom', csr_identity='synthetic-second')
    hw['trigger'].append(second)
    common_hw = {k:hw[k] for k in ('source_artifact_ids', 'evidence_ids', 'provenance')}
    hw['trigger'].append(dict(condition_id='hw:order', condition_kind='ordering', formalization_status='formalized',
        description='合成声明顺序', ordering=dict(atom_id='hw:order-atom', kind='ordering',
            before_atom_id='hw:csr', after_atom_id='hw:second', max_gap_events=10), **common_hw))
    return fw, hw


def test_positive_csr_and_downstream_not_assessed():
    result = compare()
    assert result.overall_result == 'compatible'
    assert trigger_result(result).matched_primitive_ids == ['primitive:write']
    assert result.provenance == 'derived_from_typed_contracts'
    assert {r.section for r in result.downstream_verification_requirements} == {'deviation', 'observation'}
    assert all(r.state == 'present_not_assessed' for r in result.downstream_verification_requirements)
    assert 'preconditions_missing' in result.unassessed_contract_sections


@pytest.mark.parametrize('architecture,outcome', [('riscv', 'compatible'), ('arm', 'incompatible'), ('unknown', 'unknown')])
def test_architecture_gate(architecture, outcome):
    fw, hw = inputs()
    fw['architecture'] = fw['scope']['target']['architecture'] = fw['primitives'][0]['architecture'] = architecture
    if architecture == 'unknown':
        fw['scope']['formalization_status'] = fw['primitives'][0]['formalization_status'] = 'partially_formalized'
    result = compare(fw, hw)
    assert result.overall_result == outcome
    assert next(c for c in result.platform_result.checks if c.dimension == 'architecture').outcome == outcome


@pytest.mark.parametrize('platform,outcome', [('synthetic-platform','compatible'), ('other-platform','incompatible'), (None,'unknown')])
def test_platform_gate(platform, outcome):
    fw, hw = inputs(); fw['scope']['platform_id'] = platform
    assert compare(fw,hw).overall_result == outcome


def test_known_processor_conflict_only_in_shared_platform_context():
    fw, hw = inputs(); fw['scope']['target']['processor_id'] = 'different-core'
    assert compare(fw, hw).overall_result == 'incompatible'
    fw['scope']['platform_id'] = None
    assert compare(fw, hw).overall_result == 'unknown'


@pytest.mark.parametrize('direction,required,outcome', [('CSR_READ','read','compatible'), ('CSR_WRITE','write','compatible'),
    ('CSR_READ','write','incompatible'), ('CSR_WRITE','read','incompatible'), ('CSR_READ','either','compatible')])
def test_csr_direction(direction, required, outcome):
    fw, hw = inputs(direction); hw['trigger'][0]['access']['access'] = required
    assert compare(fw,hw).overall_result == outcome


@pytest.mark.parametrize('identity,outcome', [('synthetic-status','compatible'), ('different-csr','incompatible'), ('UNKNOWN','unknown'), (None,'unknown')])
def test_csr_identity(identity, outcome):
    fw, hw = inputs()
    if identity is None:
        fw['constraints'] = [c for c in fw['constraints'] if c['kind'] != 'CSR']
        fw['primitives'][0]['constraint_ids'].remove('csr')
        fw['primitives'][0]['formalization_status'] = 'partially_formalized'
    else:
        fw['constraints'][1]['identity'] = identity
    assert compare(fw,hw).overall_result == outcome


def test_csr_numeric_address_is_not_guessed_from_name():
    fw, hw = inputs(); hw['trigger'][0]['access']['csr_address'] = 0x300
    assert compare(fw,hw).overall_result == 'unknown'


@pytest.mark.parametrize('address,outcome', [(0x1000,'compatible'),(0x10ff,'compatible'),(0x2000,'incompatible')])
def test_mmio_range(address,outcome):
    fw, hw = mmio_inputs(); hw['trigger'][0]['access']['address'] = address
    assert compare(fw,hw).overall_result == outcome


@pytest.mark.parametrize('provided,outcome', [({'exact':0x1000},'compatible'),({'exact':0x2000},'incompatible'),(None,'unknown')])
def test_mmio_exact_or_missing(provided,outcome):
    fw, hw = mmio_inputs()
    if provided is not None:
        fw['constraints'][1]['domain'] = provided
    else:
        fw['constraints'] = [c for c in fw['constraints'] if c['kind'] != 'address']
        fw['primitives'][0]['constraint_ids'].remove('address')
        fw['primitives'][0]['formalization_status'] = 'partially_formalized'
    assert compare(fw,hw).overall_result == outcome


def test_mmio_width_and_unsupported_huge_address():
    fw, hw = mmio_inputs(); hw['trigger'][0]['access']['width_bits'] = 8
    assert compare(fw,hw).overall_result == 'incompatible'
    hw['trigger'][0]['access']['width_bits'] = 32
    hw['trigger'][0]['access']['address'] = 1 << 100
    assert compare(fw,hw).overall_result == 'unknown'


@pytest.mark.parametrize('provided,required,quantifier,outcome', [
    ({'exact':0},{'exact':0},'unspecified','compatible'),
    ({'exact':5},{'exact':0},'unspecified','incompatible'),
    ({'minimum':0,'maximum':255},{'exact':0},'unspecified','compatible'),
    ({'minimum':0,'maximum':255},{'exact':256},'unspecified','incompatible'),
    ({'minimum':0,'maximum':255},{'minimum':0,'maximum':255},'contains_all','compatible'),
    ({'minimum':0,'maximum':255},{'minimum':0,'maximum':1024},'contains_all','incompatible'),
    ({'minimum':0,'maximum':255},{'minimum':128,'maximum':512},'contains_all','incompatible'),
    ({'minimum':0,'maximum':1024},{'minimum':0,'maximum':255},'contains_all','compatible'),
    ({'minimum':0,'maximum':255},{'minimum':0,'maximum':1024},'unspecified','unknown'),
    ({'exact':5},{'minimum':5,'maximum':5},'unspecified','compatible'),
    ({'controlled_bits':255,'bit_width':8},{'exact':0},'unspecified','unknown'),
    ({'mask':255,'masked_value':0},{'exact':0},'unspecified','unknown'),
])
def test_numeric_direction(provided,required,quantifier,outcome):
    assert xl2.compare_numeric_domains(NumericDomain(**provided), NumericDomain(**required), quantifier=quantifier).outcome == outcome


def test_xl1_range_has_no_quantifier_even_when_ranges_overlap():
    fw, hw = inputs(); hw['trigger'][0]['access']['value_constraint'] = dict(operator='in_range', range_min=0, range_max=1024)
    result = compare(fw,hw)
    assert result.overall_result == 'unknown'
    assert any(c.reason == 'RANGE_QUANTIFIER_UNSPECIFIED' for c in trigger_result(result).alternatives[0].checks)


def test_memory_cannot_supply_csr_access():
    original = synthetic_input(); fw, hw = inputs()
    fw['primitives'] = original['primitives']; fw['constraints'] = original['constraints']; fw['conditions'] = original['conditions']
    fw['primitives'][0]['architecture'] = 'riscv'
    result = compare(fw,hw)
    assert result.overall_result == 'incompatible'
    assert trigger_result(result).alternatives[0].checks[0].reason == 'EXPLICIT_RESOURCE_CLASS_CONFLICT'


@pytest.mark.parametrize('value,outcome', [('M','compatible'), ('U','incompatible'), (None,'unknown')])
def test_privilege(value,outcome):
    fw, hw = add_precondition(*inputs())
    if value:
        common = {k: fw[k] for k in ('source_artifact_ids','evidence_ids','provenance')}
        fw['constraints'].append(dict(constraint_id='priv', kind='privilege', identity=value, **common))
        fw['primitives'][0]['constraint_ids'].append('priv')
    assert compare(fw,hw).overall_result == outcome


@pytest.mark.parametrize('kind,subject', [('register_state','x1'),('execution_context','execution_context')])
def test_state_conditions_are_typed_and_do_not_use_function_names(kind,subject):
    fw, hw = add_precondition(*inputs(),kind=kind,subject=subject,value=4)
    common = {k: fw[k] for k in ('source_artifact_ids','evidence_ids','provenance')}
    fw['conditions'] = [dict(condition_id='state', condition_kind=kind, formalization_status='formalized',
        predicate=dict(subject=subject, operator='eq', operands=[4]), description='synthetic', **common)]
    fw['primitives'][0]['condition_ids'] = ['state']
    assert compare(fw,hw).overall_result == 'compatible'
    fw['conditions'][0]['predicate']['operands'] = [5]
    assert compare(fw,hw).overall_result == 'incompatible'
    fw['conditions'] = []; fw['primitives'][0]['condition_ids'] = []
    fw['entry']['function_name'] = subject
    assert compare(fw,hw).overall_result == 'unknown'


@pytest.mark.parametrize('status,outcome', [('not_established','unknown'),('input_influenced','unknown'),('bounded_external_control','compatible')])
def test_only_explicit_control_requirement_invokes_gate(status,outcome):
    fw, hw = add_precondition(*inputs(),kind='other',subject='external_control.value',value=True)
    if status != 'not_established':
        fw['primitives'][0]['control'].update(status=status,dimensions=['value'],support_basis='synthetic_definition')
    assert compare(fw,hw).overall_result == outcome
    hw['preconditions'] = []
    assert compare(fw,hw).overall_result == 'compatible'


def instruction_inputs(primitive_kind):
    fw, hw = inputs(); p = fw['primitives'][0]
    p.update(kind=primitive_kind,constraint_ids=['resource'])
    fw['constraints'] = [fw['constraints'][0]]
    fw['constraints'][0].update(resource_kind='instruction', identity='synthetic-instruction')
    if primitive_kind == 'DIRECT_CONTROL_TRANSFER':
        p.update(target_status='resolved_direct',transfer_kind='direct_jump')
        fw['constraints'][0]['resource_kind'] = 'control_flow'
        common={k:fw[k] for k in ('source_artifact_ids','evidence_ids','provenance')}
        fw['constraints'].append(dict(constraint_id='target',kind='target_set',targets=[0x100346],**common))
        p['constraint_ids'].append('target')
    common_hw={k:hw[k] for k in ('source_artifact_ids','evidence_ids','provenance')}
    hw['trigger'] = [dict(condition_id='hw:instruction',condition_kind='instruction',formalization_status='formalized',
        description='synthetic instruction',instructions=[dict(atom_id='i',architecture='riscv',mnemonic='addi')],**common_hw)]
    return fw,hw


def test_control_transfer_cannot_be_retyped_into_instruction():
    fw,hw=instruction_inputs('DIRECT_CONTROL_TRANSFER')
    result=compare(fw,hw)
    assert result.overall_result=='unknown'
    assert result.requirement_results[0].alternatives[0].checks[0].reason=='NO_SUPPORTED_MAPPING'


def test_instruction_sequence_strings_are_not_typed_mnemonics():
    fw,hw=instruction_inputs('INSTRUCTION_EXECUTION')
    fw['primitives'][0]['instruction_sequence']=['addi']
    result=compare(fw,hw)
    assert result.overall_result=='unknown'
    checks=result.requirement_results[0].alternatives[0].checks
    assert checks[0].outcome=='compatible'
    assert checks[-1].reason=='FW_TYPED_INSTRUCTION_FIELD_UNAVAILABLE'


def test_order_only_after_semantic_endpoint_mapping():
    fw,hw=ordered_inputs()
    assert compare(fw,hw).overall_result=='compatible'
    assert trigger_result(compare(fw,hw),'hw:order').outcome=='compatible'
    fw['constraints'][-1].update(before_primitive_id='fw:second',after_primitive_id='primitive:write')
    assert trigger_result(compare(fw,hw),'hw:order').outcome=='incompatible'
    fw['constraints']=fw['constraints'][:-1]
    assert trigger_result(compare(fw,hw),'hw:order').outcome=='unknown'


def test_order_unknown_endpoint_and_weak_or_time_bound():
    fw,hw=ordered_inputs(); fw['constraints'][-1]['max_gap_events']=20
    assert compare(fw,hw).overall_result=='unknown'
    fw['constraints'][-1]['max_gap_events']=5
    hw['trigger'][-1]['ordering'].update(max_gap_time=10,time_unit='ns')
    assert compare(fw,hw).overall_result=='unknown'
    hw['trigger'][-1]['ordering'].pop('max_gap_time');hw['trigger'][-1]['ordering'].pop('time_unit')
    fw['constraints'][4]['identity']='missing-identity'
    result=compare(fw,hw)
    assert trigger_result(result,'hw:order').outcome=='unknown'


def test_zero_requirements_and_aggregation():
    assert xl2.aggregate_required([])=='unknown'
    fw,hw=inputs();hw['trigger']=[]
    assert compare(fw,hw).overall_result=='unknown'
    fw,hw=inputs();fw['primitives']=[]
    assert compare(fw,hw).overall_result=='unknown'
    fw,hw=inputs();fw['scope']['platform_id']=None
    assert compare(fw,hw).overall_result=='unknown'
    fw['constraints'][1]['identity']='wrong-csr'
    assert compare(fw,hw).overall_result=='incompatible'


def test_result_identity_round_trip_version_and_input_immutability(monkeypatch):
    fw,hw=build_pair(*inputs())
    original_fw,original_hw=fw.model_dump_json(),hw.model_dump_json()
    value=xl2.compare_capability_contract(fw,hw)
    assert xl2.parse_compatibility_result(xl2.serialize_compatibility_result(value))==value
    assert xl2.compare_capability_contract(fw,hw).result_id==value.result_id
    assert fw.model_dump_json()==original_fw and hw.model_dump_json()==original_hw
    monkeypatch.setattr(xl2,'MATCHER_VERSION','xl2-typed-subset/test-rule-revision')
    assert xl2.compare_capability_contract(fw,hw).result_id!=value.result_id


def test_result_duplicate_keys_tampering_and_binding_rejected():
    value=compare();text=xl2.serialize_compatibility_result(value)
    with pytest.raises(ValueError,match='Duplicate JSON key'):
        xl2.parse_compatibility_result(text.replace('{','{"result_id":"duplicate",',1))
    data=json.loads(text);data['overall_result']='unknown'
    with pytest.raises(ValueError,match='Overall outcome'):
        xl2.parse_compatibility_result(json.dumps(data))
    data=json.loads(text);data['result_sha256']='0'*64
    with pytest.raises(ValueError,match='identity mismatch'):
        xl2.parse_compatibility_result(json.dumps(data))
    data=json.loads(text);data['source_references']=[]
    with pytest.raises(ValueError,match='unbound'):
        xl2.parse_compatibility_result(json.dumps(data))
    for field in ('confidence','score','timestamp','run_uuid','host_path','llm_text'):
        data=json.loads(text);data[field]='not allowed'
        with pytest.raises(ValueError):
            xl2.parse_compatibility_result(json.dumps(data))


def test_unknown_constraint_cannot_be_treated_as_established():
    fw,hw=inputs();fw['constraints'][1]['formalization_status']='unknown'
    assert compare(fw,hw).overall_result=='unknown'


def test_set_order_normalization():
    fw,hw=inputs()
    before=compare(fw,hw)
    fw['primitives'][0]['constraint_ids'].reverse()
    assert compare(fw,hw).result_id==before.result_id


def test_multiple_offers_can_satisfy_a_requirement_without_false_conflict():
    fw,hw=inputs()
    other=copy.deepcopy(fw['primitives'][0]);other['primitive_id']='fw:other'
    other['constraint_ids']=['resource','csr:other','value','width']
    fw['primitives'].append(other)
    c=copy.deepcopy(fw['constraints'][1]);c.update(constraint_id='csr:other',identity='wrong-csr')
    fw['constraints'].append(c)
    result=compare(fw,hw)
    assert result.overall_result=='compatible'
    assert trigger_result(result).matched_primitive_ids==['primitive:write']
    assert {a.outcome for a in trigger_result(result).alternatives}=={'compatible','incompatible'}


def test_unknown_alternative_prevents_global_negative_if_no_offer_matches():
    fw,hw=inputs();fw['constraints'][1]['identity']='wrong-csr'
    other=copy.deepcopy(fw['primitives'][0]);other.update(primitive_id='fw:unknown',kind='UNKNOWN',
        formalization_status='unknown',constraint_ids=[])
    fw['primitives'].append(other)
    assert compare(fw,hw).overall_result=='unknown'


def test_precondition_does_not_mix_temporal_contexts_between_primitives():
    fw,hw=ordered_inputs()
    add_precondition(fw,hw)
    common={k:fw[k] for k in ('source_artifact_ids','evidence_ids','provenance')}
    fw['constraints'].append(dict(constraint_id='priv',kind='privilege',identity='M',**common))
    for p in fw['primitives']:
        p['constraint_ids'].append('priv')
    result=compare(fw,hw)
    assert result.overall_result=='unknown'
    assert next(r for r in result.requirement_results if r.section=='precondition').checks[0].reason=='NO_UNAMBIGUOUS_TRIGGER_CONTEXT'


def test_revision_requirement_and_unknown_platform_placeholder_are_unknown():
    fw,hw=inputs();hw['platform']['rtl_revision']='rev:known'
    assert compare(fw,hw).overall_result=='unknown'
    hw['platform']['rtl_revision']=None
    hw['platform']['platform_id']='UNKNOWN';hw['scope']['applicable_platforms']=['UNKNOWN']
    assert compare(fw,hw).overall_result=='unknown'


def test_partial_deviation_missing_does_not_become_whole_contract_success():
    fw,hw=inputs();hw['deviation']=[];hw['observation']=[]
    result=compare(fw,hw)
    assert result.overall_result=='compatible'
    assert all(d.state=='missing' for d in result.downstream_verification_requirements)
    assert 'deviation' in result.unassessed_contract_sections and 'observation' in result.unassessed_contract_sections


def test_unknown_coverage_cannot_be_promoted_and_unclassified_cannot_be_ignored():
    with pytest.raises(ValueError,match='Missing/unsupported'):
        xl2.FieldComparison(dimension='missing',outcome='compatible',reason='fake',coverage='missing')
    fw,hw=inputs();common={k:hw[k] for k in ('source_artifact_ids','evidence_ids','provenance')}
    hw['unclassified_atoms']=[dict(atom=dict(atom_id='unknown-state',kind='register_state',register='x1',operator='eq',value=0),
        reason='state_timing_unknown',**common)]
    assert compare(fw,hw).overall_result=='unknown'


def test_replay_binds_actual_inputs_and_rule_version(monkeypatch):
    fw,hw=build_pair(*inputs())
    value=xl2.compare_capability_contract(fw,hw)
    assert xl2.validate_compatibility_replay(value,fw,hw)==value
    monkeypatch.setattr(xl2,'MATCHER_VERSION','test:different-rules')
    with pytest.raises(ValueError,match='does not replay'):
        xl2.validate_compatibility_replay(value,fw,hw)
