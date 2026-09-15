"""Typed contracts, stable identities, and rejection of unsupported authority."""
import json
import pytest
from chipchain.cross_layer import *
from chipchain.cross_layer.codec import digest
from chipchain.cross_layer.contracts import FactCapabilities, CandidateCapabilities
from chipchain.cross_layer.trigger import *
from tests.cross_layer_fakes import condition, pair, sources, instruction, binding


def atom(**kwargs):
    return InstructionTriggerAtom(atom_id='a', architecture='riscv', mnemonic='lw', **kwargs)


@pytest.mark.parametrize('value', [
    {'operator':'eq'}, {'operator':'eq','value':True}, {'operator':'neq','value':1,'mask':3},
    {'operator':'masked_eq','value':4,'mask':3}, {'operator':'in_range','range_min':2,'range_max':1},
])
def test_invalid_value_constraints(value):
    with pytest.raises(ValueError): ValueConstraint(**value)


@pytest.mark.parametrize('status', ['verified','unknown','refuted'])
def test_xl0_never_generates_verified_condition(status):
    with pytest.raises(ValueError): condition(atom(), epistemic_status=status)


def test_hypothesis_only_hypothesized_and_no_prose_parser():
    with pytest.raises(ValueError, match='remain hypothesized'):
        condition(atom(), source_kind='hardware_trigger_hypothesis', epistemic_status='derived')
    with pytest.raises(ValueError):
        HardwareTriggerConditionInput(summary='load triggers bug')
    value = condition(atom(), source_kind='hardware_trigger_hypothesis', source_ids=['H1'], source_hardware_hypothesis_id='H1')
    assert value.epistemic_status == 'hypothesized'


@pytest.mark.parametrize('atoms', [[], [atom(),atom()],
    [atom(),OrderingTriggerAtom(atom_id='o',before_atom_id='a',after_atom_id='missing')],
    [InstructionTriggerAtom(atom_id='a',architecture='riscv',mnemonic='lw',purpose='verification_only_metadata')]])
def test_all_of_requires_valid_unique_required_atoms(atoms):
    with pytest.raises(ValueError): condition(*atoms)


def test_all_seven_atom_kinds_serialize():
    atoms = [atom(), RegisterStateTriggerAtom(atom_id='r',register='x10',operator='eq',value=4096),
        MMIOTriggerAtom(atom_id='m',address=0x40000000,access='write'),
        CSRTriggerAtom(atom_id='c',csr_identity='status',access='read'),
        PrivilegeTriggerAtom(atom_id='p',architecture='riscv',required_mode='machine'),
        HardwareStateTriggerAtom(atom_id='h',state_identity='fsm',operator='eq',value=2),
        OrderingTriggerAtom(atom_id='o',before_atom_id='a',after_atom_id='r')]
    value = condition(*atoms)
    assert len({a.kind for a in value.all_of_atoms}) == 7
    assert parse_hardware_trigger_condition(serialize_hardware_trigger_condition(value)) == value
    assert '"register":"x10"' in serialize_hardware_trigger_condition(value)


def test_encoding_and_operand_validation():
    assert atom().encoding is None
    with pytest.raises(ValueError): atom(encoding=1)
    with pytest.raises(ValueError): atom(encoding=4,encoding_mask=3,representation='instruction_word')
    with pytest.raises(ValueError): OperandPattern()
    with pytest.raises(ValueError): OperandPattern(immediate_exact=1,immediate_range=IntegerRange(minimum=0,maximum=2))
    with pytest.raises(ValueError): OrderingTriggerAtom(atom_id='o',before_atom_id='a',after_atom_id='b',max_gap_time=1)


def test_two_fresh_builds_stable_codecs_and_provenance():
    def build():
        p, t, s = pair(), condition(atom()), sources(instruction())
        c = match_trigger_condition(pair=p,condition=t,sources=s,bindings=[binding(s)])
        return p,t,c
    first, second = build(), build()
    codecs = [(serialize_cross_layer_pair,parse_cross_layer_pair,cross_layer_pair_sha256),
        (serialize_hardware_trigger_condition,parse_hardware_trigger_condition,hardware_trigger_condition_sha256),
        (serialize_cross_layer_candidate,parse_cross_layer_candidate,cross_layer_candidate_sha256)]
    for a,b,(dump,load,hash_) in zip(first,second,codecs):
        assert dump(a).encode() == dump(b).encode()
        assert hash_(a) == hash_(b)
        assert dump(load(dump(a))) == dump(a)
        with pytest.raises(ValueError): load(dump(a).replace('{','{"schema_version":"forged",',1))
    p,t,c = first
    assert c.pair_descriptor_sha256 == cross_layer_pair_sha256(p)
    assert c.trigger_condition_sha256 == hardware_trigger_condition_sha256(t)
    assert c.matcher.version == '1' and c.synthetic
    assert c.firmware_fact_source_identities
    assert c.epistemic_status == 'hypothesized'


def test_capability_and_aggregation_forgery_rejected():
    s=sources(instruction()); c=match_trigger_condition(pair=pair(),condition=condition(atom()),sources=s,bindings=[binding(s)])
    for field in ('supports_runtime_trigger','supports_path_feasibility','supports_exploitability','supports_vulnerability_verification'):
        fields=c.capabilities.model_dump();fields[field]=True
        with pytest.raises(ValueError): CandidateCapabilities(**fields)
    fields=c.model_dump();fields['overall_status']='conflict'
    fields['candidate_id']='xlcandidate:'+digest({k:v for k,v in fields.items() if k!='candidate_id'})
    with pytest.raises(ValueError, match='derived'): CrossLayerTriggerCandidate(**fields)
    fields=c.model_dump();fields['candidate_id']='runtime-uuid'
    with pytest.raises(ValueError, match='identity'): CrossLayerTriggerCandidate(**fields)


@pytest.mark.parametrize('kind', ['firmware_constrained_path','firmware_report','hardware_report','summary'])
def test_no_report_or_future_a6_fact_authority(kind):
    s=sources(instruction());data=s.reference('processor_behavior','inst').model_dump();data['source_kind']=kind
    with pytest.raises(ValueError): FirmwareCrossLayerFactRef(**data)


def test_order_of_set_like_builder_inputs_does_not_change_identity():
    a=atom(); b=InstructionTriggerAtom(atom_id='b',architecture='riscv',mnemonic='sw')
    assert serialize_hardware_trigger_condition(condition(a,b)) == serialize_hardware_trigger_condition(condition(b,a))
