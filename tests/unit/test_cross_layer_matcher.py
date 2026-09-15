"""Synthetic positive/conflict/unknown matches; never an actual trigger or attack chain."""
import pytest
from chipchain.cross_layer import *
from chipchain.cross_layer.adapters import architecture_adapter
from chipchain.cross_layer.codec import serialize
from chipchain.cross_layer.trigger import *
from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.common import Architecture
from chipchain.tools.firmware.static_reachability import build_static_reachability
from chipchain.cross_layer.facts import function_path_id
from tests.cross_layer_fakes import annotated, binding, condition, instruction, pair, sources, target
from tests.unit.test_static_reachability import cfg  # Pure synthetic graph fixture; no angr execution.


def load_atom(**updates):
    fields=dict(atom_id='a',architecture='riscv',mnemonic='lw')
    fields.update(updates)
    return InstructionTriggerAtom(**fields)


def match_one(atom, behavior=None):
    source=sources(*([behavior] if behavior else []))
    bindings=[binding(source,atom.atom_id,behavior.behavior_id)] if behavior else []
    result=match_trigger_condition(pair=pair(),condition=condition(atom),sources=source,bindings=bindings)
    return result.atom_matches[0],result


def test_exact_instruction_match_is_static_only():
    atom=load_atom(operand_pattern=OperandPattern(destination_register='x10',base_register='x28',immediate_exact=7))
    m,c=match_one(atom,instruction())
    assert m.status=='matched' and c.overall_status=='full_static_match'
    assert c.capabilities.supports_static_cross_layer_match
    assert not c.capabilities.supports_runtime_trigger and not c.capabilities.supports_path_feasibility
    assert 'synthetic_not_real_vulnerability' in c.limitations


def test_mnemonic_only_partial_and_wrong_mnemonic_same_site():
    atom=load_atom(operand_pattern=OperandPattern(destination_register='x10',base_register='x28',immediate_exact=7))
    m,c=match_one(atom,instruction(complete=False))
    assert m.status=='partial' and c.overall_status=='insufficient_information'
    assert m.missing_fields
    assert match_one(load_atom(),instruction(mnemonic='sw'))[0].status=='conflict'


@pytest.mark.parametrize('pattern,expected', [
    (OperandPattern(immediate_range=IntegerRange(minimum=6,maximum=8)),'matched'),
    (OperandPattern(immediate_exact=8),'conflict'),
    (OperandPattern(destination_register='x11'),'conflict'),
    (OperandPattern(base_register='unknown-register'),'partial'),
    (OperandPattern(source_registers=['x1']),'partial'),
])
def test_bounded_operand_constraints(pattern,expected):
    assert match_one(load_atom(operand_pattern=pattern),instruction())[0].status==expected


@pytest.mark.parametrize('encoding,mask,representation,status', [
    (0x007e2503,None,'instruction_word','matched'),
    (3,0x7f,'instruction_word','matched'),(0x23,0x7f,'instruction_word','conflict'),
    (0x007e2503,None,'decompressed_word','partial'),
])
def test_encoding_precision_and_representation(encoding,mask,representation,status):
    atom=load_atom(encoding=encoding,encoding_mask=mask,representation=representation)
    assert match_one(atom,instruction())[0].status==status


def test_stage_requirement_not_proved_by_static_decode():
    assert match_one(load_atom(stage_requirement='retired'),instruction())[0].status=='partial'


@pytest.mark.parametrize('constraint,actual,expected', [
    ({'operator':'eq','value':4096},4096,'matched'),({'operator':'neq','value':4096},0,'matched'),
    ({'operator':'masked_eq','value':0x1000,'mask':0xf000},0x1001,'matched'),
    ({'operator':'in_range','range_min':0,'range_max':3},2,'matched'),
    ({'operator':'eq','value':4096},0,'conflict'),
])
def test_register_state_operators(constraint,actual,expected):
    atom=RegisterStateTriggerAtom(atom_id='a',register='x10',**constraint)
    assert match_one(atom,annotated('register_access',register='x10',state_value=actual))[0].status==expected


def test_register_write_is_not_a_known_state_and_absence_is_unknown():
    atom=RegisterStateTriggerAtom(atom_id='a',register='x10',operator='eq',value=4096)
    assert match_one(atom,annotated('register_access',register='x10',access='write'))[0].status=='partial'
    assert match_one(atom)[0].status=='unknown'


@pytest.mark.parametrize('access,want,expected', [('read','write','conflict'),('write','either','matched'),
    ('read','read','matched'),('either','write','partial')])
def test_mmio_direction(access,want,expected):
    atom=MMIOTriggerAtom(atom_id='a',address=0x40000000,access=want)
    assert match_one(atom,annotated('mmio_access',address=0x40000000,access=access))[0].status==expected


def test_mmio_width_value_and_csr_constraints():
    atom=MMIOTriggerAtom(atom_id='a',address=1,access='read',width_bits=32,
        value_constraint=ValueConstraint(operator='eq',value=7))
    assert match_one(atom,annotated('mmio_access',address=1,access='read'))[0].status=='partial'
    assert match_one(atom,annotated('mmio_access',address=1,access='read',width_bits=32,value=7))[0].status=='matched'
    csr=CSRTriggerAtom(atom_id='a',csr_identity='status',csr_address=0x300,access='read')
    assert match_one(csr,annotated('csr_access',csr_identity='status',csr_address=0x300,access='read'))[0].status=='matched'
    assert match_one(csr,annotated('csr_access',csr_identity='status',csr_address=0x300,access='write'))[0].status=='conflict'


def test_privilege_and_internal_hardware_state():
    atom=PrivilegeTriggerAtom(atom_id='a',architecture='riscv',required_mode='machine')
    assert match_one(atom,annotated('privilege',mode='machine'))[0].status=='matched'
    assert match_one(atom,annotated('privilege',mode='unknown'))[0].status=='unknown'
    hw=HardwareStateTriggerAtom(atom_id='a',state_identity='fsm',operator='eq',value=2)
    assert match_one(hw,instruction())[0].status=='unknown'


@pytest.mark.parametrize('architecture,mnemonic,register', [
    (Architecture.ARM,'ldr','r0'),(Architecture.RISCV,'lw','x10'),(Architecture.POWERPC,'lwz','r3')])
def test_architecture_first_class(architecture,mnemonic,register):
    inst=instruction(architecture=architecture,mnemonic=mnemonic,complete=False)
    s=sources(inst,architecture=architecture)
    t=condition(InstructionTriggerAtom(atom_id='a',architecture=architecture,mnemonic=mnemonic),architecture=architecture)
    result=match_trigger_condition(pair=pair(architecture),condition=t,sources=s,bindings=[binding(s)])
    assert result.overall_status=='full_static_match'
    assert result.firmware_fact_source_identities[0].architecture==architecture
    assert architecture_adapter(architecture).normalize_register(register)==register


def test_arm_does_not_guess_thumb_operand_roles():
    s=sources(instruction(architecture=Architecture.ARM,mnemonic='ldr'),architecture=Architecture.ARM)
    t=condition(InstructionTriggerAtom(atom_id='a',architecture='arm',mnemonic='ldr',
        operand_pattern=OperandPattern(destination_register='r0')),architecture=Architecture.ARM)
    assert match_trigger_condition(pair=pair(Architecture.ARM),condition=t,sources=s,bindings=[binding(s)]).atom_matches[0].status=='partial'


def test_pair_gate_runs_before_fact_access():
    with pytest.raises(PairNotEligible):
        match_trigger_condition(pair=pair(manifest=False),condition=None,sources=None)


def test_reference_hash_capability_case_and_site_tampering_rejected():
    s=sources(instruction()); t=condition(load_atom())
    for field,value in [('source_sha256','0'*64),('source_id','missing'),('case_id','other'),('architecture','arm')]:
        b=binding(s); setattr(b.firmware_fact_refs[0],field,value)
        with pytest.raises(ValueError): match_trigger_condition(pair=pair(),condition=t,sources=s,bindings=[b])
    b=binding(s); b.firmware_fact_refs[0].capabilities.comparable_fields.append('state_value')
    with pytest.raises(ValueError): match_trigger_condition(pair=pair(),condition=t,sources=s,bindings=[b])
    b=binding(s); b.site_id='address:999'
    with pytest.raises(ValueError, match='site'): match_trigger_condition(pair=pair(),condition=t,sources=s,bindings=[b])


def test_no_cross_case_or_hypothesized_fact_or_unmarked_synthetic():
    b=instruction();b.epistemic_status='hypothesized'
    with pytest.raises(ValueError): sources(b)
    b=annotated('register_access',register='x10',state_value=4096)
    with pytest.raises(ValueError,match='Synthetic'):
        FirmwareFactSources(case_id='synthetic-fw',target=target(),processor_ir=ProcessorBehaviorIR(case_id='synthetic-fw',behaviors=[b]))
    s=sources(instruction(),case_id='other')
    with pytest.raises(ValueError,match='case'):
        match_trigger_condition(pair=pair(),condition=condition(load_atom()),sources=s)


def test_no_prose_authority_and_source_inputs_not_mutated():
    inst=instruction(); ir=ProcessorBehaviorIR(case_id='synthetic-fw',behaviors=[inst]); before=serialize(ir)
    s=FirmwareFactSources(case_id='synthetic-fw',target=target(),processor_ir=ir)
    c=match_trigger_condition(pair=pair(),condition=condition(load_atom()),sources=s,bindings=[binding(s)])
    assert serialize(ir)==before
    assert revalidate_candidate(c,pair=pair(),condition=condition(load_atom()),sources=s,bindings=[binding(s)])==c
    # Text is never interpreted into additional fields.
    inst.summary='the register is 4096 and the trigger fired'; inst.attributes={'value':4096,'register':'x10'}
    s=sources(inst)
    t=condition(RegisterStateTriggerAtom(atom_id='a',register='x10',operator='eq',value=4096))
    assert match_trigger_condition(pair=pair(),condition=t,sources=s,bindings=[binding(s)]).atom_matches[0].status=='unknown'


@pytest.mark.parametrize('second,overall', [('unknown','partial_static_match'),('partial','partial_static_match'),
    ('conflict','conflict'),('matched','full_static_match')])
def test_all_of_aggregation(second,overall):
    a=load_atom(); b=load_atom(atom_id='b',operand_pattern=OperandPattern(immediate_exact=7))
    behaviors=[instruction()]
    if second!='unknown':behaviors.append(instruction('other',complete=second!='partial',mnemonic='sw' if second=='conflict' else 'lw',site=512))
    s=sources(*behaviors); bindings=[binding(s)]
    if second!='unknown':bindings.append(binding(s,'b','other'))
    assert match_trigger_condition(pair=pair(),condition=condition(a,b),sources=s,bindings=bindings).overall_status==overall


def test_empty_facts_and_explicit_metadata():
    a=load_atom(); meta=load_atom(atom_id='meta',purpose='verification_only_metadata')
    c=match_trigger_condition(pair=pair(),condition=condition(a,meta),sources=sources())
    assert c.overall_status=='insufficient_information'
    assert [m.status for m in c.atom_matches]==['unknown','not_applicable']


def test_a5_witness_static_order_and_timing_unknown(cfg):
    a,b=load_atom(),load_atom(atom_id='b')
    order=OrderingTriggerAtom(atom_id='o',before_atom_id='a',after_atom_id='b')
    reach=build_static_reachability(cfg,[])
    s=sources(instruction(site=256),instruction('other',site=512),case_id='synthetic',static_reachability=reach,cfg=cfg)
    bindings=[binding(s),binding(s,'b','other')]
    p=pair(firmware_case_id='synthetic')
    path=s.reference('firmware_static_reachability',function_path_id('f100','f200'))
    kwargs=dict(pair=p,sources=s,bindings=bindings,firmware_path_refs=[path])
    c=match_trigger_condition(condition=condition(a,b,order),**kwargs)
    assert c.overall_status=='full_static_match' and c.atom_matches[-1].evidence_strength=='static_path'
    assert not c.capabilities.supports_runtime_order
    order=OrderingTriggerAtom(atom_id='o',before_atom_id='a',after_atom_id='b',max_gap_events=2,max_gap_time=10,time_unit='ns')
    assert match_trigger_condition(condition=condition(a,b,order),**kwargs).atom_matches[-1].status=='partial'
    kwargs['firmware_path_refs']=[]
    assert match_trigger_condition(condition=condition(a,b,order),**kwargs).atom_matches[-1].status=='unknown'


def test_a5_not_found_is_missing_constraint_never_conflict(cfg):
    reach=build_static_reachability(cfg,[])
    s=sources(instruction(site=256),instruction('other',site=768),case_id='synthetic',static_reachability=reach,cfg=cfg)
    path=s.reference('firmware_static_reachability',function_path_id('f100','f300'))
    order=OrderingTriggerAtom(atom_id='o',before_atom_id='a',after_atom_id='b')
    c=match_trigger_condition(pair=pair(firmware_case_id='synthetic'),condition=condition(load_atom(),load_atom(atom_id='b'),order),
        sources=s,bindings=[binding(s),binding(s,'b','other')],firmware_path_refs=[path])
    assert c.overall_status=='partial_static_match'
    assert c.atom_matches[-1].status=='unknown'
    assert any('not_found_within_bound' in x for x in c.missing_constraints)


def test_a5_references_require_valid_bound_cfg(cfg):
    reach=build_static_reachability(cfg,[])
    with pytest.raises(ValueError,match='bound CFG'):sources(case_id='synthetic',static_reachability=reach)
    reach.cfg_sha256='0'*64
    with pytest.raises(ValueError,match='identity'):sources(case_id='synthetic',static_reachability=reach,cfg=cfg)


def test_a4_direction_does_not_reinterpret_instruction_pc_as_mmio_address(tmp_path):
    from tests.test_static_relations import canonical, build
    data=canonical(tmp_path); catalog=build(data)
    s=FirmwareFactSources(case_id=catalog.case_id,target=data[0].case.target,static_relations=catalog,synthetic=True)
    relation=next(r for r in catalog.relations if r.kind=='mmio_access_direction')
    atom=MMIOTriggerAtom(atom_id='a',address=relation.site_address,access=relation.attributes.direction)
    p0=pair(Architecture.ARM,firmware_case_id=catalog.case_id)
    p=build_cross_layer_pair(firmware_case_id=catalog.case_id,hardware_case_id='synthetic-hw',
        firmware_target=s.target,hardware_target=s.target,manifest=p0.manifest)
    t=condition(atom,architecture=Architecture.ARM)
    c=match_trigger_condition(pair=p,condition=t,sources=s,bindings=[binding(s,'a',relation.relation_id,kind='firmware_static_relation')])
    assert c.atom_matches[0].status=='partial' and 'address' in c.atom_matches[0].missing_fields


def test_multiple_sites_cannot_be_combined_and_conflicting_sources_are_unknown():
    s=sources(instruction(),instruction('other',site=512)); b=binding(s)
    b.firmware_fact_refs.append(s.reference('processor_behavior','other'))
    with pytest.raises(ValueError,match='site'):
        match_trigger_condition(pair=pair(),condition=condition(load_atom()),sources=s,bindings=[b])
    s=sources(instruction(),instruction('other',mnemonic='sw')); b=binding(s)
    b.firmware_fact_refs.append(s.reference('processor_behavior','other'))
    c=match_trigger_condition(pair=pair(),condition=condition(load_atom()),sources=s,bindings=[b])
    assert c.atom_matches[0].status=='unknown' and c.atom_matches[0].reason_code=='conflicting_firmware_sources'
