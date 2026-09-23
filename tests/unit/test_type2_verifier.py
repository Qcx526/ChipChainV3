"""Adversarial controlled-runtime semantics; no external tools or network."""
from dataclasses import replace

import pytest
from pydantic import ValidationError

from chipchain.cross_layer import type2_verifier as v
from chipchain.cross_layer.trigger import MMIOTriggerAtom, ValueConstraint
from chipchain.firmware import mmio_grounding as b1
from chipchain.firmware import mmio_execution_bridge as bridge_api
from chipchain.firmware.mmio_capability import materialize_mmio
from tests.unit.test_firmware_mmio_execution_bridge import processor_text,changed
from tests.unit.test_firmware_mmio_grounding import inputs,synthetic_elf


def run(command=0xa5,read_value=0,unknown_bridge=False):
    static,kw=inputs(command=command,read_value=read_value)
    runtime=b1.materialize_runtime(**kw)
    platform=b1.identified(bridge_api.PlatformProof,rtl_tree_sha256=kw['rtl_tree_sha256'],
        map_id=static.target_binding.map_id,map_source_id=kw['map_source'].map_evidence_id,
        source_artifacts=(),single_cored_host=True,no_other_target_master=not unknown_bridge,
        aligned_word_mask_from_instruction=True)
    identity={k:getattr(runtime.run_binding,k) for k in ('firmware_sha256','rtl_tree_sha256','simulator_sha256',
        'input_sha256','execution_context_sha256')}
    evidence=dict(inputs=identity,static=static,elf_bytes=synthetic_elf(command),platform=platform,
        bus_bytes=kw['raw_trace_bytes'],processor_bytes=processor_text(command=command,value=read_value),
        stdout_bytes=kw['stdout_bytes'],stderr_bytes=kw['stderr_bytes'])
    joint=bridge_api.make_joint_run(**evidence,process_returncode=0)
    bridge=bridge_api.materialize_bridge(joint=joint,runtime=runtime,**evidence)
    caps=materialize_mmio(static,elf_bytes=evidence['elf_bytes'],bridge=bridge,
        replay_inputs={**{k:v for k,v in evidence.items() if k not in ('static','elf_bytes')},'runtime':runtime})
    item=v.RunEvidence(static=static,bridge=bridge,runtime=runtime,platform=platform,
        capabilities=caps,inputs=identity,elf_bytes=evidence['elf_bytes'],bus_bytes=evidence['bus_bytes'],
        processor_bytes=evidence['processor_bytes'],stdout_bytes=evidence['stdout_bytes'],
        stderr_bytes=evidence['stderr_bytes'])
    return replace(item,observation_binding=v.observation_binding_for(item))


def atom(address=0x40004,value=0xa5,width=32):
    return MMIOTriggerAtom(atom_id='requirement:command',address=address,access='write',width_bits=width,
        value_constraint=ValueConstraint(operator='eq',value=value))


def evaluate_access(item,atom_value=None):
    atom_value=atom_value or atom()
    v._validate_run(item)
    return v._access_atom(atom_value,'requirement:command',item,v._capability_transactions(item))[0]


def test_a5_supported_a4_contradicted_by_executed_value():
    assert evaluate_access(run()).status=='supported'
    result=evaluate_access(run(command=0xa4))
    assert (result.status,result.reason_code)==('contradicted','EXECUTED_CONFLICTING_MMIO')
    assert result.evidence_ids


@pytest.mark.parametrize('alternate',[atom(address=0x4000c),atom(width=16)])
def test_explicit_address_or_width_conflict(alternate):
    result=evaluate_access(run(),alternate)
    assert result.status=='contradicted' and result.evidence_ids


def test_static_only_and_unknown_bridge_are_not_execution():
    base=run()
    static=materialize_mmio(base.static,elf_bytes=base.elf_bytes)
    assert not v._capability_transactions(replace(base,capabilities=static))
    assert v._access_atom(atom(),'requirement:command',replace(base,capabilities=static),())[0].status=='unknown'
    ambiguous=run(unknown_bridge=True)
    assert all(b.overall_status=='unknown' for b in ambiguous.bridge.bindings)
    assert not v._capability_transactions(ambiguous)


def test_capability_order_never_establishes_transaction_order():
    item=run()
    reversed_run=replace(item,capabilities=tuple(reversed(item.capabilities)))
    assert v._capability_transactions(item)
    assert evaluate_access(reversed_run)==evaluate_access(item)
    parsed=v._validate_run(item)
    cmd=next(o for o in item.runtime.runtime_observations if o.address==0x40004)
    binding=v.identified(v.StateBinding,source_artifact_id='synthetic:spec',source_sha256='a'*64,
        enable_subject='Peripheral.ENABLE',enable_address=0x40000,enable_reset_value=0,
        status_subject='Peripheral.STATUS',status_address=0x40008,status_reset_value=0)
    value,enable,_=v._state_before(parsed,cmd,binding)
    assert value==1 and enable['cycle']<cmd.request_cycle


def test_enable_overwrite_or_reset_changes_prestate():
    item=run();parsed=v._validate_run(item);cmd=next(o for o in item.runtime.runtime_observations if o.address==0x40004)
    binding=v.identified(v.StateBinding,source_artifact_id='synthetic:spec',source_sha256='a'*64,
        enable_subject='Peripheral.ENABLE',enable_address=0x40000,enable_reset_value=0,
        status_subject='Peripheral.STATUS',status_address=0x40008,status_reset_value=0)
    # Standalone state reducer adversarial stream; complete runtime inputs are
    # separately guarded by the frozen B1 parser before a verifier can use them.
    overwrite=dict(parsed['events'][0],phase='request',reset_n=1,reset_epoch=1,
        transaction_id=99,cycle=4,address=0x40000,write_enable=1,write_data=0)
    stream={**parsed,'events':[*parsed['events']]}
    index=next(i for i,e in enumerate(stream['events']) if e['phase']=='request' and e['address']==0x40004)
    stream['events'].insert(index,overwrite)
    stream['transactions']=[*parsed['transactions'],{'request':overwrite,'response':{}}]
    value,last,_=v._state_before(stream,cmd,binding)
    assert value==0 and last['transaction_id']==99
    reset=dict(overwrite,phase='reset_assert',reset_n=0,reset_epoch=2)
    stream['events'][index]=reset
    value,_,reason=v._state_before(stream,cmd,binding)
    assert value is None and reason=='RESET_EPOCH_MISMATCH'


def test_observation_requires_source_link_and_agreeing_sample_read():
    item=run(read_value=0xdead);parsed=v._validate_run(item)
    cmd=next(o for o in item.runtime.runtime_observations if o.address==0x40004)
    assert v._sample_read(item,parsed,0x40008,cmd)[0]==0xdead
    assert v._sample_read(replace(item,observation_binding=None),parsed,0x40008,cmd)[2]=='OBSERVATION_BINDING_MISSING'
    altered={**parsed,'events':[dict(e) for e in parsed['events']]}
    sample=next(e for e in altered['events'] if e['phase']=='status_sample' and e['cycle']==cmd.request_cycle)
    sample['status_value']=0
    assert v._sample_read(item,altered,0x40008,cmd)[2]=='SAMPLE_READ_CONFLICT'


def test_reference_zero_is_not_deviating_value():
    item=run(read_value=0);parsed=v._validate_run(item)
    cmd=next(o for o in item.runtime.runtime_observations if o.address==0x40004)
    value,_,reason=v._sample_read(item,parsed,0x40008,cmd)
    assert value==0 and reason=='SAMPLE_READ_AGREE' and value!=0xdead
    assert v._deviation_value(0,0,0xdead)=='contradicted'
    assert v._deviation_value(0xdead,0,0xdead)=='supported'
    assert v._final_status('supported','contradicted','supported','unknown')=='deviation_contradicted'
    assert v._final_status('unknown','contradicted','supported','unknown')=='unknown'


def test_malformed_trace_is_rejected_not_unknown():
    item=run()
    with pytest.raises(ValueError):v._validate_run(replace(item,bus_bytes=item.bus_bytes[:-1]))


def test_explicit_observation_binding_is_scientific_input():
    item=run();assert v._linked(item)
    wrong=changed(item.observation_binding,rtl_tree_sha256='f'*64)
    assert not v._linked(replace(item,observation_binding=wrong))
    assert v.observation_binding_for(item).binding_id==v.observation_binding_for(item).binding_id


def test_condition_content_identity_and_result_schema_are_strict():
    a=v.condition('req','supported','EXACT',('evidence:one',))
    assert a==v.condition('req','supported','EXACT',('evidence:one',))
    assert a.verification_id!=v.condition('req','unknown','MISSING',missing=('evidence',)).verification_id
    with pytest.raises(ValueError,match='SUPPORTED_WITHOUT_EVIDENCE'):
        v.condition('req','supported','EXACT')
    with pytest.raises(ValidationError):
        v.ConditionVerification.model_validate({**a.model_dump(mode='json'),'evaluation_label':'P1'})
