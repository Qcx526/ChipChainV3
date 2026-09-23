"""Small synthetic ELF / trace tests for the existing CAP0 adapter."""
import pytest

from chipchain.firmware import capability as cap
from chipchain.firmware import mmio_execution_bridge as bridge_api
from chipchain.firmware import mmio_grounding as grounding
from chipchain.firmware.mmio_capability import materialize_mmio
from tests.unit.test_firmware_mmio_execution_bridge import sample, changed
from tests.unit.test_firmware_mmio_grounding import (
    synthetic_elf, encoded_program, map_evidence, inputs, trace_rows, rebind_raw,
)


def execution(status='bound', read_value=0):
    args, runtime, joint, bridge = sample(read_value)
    if status == 'unknown':
        args['platform'] = changed(args['platform'], no_other_target_master=False)
    elif status == 'not_same':
        _, kw = inputs(read_value=read_value)
        rebind_raw(kw, trace_rows(command=0xa4, read_value=read_value))
        runtime = grounding.materialize_runtime(**kw)
        args['bus_bytes'] = kw['raw_trace_bytes']
    joint = bridge_api.make_joint_run(**args, process_returncode=0)
    bridge = bridge_api.materialize_bridge(joint=joint, runtime=runtime, **args)
    kwargs = dict(elf_bytes=args['elf_bytes'], bridge=bridge,
                  replay_inputs={k:v for k,v in args.items() if k not in ('static','elf_bytes')})
    kwargs['replay_inputs']['runtime'] = runtime
    return args['static'], kwargs


def values(capability):
    return {c.kind:c.domain.exact for c in capability.constraints if isinstance(c, cap.NumericConstraint)}


@pytest.mark.parametrize('command',[0xa5,0xa4])
def test_static_write_read_origin_and_control(command):
    elf = synthetic_elf(command)
    static = grounding.extract_rv32_mmio_static_facts(elf, map_evidence().platform_map)
    result = materialize_mmio(static, elf_bytes=elf)
    assert len(result) == 3
    assert [p.primitives[0].kind for p in result] == ['MMIO_WRITE','MMIO_WRITE','MMIO_READ']
    assert [values(p) for p in result] == [dict(address=0x40000,access_width=32,value=1),
        dict(address=0x40004,access_width=32,value=command),dict(address=0x40008,access_width=32)]
    assert all(p.entry.execution_status == 'static_only' and not p.retirement_evidence for p in result)
    assert all(p.origin.kind == 'normal_behavior' and p.primitives[0].control.status == 'not_established' for p in result)


def test_different_command_different_static_capability():
    outputs=[]
    for command in (0xa5,0xa4):
        elf=synthetic_elf(command);s=grounding.extract_rv32_mmio_static_facts(elf,map_evidence().platform_map)
        outputs.append(materialize_mmio(s,elf_bytes=elf)[1])
    assert values(outputs[0])['value'] != values(outputs[1])['value']
    assert outputs[0].capability_id != outputs[1].capability_id


@pytest.mark.parametrize('state',['bound','unknown','not_same'])
def test_only_bound_attaches_execution(state):
    static, kwargs = execution(state)
    assert {b.overall_status for b in kwargs['bridge'].bindings} == {state}
    result = materialize_mmio(static, **kwargs)
    plain = materialize_mmio(static, elf_bytes=kwargs['elf_bytes'])
    for capability, baseline, fact in zip(result, plain, static.static_facts):
        assert capability.primitives == baseline.primitives and capability.constraints == baseline.constraints
        assert capability.primitives[0].basis == 'static_instruction'
        if state == 'bound':
            assert capability.entry.execution_status == 'source_instruction_retired'
            assert len(capability.retirement_evidence) == 1
            binding = next(b for b in kwargs['bridge'].bindings if b.static_fact_id == fact.fact_id)
            bus = next(b for b in kwargs['bridge'].bus_observations if b.observation_id == binding.runtime_observation_id)
            assert {fact.fact_id,binding.binding_id,binding.processor_observation_id,
                    bus.runtime_observation.observation_id,kwargs['bridge'].joint_run.joint_run_id} <= set(capability.evidence_ids)
            assert capability.retirement_evidence[0].observation_id == binding.processor_observation_id
        else:
            assert capability == baseline
            assert not any('observed' in e.summary for e in capability.evidence)


def test_runtime_read_does_not_change_static_semantics():
    results=[]
    for value in (0,0xdead):
        s,kw=execution(read_value=value);results.append(materialize_mmio(s,**kw))
    for a,b in zip(*results):
        assert a.primitives == b.primitives and a.constraints == b.constraints
        assert a.origin == b.origin and a.scope == b.scope
        assert a.capability_id != b.capability_id  # CAP0 identity includes evidence context.
    assert 'value' not in values(results[0][-1]) and 'value' not in values(results[1][-1])


@pytest.mark.parametrize('field',['static_fact_id','joint_run_id'])
def test_wrong_binding_reference_rejected(field):
    s,kw=execution();original=kw['bridge'];binding=changed(original.bindings[0],**{field:'wrong:ref'})
    with pytest.raises(ValueError):
        kw['bridge']=changed(original,bindings=(binding,*original.bindings[1:]))
        materialize_mmio(s,**kw)


@pytest.mark.parametrize('field',['bus_bytes','processor_bytes','stdout_bytes','stderr_bytes'])
def test_raw_evidence_tamper_rejected(field):
    s,kw=execution();kw['replay_inputs'][field]+=b' '
    with pytest.raises(ValueError):materialize_mmio(s,**kw)


def test_elf_and_static_tamper_rejected():
    s,kw=execution()
    with pytest.raises(ValueError):materialize_mmio(s,elf_bytes=synthetic_elf(0xa4))
    corrupt=s.model_copy(update={'instruction_count':11})
    with pytest.raises(ValueError):materialize_mmio(corrupt,elf_bytes=kw['elf_bytes'])


def test_bridge_without_replay_rejected():
    s,kw=execution()
    with pytest.raises(ValueError,match='REPLAY_REQUIRED'):
        materialize_mmio(s,elf_bytes=kw['elf_bytes'],bridge=kw['bridge'])


@pytest.mark.parametrize('key',['host_path','timestamp','run_uuid','evaluation_label','llm_text'])
def test_metadata_not_accepted_as_scientific_input(key):
    s,kw=execution();kw['replay_inputs'][key]='anything'
    with pytest.raises(ValueError,match='REPLAY_INPUT_FIELDS'):materialize_mmio(s,**kw)


def test_unresolved_address_excluded_and_unresolved_write_not_filled():
    words=encoded_program();words[0]=10<<15|5<<7|0x13
    elf=synthetic_elf(words=words);s=grounding.extract_rv32_mmio_static_facts(elf,map_evidence().platform_map)
    assert materialize_mmio(s,elf_bytes=elf)==()
    words=encoded_program();words[3]=0xa5<<20|10<<15|6<<7|0x13
    elf=synthetic_elf(words=words);s=grounding.extract_rv32_mmio_static_facts(elf,map_evidence().platform_map)
    result=materialize_mmio(s,elf_bytes=elf)
    assert len(result)==3 and 'value' not in values(result[1])
    assert result[1].primitives[0].formalization_status=='partially_formalized'
    assert result[1].primitives[0].control.status=='not_established'


def test_cap0_identity_and_deterministic_serialization():
    s,kw=execution();a=materialize_mmio(s,**kw);b=materialize_mmio(s,**kw)
    for x,y in zip(a,b):
        text=cap.serialize_firmware_capability(x)
        assert text==cap.serialize_firmware_capability(y)
        assert cap.parse_firmware_capability(text)==x
        fields=x.model_dump(mode='json',include=set(cap.FirmwareCapabilityInput.model_fields))
        fields['evidence'].reverse();fields['source_artifacts'].reverse()
        assert cap.serialize_firmware_capability(cap.build_firmware_capability(cap.FirmwareCapabilityInput.model_validate(fields)))==text
