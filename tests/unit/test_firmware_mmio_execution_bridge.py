"""Synthetic byte/trace records only. No real run is manufactured by these fixtures."""
import re

import pytest

from chipchain.firmware import mmio_grounding as b1
from chipchain.firmware import mmio_execution_bridge as b
from tests.unit.test_firmware_mmio_grounding import inputs, encoded_program, synthetic_elf


def changed(obj, **changes):
    fields={k:getattr(obj,k) for k in type(obj).model_fields if k not in (obj.id_field,obj.hash_field)}
    fields.update(changes)
    return b1.identified(type(obj),**fields)


def processor_text(command=0xa5, value=0, cycle_shift=0):
    words=encoded_program(command);registers=[0]*32;lines=[b.HEADER]
    for i,word in enumerate(words):
        pc=0x100080+4*i;op=word&127;rd=(word>>7)&31;rs1=(word>>15)&31;rs2=(word>>20)&31
        imm=(((word>>25)<<5)|((word>>7)&31)) if op==0x23 else word>>20
        if imm&2048:imm-=4096
        if op==0x37:
            name='lui';oper=f'x{rd},0x{word>>12:x}';registers[rd]=word&0xfffff000;tail=f'  x{rd}=0x{registers[rd]:08x}'
        elif op==0x13:
            name='addi';oper=f'x{rd},x{rs1},{imm}';old=registers[rs1];registers[rd]=(old+imm)&0xffffffff
            tail=f'  x{rs1}:0x{old:08x}  x{rd}=0x{registers[rd]:08x}'
        else:
            address=(registers[rs1]+imm)&0xffffffff
            if op==0x23:
                name='sw';oper=f'x{rs2},{imm}(x{rs1})'
                tail=f'  x{rs1}:0x{registers[rs1]:08x}  x{rs2}:0x{registers[rs2]:08x} PA:0x{address:08x} store:0x{registers[rs2]:08x}'
            else:
                name='lw';oper=f'x{rd},{imm}(x{rs1})';registers[rd]=value
                tail=f'  x{rs1}:0x{registers[rs1]:08x}  x{rd}=0x{value:08x} PA:0x{address:08x} load:0x{value:08x}'
        lines.append(f'{(i+1)*2}\t{i+1+cycle_shift}\t{pc:08x}\t{word:08x}\t{name}\t{oper}\t{tail}')
    return ('\n'.join(lines)+'\n').encode()


def sample(value=0):
    static,kw=inputs(read_value=value);runtime=b1.materialize_runtime(**kw)
    platform=b1.identified(b.PlatformProof,rtl_tree_sha256=kw['rtl_tree_sha256'],map_id=static.target_binding.map_id,
        map_source_id=kw['map_source'].map_evidence_id,source_artifacts=(),single_cored_host=True,
        no_other_target_master=True,aligned_word_mask_from_instruction=True)
    sci={k:getattr(runtime.run_binding,k) for k in ('firmware_sha256','rtl_tree_sha256','simulator_sha256','input_sha256','execution_context_sha256')}
    args=dict(inputs=sci,static=static,elf_bytes=synthetic_elf(),platform=platform,bus_bytes=kw['raw_trace_bytes'],
        processor_bytes=processor_text(value=value),stdout_bytes=kw['stdout_bytes'],stderr_bytes=kw['stderr_bytes'])
    joint=b.make_joint_run(**args,process_returncode=0)
    result=b.materialize_bridge(joint=joint,runtime=runtime,**args)
    return args,runtime,joint,result


def test_complete_joint_bridge_and_static_read_separation():
    a,_,joint,result=sample(0xdead)
    assert [x.overall_status for x in result.bindings]==['bound']*3
    assert result.processor_observations[-1].read_value==0xdead
    assert result.processor_observations[-1].byte_mask is None
    assert a['static'].static_facts[-1].value is None
    assert b.BridgeSet.model_validate_json(b1.serialize(result))==result
    assert 'BOUND 3' in b.render_report(result,a['static'])


@pytest.mark.parametrize('field,value',[
    ('pc',0x100084),('instruction_encoding','23206200'),('operation','read'),
    ('address',0x40004),('width_bits',16),('write_value',7)])
def test_static_processor_explicit_conflicts(field,value):
    a,_,_,r=sample();p=r.processor_observations[0]
    p=changed(p,**{field:value})
    assert b.static_processor_status(a['static'].static_facts[0],p)=='not_same'


def test_static_processor_wrong_firmware_rejected():
    a,_,_,r=sample();p=changed(r.processor_observations[0],firmware_sha256='f'*64)
    with pytest.raises(ValueError,match='WRONG_FIRMWARE'):b.static_processor_status(a['static'].static_facts[0],p)


@pytest.mark.parametrize('field,value',[('address',0x4000c),('operation','read'),('write_value',99)])
def test_processor_bus_semantic_conflicts_not_position(field,value):
    _,_,joint,r=sample();changes={field:value}
    if field=='operation':changes.update(read_value=1,write_value=None)
    p=changed(r.processor_observations[0],**changes)
    status,_,mapping=b.semantic_bijection((p,*r.processor_observations[1:]),r.bus_observations,joint.joint_run_id,r.platform_proof)
    assert status=='not_same' and not mapping


def test_duplicate_semantics_unknown_even_when_order_could_pair():
    _,_,joint,r=sample();p=r.processor_observations[1];bus=r.bus_observations[1]
    p2=changed(p,trace_sequence=p.trace_sequence+1,processor_cycle=p.processor_cycle+1)
    o=bus.runtime_observation;o2=changed(o,transaction_id=99,request_cycle=o.request_cycle+1,response_cycle=o.response_cycle+1)
    bus2=changed(bus,runtime_observation=o2)
    status,reason,mapping=b.semantic_bijection((p,p2),(bus,bus2),joint.joint_run_id,r.platform_proof)
    assert (status,reason,mapping)==('unknown','UNKNOWN_AMBIGUOUS',{})


def test_no_cycle_offset_or_ordinal_join():
    _,_,joint,r=sample()
    processors=tuple(changed(p,processor_cycle=p.processor_cycle+200) for p in reversed(r.processor_observations))
    status,_,mapping=b.semantic_bijection(processors,r.bus_observations,joint.joint_run_id,r.platform_proof)
    assert status=='bound'
    for p in processors:
        bus=next(x for x in r.bus_observations if x.observation_id==mapping[p.observation_id])
        assert p.address==bus.runtime_observation.address


def test_single_candidate_needs_full_semantics_and_platform():
    _,_,joint,r=sample();p=changed(r.processor_observations[0],write_value=None)
    assert b.semantic_bijection((p,),(r.bus_observations[0],),joint.joint_run_id,r.platform_proof)[:2]==('unknown','UNKNOWN_INSUFFICIENT')
    platform=changed(r.platform_proof,no_other_target_master=False)
    assert b.semantic_bijection(r.processor_observations,r.bus_observations,joint.joint_run_id,platform)[:2]==('unknown','UNKNOWN_PLATFORM')


def test_cross_run_observations_rejected():
    _,_,joint,r=sample();p=changed(r.processor_observations[0],joint_run_id='mmio-joint-run:other')
    with pytest.raises(ValueError,match='CROSS_RUN'):b.semantic_bijection((p,),r.bus_observations,joint.joint_run_id,r.platform_proof)


@pytest.mark.parametrize('defect',['header','row','duplicate','pc','encoding','partial','direction','missing','truncated','extra','value'])
def test_processor_parser_fail_closed(defect):
    data=processor_text()
    if defect=='header':data=data.replace(b'Time\tCycle',b'time\tcycle')
    if defect=='row':data=data.replace(b'\tlui\t',b'\tgarbage\t',1)
    if defect=='duplicate':
        lines=data.splitlines();lines.insert(2,lines[1]);data=b'\n'.join(lines)+b'\n'
    if defect=='pc':data=data.replace(b'00100080',b'00100081',1)
    if defect=='encoding':data=data.replace(b'000402b7',b'0000006f',1)
    if defect=='partial':data=data.replace(b'store:0x00000001',b'store:0x??????01',1)
    if defect=='direction':data=data.replace(b'store:',b'load:',1)
    if defect=='missing':data=b''
    if defect=='truncated':data=data[:-1]
    if defect=='extra':data=data.replace(b'\n',b'\nextra\n',1)
    if defect=='value':data=data.replace(b'load:0x00000000',b'load:0x0000dead')
    with pytest.raises(ValueError):b.parse_processor_trace(data)


def test_processor_prefix_completeness_not_just_valid_rows():
    a,_,_,_=sample();rows=b.parse_processor_trace(a['processor_bytes']);bus=b1.parse_apparatus_trace(a['bus_bytes'].decode())
    for incomplete in (rows[:-1],rows[1:],rows[:4]+rows[5:]):
        with pytest.raises(ValueError,match='PREFIX_INCOMPLETE'):b.validate_processor_coverage(incomplete,a['elf_bytes'],a['static'],bus)


@pytest.mark.parametrize('field',['bus_bytes','processor_bytes','stdout_bytes','stderr_bytes','elf_bytes'])
def test_joint_file_tamper_rejected(field):
    args,runtime,joint,_=sample();args[field]+=b' '
    with pytest.raises((ValueError,UnicodeError)):b.materialize_bridge(joint=joint,runtime=runtime,**args)


@pytest.mark.parametrize('field',['firmware_sha256','rtl_tree_sha256','simulator_sha256','input_sha256','execution_context_sha256'])
def test_wrong_joint_input_rejected(field):
    args,runtime,joint,_=sample();args['inputs']={**args['inputs'],field:'f'*64}
    with pytest.raises(ValueError):b.materialize_bridge(joint=joint,runtime=runtime,**args)


def test_wrong_processor_trace_hash_rejected():
    args,runtime,joint,_=sample();payload=joint.evidence_payload();payload['processor_trace_sha256']='f'*64
    collection=changed(joint.collection,joint_evidence_sha256=b1.digest(payload))
    forged=changed(joint,processor_trace_sha256='f'*64,collection=collection)
    with pytest.raises(ValueError,match='REPLAY_MISMATCH'):b.materialize_bridge(joint=forged,runtime=runtime,**args)


def test_wall_time_pid_logs_are_attested_separately_not_semantic_identity():
    a,_,joint,_=sample();a['stdout_bytes']+=b'PID 123; wallclock 2026-09-22\n'
    other=b.make_joint_run(**a,process_returncode=0)
    assert other.joint_run_id==joint.joint_run_id
    assert other.collection.attestation_id!=joint.collection.attestation_id
    assert 'path' not in joint.evidence_payload()
    with pytest.raises(ValueError,match='JOINT_INPUT_FIELDS'):
        b.make_joint_run(**{**a,'inputs':{**a['inputs'],'evaluation_label':'anything'}},process_returncode=0)


def test_rule_version_changes_binding_id():
    _,_,_,r=sample();original=r.bindings[0]
    assert changed(original,binding_rule_version=original.binding_rule_version+'-future').binding_id!=original.binding_id


def test_unreviewed_platform_rejected(tmp_path):
    from tests.unit.test_firmware_mmio_grounding import map_evidence
    with pytest.raises(ValueError,match='UNREVIEWED_PLATFORM'):b.verify_platform(tmp_path,b'{}',map_evidence())


def test_stage_bound_requires_selected_evidence_references():
    _,_,_,r=sample();binding=r.bindings[0]
    with pytest.raises(ValueError,match='STAGE_BOUND_WITHOUT_REFS'):
        changed(binding,static_processor_status='not_same',overall_status='not_same',runtime_observation_id=None)
