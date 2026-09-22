"""Small synthetic ELF/XML/bus fixtures only; no simulation or model calls."""
import json
import struct

import pytest

from chipchain.domain.common import Architecture
from chipchain.firmware import mmio_grounding as m


def encoded_program(command=0xa5):
    return [0x000402b7, 0x00100313, 0x0062a023, command << 20 | 0x313,
            0x0062a223, 0x0082a383, 0x00101e37, 0x000e0e13,
            0x007e2023, 0x000202b7, 0x00100313, 0x0062a423]


def synthetic_elf(command=0xa5, *, words=None, machine=243):
    code = b''.join(struct.pack('<I', w) for w in (words or encoded_program(command)))
    data = bytearray(0x200 + 3 * 40)
    names = b'\0.text\0.shstrtab\0'
    data[:52] = struct.pack('<16sHHIIIIIHHHHHH', b'\x7fELF\x01\x01\x01' + b'\0'*9,
                           2, machine, 1, 0x100080, 52, 0x200, 0, 52, 32, 1, 40, 3, 2)
    data[52:84] = struct.pack('<IIIIIIII', 1, 0x100, 0x100080, 0x100080, len(code), len(code), 5, 4)
    data[0x100:0x100+len(code)] = code
    data[0x180:0x180+len(names)] = names
    data[0x228:0x250] = struct.pack('<IIIIIIIIII', 1, 1, 6, 0x100080, 0x100, len(code), 0, 0, 4, 0)
    data[0x250:0x278] = struct.pack('<IIIIIIIIII', 7, 3, 0, 0, 0x180, len(names), 0, 0, 1, 0)
    return bytes(data)


def map_inputs(label='a'):
    entries = [dict(name=n, base=b, mask=mask) for n,b,mask in (
        ('Ram',0x100000,0xfff00000), ('SimCtrl',0x20000,0xfffffc00),
        ('Timer',0x30000,0xfffffc00), ('SyntheticPeripheral',0x40000,0xfffffc00))]
    params = {'NrDevices': "32'sh4", 'RV32E': "1'h0"}
    xml = '<root><module name="ibex_simple_system"><instance name="u_synthetic_mmio"/>'
    for k,v in params.items():
        xml += f'<var name="{k}" localparam="true"><const name="{v}"/></var>'
    for i,entry in enumerate(entries):
        for key in ('base','mask'):
            xml += f'<contassign><const name="32\'h{entry[key]:x}"/><arraysel><varref name="cfg_device_addr_{key}"/><const name="32\'h{i:x}"/></arraysel></contassign>'
    xml = (xml + '</module></root>').encode()
    record = dict(xml_sha256=m.bytes_sha(xml), address_map=entries, parameters=params, peripheral_instance='u_synthetic_mmio')
    manifest = {'unit.sv': m.bytes_sha(label.encode())}
    return dict(xml_bytes=xml, record_bytes=m.canonical(record).encode(),
                source_manifest_bytes=m.canonical(manifest).encode(), rtl_tree_sha256=m.digest(manifest),
                target_device='SyntheticPeripheral')


def map_evidence(label='a'):
    return m.extract_platform_map(**map_inputs(label))


def trace_rows(command=0xa5, read_value=0):
    events=[]
    def emit(cycle, phase, **kw):
        e=dict(schema='syn-mmio-event/v1', sequence=len(events), cycle=cycle, reset_epoch=1,
               phase=phase, transaction_id=0,address=0,write_enable=0,byte_enable=0,write_data=0,
               read_data=0,error=0,request_valid=0,response_valid=0,reset_n=1,
               enable_value=0,command_value=0,status_value=0)
        e.update(kw); events.append(e)
    emit(1,'reset_assert',reset_n=0);emit(1,'status_sample',reset_n=0);emit(2,'reset_release')
    for cycle in range(2,12):
        if cycle in (3,5,7):
            emit(cycle,'request',transaction_id=(cycle-1)//2,address={3:0x40000,5:0x40004,7:0x40008}[cycle],
                 write_enable=int(cycle!=7),byte_enable=15,write_data={3:1,5:command,7:0}[cycle],request_valid=1)
        if cycle in (4,6,8):
            emit(cycle,'response',transaction_id=(cycle-2)//2,address={4:0x40000,6:0x40004,8:0x40008}[cycle],
                 write_enable=int(cycle!=8),byte_enable=15,write_data={4:1,6:command,8:0}[cycle],response_valid=1,
                 read_data=read_value if cycle==8 else 0)
        if cycle==10:emit(cycle,'software_stop',address=0x20008,write_data=1,write_enable=1,byte_enable=15,request_valid=1)
        emit(cycle,'status_sample',enable_value=int(cycle>=3),command_value=command if cycle>=5 else 0,
             status_value=read_value if cycle>=5 else 0)
    return [dict(schema='syn-mmio-trace/v1',phase='header'),*events,
            dict(schema='syn-mmio-footer/v1',phase='footer',complete=1,event_count=len(events),last_cycle=12,reset_epoch_count=1,normal_sim_exit=1)]


def raw_text(rows):
    return ''.join(m.canonical(r)+'\n' for r in rows).encode()


def inputs(command=0xa5, read_value=0, rtl_label='a'):
    map_source=map_evidence(rtl_label)
    static=m.extract_rv32_mmio_static_facts(synthetic_elf(command),map_source.platform_map)
    raw=raw_text(trace_rows(command,read_value)); parsed=m.parse_apparatus_trace(raw.decode())
    stdout=b'Terminating simulation by software request.\nReceived $finish() from Verilog\n'
    recipe=dict(target_config={'RV32E':0},clock_policy='posedge/negedge',reset_schedule={'delay':2,'duration':2},
                runtime_options=['seed=1'],tools={'verilator':'synthetic-unit-version'})
    identity=dict(firmware_sha256=static.firmware_artifact.sha256,rtl_tree_sha256=map_source.rtl_tree_sha256,
                  simulator_sha256='1'*64,input_sha256='2'*64,build_recipe_sha256=m.digest(recipe),variant_patch_sha256='3'*64)
    manifest=dict(schema_version='syn-apparatus-run/v1',identity_inputs=identity,run_case_neutral_id='run:'+m.digest(identity),
                  raw_trace_sha256=m.bytes_sha(raw),parsed_trace_sha256=m.digest(parsed),normal_exit=True,trace_complete=True,
                  stdout_sha256=m.bytes_sha(stdout),stderr_sha256=m.bytes_sha(b''))
    binding={k:manifest[k] for k in ('run_case_neutral_id','raw_trace_sha256','parsed_trace_sha256')}
    binding.update({k:identity[k] for k in ('firmware_sha256','rtl_tree_sha256')})
    kwargs=dict(manifest_bytes=m.canonical(manifest).encode(),binding_bytes=m.canonical(binding).encode(),
                raw_trace_bytes=raw,parsed_trace_bytes=m.canonical(parsed).encode(),firmware=static.firmware_artifact,
                map_source=map_source,rtl_tree_sha256=map_source.rtl_tree_sha256,simulator_sha256='1'*64,input_sha256='2'*64,
                recipe=recipe,stdout_bytes=stdout,stderr_bytes=b'')
    return static,kwargs


def replace_json(kwargs,key,mutate):
    value=json.loads(kwargs[key]);mutate(value);kwargs[key]=m.canonical(value).encode()


def rebind_raw(kwargs,rows):
    raw=raw_text(rows);parsed=m.parse_apparatus_trace(raw.decode())
    kwargs['raw_trace_bytes']=raw;kwargs['parsed_trace_bytes']=m.canonical(parsed).encode()
    for key in ('manifest_bytes','binding_bytes'):
        replace_json(kwargs,key,lambda x:x.update(raw_trace_sha256=m.bytes_sha(raw),parsed_trace_sha256=m.digest(parsed)))


@pytest.mark.parametrize('command',[0xa5,0xa4])
def test_exact_static_sites_and_non_target_accesses(command):
    s=m.extract_rv32_mmio_static_facts(synthetic_elf(command),map_evidence().platform_map)
    assert [(f.instruction_pc,f.operation,f.address,f.value) for f in s.static_facts]==[
        (0x100088,'write',0x40000,1),(0x100090,'write',0x40004,command),(0x100094,'read',0x40008,None)]
    assert s.static_facts[-1].value_status=='not_applicable'
    assert [(f.address,f.value_status) for f in s.non_target_accesses]==[(0x101000,'unresolved'),(0x20008,'resolved_exact')]
    assert len(s.static_sequence)==5
    assert m.FirmwareMmioStaticCatalog.model_validate_json(m.serialize(s))==s


def test_same_elf_same_static_id_different_elf_different_id():
    p=map_evidence().platform_map
    a=m.extract_rv32_mmio_static_facts(synthetic_elf(),p)
    b=m.extract_rv32_mmio_static_facts(synthetic_elf(),p)
    c=m.extract_rv32_mmio_static_facts(synthetic_elf(0xa4),p)
    assert a.catalog_id==b.catalog_id!=c.catalog_id
    assert a.static_facts[1].fact_id!=c.static_facts[1].fact_id


def test_map_semantics_separate_from_rtl_source_provenance():
    a,b=map_evidence('a'),map_evidence('b')
    assert a.platform_map==b.platform_map
    assert a.map_evidence_id!=b.map_evidence_id and a.rtl_tree_sha256!=b.rtl_tree_sha256
    assert m.extract_rv32_mmio_static_facts(synthetic_elf(),a.platform_map).catalog_id==m.extract_rv32_mmio_static_facts(synthetic_elf(),b.platform_map).catalog_id


@pytest.mark.parametrize('mode',['architecture','unsupported','compressed','bound','elf_mapping'])
def test_static_fail_closed(mode):
    data=synthetic_elf();kw={}
    if mode=='architecture':data=synthetic_elf(machine=40)
    if mode=='unsupported':data=synthetic_elf(words=[0x0000006f]+encoded_program()[1:])
    if mode=='compressed':data=synthetic_elf(words=[0x00000001]+encoded_program()[1:])
    if mode=='bound':kw['instruction_count']=257
    if mode=='elf_mapping':
        data=bytearray(data);struct.pack_into('<I',data,0x228+16,0x104);data=bytes(data)
    with pytest.raises(ValueError):m.extract_rv32_mmio_static_facts(data,map_evidence().platform_map,**kw)


def test_unknown_initial_register_and_load_clobber_not_zero():
    words=encoded_program();words[0]=10<<15|5<<7|0x13
    s=m.extract_rv32_mmio_static_facts(synthetic_elf(words=words),map_evidence().platform_map)
    assert len(s.unresolved_accesses)==3 and not s.static_facts
    assert all(f.address is None and f.address_status=='unresolved' for f in s.unresolved_accesses)
    # Baseline load kills x7; its later RAM store value remains unknown.
    baseline=m.extract_rv32_mmio_static_facts(synthetic_elf(),map_evidence().platform_map)
    assert baseline.non_target_accesses[0].value is None


def test_unknown_store_value_not_filled_from_runtime():
    words=encoded_program();words[3]=0xa5<<20|10<<15|6<<7|0x13
    s=m.extract_rv32_mmio_static_facts(synthetic_elf(words=words),map_evidence().platform_map)
    assert s.static_facts[1].value_status=='unresolved' and s.static_facts[1].value is None
    baseline,kw=inputs();r=m.materialize_runtime(**kw)
    assert r.runtime_observations[1].write_value==0xa5
    with pytest.raises(ValueError,match='WRONG_FIRMWARE_BINDING'):m.bind_static_runtime(s,r)
    assert s.static_facts[1].value is None


def test_runtime_cannot_be_static_authority_or_prose_input():
    s,_=inputs();fields={k:getattr(s,k) for k in type(s).model_fields if k not in ('catalog_id','catalog_sha256')}
    fields['source_artifacts']=(m.source('raw_bus_trace',raw=b'unit'),)
    with pytest.raises(ValueError):m.identified(m.FirmwareMmioStaticCatalog,**fields)
    with pytest.raises(TypeError):m.extract_rv32_mmio_static_facts(synthetic_elf(),map_evidence().platform_map,objdump='write A5')


@pytest.mark.parametrize('value,rtl',[ (0,'a'),(0xdead,'b') ])
def test_runtime_value_is_independent_static_read(value,rtl):
    s,kw=inputs(read_value=value,rtl_label=rtl);r=m.materialize_runtime(**kw)
    baseline,_=inputs()
    assert m.serialize(s)==m.serialize(baseline)
    assert r.runtime_observations[-1].read_value==value
    assert s.static_facts[-1].value is None
    assert m.RuntimeMmioObservationSet.model_validate_json(m.serialize(r))==r
    b=m.bind_static_runtime(s,r)
    assert len(b.bindings)==3 and all(x.status=='unknown' and len(x.candidate_static_fact_ids)==3 for x in b.bindings)
    assert 'UNKNOWN' in m.render_report(s,r,b)


def test_runtime_values_change_observation_but_never_static_id():
    s,k=inputs();r=m.materialize_runtime(**k)
    ss,kk=inputs(read_value=0xdead);rr=m.materialize_runtime(**kk)
    assert s==ss and r.set_id!=rr.set_id
    assert r.runtime_observations[-1].observation_id!=rr.runtime_observations[-1].observation_id


def test_differential_metadata_does_not_pollute_runtime_semantics():
    _,kw=inputs();r=m.materialize_runtime(**kw)
    manifest=json.loads(kw['manifest_bytes']);manifest['identity_inputs']['variant_patch_sha256']='f'*64
    manifest['identity_inputs']['optional_human_label']='not scientific'
    manifest['run_case_neutral_id']='run:'+m.digest(manifest['identity_inputs'])
    kw['manifest_bytes']=m.canonical(manifest).encode()
    replace_json(kw,'binding_bytes',lambda b:b.update(run_case_neutral_id=manifest['run_case_neutral_id']))
    rr=m.materialize_runtime(**kw)
    assert r.set_id==rr.set_id and r.runtime_observations==rr.runtime_observations
    assert r.source_attestation.attestation_id!=rr.source_attestation.attestation_id


@pytest.mark.parametrize('defect',['firmware','rtl','binding_missing','upstream','raw','parsed','manifest_complete',
                                  'manifest_exit','stdout','simulator','recipe','input','map_rtl'])
def test_runtime_source_binding_rejects_tampering(defect):
    _,kw=inputs()
    if defect in ('firmware','rtl'):
        replace_json(kw,'binding_bytes',lambda b:b.update({defect+'_sha256' if defect=='firmware' else 'rtl_tree_sha256':'f'*64}))
    if defect=='binding_missing':replace_json(kw,'binding_bytes',lambda b:b.pop('rtl_tree_sha256'))
    if defect=='upstream':replace_json(kw,'binding_bytes',lambda b:b.update(run_case_neutral_id='run:other'))
    if defect=='raw':kw['raw_trace_bytes']+=b'\n'
    if defect=='parsed':replace_json(kw,'parsed_trace_bytes',lambda p:p['transactions'][0]['request'].update(write_data=99))
    if defect=='manifest_complete':replace_json(kw,'manifest_bytes',lambda b:b.update(trace_complete=False))
    if defect=='manifest_exit':replace_json(kw,'manifest_bytes',lambda b:b.update(normal_exit=False))
    if defect=='stdout':kw['stdout_bytes']=b'timeout'
    if defect=='simulator':kw['simulator_sha256']='f'*64
    if defect=='recipe':kw['recipe']['runtime_options']=['other']
    if defect=='input':kw['input_sha256']='f'*64
    if defect=='map_rtl':kw['map_source']=map_evidence('other')
    with pytest.raises(ValueError):m.materialize_runtime(**kw)


@pytest.mark.parametrize('defect',['response_missing','footer_missing','sample_missing','error','duplicate_sequence','reset_epoch'])
def test_incomplete_or_error_transaction_is_not_success(defect):
    _,kw=inputs();rows=trace_rows()
    if defect=='error':
        for e in rows:
            if e.get('transaction_id')==2:
                e['byte_enable']=1
                if e['phase']=='response':e['error']=1
        rebind_raw(kw,rows)
        with pytest.raises(ValueError,match='ERROR_TRANSACTION'):m.materialize_runtime(**kw)
        return
    if defect=='response_missing':rows.remove(next(e for e in rows if e['phase']=='response'))
    if defect=='footer_missing':rows.pop()
    if defect=='sample_missing':rows.remove(next(e for e in rows if e['phase']=='status_sample' and e['cycle']==5))
    if defect=='duplicate_sequence':rows[2]['sequence']=0
    if defect=='reset_epoch':rows[3]['reset_epoch']=0
    with pytest.raises(ValueError):m.parse_apparatus_trace(raw_text(rows).decode())


def test_unique_site_still_unknown_and_order_not_used():
    s,kw=inputs();r=m.materialize_runtime(**kw)
    single=m.extract_rv32_mmio_static_facts(synthetic_elf(),s.target_binding,instruction_count=3)
    b=m.bind_static_runtime(single,r)
    assert len(b.bindings)==3
    assert all(x.status=='unknown' and len(x.candidate_static_fact_ids)==1 for x in b.bindings)
    assert all(not x.bridge_evidence_ids for x in b.bindings)
    assert m.StaticRuntimeMmioBindingSet.model_validate_json(m.serialize(b))==b


def test_map_mismatch_prevents_even_candidate_binding():
    s,kw=inputs();r=m.materialize_runtime(**kw)
    p=s.target_binding.model_dump(exclude={'map_id'});p['configuration']=(('RV32E',1),)
    p['architecture']=Architecture.RISCV;p['entries']=s.target_binding.entries
    other=m.identified(m.PlatformMap,**p)
    s2=m.extract_rv32_mmio_static_facts(synthetic_elf(),other)
    with pytest.raises(ValueError,match='MAP_IDENTITY_MISMATCH'):m.bind_static_runtime(s2,r)


@pytest.mark.parametrize('defect',['xml_hash','map_record','rtl_sha'])
def test_map_extraction_rejects_unbound_sources(defect):
    kw=map_inputs()
    if defect=='xml_hash':kw['xml_bytes']+=b' '
    if defect=='map_record':replace_json(kw,'record_bytes',lambda r:r['address_map'][0].update(base=0x40000))
    if defect=='rtl_sha':kw['rtl_tree_sha256']='f'*64
    with pytest.raises(ValueError):m.extract_platform_map(**kw)


def test_path_and_diagnostic_prose_not_identity(tmp_path):
    p=map_evidence().platform_map;data=synthetic_elf()
    (tmp_path/'one.elf').write_bytes(data);(tmp_path/'different-name.elf').write_bytes(data)
    (tmp_path/'objdump.txt').write_text('misleading decoded instruction COMMAND=0xff')
    assert m.extract_rv32_mmio_static_facts((tmp_path/'one.elf').read_bytes(),p).catalog_id==m.extract_rv32_mmio_static_facts((tmp_path/'different-name.elf').read_bytes(),p).catalog_id


def test_serialized_fact_tamper_rejected():
    s,_=inputs();d=json.loads(m.serialize(s));d['static_facts'][1]['value']=0xa4
    with pytest.raises(ValueError):m.FirmwareMmioStaticCatalog.model_validate(d)


def test_set_like_ref_order_is_canonical_but_sequences_are_not():
    s,kw=inputs();d=s.model_dump(mode='json')
    d['source_artifacts'].reverse();d['evidence'].reverse()
    other=m.FirmwareMmioStaticCatalog.model_validate(d)
    assert other.catalog_id==s.catalog_id and m.serialize(other)==m.serialize(s)
    d['static_sequence'].reverse()
    with pytest.raises(ValueError):m.FirmwareMmioStaticCatalog.model_validate(d)
    r=m.materialize_runtime(**kw);d=r.model_dump(mode='json');d['runtime_sequence'].reverse()
    with pytest.raises(ValueError):m.RuntimeMmioObservationSet.model_validate(d)


def test_unresolved_static_value_remains_unknown_with_same_firmware_runtime():
    words=encoded_program();words[3]=0xa5<<20|10<<15|6<<7|0x13
    s=m.extract_rv32_mmio_static_facts(synthetic_elf(words=words),map_evidence().platform_map)
    _,kw=inputs();kw['firmware']=s.firmware_artifact
    manifest=json.loads(kw['manifest_bytes']);manifest['identity_inputs']['firmware_sha256']=s.firmware_artifact.sha256
    manifest['run_case_neutral_id']='run:'+m.digest(manifest['identity_inputs'])
    kw['manifest_bytes']=m.canonical(manifest).encode()
    replace_json(kw,'binding_bytes',lambda b:b.update(firmware_sha256=s.firmware_artifact.sha256,run_case_neutral_id=manifest['run_case_neutral_id']))
    runtime=m.materialize_runtime(**kw);before=m.serialize(s)
    bindings=m.bind_static_runtime(s,runtime)
    assert runtime.runtime_observations[1].write_value==0xa5
    assert s.static_facts[1].value_status=='unresolved' and s.static_facts[1].value is None
    assert m.serialize(s)==before and all(b.status=='unknown' for b in bindings.bindings)


def test_normal_exit_boolean_cannot_replace_actual_log_evidence():
    _,kw=inputs();kw['stdout_bytes']=b'elapsed timeout'
    replace_json(kw,'manifest_bytes',lambda x:x.update(stdout_sha256=m.bytes_sha(kw['stdout_bytes'])))
    with pytest.raises(ValueError,match='NORMAL_EXIT_NOT_CORROBORATED'):m.materialize_runtime(**kw)


def test_source_manifest_alone_does_not_prove_tree_bytes(tmp_path):
    (tmp_path/'rtl.sv').write_bytes(b'original');manifest={'rtl.sv':m.bytes_sha(b'original')}
    m.verify_source_tree(tmp_path,m.canonical(manifest),m.digest(manifest))
    (tmp_path/'rtl.sv').write_bytes(b'tampered')
    with pytest.raises(ValueError,match='SOURCE_TREE_MISMATCH'):
        m.verify_source_tree(tmp_path,m.canonical(manifest),m.digest(manifest))


def test_footer_cannot_request_unbounded_completeness_allocation():
    rows=trace_rows();rows[-1]['last_cycle']=10**12
    with pytest.raises(ValueError,match='TRACE_BOUNDS'):m.parse_apparatus_trace(raw_text(rows).decode())
