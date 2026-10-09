"""Portable synthetic signature/dataflow tests; no real sample or simulator."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from chipchain.firmware.elf import ElfImage
from chipchain.firmware.static_ir import build_analysis, content_id
from experiments.rtl.rocket import signature_analysis as api
from scripts.rtl import run_rocket_reproduction as runner
from scripts.rtl import analyze_rocket_differential as investigation


def synthetic_elf():
    # Reuse the existing small R3 ELF builder; no ignored research inputs needed.
    source = Path(__file__).with_name('test_rocket_reproduction.py')
    spec = importlib.util.spec_from_file_location('rocket_r3_test_fixture', source)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module.tiny_elf()[0]


def synthetic_static(*, second_writer=False, gap=False):
    data = bytearray(synthetic_elf()); base = 0x80000000
    encodings = [0x00000097, 0x30008093, 0x30002173, 0x0020b423]
    if second_writer: encodings += [0x34302173, 0x0020b423]
    for n, word in enumerate(encodings): data[0x100+4*n:0x104+4*n] = word.to_bytes(4, 'little')
    elf = bytes(data); image = ElfImage(elf); instructions=[]
    for n, word in enumerate(encodings):
        raw = word.to_bytes(4, 'little').hex(); pc = base+n*4
        if gap and n == 2: continue
        instructions.append({'fact_id':content_id('fwinstruction', {'elf':image.identity.sha256,'pc':pc,'bytes':raw}),
                             'pc':pc,'raw_bytes':raw,'mnemonic':'diagnostic_fixture','operands':[],
                             'text':'synthetic byte decoder input','function_ids':[],'block_id':'one_block'})
    model = build_analysis(artifact=image.identity,ghidra_language='RISCV:LE:64:default',
                           ghidra_version='synthetic',producer={'role':'synthetic'},
                           functions=[],blocks=[],instructions=instructions,edges=[],calls=[],references=[],behaviors=[])
    return elf, model.model_dump_json().encode()


def layout():
    elf = synthetic_elf(); digest=api.sha256(elf).hexdigest()
    return api.make_layout(elf,expected_elf_sha256=digest,
                           range_symbols=[('begin_signature','end_signature')])


def test_signature_high_low_addresses_and_memory_endianness():
    descriptor=layout()
    data=b'0123456789abcdef1122334455667788\n'
    mapped=api.map_signature(data,descriptor,expected_elf_sha256=descriptor['elf_sha256'])
    word=mapped['words'][0]
    assert word['halves']['low']['address']==0x80000300
    assert word['halves']['high']['address']==0x80000308
    assert word['halves']['low']['memory_bytes']=='8877665544332211'
    assert word['halves']['high']['memory_bytes']=='efcdab8967452301'


@pytest.mark.parametrize('data',[b'',b'0'*31+b'\n',b'x'*32+b'\n',b'0'*32+b'\n'+b'0'*32+b'\n'])
def test_missing_or_wrong_signature_is_rejected_not_zero(data):
    descriptor=layout()
    with pytest.raises(ValueError):api.map_signature(data,descriptor,expected_elf_sha256=descriptor['elf_sha256'])


def test_signature_wrong_elf_layout_and_overlaps_rejected():
    descriptor=layout()
    with pytest.raises(ValueError):api.map_signature(b'0'*32+b'\n',descriptor,expected_elf_sha256='f'*64)
    elf=synthetic_elf()
    with pytest.raises(ValueError):api.make_layout(elf,expected_elf_sha256='f'*64,range_symbols=[('begin_signature','end_signature')])
    with pytest.raises(ValueError):api.make_layout(elf,expected_elf_sha256=descriptor['elf_sha256'],
        range_symbols=[('begin_signature','end_signature')]*2)
    mapped=api.map_signature(b'0'*32+b'\n',descriptor,expected_elf_sha256=descriptor['elf_sha256'])
    other={**mapped,'layout':{**descriptor,'ranges':[]}}
    with pytest.raises(ValueError):api.compare_mapped(mapped,other)


def test_static_csr_source_comes_from_bytes_not_mnemonic_or_word_number():
    elf,static=synthetic_static()
    origins=api.store_origins(elf,static)
    store=origins['stores'][0]
    assert store['address']==0x80000308
    assert store['store_pc']==0x8000000c
    assert store['value_source']['read_pc']==0x80000008
    assert store['value_source']['csr_name']=='mstatus'
    assert store['address_source_pcs']==[0x80000000,0x80000004]


def test_wrong_static_elf_or_instruction_bytes_rejected_even_with_recomputed_ids():
    elf,static=synthetic_static(); changed=bytearray(elf);changed[0x101]^=1
    with pytest.raises(ValueError):api.store_origins(bytes(changed),static)
    value=json.loads(static);instruction=value['instructions'][0];instruction['raw_bytes']='ffffffff'
    instruction['fact_id']=content_id('fwinstruction',{'elf':value['artifact']['sha256'],'pc':instruction['pc'],'bytes':'ffffffff'})
    value['analysis_id']=content_id('firmware-static',{k:v for k,v in value.items() if k!='analysis_id'})
    with pytest.raises(ValueError,match='instruction bytes'):api.store_origins(elf,json.dumps(value).encode())


def test_missing_csr_read_does_not_invent_value_source():
    elf,static=synthetic_static(gap=True)
    assert api.store_origins(elf,static)['stores']==[]


def test_multiple_bounded_writers_are_ambiguous():
    elf,static=synthetic_static(second_writer=True);digest=api.sha256(elf).hexdigest()
    desc=api.make_layout(elf,expected_elf_sha256=digest,range_symbols=[('begin_signature','end_signature')])
    mapped=api.map_signature(b'0'*32+b'\n',desc,expected_elf_sha256=digest)
    result=api.annotate_origins(mapped,api.store_origins(elf,static))
    high=result['halves'][1]
    assert high['static_source_status']=='AMBIGUOUS'
    assert high['all_possible_writers_established'] is False


@pytest.mark.parametrize('different',[True,False])
def test_raw_comparison_never_verifies_deviation_or_vulnerability(different):
    desc=layout();a=api.map_signature(b'0'*32+b'\n',desc,expected_elf_sha256=desc['elf_sha256'])
    b=api.map_signature((b'1' if different else b'0')*32+b'\n',desc,expected_elf_sha256=desc['elf_sha256'])
    compared=api.compare_mapped(a,b)
    assert compared['verified_deviation'] is False
    assert compared['architectural_differential']=='UNKNOWN'


def test_human_report_explains_exact_source_and_missing_evidence():
    elf,static=synthetic_static();digest=api.sha256(elf).hexdigest()
    desc=api.make_layout(elf,expected_elf_sha256=digest,range_symbols=[('begin_signature','end_signature')])
    a=api.map_signature(b'0'*32+b'\n',desc,expected_elf_sha256=digest)
    b=api.map_signature(b'1'*16+b'0'*16+b'\n',desc,expected_elf_sha256=digest)
    report=api.render_signature_analysis(api.compare_mapped(a,b),api.annotate_origins(a,api.store_origins(elf,static)))
    assert 'mstatus' in report and '0x80000008' in report and '0x8000000c' in report
    assert '轨迹和控制实验' in report and '不能单凭签名差异认定硬件漏洞' in report
    unknown=api.render_signature_analysis(api.compare_mapped(a,b),{'halves':[]})
    assert '唯一来源尚未确定' in unknown


def test_explicit_alternate_research_root_is_bounded_and_reports_missing_input(tmp_path,monkeypatch):
    repository=tmp_path/'repo'
    monkeypatch.setattr(runner,'__file__',str(repository/'scripts/rtl/run_rocket_reproduction.py'))
    declared=repository/'output/another-research'
    args=SimpleNamespace(output=declared/'run',output_root=declared,top='Synthetic',rtl=tmp_path/'absent',
                         compile_arg=[],max_cycles=10,seed=0,upstream_commit='a'*40)
    assert runner.run(args)==1
    assert json.loads((args.output/'rtl-run-summary.json').read_text())['simulation_status']=='NOT_ESTABLISHED'
    args.output_root=tmp_path/'outside';args.output=args.output_root/'run'
    with pytest.raises(ValueError,match='repository output'):runner.run(args)


def test_acquisition_summary_cannot_replace_missing_actual_trace(tmp_path):
    path=tmp_path/'manifest.json'
    path.write_text(json.dumps({'summary':{'source_binding_status':'SOURCE_BOUND_EXECUTION'},'artifacts':{}}))
    with pytest.raises(ValueError,match='missing required trace'):investigation.verify_rtl_run(path)


@pytest.mark.parametrize('problem',['different_final_value','missing_event','repeated_event','different_hart','correct'])
def test_read_store_association_requires_both_final_values_unique_events_and_context(problem):
    read={'kind':'instruction','pc':16,'bytes_hex':'73210030','line':1,'hart':0,'mode':3,
          'elf_binding':{'status':'MATCHED'},'csr_instruction_read':{'value':7}}
    store={'kind':'instruction','pc':20,'bytes_hex':'23b42000','line':2,'hart':0,'mode':3,
           'elf_binding':{'status':'MATCHED'},'integer_register_snapshot':{1:0x100,2:7},
           'memory_writes':[{'address':0x108,'value':7}],'commit_line':3}
    events=[read,store]
    if problem=='missing_event':events=[read]
    if problem=='repeated_event':events=[read,store,dict(store)]
    if problem=='different_hart':store['hart']=1
    origins={'elf_sha256':'a'*64,'halves':[{'address':0x108,'value':7,'store_candidates':[
        {'store_pc':20,'store_bytes':'23b42000','source_register':2,
         'value_source':{'read_pc':16,'read_bytes':'73210030'}}]}]}
    ref={'elf_sha256':'a'*64,'words':[{'halves':{'high':{'address':0x108,
          'value':8 if problem=='different_final_value' else 7}}}]}
    record={'elf_sha256':'a'*64,'binding_status':'SOURCE_BOUND_PREFIX','events':events}
    result=investigation.associate_origins(origins,record,record,ref)
    assert result['halves'][0]['execution_relation']==('BOUND_READ_AND_STORE_DIAGNOSTIC' if problem=='correct' else 'UNKNOWN')


@pytest.mark.parametrize('problem',['wrong_elf','missing_elf','instruction_mismatch'])
def test_origin_association_rejects_conflicting_trace_identity(problem):
    origins={'elf_sha256':'a'*64,'halves':[]}
    reference={'elf_sha256':'a'*64,'words':[]}
    correct={'elf_sha256':'a'*64,'binding_status':'SOURCE_BOUND_PREFIX','events':[]}
    altered=dict(correct)
    if problem=='wrong_elf':altered['elf_sha256']='b'*64
    if problem=='missing_elf':altered.pop('elf_sha256')
    if problem=='instruction_mismatch':altered['binding_status']='MISMATCH'
    with pytest.raises(ValueError,match='identity mismatch'):
        investigation.associate_origins(origins,correct,altered,reference)
