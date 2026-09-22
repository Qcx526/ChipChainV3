"""Synthetic parser unit records are NOT runtime evidence; real opt-in builds Ibex.

No real RTL/ELF/trace fixture is committed. Expected outcomes live only here.
"""
import importlib.util
import json
import os
from pathlib import Path

import pytest

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('syn_apparatus',ROOT/'experiments/syn_e2e1/run.py')
a=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(a)


def raw_fixture(command_value=0xa5, status=0):
    """Handwritten UNIT-only trace; never used by run_experiment or real acceptance."""
    events=[]
    def emit(cycle,phase,**kw):
        e=dict(schema='syn-mmio-event/v1',sequence=len(events),cycle=cycle,reset_epoch=1,phase=phase,
               transaction_id=0,address=0,write_enable=0,byte_enable=0,write_data=0,read_data=0,error=0,
               request_valid=0,response_valid=0,reset_n=1,enable_value=0,command_value=0,status_value=0)
        e.update(kw);events.append(e)
    emit(1,'reset_assert',reset_n=0);emit(1,'status_sample',reset_n=0)
    emit(2,'reset_release')
    for cycle in range(2,12):
        if cycle in (3,5,7):
            tid=(cycle-1)//2;addr={3:0x40000,5:0x40004,7:0x40008}[cycle]
            emit(cycle,'request',transaction_id=tid,address=addr,write_enable=int(cycle!=7),byte_enable=15,
                 write_data={3:1,5:command_value,7:0}[cycle],request_valid=1)
        if cycle in (4,6,8):
            tid=(cycle-2)//2;addr={4:0x40000,6:0x40004,8:0x40008}[cycle]
            emit(cycle,'response',transaction_id=tid,address=addr,write_enable=int(cycle!=8),byte_enable=15,
                 write_data={4:1,6:command_value,8:0}[cycle],read_data=status if cycle==8 else 0,response_valid=1)
        if cycle==9:emit(cycle,'ram_write',address=0x101000,write_enable=1,byte_enable=15,write_data=status,request_valid=1)
        if cycle==10:emit(cycle,'software_stop',address=0x20008,write_enable=1,byte_enable=15,write_data=1,request_valid=1)
        emit(cycle,'status_sample',enable_value=int(cycle>=3),command_value=command_value if cycle>=5 else 0,status_value=status if cycle>=5 else 0)
    rows=[dict(schema='syn-mmio-trace/v1',phase='header'),*events,
          dict(schema='syn-mmio-footer/v1',phase='footer',complete=1,event_count=len(events),last_cycle=12,reset_epoch_count=1,normal_sim_exit=1)]
    return rows


def text(rows):return ''.join(a.canonical(r) for r in rows)


def record(parsed, rtl='a'):
    identity=dict(firmware_sha256='1'*64,firmware_source_sha256='2'*64,rtl_tree_sha256=rtl*64,
                  simulator_sha256=rtl*64,input_sha256='3'*64,build_recipe_sha256='4'*64)
    manifest=dict(run_case_neutral_id='run:'+a.digest(identity),identity_inputs=identity,
                  raw_trace_sha256='5'*64,parsed_trace_sha256=a.digest(parsed),normal_exit=True,trace_complete=True)
    binding={k:manifest[k] for k in ('run_case_neutral_id','raw_trace_sha256','parsed_trace_sha256')}
    binding.update({k:identity[k] for k in ('firmware_sha256','rtl_tree_sha256')})
    return manifest,binding


def test_parser_valid_unit_record():
    parsed=a.parse_trace(text(raw_fixture()))
    assert len(parsed['transactions'])==3
    assert parsed['footer']['complete']==1


@pytest.mark.parametrize('defect', ['malformed','sequence','response','duplicate_tid','footer','truncated','epoch','status_sample','latency','stop','extra_key','boolean','missing_response','duplicate_json_key'])
def test_invalid_trace_rejected(defect):
    rows=raw_fixture();target=next(r for r in rows if r['phase']=='request')
    if defect=='duplicate_json_key':
        with pytest.raises(a.ApparatusError,match='DUPLICATE_JSON_KEY'):
            a.parse_trace(text(rows).replace('"cycle":3,','"cycle":3,"cycle":3,',1))
        return
    if defect=='missing_response':
        rows.remove(next(r for r in rows if r['phase']=='response'))
        for i,r in enumerate(rows[1:-1]):r['sequence']=i
        rows[-1]['event_count']=len(rows)-2
    if defect=='malformed':
        with pytest.raises(a.ApparatusError):a.parse_trace('{garbage}\n')
        return
    if defect=='sequence':target['sequence']=0
    if defect=='response':next(r for r in rows if r['phase']=='response')['transaction_id']=99
    if defect=='duplicate_tid':
        [r for r in rows if r['phase']=='request'][1]['transaction_id']=1
    if defect=='footer':rows=rows[:-1]
    if defect=='truncated':
        with pytest.raises(a.ApparatusError):a.parse_trace(text(rows)[:-1])
        return
    if defect=='epoch':target['reset_epoch']=0
    if defect=='status_sample':
        rows=[r for r in rows if not (r['phase']=='status_sample' and r['cycle']==5)]
        for i,r in enumerate(rows[1:-1]):r['sequence']=i
        rows[-1]['event_count']=len(rows)-2
    if defect=='latency':next(r for r in rows if r['phase']=='response')['cycle']=5
    if defect=='stop':rows[-1]['normal_sim_exit']=0
    if defect=='extra_key':target['expected_value']=0
    if defect=='boolean':target['write_enable']=True
    with pytest.raises(a.ApparatusError):a.parse_trace(text(rows))


@pytest.mark.parametrize('defect', ['missing','firmware','rtl','run','raw','parsed','normal_exit'])
def test_binding_missing_or_mismatched_rejected(defect):
    parsed=a.parse_trace(text(raw_fixture(status=0xdead)));manifest,binding=record(parsed)
    if defect=='missing':binding.pop('rtl_tree_sha256')
    if defect=='firmware':binding['firmware_sha256']='f'*64
    if defect=='rtl':binding['rtl_tree_sha256']='f'*64
    if defect=='run':binding['run_case_neutral_id']='run:other'
    if defect=='raw':binding['raw_trace_sha256']='f'*64
    if defect=='parsed':parsed['footer']['last_cycle']+=1
    if defect=='normal_exit':manifest['normal_exit']=False
    with pytest.raises(a.ApparatusError):a.validate_binding(manifest,parsed,binding)


def test_u1_missing_binding_is_invalid_not_numeric_acceptance():
    parsed=a.parse_trace(text(raw_fixture(status=0xdead)));m,b=record(parsed)
    a.validate_binding(m,parsed,b);b.pop('run_case_neutral_id')
    with pytest.raises(a.ApparatusError,match='INVALID_BINDING'):a.validate_binding(m,parsed,b)


def test_same_firmware_required_and_first_monitored_difference():
    left=a.parse_trace(text(raw_fixture()));right=a.parse_trace(text(raw_fixture(status=0xdead)))
    lm,_=record(left);rm,_=record(right,'b')
    d=a.compare_runs(lm,rm,left,right)
    assert d['first_observable_difference']['phase']=='status_sample'
    assert d['first_observable_difference']['cycle']==5
    rm['identity_inputs']['firmware_sha256']='f'*64
    with pytest.raises(a.ApparatusError,match='CONTROLLED_INPUT_MISMATCH:firmware_sha256'):a.compare_runs(lm,rm,left,right)


def test_nontrigger_no_difference_requires_complete_records():
    p=a.parse_trace(text(raw_fixture(command_value=0xa4)));m,_=record(p);n,_=record(p,'b')
    assert a.compare_runs(m,n,p,p)['first_observable_difference'] is None
    raw=raw_fixture(command_value=0xa4);raw[-1]['complete']=0
    with pytest.raises(a.ApparatusError,match='TRACE_INCOMPLETE'):a.parse_trace(text(raw))


def test_address_map_disjointness():
    entries=[dict(name=n,base=b,mask=m) for n,b,m in [('ram',0x100000,0xfff00000),('sim',0x20000,0xfffffc00),('timer',0x30000,0xfffffc00),('test',0x40000,0xfffffc00)]]
    a.validate_map(entries);entries[2]['base']=0x40000
    with pytest.raises(a.ApparatusError,match='MAP_OVERLAP'):a.validate_map(entries)


def test_pinned_source_rejection_and_patch_sha(tmp_path):
    (tmp_path/'arbitrary.sv').write_text('unit fixture')
    with pytest.raises(a.ApparatusError,match='PINNED_SOURCE_MISMATCH'):a.verify_source(tmp_path)
    bad=tmp_path/'bad.patch';bad.write_text('not reviewed')
    with pytest.raises(a.ApparatusError,match='PATCH_IDENTITY_MISMATCH'):a.patch_source(tmp_path,bad,a.VARIANT_PATCH_SHA)
    exp=ROOT/'experiments/syn_e2e1'
    assert a.file_sha(exp/'integrate.patch')==a.COMMON_PATCH_SHA
    assert a.file_sha(exp/'variant.patch')==a.VARIANT_PATCH_SHA


def test_controlled_diff_only_reviewed_delta(tmp_path):
    exp=ROOT/'experiments/syn_e2e1';left=tmp_path/'left';right=tmp_path/'right'
    for p in (left,right):
        (p/a.PERIPHERAL).parent.mkdir(parents=True);(p/a.PERIPHERAL).write_bytes((exp/'synthetic_mmio.sv').read_bytes())
        (p/'unrelated.sv').write_text('unchanged fixture')
    a.patch_source(right,exp/'variant.patch',a.VARIANT_PATCH_SHA)
    assert a.verify_controlled_delta(left,right,exp)['changed_files']==[a.PERIPHERAL]
    (right/'unrelated.sv').write_text('unexpected change')
    with pytest.raises(a.ApparatusError,match='UNEXPECTED_RTL_DIFF'):a.verify_controlled_delta(left,right,exp)
    (right/'unrelated.sv').write_text('unchanged fixture')
    with (right/a.PERIPHERAL).open('a') as stream:stream.write('// unreviewed monitor change\n')
    with pytest.raises(a.ApparatusError,match='UNREVIEWED_RTL_DELTA'):a.verify_controlled_delta(left,right,exp)


def assert_real_result(out):
    """Evaluator-only expectations; never called by runner/parser/monitor."""
    result=json.loads((out/'apparatus-result.json').read_text())
    assert len(result['runs'])==4
    observations=[]
    for item in result['runs']:
        path=out/item['manifest'];m=json.loads(path.read_text());directory=path.parent
        raw=directory/'synthetic-mmio.jsonl';parsed=a.parse_trace(raw.read_text())
        assert a.file_sha(raw)==m['raw_trace_sha256']
        assert a.file_sha(out/m['firmware_path'])==m['identity_inputs']['firmware_sha256']
        assert a.file_sha(out/m['simulator_path'])==m['identity_inputs']['simulator_sha256']
        a.validate_binding(m,parsed,json.loads((directory/'trace-binding.json').read_text()))
        assert parsed==json.loads((directory/'parsed-trace.json').read_text())
        assert parsed==a.parse_trace((directory.parent/'2/synthetic-mmio.jsonl').read_text())
        tx=parsed['transactions'];assert len(tx)==3
        assert [t['request']['address'] for t in tx]==[0x40000,0x40004,0x40008]
        assert [t['request']['write_enable'] for t in tx]==[1,1,0]
        assert all(t['request']['byte_enable']==15 and t['response']['error']==0 for t in tx)
        assert tx[0]['request']['write_data']==1
        assert tx[0]['request']['cycle']<tx[1]['request']['cycle']<tx[2]['request']['cycle']
        observations.append((m,parsed,tx[1]['request']['write_data'],tx[2]['response']['read_data']))
    assert [(x[2],x[3]) for x in observations]==[(0xa5,0),(0xa5,0xdead),(0xa4,0),(0xa4,0)]
    for i,(m,p,cmd,value) in enumerate(observations):
        samples=[e for e in p['events'] if e['phase']=='status_sample']
        command_cycle=p['transactions'][1]['request']['cycle']
        assert all(e['status_value']==(value if e['cycle']>=command_cycle else 0) for e in samples)
        assert [e['write_data'] for e in p['events'] if e['phase']=='ram_write']==[value]
        assert p['footer']['complete']==p['footer']['normal_sim_exit']==1
    for i in (0,2):
        assert observations[i][0]['identity_inputs']['firmware_sha256']==observations[i+1][0]['identity_inputs']['firmware_sha256']
    d=result['comparisons'][0]['first_observable_difference']
    assert d['phase']=='status_sample' and d['different_fields']==['status_value']
    assert d['cycle']==observations[0][1]['transactions'][1]['request']['cycle']
    assert d['left']=={'status_value':0} and d['right']=={'status_value':0xdead}
    assert result['comparisons'][1]['first_observable_difference'] is None
    return observations


def test_real_offline_apparatus(monkeypatch):
    if os.environ.get('CHIPCHAIN_SYN_E2E1_REAL')!='1':pytest.skip('explicit real FuseSoC/Verilator apparatus opt-in required')
    # Only this explicit integration test lifts the suite subprocess ban. Runner
    # supplies its own sanitized, offline environment; no production LLM imports.
    monkeypatch.undo()
    out=a.run_experiment(ROOT)
    assert_real_result(out)
    assert_real_peripheral_protocol(out)
    print('REAL_APPARATUS_OUTPUT='+str(out))


def assert_real_peripheral_protocol(out):
    """Separate RTL unit harness; not an Ibex trace or cross-layer proof."""
    harness = r'''
#include "Vsynthetic_mmio.h"
#include "verilated.h"
#include <cstdint>
#include <cstdlib>
#include <iostream>
static Vsynthetic_mmio dut;
static void check(bool v) { if (!v) { std::cerr << "RTL protocol assertion failed\n"; std::abort(); } }
static void tick() { dut.clk_i=0; dut.eval(); dut.clk_i=1; dut.eval(); dut.clk_i=0; dut.eval(); }
static uint32_t access(uint32_t addr, bool we, uint32_t data=0, unsigned be=15, bool error=false) {
  check(!dut.rvalid_o);
  dut.req_i=1; dut.addr_i=addr; dut.we_i=we; dut.wdata_i=data; dut.be_i=be;
  tick(); check(dut.rvalid_o && bool(dut.err_o)==error); uint32_t value=dut.rdata_o;
  dut.req_i=0; tick(); check(!dut.rvalid_o && !dut.err_o); return value;
}
static void reset() { dut.req_i=0; dut.rst_ni=0; tick(); tick(); dut.rst_ni=1; tick(); }
int main(int argc, char** argv) {
  Verilated::commandArgs(argc, argv); uint32_t expected=std::strtoul(argv[1],nullptr,0);
  dut.stop_i=0; dut.result_valid_i=0; dut.result_data_i=0; dut.rst_ni=1; reset();
  check(access(0x40000,0)==0 && access(0x40004,0)==0 && access(0x40008,0)==0);
  // A matching COMMAND with pre-state ENABLE=0 must not change STATUS.
  access(0x40004,1,0xa5); check(access(0x40008,0)==0); access(0x40000,1,1);
  // Illegal accesses must error and preserve all three registers.
  access(0x40000,1,0,1,true); access(0x40004,1,0xa5,1,true);
  access(0x40001,1,0xa5,15,true); access(0x4000c,1,0xa5,15,true);
  access(0x40008,1,0xdead,15,true); access(0x40008,0,0,1,true);
  access(0x40009,0,0,15,true); access(0x4000c,0,0,15,true);
  check(access(0x40000,0)==1 && access(0x40004,0)==0xa5 && access(0x40008,0)==0);
  access(0x40004,1,0xa4); check(access(0x40008,0)==0);
  access(0x40004,1,0xa5); check(access(0x40008,0)==expected);
  access(0x40004,1,0xa4); access(0x40000,1,0); check(access(0x40008,0)==expected);
  reset(); check(access(0x40000,0)==0 && access(0x40004,0)==0 && access(0x40008,0)==0);
  dut.stop_i=1; tick(); dut.stop_i=0; tick(); tick(); tick(); dut.final();
  std::cout << "RTL unit protocol checks passed\n";
}
'''
    folder=out/'peripheral-unit';folder.mkdir();(folder/'driver.cpp').write_text(harness)
    vroot=a.TOOLS/'toolchains/verilator-ci/v4.210'
    env={'PATH':str(out/'offline')+':/usr/bin:/bin','VERILATOR_ROOT':str(vroot/'share/verilator'),
         'MAKEFLAGS':'-j2','LANG':'C','LC_ALL':'C'}
    for name,expected in [('a',0),('b',0xdead)]:
        run=folder/name;run.mkdir();build=run/'build'
        # Port reset is asynchronously consumed and synchronously observed. Same
        # localized waiver as the Ibex wrapper, only for this direct unit harness.
        args=[vroot/'bin/verilator','--cc','--exe','--build','--top-module','synthetic_mmio',
              '-Wno-SYNCASYNCNET','--Mdir',build,out/'sources'/name/a.PERIPHERAL,folder/'driver.cpp']
        a.command(args,run,env,run/'build-process')
        a.command([build/'Vsynthetic_mmio',str(expected)],run,env,run/'unit-process')
        assert 'RTL unit protocol checks passed' in (run/'unit-process.stdout.log').read_text()
