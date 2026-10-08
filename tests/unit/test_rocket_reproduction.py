"""Synthetic loader and fail-closed diagnostic tests; never start a simulator."""
import importlib.util
import json
from pathlib import Path
import struct
from types import SimpleNamespace

import pytest

SCRIPT=Path(__file__).resolve().parents[2]/'scripts/rtl/run_rocket_reproduction.py'
spec=importlib.util.spec_from_file_location('rocket_reproduction',SCRIPT)
runner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def tiny_elf(*, physical_delta=0):
    base=0x80000000
    symbols={'_start':base,'_end_main':base+16,'tohost':base+0x80,
             'begin_signature':base+0x300,'end_signature':base+0x310}
    for i in range(6):
        symbols[f'_random_data{i}']=base+0x100+i*16
        symbols[f'_end_data{i}']=base+0x110+i*16
    data=bytearray(0x1900)
    data[:64]=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+b'\0'*9,
                         2,243,1,base,64,0x1800,0,64,56,1,64,4,3)
    data[64:120]=struct.pack('<IIQQQQQQ',1,5,0x100,base,base+physical_delta,0x800,0x800,8)
    data[0x100:0x104]=bytes.fromhex('970f0100')
    strings=b'\0';entries=b'\0'*24
    for name,value in symbols.items():
        offset=len(strings);strings+=name.encode()+b'\0'
        entries+=struct.pack('<IBBHQQ',offset,0x10,0,1,value,0)
    data[0x1000:0x1000+len(strings)]=strings
    data[0x1200:0x1200+len(entries)]=entries
    names=b'\0.strtab\0.symtab\0.shstrtab\0'
    data[0x1700:0x1700+len(names)]=names
    for index,fields in enumerate([(1,3,0,0,0x1000,len(strings),0,0,1,0),
                                  (9,2,0,0,0x1200,len(entries),1,1,8,24),
                                  (17,3,0,0,0x1700,len(names),0,0,1,0)],1):
        data[0x1800+index*64:0x1800+(index+1)*64]=struct.pack('<IIQQQQIIQQ',*fields)
    flat=data[0x100:0x900]
    native=b''.join(f'{int.from_bytes(flat[i:i+8],"little"):016x}\n'.encode() for i in range(0,len(flat),8))
    return bytes(data),native


def status(**updates):
    fields=dict(build_passed=True,process_code=0,
                driver_result={'driver_started':True,'clock_rising_edges':100,
                               'driver_return_code':0,'stop_reason':'tohost_observed_and_adapter_drained'},
                trace_present=True,signature_present=True,inputs_unchanged=True,
                trace_audit={'elf_entry_byte_match':True},cocotb_passed=True)
    fields.update(updates)
    return runner.summarize(**fields)


def test_exact_elf_native_hex_loader_and_actual_rounded_span():
    elf,native=tiny_elf();config=runner.prepare_input(elf,native)
    assert len(config['data'])==12
    assert config['loader_policy']['upstream_code_range_stop']==0x80000034
    assert config['loader_policy']['code_loaded_end_exclusive']==0x80000038
    assert config['loader_policy']['assert_interrupts'] is False


@pytest.mark.parametrize('kind',['physical_mapping','hex_conflict','malformed_hex'])
def test_incompatible_loader_inputs_rejected(kind):
    elf,native=tiny_elf(physical_delta=8 if kind=='physical_mapping' else 0)
    if kind=='hex_conflict':native=b'ffffffffffffffff\n'+native.split(b'\n',1)[1]
    if kind=='malformed_hex':native=b'@80000000\n'+native
    with pytest.raises(ValueError):runner.prepare_input(elf,native)


@pytest.mark.parametrize('change',[{'build_passed':False},{'driver_result':None},
                                  {'trace_present':False},{'inputs_unchanged':False},
                                  {'trace_audit':{'elf_entry_byte_match':False}}])
def test_build_missing_execution_or_missing_binding_never_establishes_evidence(change):
    result=status(**change)
    assert result['source_binding_status']=='NOT_ESTABLISHED'
    assert result['architectural_differential']=='UNKNOWN'
    assert result['hardware_trigger']==result['hardware_deviation']=='NOT_ESTABLISHED'
    if not change.get('trace_present',True):assert result['trace_status']=='MISSING'


@pytest.mark.parametrize('record',[
    'HartID mode PC INSTR WDATA COV\n',
    '0 3 0x00010000 0x00000297 0x00000000 0\n',
    '0 3 0x80000000 0xffffffff 0x00000000 0\n',
    '0 3 0x80000000 0x00010f97 0x00000000 EXCEPTION\n',
])
def test_header_boot_rom_wrong_bytes_or_exception_cannot_prove_normal_input_execution(record):
    elf,_=tiny_elf();audit=runner.audit_trace(record.encode(),elf)
    assert audit['elf_entry_byte_match'] is False
    assert status(trace_audit=audit)['source_binding_status']=='NOT_ESTABLISHED'


def test_valid_monitor_prefix_is_separate_from_completion_and_differential():
    elf,_=tiny_elf()
    audit=runner.audit_trace(b'0 3 0x80000000 0x00010f97 0x00000000 0\n',elf)
    assert audit['elf_entry_byte_match'] is True
    result=status(process_code=1,trace_audit=audit,
                  driver_result={'driver_started':True,'clock_rising_edges':100,
                                 'driver_return_code':2,'stop_reason':'cycle_limit'})
    assert result['source_binding_status']=='SOURCE_BOUND_EXECUTION'
    assert result['completion_status']=='NOT_COMPLETED'
    assert result['stop_reason']=='cycle_limit'
    assert result['architectural_differential']=='UNKNOWN'
    assert result['type2_chain']=='NOT_VERIFIED'


def test_failed_configuration_writes_audit_without_starting_tools(tmp_path,monkeypatch):
    root=tmp_path/'repo'
    monkeypatch.setattr(runner,'__file__',str(root/'scripts/rtl/run_rocket_reproduction.py'))
    out=root/'output/rtl-rocket-feasibility/failed'
    args=SimpleNamespace(output=out,top='SyntheticTop',rtl=tmp_path/'missing.v',
                         compile_arg=[],max_cycles=10,seed=0,upstream_commit='a'*40)
    assert runner.run(args)==1
    manifest=json.loads((out/'rtl-run-manifest.json').read_text())
    assert manifest['commands']==[]
    assert manifest['failure']['type']=='FileNotFoundError'
    assert manifest['summary']['build_status']=='BUILD_FAILED'
    assert manifest['summary']['simulation_status']=='NOT_ESTABLISHED'


def test_case_name_does_not_determine_result():
    source=SCRIPT.read_text()
    assert 'real_case_001' not in source
    assert 'real_case_002' not in source
    assert status()['source_binding_status']=='SOURCE_BOUND_EXECUTION'


def test_raw_signature_difference_never_guesses_cause_or_configuration():
    result=runner.compare_signature_bytes(b'0'*32+b'\n',b'1'*32+b'\n')
    assert result['different_words'][0]['index']==0
    assert result['architectural_differential']=='UNKNOWN'
    assert 'hardware_trigger' not in result
    with pytest.raises(ValueError):runner.compare_signature_bytes(b'',b'1'*32+b'\n')


def test_xml_failure_cannot_be_reported_as_normal_completion():
    result=status(cocotb_passed=False)
    assert result['source_binding_status']=='SOURCE_BOUND_EXECUTION'
    assert result['completion_status']=='NOT_COMPLETED'
