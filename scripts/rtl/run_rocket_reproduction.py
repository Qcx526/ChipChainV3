"""Bounded Rocket feasibility smoke; all results are diagnostic, not core evidence."""
from __future__ import annotations

import argparse
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import xml.etree.ElementTree as ET

from elftools.elf.elffile import ELFFile


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def prepare_input(elf_bytes: bytes, hex_bytes: bytes) -> dict:
    """Reconstruct upstream loader data from exact ELF bytes, verify native HEX."""
    elf = ELFFile(BytesIO(elf_bytes))
    if elf['e_machine'] != 'EM_RISCV' or elf.elfclass != 64 or not elf.little_endian:
        raise ValueError('This Rocket testbench profile requires little-endian RV64 ELF')
    table = elf.get_section_by_name('.symtab')
    if table is None:
        raise ValueError('Upstream loader requires explicit ELF symbols')
    symbols = {}
    for symbol in table.iter_symbols():
        if symbol.name:
            value = int(symbol['st_value'])
            if symbol.name in symbols and symbols[symbol.name] != value:
                raise ValueError('Ambiguous ELF symbols')
            symbols[symbol.name] = value
    names = ['_start', '_end_main', 'tohost', 'begin_signature', 'end_signature']
    names += [f'{prefix}{i}' for i in range(6) for prefix in ('_random_data', '_end_data')]
    if any(name not in symbols for name in names):
        raise ValueError('ELF lacks upstream loader symbols')
    if symbols['_start'] != elf['e_entry'] or symbols['_start'] != 0x80000000:
        raise ValueError('This inspected upstream boot ROM enters 0x80000000')
    lines = hex_bytes.decode('ascii').splitlines()
    if any(len(line) != 16 or any(c not in '0123456789abcdefABCDEF' for c in line) for line in lines):
        raise ValueError('Native HEX requires exact 64-bit words')
    flat = b''.join(int(line, 16).to_bytes(8, 'little') for line in lines)
    base = symbols['_start']
    loads = [segment for segment in elf.iter_segments() if segment['p_type'] == 'PT_LOAD']
    for segment in loads:
        if segment['p_paddr'] != segment['p_vaddr']:
            raise ValueError('This TileLink loader requires declared physical/virtual identity')
        offset = segment['p_vaddr'] - base
        if offset < 0 or flat[offset:offset + segment['p_filesz']] != segment.data():
            raise ValueError('Native HEX does not match file-backed ELF load bytes')
    if (symbols['_end_main'] + 36 - base) > len(flat):
        raise ValueError('Native HEX does not cover upstream code loading span')
    data = []
    for i in range(6):
        begin, end = symbols[f'_random_data{i}'], symbols[f'_end_data{i}']
        if begin % 8 or end <= begin or (end-begin) % 8:
            raise ValueError('Invalid upstream random data range')
        matches = [s for s in loads if s['p_vaddr'] <= begin and end <= s['p_vaddr']+s['p_filesz']]
        if len(matches) != 1:
            raise ValueError('Random data requires unique file-backed ELF range')
        block = matches[0].data()[begin-matches[0]['p_vaddr']:end-matches[0]['p_vaddr']]
        data += [int.from_bytes(block[j:j+8], 'little') for j in range(0,len(block),8)]
    return {'elf_sha256': sha256(elf_bytes).hexdigest(), 'symbols': symbols, 'data': data,
            'loader_policy': {'boot_rom_base': 0x10000, 'entry': base,
                              'upstream_code_range_stop': symbols['_end_main']+36,
                              'code_loaded_end_exclusive': base+((symbols['_end_main']+36-base+7)//8)*8,
                              'tohost_initial': 0, 'signature_initial': 0,
                              'random_data_source': 'exact_ELF_file_bytes',
                              'assert_interrupts': False, 'reset_cycles': [5,5]}}


def summarize(*, build_passed, process_code, driver_result, trace_present,
              signature_present, inputs_unchanged, trace_audit=None, cocotb_passed=False) -> dict:
    executed = bool(build_passed and driver_result and driver_result.get('driver_started')
                    and driver_result.get('clock_rising_edges',0)>0)
    bound = bool(executed and inputs_unchanged and trace_present and trace_audit
                 and trace_audit.get('elf_entry_byte_match'))
    return {'build_status': 'BUILD_PASSED' if build_passed else 'BUILD_FAILED',
            'simulation_status': 'SIMULATION_EXECUTED' if executed else 'NOT_ESTABLISHED',
            'source_binding_status': 'SOURCE_BOUND_EXECUTION' if bound else 'NOT_ESTABLISHED',
            'source_binding_scope': 'this_new_run_inputs_driver_and_selected_RTL_only',
            'simulation_exit_code': process_code, 'trace_status': 'PRESENT' if trace_present else 'MISSING',
            'completion_status': ('COMPLETED' if cocotb_passed and process_code==0 and driver_result
                                   and driver_result.get('driver_return_code')==0 else 'NOT_COMPLETED'),
            'stop_reason': driver_result.get('stop_reason','UNKNOWN') if driver_result else 'UNKNOWN',
            'signature_status': 'PRESENT' if signature_present else 'MISSING',
            'architectural_differential': 'UNKNOWN', 'hardware_trigger': 'NOT_ESTABLISHED',
            'hardware_deviation': 'NOT_ESTABLISHED', 'silicon_applicability': 'NOT_ESTABLISHED',
            'type2_chain': 'NOT_VERIFIED'}


def audit_trace(data: bytes, elf_bytes: bytes) -> dict:
    """First columns only; match entry bytes, retain opaque state and exceptions."""
    elf=ELFFile(BytesIO(elf_bytes));entry=int(elf['e_entry'])
    segments=[s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_flags']&1]
    matched=False;rows=0;opaque=0;exceptions=0
    for line in data.decode('utf-8').splitlines():
        found=re.match(r'^(\d+)\s+(\d+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+',line)
        if not found:
            opaque+=1;continue
        rows+=1;pc=int(found[3],16);encoding=int(found[4],16)
        if 'EXCEPTION' in line:
            exceptions+=1
            continue
        candidates=[s for s in segments if s['p_vaddr']<=pc and pc+4<=s['p_vaddr']+s['p_filesz']]
        if pc==entry and len(candidates)==1:
            offset=pc-candidates[0]['p_vaddr']
            matched |= int.from_bytes(candidates[0].data()[offset:offset+4],'little')==encoding
    return {'instruction_rows':rows-exceptions,'exception_rows':exceptions,
            'opaque_rows':opaque,'elf_entry_byte_match':matched,
            'scope':'source-defined_monitor_records; no whole-trace state or retirement validation'}


def compare_signature_bytes(rtl: bytes, reference: bytes) -> dict:
    def words(data):
        rows=data.decode('ascii').splitlines()
        if not rows or any(not re.fullmatch('[0-9a-fA-F]{32}',row) for row in rows):
            raise ValueError('Signature must contain explicit 128-bit words')
        return [row.lower() for row in rows]
    left,right=words(rtl),words(reference)
    return {'comparison_scope':'raw 128-bit word indexes only',
            'rtl_sha256':sha256(rtl).hexdigest(),'reference_sha256':sha256(reference).hexdigest(),
            'rtl_word_count':len(left),'reference_word_count':len(right),
            'length_match':len(left)==len(right),
            'different_words':[{'index':i,'rtl_raw':a,'reference_raw':b}
                               for i,(a,b) in enumerate(zip(left,right)) if a!=b],
            'architectural_differential':'UNKNOWN',
            'reason':'Raw comparison does not establish matching architecture configuration or deviation rules'}


def execute(command, *, cwd, env, timeout, log_prefix):
    started = time.monotonic()
    with Path(str(log_prefix)+'.stdout.log').open('wb') as stdout, Path(str(log_prefix)+'.stderr.log').open('wb') as stderr:
        try:
            result = subprocess.Popen(command, cwd=cwd, env=env, stdout=stdout, stderr=stderr,
                                      start_new_session=True)
            result.wait(timeout=timeout)
            return {'command': command, 'exit_code': result.returncode,
                    'elapsed_seconds': round(time.monotonic()-started,3), 'watchdog_expired': False}
        except subprocess.TimeoutExpired:
            os.killpg(result.pid,signal.SIGTERM)
            try:result.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(result.pid,signal.SIGKILL);result.wait()
            return {'command': command, 'exit_code': None,
                    'elapsed_seconds': round(time.monotonic()-started,3), 'watchdog_expired': True}


def run(args):
    output = args.output.resolve()
    repository_output = Path(__file__).resolve().parents[2] / 'output'
    boundary = getattr(args, 'output_root', None) or repository_output / 'rtl-rocket-feasibility'
    boundary = boundary.resolve()
    if not boundary.is_relative_to(repository_output.resolve()) or boundary == repository_output.resolve():
        raise ValueError('Research output root must be an explicit child of repository output')
    if not output.is_relative_to(boundary) or output == boundary:
        raise ValueError('Research outputs must use a child of the declared research output root')
    if output.exists() and any(output.iterdir()):
        raise ValueError('Output must be new or empty')
    output.mkdir(parents=True,exist_ok=True)
    raw=output/'raw';raw.mkdir()
    manifest={'artifact_role':'feasibility_diagnostic', 'top':args.top,
              'original_case_rtl_revision_binding':'UNKNOWN', 'commands':[]}
    build=None;sim=None;input_hashes={};driver=None
    try:
        paths={'rtl':args.rtl.resolve(strict=True),'elf':args.elf.resolve(strict=True),
               'hex':args.hex.resolve(strict=True),'verilator':args.verilator.resolve(strict=True)}
        for name,expected in [('rtl',args.rtl_sha256),('elf',args.elf_sha256)]:
            if digest(paths[name]) != expected:
                raise ValueError(name+' input SHA256 conflict')
        upstream=args.upstream.resolve(strict=True)
        actual=subprocess.check_output(['git','-C',str(upstream),'rev-parse','HEAD'],text=True).strip()
        if actual != args.upstream_commit:
            raise ValueError('Driver commit identity mismatch')
        for path in (upstream/'Fuzzer').rglob('*'):
            if path.is_file() and path.suffix in ('.py','.txt'):
                input_hashes[str(path)]=digest(path)
        harness=Path(__file__).resolve().parents[2]/'experiments/rtl/rocket/reproduction_test.py'
        for path in [*paths.values(),harness,Path(__file__).resolve()]:input_hashes[str(path)]=digest(path)
        for label,path in [('test-wrapper.py',harness),('run-tool.py',Path(__file__).resolve())]:
            (raw/label).write_bytes(path.read_bytes())
        config=prepare_input(paths['elf'].read_bytes(),paths['hex'].read_bytes())
        top_header=re.search(r'\bmodule\s+'+re.escape(args.top)+r'\s*\((.*?)\)\s*;',
                             paths['rtl'].read_text(),re.S)
        if top_header is None:raise ValueError('Explicit top ANSI port header is required')
        initial_inputs=sorted(set(re.findall(r'\binput\s+(?:\[[^\]]+\]\s*)?(\w+)',top_header[1])))
        config.update(top=args.top,hex_path=str(paths['hex']),raw_directory=str(raw),
                      max_cycles=args.max_cycles,random_seed=args.seed,zero_initial_inputs=initial_inputs)
        config['loader_policy']['top_inputs_initially_zero']=initial_inputs
        (output/'loader-input.json').write_text(json.dumps(config,indent=2,sort_keys=True)+'\n')
        (output/'infos').mkdir()
        info=upstream/'Fuzzer/infos'/f'{args.top}_info.txt'
        (output/'infos'/info.name).write_bytes(info.read_bytes())
        for path in [output/'loader-input.json',output/'infos'/info.name]:input_hashes[str(path)]=digest(path)
        manifest.update(inputs=input_hashes,loader_policy=config['loader_policy'],
                        upstream_commit=actual,max_cycles=args.max_cycles,random_seed=args.seed,
                        compile_args=args.compile_arg)
        manifest['simulator_version']=subprocess.check_output([str(paths['verilator']),'--version'],text=True).strip()
        env=dict(os.environ)
        env.update(PATH=os.pathsep.join([str(args.python.absolute().parent),
                                        str(args.verilator.absolute().parent),env['PATH']]),
                   PYTHONPATH=os.pathsep.join([str(harness.parent),str(upstream/'Fuzzer'),str(upstream/'Fuzzer/RTLSim/src')]),
                   CHIPCHAIN_ROCKET_INPUT=str(output/'loader-input.json'),PYTHONHASHSEED='0',
                   COCOTB_REDUCED_LOG_FMT='1',RANDOM_SEED=str(args.seed))
        # Installed wrappers use their pinned compiled-in data prefix. An ambient
        # source-tree override can redirect the executable as well as its headers.
        env.pop('VERILATOR_ROOT',None)
        config_tool=args.python.absolute().parent/'cocotb-config'
        makefiles=subprocess.check_output([str(config_tool),'--makefiles'],env=env,text=True).strip()
        manifest['python_environment']=json.loads(subprocess.check_output([str(args.python.absolute()),'-c',
            'import sys,sysconfig,json,importlib.metadata as m;print(json.dumps({"python":sys.version,"base_prefix":sys.base_prefix,"purelib":sysconfig.get_paths()["purelib"],"cocotb":m.version("cocotb"),"cocotb_bus":m.version("cocotb-bus"),"libpython":sysconfig.get_config_var("LDLIBRARY")}))'],env=env,text=True))
        env['PYTHONPATH']+=os.pathsep+manifest['python_environment']['purelib']
        share=Path(makefiles).parent
        for path in share.rglob('*'):
            if path.is_file():input_hashes[str(path)]=digest(path)
        libs=Path(subprocess.check_output([str(config_tool),'--lib-dir'],env=env,text=True).strip())
        for path in libs.glob('*.so'):input_hashes[str(path)]=digest(path)
        libpython=Path(subprocess.check_output([str(config_tool),'--libpython'],env=env,text=True).strip())
        input_hashes[str(libpython)]=digest(libpython)
        for path in [args.python.resolve(),args.verilator.resolve().with_name('verilator_bin')]:
            input_hashes[str(path)]=digest(path)
        (output/'Makefile').write_text('COMPILE_ARGS := '+' '.join(args.compile_arg)+
                                      f'\ninclude {makefiles}/Makefile.sim\n')
        input_hashes[str(output/'Makefile')]=digest(output/'Makefile')
        common=['make','-f',str(output/'Makefile'),'SIM=verilator',f'VERILATOR_BIN_DIR={args.verilator.resolve().parent}',
                'TOPLEVEL_LANG=verilog',f'TOPLEVEL={args.top}',f'VERILOG_SOURCES={paths["rtl"]}',
                'MODULE=reproduction_test','COCOTB_HDL_TIMEUNIT=1us','COCOTB_HDL_TIMEPRECISION=1us',
                f'BUILD_ARGS=-j{args.jobs}',
                f'PLUSARGS=+DEBUG=0 +TRACE={raw}/',f'PYTHON_BIN={args.python.absolute()}',
                'PYTHONHOME='+manifest['python_environment']['base_prefix']]
        build=execute(common+['sim_build/Vtop'],cwd=output,env=env,timeout=args.build_timeout,log_prefix=raw/'build')
        manifest['commands'].append(build)
        if build['exit_code']==0:
            binary=output/'sim_build/Vtop'
            input_hashes[str(binary)]=digest(binary)
            sim=execute(common+['sim'],cwd=output,env=env,timeout=args.run_timeout,log_prefix=raw/'simulation')
            manifest['commands'].append(sim)
        if (raw/'driver-result.json').is_file():driver=json.loads((raw/'driver-result.json').read_text())
        if (output/'results.xml').is_file():
            tree=ET.parse(output/'results.xml')
            manifest['cocotb_results']={'testcases':len(tree.findall('.//testcase')),
                                      'failures':len(tree.findall('.//failure'))}
    except Exception as exc:
        manifest['failure']={'type':type(exc).__name__,'message':str(exc)}
    unchanged=bool(input_hashes) and all(Path(p).is_file() and digest(p)==h for p,h in input_hashes.items())
    trace=raw/'rtl_0.log';signature=raw/'rtl-signature.txt'
    trace_audit=None
    if trace.is_file():
        try:trace_audit=audit_trace(trace.read_bytes(),args.elf.read_bytes())
        except (ValueError,OSError) as exc:
            manifest['trace_validation_failure']={'type':type(exc).__name__,'message':str(exc)}
    summary=summarize(build_passed=bool(build and build['exit_code']==0),
                      process_code=sim['exit_code'] if sim else None,driver_result=driver,
                      trace_present=trace.is_file() and trace.stat().st_size>0,
                      signature_present=signature.is_file() and signature.stat().st_size>0,
                      inputs_unchanged=unchanged,trace_audit=trace_audit,
                      cocotb_passed=manifest.get('cocotb_results')=={'testcases':1,'failures':0})
    manifest.update(summary=summary,driver_result=driver,trace_audit=trace_audit,inputs_unchanged=unchanged,
                    artifacts={str(p.relative_to(output)):digest(p) for p in raw.iterdir() if p.is_file()})
    if (output/'sim_build/Vtop').is_file():manifest['simulator_binary_sha256']=digest(output/'sim_build/Vtop')
    # The copied config/Makefile contain this run's absolute output path. They
    # stay inspectable in the manifest, while identity uses their verified
    # external source bytes and the effective loader policy instead.
    identity={'input_bytes_sha256':sorted(h for p,h in input_hashes.items()
                                          if not Path(p).is_relative_to(output)),
              'simulator_binary_sha256':manifest.get('simulator_binary_sha256'),
              'top':args.top,'compile_args':args.compile_arg,'max_cycles':args.max_cycles,
              'random_seed':args.seed,'upstream_commit':args.upstream_commit,
              'simulator_version':manifest.get('simulator_version'),
              'python_environment':{k:v for k,v in manifest.get('python_environment',{}).items()
                                    if k not in ('base_prefix','purelib')},
              'loader_policy':manifest.get('loader_policy')}
    # Local diagnostic identity, not a formal HardwareRuntimeEvidence schema.
    manifest['diagnostic_run_id']='rocket-feasibility:'+sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()
    for name,obj in [('rtl-run-manifest.json',manifest),('rtl-run-summary.json',summary)]:
        (output/name).write_text(json.dumps(obj,sort_keys=True,indent=2)+'\n')
    print(json.dumps(summary,indent=2));print(str(output/'rtl-run-manifest.json'))
    return 0 if summary['source_binding_status']=='SOURCE_BOUND_EXECUTION' and summary['completion_status']=='COMPLETED' else 1


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('rtl','elf','hex','upstream','verilator','python','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--output-root',type=Path,
                   help='Explicit research root below repository output; defaults to output/rtl-rocket-feasibility')
    for name in ('rtl-sha256','elf-sha256','upstream-commit'):p.add_argument('--'+name,required=True)
    p.add_argument('--top',required=True)
    p.add_argument('--compile-arg',action='append',default=[])
    p.add_argument('--max-cycles',type=int,default=6000)
    p.add_argument('--jobs',type=int,default=2)
    p.add_argument('--seed',type=int,default=0)
    p.add_argument('--build-timeout',type=int,default=900)
    p.add_argument('--run-timeout',type=int,default=120)
    args=p.parse_args()
    if min(args.max_cycles,args.jobs,args.build_timeout,args.run_timeout)<1:p.error('Limits must be positive')
    raise SystemExit(run(args))


if __name__=='__main__':main()
