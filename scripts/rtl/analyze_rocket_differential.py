#!/usr/bin/env python3
"""Explicit, read-only R3 replay and bounded R4 diagnostic analysis.

No simulator is launched here. New control runs must be collected separately.
This tool never constructs a hardware contract or invokes the Type-II verifier.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys
import subprocess

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY))
from experiments.rtl.rocket import signature_analysis as sig
from experiments.rtl.rocket import trace_analysis as traces


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def verify_checkout(path: Path, expected_commit: str) -> dict:
    environment = {**os.environ, 'GIT_OPTIONAL_LOCKS': '0'}
    actual = subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True,env=environment).strip()
    changes = subprocess.check_output(['git','-C',str(path),'status','--porcelain','--untracked-files=no'],text=True,env=environment).strip()
    if actual != expected_commit or changes:
        raise ValueError('Driver/reference tracked source is not the acquisition revision')
    return {'commit':actual,'tracked_source_changes':False}


def verify_rtl_run(manifest_path: Path) -> dict:
    """Validate original acquisition bytes, including preserved source snapshots."""
    root = manifest_path.parent.resolve()
    manifest = json.loads(manifest_path.read_text())
    summary = manifest['summary']
    required = {'raw/rtl_0.log','raw/rtl-signature.txt','raw/driver-result.json',
                'raw/run-tool.py','raw/test-wrapper.py'}
    if not required.issubset(manifest['artifacts']):
        raise ValueError('RTL acquisition is missing required trace/source artifacts')
    if (summary['source_binding_status'] != 'SOURCE_BOUND_EXECUTION'
            or summary['completion_status'] != 'COMPLETED'
            or not manifest['inputs_unchanged']):
        raise ValueError('RTL run lacks completed source-bound acquisition')
    snapshots = {
        str(REPOSITORY/'scripts/rtl/run_rocket_reproduction.py'): root/'raw/run-tool.py',
        str(REPOSITORY/'experiments/rtl/rocket/reproduction_test.py'): root/'raw/test-wrapper.py',
    }
    retained_sources = []
    for name, expected in manifest['inputs'].items():
        path = Path(name)
        if path.is_file() and digest(path) == expected:
            continue
        archived = snapshots.get(name)
        if archived is not None and archived.is_file() and digest(archived) == expected:
            retained_sources.append({'original_path': name, 'frozen_snapshot': str(archived), 'sha256': expected})
            continue
        raise ValueError('RTL acquisition input changed or missing: ' + name)
    for name, expected in manifest['artifacts'].items():
        path = (root/name).resolve()
        if not path.is_relative_to(root) or not path.is_file() or digest(path) != expected:
            raise ValueError('RTL acquisition artifact changed or missing: ' + name)
    driver = json.loads((root/'raw/driver-result.json').read_text())
    if (driver != manifest['driver_result'] or driver.get('driver_return_code') != 0
            or driver.get('clock_rising_edges',0) <= 0
            or manifest['cocotb_results'] != {'testcases':1,'failures':0}):
        raise ValueError('RTL completion disagrees with actual driver records')
    if digest(root/'sim_build/Vtop') != manifest['simulator_binary_sha256']:
        raise ValueError('RTL model binary identity mismatch')
    return {'manifest_sha256': digest(manifest_path), 'retained_source_snapshots_used': retained_sources,
            'diagnostic_configuration_id': manifest['diagnostic_run_id'], 'summary': summary}


def verify_spike_run(summary_path: Path, elf_sha256: str) -> dict:
    record = json.loads(summary_path.read_text())
    if not {'isa-trace.log','isa-signature.txt','stdout.log','stderr.log'}.issubset(record['outputs']):
        raise ValueError('Spike acquisition is missing trace/signature artifacts')
    if record['exit_code'] != 0 or record['timed_out'] or record['input_elf_sha256'] != elf_sha256:
        raise ValueError('Spike acquisition failed or ELF identity differs')
    for name, info in record['outputs'].items():
        path = (summary_path.parent/name).resolve()
        if not path.is_relative_to(summary_path.parent.resolve()) or not path.is_file() or digest(path) != info['sha256']:
            raise ValueError('Spike acquisition artifact changed or missing: ' + name)
    if any((summary_path.parent/name).stat().st_size == 0 for name in ('isa-trace.log','isa-signature.txt')):
        raise ValueError('Spike trace/signature is empty')
    binary = Path(record['argv'][0])
    if digest(binary) != record['spike_binary_sha256'] or digest(Path(record['argv'][-1])) != elf_sha256:
        raise ValueError('Spike execution input identity mismatch')
    return {'summary_sha256': digest(summary_path), 'argv': record['argv'],
            'source_commit': record['source_commit'], 'spike_binary_sha256': record['spike_binary_sha256']}


def signature_ranges(elf_bytes: bytes, host_bytes: bytes, htif_bytes: bytes) -> list[tuple[str, str]]:
    """Validate the inspected writers, deriving their data-range count from source."""
    host, htif = host_bytes.decode(), htif_bytes.decode()
    count = re.findall(r'for n in range\((\d+)\):\s*data_start = symbols\[\x27_random_data', host)
    reference_count = re.findall(r'for \(int i = 0; i < (\d+); i\+\+\)', htif)
    if len(count) != 1 or count != reference_count:
        raise ValueError('Signature range recipes are ambiguous or incompatible')
    if ('format(memory[i+8], memory[i])' not in host or 'line_size = 16;' not in htif
            or 'buf[i+j-1]' not in htif):
        raise ValueError('Unsupported signature byte-order recipe')
    ranges = [('begin_signature', 'end_signature')]
    ranges += [(f'_random_data{i}', f'_end_data{i}') for i in range(int(count[0]))]
    symbols = sig.symbols_from_elf(elf_bytes)
    if any(a not in symbols or b not in symbols for a, b in ranges):
        raise ValueError('ELF lacks a range required by both actual signature writers')
    return ranges


def associate_origins(origins: dict, rocket: dict, spike: dict, reference_signature: dict) -> dict:
    """Relate recognized stores to actual reads, register samples and commits."""
    identity = origins.get('elf_sha256')
    if (not identity or any(record.get('elf_sha256') != identity
            for record in (rocket, spike, reference_signature))
            or any(record.get('binding_status') == 'MISMATCH' for record in (rocket, spike))):
        raise ValueError('Reference signature origin identity mismatch')
    reference_values = {h['address']:h['value'] for w in reference_signature['words'] for h in w['halves'].values()}
    result = []
    for half in origins['halves']:
        candidates = half['store_candidates']
        row = {**half, 'reference_signature_value':reference_values.get(half['address']),
               'execution_relation': 'UNKNOWN'}
        if len(candidates) != 1 or not candidates[0]['value_source'] or 'read_pc' not in candidates[0]['value_source']:
            result.append(row); continue
        store = candidates[0]; source = store['value_source']
        def matches(record, pc, raw):
            return [e for e in record['events'] if e['kind'] == 'instruction' and e.get('pc') == pc
                    and e.get('bytes_hex') == raw and e.get('elf_binding', {}).get('status') == 'MATCHED']
        rr = matches(rocket, source['read_pc'], source['read_bytes'])
        rs = matches(rocket, store['store_pc'], store['store_bytes'])
        sr = matches(spike, source['read_pc'], source['read_bytes'])
        ss = matches(spike, store['store_pc'], store['store_bytes'])
        if any(len(events) != 1 for events in (rr, rs, sr, ss)):
            row['reason'] = 'missing or ambiguous dynamic read/store events'
            result.append(row); continue
        read_r, store_r, read_s, store_s = rr[0], rs[0], sr[0], ss[0]
        w = int.from_bytes(bytes.fromhex(store['store_bytes']), 'little')
        immediate = ((w>>25)<<5) | ((w>>7)&31)
        if immediate & 0x800: immediate -= 0x1000
        registers = store_r.get('integer_register_snapshot', {})
        base = registers.get((w>>15)&31)
        register_value = registers.get(store['source_register'])
        address = (base+immediate) & ((1<<64)-1) if base is not None else None
        writes = [m for m in store_s['memory_writes'] if m['address'] == half['address']]
        a, b = read_r.get('csr_instruction_read'), read_s.get('csr_instruction_read')
        contexts = {(e.get('hart'),e.get('mode')) for e in (read_r,store_r,read_s,store_s)}
        same_context = len(contexts) == 1 and all(None not in context for context in contexts)
        row['runtime'] = {'rocket_read_line': read_r['line'], 'rocket_store_line': store_r['line'],
                          'spike_read_line': read_s['line'], 'spike_store_line': store_s['line'],
                          'spike_store_commit_line': store_s.get('commit_line'),
                          'rocket_csr_read': a, 'spike_csr_read': b, 'same_hart_and_mode':same_context,
                          'rocket_store_source_register_sample': register_value,
                          'rocket_store_address_from_sampled_base': address, 'spike_memory_commits': writes}
        if (a and b and same_context and len(writes) == 1 and read_r['line'] < store_r['line'] and read_s['line'] < store_s['line']
                and address == half['address'] and register_value == a['value'] == half['value']
                and writes[0]['value'] == b['value'] == row['reference_signature_value']):
            row['execution_relation'] = 'BOUND_READ_AND_STORE_DIAGNOSTIC'
        row['scope'] = 'RTL source-register sample and instruction monitor; Spike memory commit; not independent RTL bus attestation or proof of all writers'
        result.append(row)
    return {'elf_sha256': origins['elf_sha256'], 'halves': result}


def analyze(args):
    output = args.output.resolve(); boundary = REPOSITORY/'output/rtl-differential-r4'
    if not output.is_relative_to(boundary) or output == boundary or output.exists():
        raise ValueError('Analysis output must be a new child of output/rtl-differential-r4')
    output.mkdir(parents=True)
    try:
        elf = args.elf.read_bytes(); elf_sha = sha256(elf).hexdigest()
        rtl_manifest = json.loads(args.rtl_run.read_text())
        if rtl_manifest['inputs'].get(str(args.elf.resolve())) != elf_sha or rtl_manifest['inputs'].get(str(args.rtl.resolve())) != digest(args.rtl):
            raise ValueError('Explicit ELF/RTL is not a recorded input of this acquisition')
        validation = {'rtl': verify_rtl_run(args.rtl_run), 'spike': verify_spike_run(args.spike_run, elf_sha)}
        validation['driver_source'] = verify_checkout(args.upstream,rtl_manifest['upstream_commit'])
        validation['reference_source'] = verify_checkout(args.spike_source,validation['spike']['source_commit'])
        if args.rtl_repeat:
            validation['rtl_repeat'] = verify_rtl_run(args.rtl_repeat)
            for name in ('raw/rtl_0.log', 'raw/rtl-signature.txt'):
                if (args.rtl_run.parent/name).read_bytes() != (args.rtl_repeat.parent/name).read_bytes():
                    raise ValueError('Explicit RTL repeat has different raw outputs')
        host = args.upstream/'Fuzzer/RTLSim/host.py'
        htif = args.spike_source/'fesvr/htif.cc'
        processor, execute = args.spike_source/'riscv/processor.cc', args.spike_source/'riscv/execute.cc'
        layout = sig.make_layout(elf, expected_elf_sha256=elf_sha,
                                range_symbols=signature_ranges(elf,host.read_bytes(),htif.read_bytes()))
        rtl_sig = sig.map_signature((args.rtl_run.parent/'raw/rtl-signature.txt').read_bytes(),layout,expected_elf_sha256=elf_sha)
        spike_sig = sig.map_signature((args.spike_run.parent/'isa-signature.txt').read_bytes(),layout,expected_elf_sha256=elf_sha)
        raw_diff = sig.compare_mapped(rtl_sig, spike_sig)
        store_sources = sig.store_origins(elf,args.static_analysis.read_bytes())
        origins = sig.annotate_origins(rtl_sig,store_sources)
        rocket = traces.parse_rocket_trace((args.rtl_run.parent/'raw/rtl_0.log').read_bytes(),
            rtl_bytes=args.rtl.read_bytes(),expected_rtl_sha256=digest(args.rtl),elf_bytes=elf,expected_elf_sha256=elf_sha)
        spike = traces.parse_spike_trace((args.spike_run.parent/'isa-trace.log').read_bytes(),
            processor_source_bytes=processor.read_bytes(),execute_source_bytes=execute.read_bytes(),
            expected_processor_source_sha256=digest(processor),expected_execute_source_sha256=digest(execute),
            elf_bytes=elf,expected_elf_sha256=elf_sha)
        alignment = traces.align_events(rocket,spike,configurations_equivalent=None,trace_complete=False)
        if any(r['binding_status'] == 'MISMATCH' for r in (rocket,spike)):
            raise ValueError('Trace instruction bytes conflict with selected ELF')
        association = associate_origins(origins,rocket,spike,spike_sig)
        index = {'artifact_role':'research_diagnostic_only','validation':validation,
                 'analysis_tool_sources':{str(p.resolve()):digest(p) for p in
                    [Path(__file__),Path(sig.__file__),Path(traces.__file__)]},
                 'explicit_inputs':{str(p.resolve()):digest(p) for p in
                    [args.rtl_run,args.spike_run,args.elf,args.rtl,args.static_analysis,host,htif,processor,execute]},
                 'signature_writer_ranges':layout['ranges'],
                 'formal_architectural_differential':'UNKNOWN','full_type2_chain':'NOT_VERIFIED'}
        outputs={'run-input-index.json':index,'signature-word-mapping.json':{'rtl':rtl_sig,'spike':spike_sig},
                 'signature-origin-analysis.json':association,'signature-differential.json':raw_diff,
                 'rtl-trace-normalized.json':rocket,'spike-trace-normalized.json':spike,
                 'trace-alignment.json':alignment,
                 'first-divergence-analysis.json':{k:v for k,v in alignment.items() if k not in ('pairs','field_differences')}}
        for name,value in outputs.items():
            (output/name).write_text(json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2)+'\n')
        (output/'signature-analysis.md').write_text(sig.render_signature_analysis(raw_diff,association))
        print(json.dumps({'differences':len(raw_diff['different_words']),'unique_instruction_pairs':len(alignment['pairs']),
                          'output':str(output),'architectural_differential':'UNKNOWN'},ensure_ascii=False))
        return 0
    except Exception as error:
        (output/'failure.json').write_text(json.dumps({'status':'BLOCKED','type':type(error).__name__,
            'reason':str(error),'execution_not_inferred':True},ensure_ascii=False,indent=2)+'\n')
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('rtl-run','spike-run','elf','rtl','static-analysis','upstream','spike-source','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--rtl-repeat',type=Path)
    try:
        return analyze(parser.parse_args())
    except (ValueError,OSError,KeyError) as error:
        print('BLOCKED: '+str(error),file=sys.stderr);return 2


if __name__=='__main__':
    raise SystemExit(main())
