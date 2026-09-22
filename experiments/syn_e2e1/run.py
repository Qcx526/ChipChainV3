"""Explicit offline controlled apparatus; never a ChipChain scientific verifier.

All builds and records are disposable output. No case labels, ground truth,
model clients or production ChipChain imports. Real processes only on explicit run.
"""
from __future__ import annotations
import argparse
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

BASE_TREE_SHA = '030425ba50863f72ccf05051d35c198811d5248be1f79c3ce5d430968a315c5d'
COMMON_PATCH_SHA = '741dbd77474202318f3f0344f7fc947f07ac236c29f2aa7408d9f610c7f1d1bb'
VARIANT_PATCH_SHA = 'acd5a0b8eebe1bf47f739a82ce212d605df01a17ecbabf598db7c312d3d86272'
PERIPHERAL = 'examples/simple_system/rtl/synthetic_mmio.sv'
TOP = 'examples/simple_system/rtl/ibex_simple_system.sv'
CORE = 'examples/simple_system/ibex_simple_system_core.core'
SOURCE = 'samples/hardware/ibex-simple-system/source'
TOOLS = Path('/home/qcx/ChipChainV3_res')
EVENT_KEYS = set('schema sequence cycle reset_epoch phase transaction_id address write_enable byte_enable write_data read_data error request_valid response_valid reset_n enable_value command_value status_value'.split())
PHASES = {'request', 'response', 'status_sample', 'reset_assert', 'reset_release', 'software_stop', 'ram_write'}
LINKER = 'OUTPUT_ARCH(riscv)\nENTRY(_start)\nSECTIONS { . = 0x100000; .text : { *(.vectors) *(.text*) } . = 0x101000; .data : { *(.data*) } }\n'


class ApparatusError(ValueError):
    """Invalid/incomplete evidence is not a negative experimental result."""


def require(condition, reason):
    if not condition:
        raise ApparatusError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n'


def digest(value):
    return hashlib.sha256(canonical(value).rstrip('\n').encode()).hexdigest()


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def write(path, value):
    with Path(path).open('x') as stream:
        stream.write(value if isinstance(value, str) else canonical(value))


def tree_files(path):
    path = Path(path)
    files = {}
    for p in sorted(path.rglob('*')):
        require(not p.is_symlink(), 'SYMLINK_SOURCE')
        if p.is_file():
            files[str(p.relative_to(path))] = file_sha(p)
    return files


def verify_source(path):
    files = tree_files(path)
    require(digest(files) == BASE_TREE_SHA, 'PINNED_SOURCE_MISMATCH')
    return files


def patch_source(path, patch, expected_sha):
    require(file_sha(patch) == expected_sha, 'PATCH_IDENTITY_MISMATCH')
    # Strict unified patch subset; no git subprocess, fuzz, offset, path traversal or network.
    lines = Path(patch).read_text().splitlines(keepends=True)
    i = 0
    while i < len(lines):
        require(lines[i].startswith('--- a/'), 'BAD_PATCH_HEADER')
        relative = lines[i][6:].strip(); i += 1
        require(lines[i] == '+++ b/' + relative + '\n', 'PATCH_PATH_MISMATCH'); i += 1
        require(relative in (TOP, CORE, PERIPHERAL), 'PATCH_PATH_NOT_ALLOWED')
        original = (path / relative).read_text().splitlines(keepends=True)
        result, cursor = [], 0
        while i < len(lines) and lines[i].startswith('@@'):
            match = re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@.*\n', lines[i])
            require(match is not None, 'BAD_PATCH_HUNK')
            start = int(match[1]) - 1
            require(start >= cursor, 'PATCH_HUNK_OVERLAP')
            result.extend(original[cursor:start]); cursor = start; i += 1
            old_count = new_count = 0
            while i < len(lines) and not lines[i].startswith(('@@', '--- a/')):
                line = lines[i]; i += 1
                require(line[:1] in (' ', '+', '-'), 'BAD_PATCH_LINE')
                if line[0] in (' ', '-'):
                    require(cursor < len(original) and original[cursor] == line[1:], 'PATCH_CONTEXT_MISMATCH')
                    cursor += 1; old_count += 1
                if line[0] in (' ', '+'):
                    result.append(line[1:]); new_count += 1
            require(old_count == int(match[2] or 1) and new_count == int(match[4] or 1), 'PATCH_COUNT_MISMATCH')
        result.extend(original[cursor:]); (path / relative).write_text(''.join(result))


def verify_controlled_delta(reference, variant, experiment_files):
    a, b = tree_files(reference), tree_files(variant)
    require(a.keys() == b.keys(), 'UNEXPECTED_SOURCE_SET_DIFF')
    require([p for p in a if a[p] != b[p]] == [PERIPHERAL], 'UNEXPECTED_RTL_DIFF')
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp); target = temp / PERIPHERAL; target.parent.mkdir(parents=True)
        target.write_bytes((reference / PERIPHERAL).read_bytes())
        patch_source(temp, experiment_files / 'variant.patch', VARIANT_PATCH_SHA)
        require(target.read_bytes() == (variant / PERIPHERAL).read_bytes(), 'UNREVIEWED_RTL_DELTA')
    marker = '  // Observation only:'
    require((reference / PERIPHERAL).read_text().split(marker)[1] ==
            (variant / PERIPHERAL).read_text().split(marker)[1], 'MONITOR_CHANGED')
    return dict(reference_tree_sha256=digest(a), variant_tree_sha256=digest(b), changed_files=[PERIPHERAL])


def validate_map(entries):
    require(len(entries) == 4 and len({x['name'] for x in entries}) == 4, 'DEVICE_COUNT')
    for x in entries:
        require(x['base'] & x['mask'] == x['base'], 'MAP_ALIGNMENT')
    for i, a in enumerate(entries):
        for b in entries[i + 1:]:
            require(((a['base'] ^ b['base']) & a['mask'] & b['mask']) != 0, 'MAP_OVERLAP')
    require(sum(x['base'] == 0x40000 and x['mask'] == 0xfffffc00 for x in entries) == 1, 'SYNTHETIC_DECODE_COUNT')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def parse_trace(text):
    require(len(text) <= 20_000_000 and text.endswith('\n'), 'TRACE_INCOMPLETE')
    try:
        rows = [json.loads(line, object_pairs_hook=unique) for line in text.splitlines()]
    except (json.JSONDecodeError, TypeError) as exc:
        raise ApparatusError('MALFORMED_TRACE') from exc
    require(len(rows) >= 4 and rows[0] == {'schema': 'syn-mmio-trace/v1', 'phase': 'header'}, 'TRACE_HEADER')
    footer = rows[-1]
    require(isinstance(footer, dict) and set(footer) == set('schema phase complete event_count last_cycle reset_epoch_count normal_sim_exit'.split()), 'TRACE_INCOMPLETE')
    require(footer['schema'] == 'syn-mmio-footer/v1' and footer['phase'] == 'footer', 'TRACE_INCOMPLETE')
    require(all(type(footer[k]) is int for k in ('complete','event_count','last_cycle','reset_epoch_count','normal_sim_exit')), 'BAD_FOOTER')
    require(footer['complete'] == footer['normal_sim_exit'] == 1, 'TRACE_INCOMPLETE')
    pending, seen, samples = {}, set(), {}
    epoch, reset, last_cycle, stop_cycle = 0, False, 0, None
    transactions, events = [], rows[1:-1]
    release_cycles = []
    for sequence, e in enumerate(events):
        require(isinstance(e, dict) and set(e) == EVENT_KEYS, 'MALFORMED_EVENT')
        require(e['schema'] == 'syn-mmio-event/v1' and e['phase'] in PHASES, 'MALFORMED_EVENT')
        require(all(type(e[k]) is int and 0 <= e[k] <= 0xffffffff for k in EVENT_KEYS - {'schema','phase'}), 'BAD_EVENT_VALUE')
        require(all(e[k] in (0, 1) for k in ('write_enable','error','request_valid','response_valid','reset_n')) and e['byte_enable'] <= 15, 'BAD_EVENT_BITS')
        require(e['sequence'] == sequence, 'DUPLICATE_OR_MISSING_SEQUENCE')
        require(last_cycle <= e['cycle'] <= 100_000, 'BAD_CYCLE')
        last_cycle = e['cycle']; phase = e['phase']; tid = e['transaction_id']
        if phase == 'reset_assert':
            require(not reset and not pending and e['reset_n'] == 0 and e['reset_epoch'] == epoch + 1, 'INVALID_RESET_EPOCH')
            epoch += 1; reset = True
        else:
            require(epoch > 0 and e['reset_epoch'] == epoch, 'INVALID_RESET_EPOCH')
            if phase == 'reset_release':
                require(reset and e['reset_n'] == 1, 'INVALID_RESET_RELEASE')
                reset = False; release_cycles.append(e['cycle'])
            else:
                require(e['reset_n'] == int(not reset), 'RESET_STATE_MISMATCH')
        if phase == 'request':
            require(not reset and not pending and tid > 0 and tid not in seen, 'DUPLICATE_TRANSACTION_OR_PENDING_REQUEST')
            require(e['request_valid'] == 1 and e['response_valid'] == 0, 'BAD_REQUEST')
            require(0x40000 <= e['address'] <= 0x403ff, 'REQUEST_OUTSIDE_DEVICE')
            seen.add(tid); pending[tid] = e
        elif phase == 'response':
            require(not reset and tid in pending and e['response_valid'] == 1 and e['request_valid'] == 0, 'UNMATCHED_RESPONSE')
            request = pending.pop(tid)
            require(e['cycle'] == request['cycle'] + 1, 'RESPONSE_LATENCY')
            require(all(e[k] == request[k] for k in ('address','write_enable','byte_enable','write_data','reset_epoch')), 'RESPONSE_BINDING_MISMATCH')
            legal = request['byte_enable'] == 15 and request['address'] % 4 == 0 and (request['address'] in (0x40000,0x40004) or (request['address'] == 0x40008 and request['write_enable'] == 0))
            require(e['error'] == int(not legal), 'RESPONSE_ERROR_PROTOCOL')
            transactions.append({'request': request, 'response': e})
        elif phase == 'status_sample':
            require(e['cycle'] not in samples and tid == 0, 'DUPLICATE_STATUS_SAMPLE')
            samples[e['cycle']] = e
            if reset:require(e['enable_value'] == e['command_value'] == e['status_value'] == 0, 'RESET_NOT_ZERO')
        elif phase == 'software_stop':
            require(stop_cycle is None and not reset and e['address'] == 0x20008 and e['write_data'] == 1, 'BAD_STOP')
            stop_cycle = e['cycle']
        elif phase == 'ram_write':
            require(not reset and e['address'] == 0x101000 and e['byte_enable'] == 15 and e['write_enable'] == 1, 'BAD_RAM_RECORD')
    require(not pending and not reset and footer['event_count'] == len(events) and footer['reset_epoch_count'] == epoch, 'TRACE_INCOMPLETE')
    require(epoch == 1 and len(release_cycles) == 1, 'UNSUPPORTED_RESET_SCHEDULE')
    require(footer['last_cycle'] >= last_cycle and stop_cycle is not None and footer['last_cycle'] >= stop_cycle + 2, 'TRACE_INCOMPLETE')
    require(set(range(release_cycles[0], footer['last_cycle'])) <= samples.keys(), 'STATUS_WINDOW_INCOMPLETE')
    for tx in transactions:
        require(tx['request']['cycle'] in samples, 'MISSING_POST_UPDATE_SAMPLE')
    return {'schema_version':'syn-mmio-parsed/v1','header':rows[0],'events':events,'transactions':transactions,'footer':footer}


def validate_binding(manifest, parsed, binding):
    require(isinstance(binding, dict) and set(binding) == {'run_case_neutral_id','firmware_sha256','rtl_tree_sha256','raw_trace_sha256','parsed_trace_sha256'}, 'INVALID_BINDING')
    identity = manifest.get('identity_inputs', {})
    require(manifest.get('run_case_neutral_id') == 'run:' + digest(identity), 'RUN_IDENTITY_MISMATCH')
    require(binding['run_case_neutral_id'] == manifest['run_case_neutral_id'], 'INVALID_BINDING')
    require(binding['firmware_sha256'] == identity.get('firmware_sha256'), 'WRONG_FIRMWARE_BINDING')
    require(binding['rtl_tree_sha256'] == identity.get('rtl_tree_sha256'), 'WRONG_RTL_BINDING')
    require(binding['raw_trace_sha256'] == manifest.get('raw_trace_sha256'), 'WRONG_TRACE_BINDING')
    require(binding['parsed_trace_sha256'] == digest(parsed) == manifest.get('parsed_trace_sha256'), 'WRONG_PARSED_BINDING')
    require(manifest.get('normal_exit') is True and manifest.get('trace_complete') is True and parsed['footer']['complete'] == 1, 'TRACE_INCOMPLETE')


def compare_runs(a, b, parsed_a, parsed_b):
    for k in a['identity_inputs'].keys() | b['identity_inputs'].keys():
        if k not in ('rtl_tree_sha256','simulator_sha256'):
            require(a['identity_inputs'].get(k) == b['identity_inputs'].get(k), 'CONTROLLED_INPUT_MISMATCH:' + k)
    left, right = parsed_a['events'], parsed_b['events']
    require(len(left) == len(right), 'EVENT_ALIGNMENT_MISMATCH')
    first = None
    for ea, eb in zip(left, right):
        require(all(ea[k] == eb[k] for k in ('sequence','cycle','reset_epoch','phase','transaction_id')), 'EVENT_ALIGNMENT_MISMATCH')
        # Every MMIO request must coincide, including after the status read.
        if ea['phase'] == 'request':
            require(all(ea[k] == eb[k] for k in ('address','write_enable','byte_enable','write_data','request_valid')), 'REQUEST_DIFFERENCE')
        different = sorted(k for k in ea if ea[k] != eb[k])
        if different and first is None:
            first = {'cycle':ea['cycle'],'phase':ea['phase'],'sequence':ea['sequence'],
                     'different_fields':different,'left':{k:ea[k] for k in different},'right':{k:eb[k] for k in different}}
    return {'schema_version':'syn-monitored-differential/v1','input_equality_checked':True,
            'scope':'monitored synthetic-peripheral events/state and explicit RAM result write only',
            'first_observable_difference':first}


def verify_elf(path):
    from elftools.elf.elffile import ELFFile
    elf = ELFFile(BytesIO(Path(path).read_bytes()))
    require(elf.elfclass == 32 and elf.little_endian and elf['e_machine'] == 'EM_RISCV', 'ELF_TARGET')
    symbols = {s.name:s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols()}
    require(elf['e_entry'] == symbols['_start'] == 0x100080 and symbols['result_slot'] == 0x101000, 'ELF_ENTRY_OR_RESULT_SLOT')
    section = elf.get_section_by_name('.text'); offset = elf['e_entry'] - section['sh_addr']; raw = section.data()[offset:offset + 48]
    regs = [0] * 32; instructions, accesses = [], []
    for i in range(12):
        pc=elf['e_entry'] + 4*i; data=raw[i*4:i*4+4]; word=int.from_bytes(data,'little')
        op=word&127; rd=(word>>7)&31; rs1=(word>>15)&31; rs2=(word>>20)&31; f3=(word>>12)&7
        signed=lambda n:n-4096 if n&2048 else n
        if op==0x37:regs[rd]=word&0xfffff000
        elif op==0x13 and f3==0:
            require(regs[rs1] is not None,'ELF_UNKNOWN_ADDRESS');regs[rd]=(regs[rs1]+signed(word>>20))&0xffffffff
        elif op in (0x23,0x03) and f3==2:
            imm=signed(((word>>25)<<5)|((word>>7)&31)) if op==0x23 else signed(word>>20)
            require(regs[rs1] is not None,'ELF_UNKNOWN_ADDRESS');address=(regs[rs1]+imm)&0xffffffff
            accesses.append({'pc':pc,'address':address,'direction':'write' if op==0x23 else 'read','width_bits':32,'value':regs[rs2] if op==0x23 else None,'encoding':data.hex()})
            if op==0x03:regs[rd]=None
        else:raise ApparatusError('ELF_UNSUPPORTED_APPARATUS_INSTRUCTION')
        regs[0]=0;instructions.append({'pc':pc,'encoding':data.hex()})
    require([a['address'] for a in accesses] == [0x40000,0x40004,0x40008,0x101000,0x20008], 'ELF_ACCESS_SITES')
    return {'schema_version':'syn-elf-inspection/v1','architecture':'rv32','endianness':'little','entry':elf['e_entry'],
            'symbols':{k:symbols[k] for k in ('_start','enable_site','command_site','status_site','result_site','result_slot')},
            'instructions':instructions,'accesses':accesses,'limit':'bounded compiled apparatus inspection, not a general MMIO capability producer or runtime evidence'}


def command(args, cwd, env, prefix, timeout=900):
    with Path(str(prefix)+'.stdout.log').open('xb') as stdout, Path(str(prefix)+'.stderr.log').open('xb') as stderr:
        result=subprocess.run([str(a) for a in args],cwd=cwd,env=env,stdout=stdout,stderr=stderr,timeout=timeout)
    require(result.returncode == 0, 'COMMAND_FAILED:'+str(prefix))


def inspect_elaboration(path, config=None):
    tree=ET.parse(path);top=next(n for n in tree.iter('module') if n.get('name')=='ibex_simple_system')
    require(any(n.get('name')=='u_synthetic_mmio' for n in top.iter('instance')), 'PERIPHERAL_NOT_ELABORATED')
    # Keep the XML as raw evidence; extract the actual elaborated array assignments.
    entries={}; enum={'Ram':0,'SimCtrl':1,'Timer':2,'SyntheticPeripheral':3}
    def number(text):
        m=re.fullmatch(r"\d+'s?h([0-9a-fA-F]+)",text)
        require(m is not None,'ELABORATION_CONSTANT');return int(m[1],16)
    for node in top.iter('contassign'):
        kids=list(node)
        if len(kids)!=2 or kids[0].tag!='const' or kids[1].tag!='arraysel':continue
        arr=list(kids[1]); name=arr[0].get('name') if arr else None
        if name not in ('cfg_device_addr_base','cfg_device_addr_mask'):continue
        index=number(arr[1].get('name'));entries.setdefault(index,{})[name.rsplit('_',1)[1]]=number(kids[0].get('name'))
    result=[{'name':name,**entries.get(index,{})} for name,index in enum.items()]
    require(all(set(e)=={'name','base','mask'} for e in result),'ELABORATED_MAP_MISSING')
    validate_map(result)
    parameters={n.get('name'):list(n)[0].get('name') for n in top.findall('var') if (n.get('param')=='true' or n.get('localparam')=='true') and len(n) and list(n)[0].tag=='const'}
    require(number(parameters['NrDevices'])==4,'ELABORATED_DEVICE_COUNT')
    if config is not None:
        # Enum values from the SHA-pinned rtl/ibex_pkg.sv.
        enums={'ibex_pkg::BaseIsaRV32I':0,'ibex_pkg::RV32MFast':2,
               'ibex_pkg::RV32BNone':0,'ibex_pkg::RV32Zca':0,'ibex_pkg::RegFileFF':0}
        for key,value in config.items():
            expected=enums.get(value,value)
            require(key in parameters and number(parameters[key])==expected,'ELABORATED_CONFIG_MISMATCH:'+key)
    return {'address_map':result,'parameters':parameters,'xml_sha256':file_sha(path),'peripheral_instance':'u_synthetic_mmio'}


def run_experiment(root, resources=TOOLS):
    root=Path(root).resolve();exp=root/'experiments/syn_e2e1';source=root/SOURCE
    parent=root/'output/syn-e2e1-a';parent.mkdir(parents=True,exist_ok=True)
    out=Path(tempfile.mkdtemp(prefix='experiment-',dir=parent))
    try:
        baseline=verify_source(source);write(out/'base-source-files.json',baseline)
        require(file_sha(exp/'integrate.patch')==COMMON_PATCH_SHA and file_sha(exp/'variant.patch')==VARIANT_PATCH_SHA,'PATCH_IDENTITY_MISMATCH')
        gcc=resources/'toolchains/lowrisc-20220210-1/bin/riscv32-unknown-elf-gcc'
        vroot=resources/'toolchains/verilator-ci/v4.210';fusesoc=resources/'envs/ibex-simple-system/bin/fusesoc'
        libelf=resources/'toolchains/libelf-0.186/usr'
        for p in (gcc,vroot/'bin/verilator',fusesoc):require(p.is_file(),'PINNED_TOOL_MISSING:'+str(p))
        guard=out/'offline';guard.mkdir()
        write(guard/'sitecustomize.py', 'import socket\ndef deny(*a,**k): raise RuntimeError("OFFLINE_APPARATUS_NETWORK_DENIED")\nsocket.socket.connect=deny\nsocket.socket.connect_ex=deny\nsocket.socket.sendto=deny\nsocket.getaddrinfo=deny\n')
        for name in ('git','curl','wget','ssh','pip','pip3'):
            p=guard/name;write(p,'#!/bin/sh\nprintf "offline apparatus forbids this command\\n" >&2\nexit 97\n');p.chmod(0o755)
        env={'PATH':f'{guard}:{gcc.parent}:{fusesoc.parent}:{vroot}/bin:/usr/bin:/bin',
             'VERILATOR_ROOT':str(vroot/'share/verilator'),'CPLUS_INCLUDE_PATH':str(libelf/'include'),
             'LIBRARY_PATH':str(libelf/'lib/x86_64-linux-gnu'),'LD_LIBRARY_PATH':str(libelf/'lib/x86_64-linux-gnu'),
             'MAKEFLAGS':'-j2','PYTHONPATH':str(guard),'PYTHONDONTWRITEBYTECODE':'1','LANG':'C','LC_ALL':'C',
             'LANGSMITH_TRACING':'false','LANGCHAIN_TRACING_V2':'false'}
        versions={}
        for name,args,expected in [('compiler',[gcc,'-dumpversion'],'10.2.0'),('fusesoc',[fusesoc,'--version'],'2.4.3'),('verilator',[vroot/'bin/verilator','--version'],'Verilator 4.210 ')]:
            value=subprocess.check_output([str(a) for a in args],env=env,cwd=out,text=True).strip()
            require(value.startswith(expected),'PINNED_TOOL_VERSION:'+name)
            versions[name]={'version':value,'executable_sha256':file_sha(args[0])}
        write(out/'tool-identities.json',versions)
        freeze=json.loads((root/'docs/research/data1/ibex-simple-system-baseline.json').read_text())
        config=freeze['repository']['configuration'];options=freeze['simulator_build']['command'][9:]
        # Retain the frozen command's explicit configuration parameters.
        options=[arg for arg in options if arg.startswith('--')]
        recipe={'tools':versions,'target':'lowrisc:ibex:ibex_simple_system','target_config':config,'options':options,
                'clock_policy':'one posedge/negedge per simulator cycle', 'reset_schedule':{'initial_delay_cycles':2,'duration_cycles':2},
                'runtime_options':['+verilator+seed+1','+verilator+rand+reset+0','--term-after-cycles=10000'],
                'compiler_flags':['-march=rv32imc','-mabi=ilp32','-nostdlib','-nostartfiles','-Wl,--build-id=none'],
                'linker_sha256':hashlib.sha256(LINKER.encode()).hexdigest(),
                'shim':{'mode':'already in verified disposable source','file_sha256':baseline['examples/simple_system/ibex_simple_system.core'],
                        'documented_delta_sha256':freeze['compatibility_shim']['sha256'],'reason':'pinned wrapper consumes BASE_ISA; common to both trees'}}
        write(out/'build-recipe.json',recipe)
        common=out/'common';shutil.copytree(source,common)
        require(tree_files(common)==baseline,'COPY_MISMATCH')
        patch_source(common,exp/'integrate.patch',COMMON_PATCH_SHA)
        (common/PERIPHERAL).write_bytes((exp/'synthetic_mmio.sv').read_bytes())
        common_files=tree_files(common)
        require({p for p in baseline if common_files[p]!=baseline[p]}=={TOP,CORE} and set(common_files)-set(baseline)=={PERIPHERAL},'UNEXPECTED_INTEGRATION_DIFF')
        reference=out/'sources'/'a';variant=out/'sources'/'b';shutil.copytree(common,reference);shutil.copytree(common,variant)
        patch_source(variant,exp/'variant.patch',VARIANT_PATCH_SHA)
        delta=verify_controlled_delta(reference,variant,exp)
        write(out/'controlled-source-delta.json',delta)
        for tree in (reference,variant):write(out/(tree.name+'-source-files.json'),tree_files(tree))
        builds=out/'builds';builds.mkdir();config_path=out/'fusesoc.conf'
        write(config_path,'[main]\ncache_root = '+str(out/'fusesoc-cache')+'\n')
        sims=[]; elaborations=[]
        for tree in (reference,variant):
            build=builds/tree.name
            args=[fusesoc,'--config',config_path,'--monochrome','--cores-root='+str(tree),'run','--target=sim','--setup','--build','--build-root='+str(build),'lowrisc:ibex:ibex_simple_system',*options]
            write(out/(tree.name+'-build-command.json'),[str(a) for a in args])
            command(args,out,env,out/(tree.name+'-build'))
            # --build-root is the backend directory in this pinned FuseSoC version.
            found=list(build.rglob('Vibex_simple_system'))
            require(len(found)==1,'SIMULATOR_BINARY_MISSING');sim=found[0]
            command(['make','xml-only'],sim.parent,env,out/(tree.name+'-elaboration'))
            xmls=list(sim.parent.rglob('Vibex_simple_system.xml'));require(len(xmls)==1,'ELABORATION_XML_MISSING')
            elaboration=inspect_elaboration(xmls[0],config);write(out/(tree.name+'-elaboration.json'),elaboration)
            elaborations.append(elaboration)
            sims.append((tree,sim))
        require(elaborations[0]['parameters']==elaborations[1]['parameters'] and
                elaborations[0]['address_map']==elaborations[1]['address_map'],'ELABORATION_PAIR_MISMATCH')
        fwdir=out/'firmware';fwdir.mkdir();write(fwdir/'link.ld',LINKER);shutil.copyfile(exp/'firmware.S',fwdir/'firmware.S')
        firmware=[]
        for value in (0xa5,0xa4):
            name='image-'+digest({'command_immediate':value})[:12];elf=fwdir/(name+'.elf')
            args=[gcc,*recipe['compiler_flags'],'-x','assembler-with-cpp','-DCOMMAND_VALUE='+str(value),'-Wl,-T,link.ld','firmware.S','-o',elf.name]
            command(args,fwdir,env,fwdir/(name+'-compile'))
            inspection=verify_elf(elf);write(fwdir/(name+'-inspection.json'),inspection)
            command([gcc.parent/'riscv32-unknown-elf-objdump','-d','-t',elf],fwdir,env,fwdir/(name+'-disassembly'))
            again=fwdir/(name+'-repeat.elf');again_args=args[:-1]+[again.name]
            command(again_args,fwdir,env,fwdir/(name+'-repeat-compile'))
            require(file_sha(elf)==file_sha(again),'FIRMWARE_BUILD_NOT_REPRODUCIBLE')
            firmware.append(elf)
        input_data={'schema':'syn-software-input/v1','external_bytes':[],'initialization':'Verilator rand-reset=0, seed=1; identical ELF load for each compared pair'}
        write(out/'software-input.json',input_data)
        all_manifests=[];parsed_by_id={}
        for elf in firmware:
            for tree,sim in sims:
                identity={'firmware_sha256':file_sha(elf),'firmware_source_sha256':file_sha(exp/'firmware.S'),
                          'input_sha256':digest(input_data),'base_source_tree_sha256':BASE_TREE_SHA,
                          'rtl_tree_sha256':delta['reference_tree_sha256' if tree==reference else 'variant_tree_sha256'],
                          'common_patch_sha256':COMMON_PATCH_SHA,'variant_patch_sha256':VARIANT_PATCH_SHA,
                          'simulator_sha256':file_sha(sim),'build_recipe_sha256':digest(recipe),
                          'apparatus_source_sha256':digest({p.name:file_sha(p) for p in sorted(exp.iterdir()) if p.is_file()})}
                rid='run:'+digest(identity);folder=out/'runs'/rid.removeprefix('run:');folder.mkdir(parents=True)
                repeat_results=[]
                for attempt in (1,2):
                    run=folder/str(attempt);run.mkdir()
                    args=[sim,'--meminit=ram,'+str(elf),*recipe['runtime_options']]
                    command(args,run,env,run/'process',timeout=60)
                    stdout=(run/'process.stdout.log').read_text()
                    require('Terminating simulation by software request.' in stdout and 'Received $finish() from Verilog' in stdout and 'timeout' not in stdout.lower(),'ABNORMAL_SIM_EXIT')
                    raw=run/'synthetic-mmio.jsonl';parsed=parse_trace(raw.read_text());write(run/'parsed-trace.json',parsed)
                    manifest={'schema_version':'syn-apparatus-run/v1','run_case_neutral_id':rid,'identity_inputs':identity,
                              'firmware_path':str(elf.relative_to(out)),'simulator_path':str(sim.relative_to(out)),
                              'raw_trace_sha256':file_sha(raw),'parsed_trace_sha256':digest(parsed),
                              'stdout_sha256':file_sha(run/'process.stdout.log'),'stderr_sha256':file_sha(run/'process.stderr.log'),
                              'normal_exit':True,'trace_complete':True}
                    binding={k:identity[k] for k in ('firmware_sha256','rtl_tree_sha256')}
                    binding.update({k:manifest[k] for k in ('run_case_neutral_id','raw_trace_sha256','parsed_trace_sha256')})
                    validate_binding(manifest,parsed,binding);write(run/'trace-binding.json',binding);write(run/'manifest.json',manifest)
                    repeat_results.append(parsed)
                require(repeat_results[0]==repeat_results[1],'OBJECTIVE_TRACE_NOT_REPEATABLE')
                all_manifests.append({'manifest':str((folder/'1/manifest.json').relative_to(out)),'run_case_neutral_id':rid,'repeat_parsed_identical':True})
                parsed_by_id[rid]=(manifest,parsed)
        comparisons=[]
        for i in (0,2):
            a,pa=parsed_by_id[all_manifests[i]['run_case_neutral_id']];b,pb=parsed_by_id[all_manifests[i+1]['run_case_neutral_id']]
            comparisons.append({'left_run':a['run_case_neutral_id'],'right_run':b['run_case_neutral_id'],**compare_runs(a,b,pa,pb)})
        require(tree_files(reference)==common_files,'BUILD_CHANGED_REFERENCE_SOURCE')
        verify_controlled_delta(reference,variant,exp);verify_source(source)
        result={'schema_version':'syn-e2e1-apparatus-result/v1','status':'objective_records_collected','runs':all_manifests,
                'comparisons':comparisons,'controlled_source_delta':delta,
                'limits':['Not a FirmwareCapability producer','Not trigger/deviation/chain verification','Only monitored synthetic peripheral and explicit RAM result domain'],
                'repeat_policy':'Two real simulations per input pair; parsed traces equal; firmware rebuilt twice. Simulator build byte reproducibility not asserted.'}
        write(out/'apparatus-result.json',result)
        return out
    except Exception as exc:
        write(out/'blocked.json',{'status':'BLOCKED','error_type':type(exc).__name__,'reason':str(exc),'no_fallback_simulation':True})
        raise ApparatusError('BLOCKED evidence: '+str(out)) from exc


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true',help='Explicit real offline build and simulation');args=parser.parse_args()
    if not args.run:parser.error('--run is required')
    print(run_experiment(Path(__file__).resolve().parents[2]))


if __name__=='__main__':
    main()
