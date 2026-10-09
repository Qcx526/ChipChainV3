"""Source-derived Rocket/Spike trace diagnostics, without verifier semantics.

Rocket and Spike readers own the ISA and text-format details. ``align_events``
only compares source-bound event identities and named observation fields. A
snapshot difference is a diagnostic observation, never a verified deviation.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
from io import BytesIO
import re

from elftools.elf.elffile import ELFFile


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _check(data: bytes, expected: str, name: str) -> None:
    if _sha(data) != expected:
        raise ValueError(f"{name} byte identity mismatch")


def _elf_regions(data: bytes) -> list[tuple[int, bytes]]:
    elf = ELFFile(BytesIO(data))
    if elf['e_machine'] != 'EM_RISCV' or elf.elfclass != 64 or not elf.little_endian:
        raise ValueError('Rocket trace reader requires little-endian RV64 ELF')
    return [(int(s['p_vaddr']), s.data()) for s in elf.iter_segments()
            if s['p_type'] == 'PT_LOAD' and s['p_flags'] & 1]


def _bind(pc: int, encoding: int, regions: list[tuple[int, bytes]]) -> dict:
    size = 2 if encoding & 3 != 3 else 4
    observed = encoding.to_bytes(size, 'little') if encoding < 1 << (8 * size) else b''
    matches = [data[pc - start:pc - start + size] for start, data in regions
               if start <= pc and pc + size <= start + len(data)]
    status = 'UNBOUND' if not matches else 'MATCHED' if len(matches) == 1 and matches[0] == observed else 'MISMATCH'
    return {'status': status, 'observed_bytes_hex': observed.hex(),
            'elf_bytes_hex': matches[0].hex() if len(matches) == 1 else None,
            'instruction_size': size}


def _args(text: str) -> list[str]:
    result, begin, depth = [], 0, 0
    for i, c in enumerate(text):
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        elif c == ',' and depth == 0:
            result.append(text[begin:i].strip())
            begin = i + 1
    return result + [text[begin:].strip()]


def _rocket_recipe(source: bytes) -> dict:
    text = source.decode('utf-8')
    normal = re.search(r'if\s*\(core\.coreMonitorBundle_valid\s*&\s*~core\.reset\)\s*begin(.*?)else if\s*\(core\.csr_io_trace_0_exception\)\s*begin', text, re.S)
    if normal is None:
        raise ValueError('Unsupported Rocket monitor gating recipe')
    block = re.sub(r'//[^\n]*', '', normal[1])
    fields = []
    for m in re.finditer(r'\$fwrite\(fd,\s*"([^"\n]*)"\s*,\s*(.*?)\);', block, re.S):
        specs = re.findall(r'%(?:0\d*)?([dx])', m[1])
        expressions = _args(m[2])
        if len(specs) != len(expressions):
            raise ValueError('Unsupported Rocket fwrite argument format')
        for spec, expression in zip(specs, expressions):
            fields.append({'index': len(fields), 'base': 10 if spec == 'd' else 16,
                           'expression': expression,
                           'source_line': text[:normal.start(1)].count('\n') + 1 + block[:m.start()].count('\n')})
    required = ['core.io_hartid', 'core.csr_io_status_prv', 'core.csr_io_trace_0_iaddr',
                'core.csr_io_trace_0_insn', 'mstatus_wire', 'core.csr.reg_mcause', 'core.csr.reg_mtval']
    if any(expression not in [f['expression'] for f in fields] for expression in required):
        raise ValueError('Rocket monitor lacks required observable fields')
    if len(fields) < 6 or 'core.rf_wdata' not in fields[4]['expression']:
        raise ValueError('Unsupported Rocket writeback recipe')
    exception_match = re.match(r'(.*?)\bend\b', re.sub(r'//[^\n]*', '', text[normal.end():]), re.S)
    if exception_match is None:
        raise ValueError('Missing Rocket exception monitor recipe')
    exception_block = re.sub(r'//[^\n]*', '', exception_match[1])
    exception_fields, marker_index = [], None
    for m in re.finditer(r'\$fwrite\(fd,\s*"([^"\n]*)"\s*,\s*(.*?)\);', exception_block, re.S):
        specs, expressions = re.findall(r'%(?:0\d*)?([dx])', m[1]), _args(m[2])
        if len(specs) != len(expressions):
            raise ValueError('Unsupported exception fwrite argument format')
        if 'EXCEPTION' in m[1]:
            marker_index = len(exception_fields) + len(re.findall(r'%(?:0\d*)?([dx])', m[1].split('EXCEPTION')[0]))
        exception_fields += [{'base': 10 if spec == 'd' else 16, 'expression': expression}
                             for spec, expression in zip(specs, expressions)]
    if marker_index is None or len(fields) != len(exception_fields):
        raise ValueError('Unsupported Rocket exception field layout')
    if any(a['base'] != b['base'] or (i != 4 and a['expression'] != b['expression'])
           for i, (a, b) in enumerate(zip(fields, exception_fields))):
        raise ValueError('Exception and normal field recipes disagree')
    return {'sha256': _sha(normal[1].encode()), 'fields': fields,
            'exception_marker_index': marker_index,
            'integer_register_indexing': ('bitwise_complement_5_bit_register_number' if all(
                re.search(r'assign\s+' + name + r'\s*=\s*~' + register + r'\s*;', text)
                for name, register in [('rf_MPORT_addr', 'rf_waddr'),
                                       ('rf_id_rs_MPORT_addr', 'id_raddr1'),
                                       ('rf_id_rs_MPORT_1_addr', 'id_raddr2')]) else 'UNKNOWN'),
            'sampling_phase': 'posedge active-region, before nonblocking register updates',
            'coverage_is_cycle_counter': False}


def _spike_recipe(source: bytes) -> dict:
    text = source.decode('utf-8')
    section = re.search(r'void processor_t::disasm\(insn_t insn\)(.*?)int processor_t::paddr_bits', text, re.S)
    if section is None:
        raise ValueError('Unsupported Spike disassembly source')
    block = re.sub(r'//[^\n]*', '', section[1])
    begin, end = block.find('" (0x"'), block.find('<< "] "')
    if begin < 0 or end < begin:
        raise ValueError('Unsupported Spike CSR snapshot source')
    fields = []
    for m in re.finditer(r'state\.(\w+)->read\(\)|state\.csrmap\[CSR_(\w+)\]->read\(\)', block[begin:end]):
        fields.append({'index': len(fields), 'name': (m[1] or m[2]).lower(),
                       'source_expression': m[0],
                       'source_line': text[:section.start(1)].count('\n') + 1 + block[:begin + m.start()].count('\n')})
    if not fields or fields[0]['name'] != 'mstatus':
        raise ValueError('Spike disassembly lacks source-defined mstatus snapshot')
    return {'sha256': _sha(section[1].encode()), 'fields': fields,
            'sampling_phase': 'disasm() before execute_insn(); repeated identical PCs may suppress snapshots'}


def _result(events: list[dict], **metadata) -> dict:
    bound = [e for e in events if e.get('elf_binding', {}).get('status') == 'MATCHED']
    mismatched = [e['line'] for e in events if e.get('elf_binding', {}).get('status') == 'MISMATCH']
    return {'events': events, 'matched_instruction_events': len(bound),
            'instruction_mismatch_lines': mismatched,
            'binding_status': 'MISMATCH' if mismatched else 'SOURCE_BOUND_PREFIX' if bound else 'UNKNOWN',
            'architectural_differential': 'UNKNOWN', 'hardware_deviation': 'NOT_ESTABLISHED',
            **metadata}


def parse_rocket_trace(trace_bytes: bytes, *, rtl_bytes: bytes, expected_rtl_sha256: str,
                       elf_bytes: bytes, expected_elf_sha256: str) -> dict:
    """Read actual monitor records, including delayed writes without a guessed PC."""
    _check(rtl_bytes, expected_rtl_sha256, 'RTL')
    _check(elf_bytes, expected_elf_sha256, 'ELF')
    regions, recipe, events = _elf_regions(elf_bytes), _rocket_recipe(rtl_bytes), []
    for line, raw in enumerate(trace_bytes.decode('utf-8').splitlines(), 1):
        words = raw.split()
        delayed = re.fullmatch(r'DELAYED ([rf])(\d+)=(?:0x)?([0-9a-fA-F]+)(?: ([0-9a-fA-F]+))?', raw)
        if delayed:
            events.append({'kind': 'delayed_write', 'line': line, 'raw': raw,
                           'phase': recipe['sampling_phase'], 'pc': None,
                           'register_bank': 'integer' if delayed[1] == 'r' else 'floating_point',
                           'register': int(delayed[2]), 'value': int(delayed[3], 16),
                           'fflags': int(delayed[4], 16) if delayed[4] else None,
                           'instruction_association': 'UNKNOWN'})
            continue
        exception = 'EXCEPTION' in words
        if exception:
            if words.count('EXCEPTION') != 1 or words.index('EXCEPTION') != recipe['exception_marker_index']:
                events.append({'kind': 'malformed', 'line': line, 'raw': raw,
                               'reason': 'exception marker position differs from selected RTL source'})
                continue
            words.remove('EXCEPTION')
        if not words or not words[0].isdigit():
            events.append({'kind': 'opaque', 'line': line, 'raw': raw})
            continue
        if len(words) != len(recipe['fields']):
            events.append({'kind': 'malformed', 'line': line, 'raw': raw,
                           'reason': 'field count differs from selected RTL source'})
            continue
        try:
            values = {f['expression']: int(word, f['base']) for f, word in zip(recipe['fields'], words)}
        except ValueError:
            events.append({'kind': 'malformed', 'line': line, 'raw': raw, 'reason': 'invalid numeric field'})
            continue
        pc, encoding = values['core.csr_io_trace_0_iaddr'], values['core.csr_io_trace_0_insn']
        csrs = {'mstatus': values['mstatus_wire']}
        for expression, value in values.items():
            m = re.fullmatch(r'core\.csr\.reg_(\w+)', expression)
            if m:
                csrs[m[1]] = value
        # The composed output and reg_mstatus are independently recorded. Both
        # should agree; an inconsistent source must not silently replace one.
        if 'core.csr.reg_mstatus' in values and values['core.csr.reg_mstatus'] != values['mstatus_wire']:
            csrs['mstatus_composed'] = values['mstatus_wire']
        events.append({'kind': 'exception' if exception else 'instruction', 'line': line,
                       'raw': raw, 'hart': values['core.io_hartid'],
                       'mode': values['core.csr_io_status_prv'], 'pc': pc, 'encoding': encoding,
                       'bytes_hex': _bind(pc, encoding, regions)['observed_bytes_hex'],
                       'elf_binding': _bind(pc, encoding, regions), 'phase': recipe['sampling_phase'],
                       'csr_snapshot': csrs, 'monitor_writeback_value': values[recipe['fields'][4]['expression']],
                       'coverage_sum': values.get('io_covSum'),
                       'internal_fields': values,
                       'integer_writes': [], 'memory_writes': [],
                       'monitor_value_semantics': 'conditional integer writeback, zero, or delayed-result sentinel; not a general memory value'})
        events[-1]['integer_register_snapshot'] = ({register: values[f'core.rf[{31-register}]']
            for register in range(1, 32) if f'core.rf[{31-register}]' in values}
            if recipe['integer_register_indexing'] == 'bitwise_complement_5_bit_register_number' else {})
        # This is restricted to SYSTEM CSR instructions. Long-latency loads,
        # FP writes and arithmetic sentinel records are not forced into it.
        if not exception and encoding & 0x7f == 0x73 and (encoding >> 12) & 7 in (1, 2, 3, 5, 6, 7) and (encoding >> 7) & 31:
            events[-1]['csr_instruction_read'] = {'csr_number': encoding >> 20,
                                                 'register': (encoding >> 7) & 31,
                                                 'value': events[-1]['monitor_writeback_value'],
                                                 'evidence': 'retired CSR instruction monitor writeback; not post-update CSR snapshot'}
    return _result(events, adapter='rocket-source-monitor/v1', trace_sha256=_sha(trace_bytes),
                   elf_sha256=_sha(elf_bytes), source_sha256=_sha(rtl_bytes), recipe=recipe)


def parse_spike_trace(trace_bytes: bytes, *, processor_source_bytes: bytes, execute_source_bytes: bytes,
                      expected_processor_source_sha256: str, expected_execute_source_sha256: str,
                      elf_bytes: bytes, expected_elf_sha256: str) -> dict:
    """Keep pre-execution snapshots, commit records and trap records distinct."""
    _check(processor_source_bytes, expected_processor_source_sha256, 'Spike processor source')
    _check(execute_source_bytes, expected_execute_source_sha256, 'Spike execute source')
    _check(elf_bytes, expected_elf_sha256, 'ELF')
    execute = execute_source_bytes.decode('utf-8')
    if 'commit_log_stash_privilege(p)' not in execute or 'commit_log_print_insn(p, pc, fetch.insn)' not in execute:
        raise ValueError('Unsupported Spike commit-log source')
    recipe, regions, events = _spike_recipe(processor_source_bytes), _elf_regions(elf_bytes), []
    latest = None
    for line, raw in enumerate(trace_bytes.decode('utf-8').splitlines(), 1):
        snap = re.fullmatch(r'core\s+(\d+): 0x([0-9a-fA-F]+) \(0x([0-9a-fA-F]+)\) \[([^\]]+)\] (.*)', raw)
        commit = re.fullmatch(r'core\s+(\d+): (\d+) 0x([0-9a-fA-F]+) \(0x([0-9a-fA-F]+)\)(.*)', raw)
        trap = re.fullmatch(r'core\s+(\d+): exception ([^,]+), epc 0x([0-9a-fA-F]+)', raw)
        tval = re.fullmatch(r'core\s+(\d+):\s+tval 0x([0-9a-fA-F]+)', raw)
        if snap:
            words = snap[4].split(',')
            if len(words) != len(recipe['fields']):
                events.append({'kind': 'malformed', 'line': line, 'raw': raw, 'reason': 'CSR field count differs from Spike source'})
                latest = None
                continue
            pc, encoding = int(snap[2], 16), int(snap[3], 16)
            latest = {'kind': 'instruction', 'line': line, 'raw': raw, 'hart': int(snap[1]),
                      'mode': None, 'pc': pc, 'encoding': encoding,
                      'bytes_hex': _bind(pc, encoding, regions)['observed_bytes_hex'],
                      'elf_binding': _bind(pc, encoding, regions), 'phase': recipe['sampling_phase'],
                      'mnemonic': snap[5], 'csr_snapshot': {f['name']: int(w, 16) for f, w in zip(recipe['fields'], words)},
                      'integer_writes': [], 'memory_writes': [], 'commit_line': None}
            events.append(latest)
        elif commit:
            pc, encoding = int(commit[3], 16), int(commit[4], 16)
            if (latest is None or latest['hart'] != int(commit[1]) or latest['pc'] != pc
                    or latest['encoding'] != encoding or latest['kind'] != 'instruction'
                    or latest.get('commit_line') is not None):
                latest = {'kind': 'instruction', 'line': line, 'raw': raw, 'hart': int(commit[1]),
                          'mode': int(commit[2]), 'pc': pc, 'encoding': encoding,
                          'bytes_hex': _bind(pc, encoding, regions)['observed_bytes_hex'],
                          'elf_binding': _bind(pc, encoding, regions), 'phase': 'post execute_insn() commit; no pre-execution snapshot',
                          'csr_snapshot': {}, 'integer_writes': [], 'memory_writes': [], 'snapshot_status': 'MISSING'}
                events.append(latest)
            latest['mode'], latest['commit_line'], latest['commit_raw'] = int(commit[2]), line, raw
            latest['integer_writes'] = [{'register': int(m[1]), 'value': int(m[2], 16)}
                                        for m in re.finditer(r' x\s*(\d+) 0x([0-9a-fA-F]+)', commit[5])]
            latest['csr_writes'] = [{'csr_number': int(m[1]), 'name': m[2], 'value': int(m[3], 16)}
                                   for m in re.finditer(r' c(\d+)_(\w+) 0x([0-9a-fA-F]+)', commit[5])]
            latest['memory_writes'] = [{'address': int(m[1], 16), 'value': int(m[2], 16)}
                                      for m in re.finditer(r' mem 0x([0-9a-fA-F]+) 0x([0-9a-fA-F]+)', commit[5])]
            if encoding & 0x7f == 0x73 and (encoding >> 12) & 7 in (1, 2, 3, 5, 6, 7) and (encoding >> 7) & 31:
                rd = (encoding >> 7) & 31
                writes = [w for w in latest['integer_writes'] if w['register'] == rd]
                if len(writes) == 1:
                    latest['csr_instruction_read'] = {'csr_number': encoding >> 20,
                                                     'register': rd, 'value': writes[0]['value'],
                                                     'evidence': 'post execute_insn() integer commit result of CSR instruction'}
        elif (trap and latest is not None and latest['hart'] == int(trap[1])
              and latest['pc'] == int(trap[3], 16) and latest.get('commit_line') is None):
            latest['kind'], latest['trap_line'], latest['trap_name'] = 'exception', line, trap[2]
            latest['trap_raw'] = raw
            latest['mode_status'] = 'UNKNOWN: trapped instruction has no privilege-bearing commit record'
        elif tval and latest is not None and latest['hart'] == int(tval[1]) and latest.get('trap_line'):
            latest['trap_value'], latest['trap_value_line'] = int(tval[2], 16), line
            latest['trap_value_semantics'] = 'trap diagnostic payload, not proof of CSR mtval write'
        else:
            events.append({'kind': 'opaque', 'line': line, 'raw': raw})
    return _result(events, adapter='spike-source-trace/v1', trace_sha256=_sha(trace_bytes),
                   elf_sha256=_sha(elf_bytes), source_sha256=_sha(processor_source_bytes),
                   commit_source_sha256=_sha(execute_source_bytes), recipe=recipe)


def align_events(left: dict, right: dict, *, configurations_equivalent: bool | None = None,
                 trace_complete: bool = False) -> dict:
    """Align unique dynamic identities; repeated identities remain ambiguous.

    This small analysis core has no Rocket CSR, signature index, ISA opcode, or
    case-specific comparison rule. Field differences retain their sample phase.
    """
    base = {'architectural_differential': 'UNKNOWN', 'hardware_deviation': 'NOT_ESTABLISHED',
            'verified_deviation': False, 'global_first_divergence': 'UNKNOWN',
            'configuration_equivalence': configurations_equivalent, 'trace_complete': trace_complete,
            'pairs': [], 'ambiguous_events': [], 'gaps': [], 'field_differences': [],
            'csr_read_differences': [], 'first_comparable_snapshot_difference': None,
            'first_comparable_csr_read_difference': None, 'first_comparable_difference_by_field': {}}
    if left.get('elf_sha256') != right.get('elf_sha256') or left.get('binding_status') == 'MISMATCH' or right.get('binding_status') == 'MISMATCH':
        base['gaps'].append('ELF or instruction bytes identity mismatch')
        return base
    def instructions(record):
        return [e for e in record.get('events', []) if e['kind'] in ('instruction', 'exception')
                and e.get('elf_binding', {}).get('status') == 'MATCHED']
    a, b = instructions(left), instructions(right)
    def key(e):
        return e.get('hart'), e.get('mode'), e.get('pc'), e.get('bytes_hex'), e['kind']
    ca, cb = Counter(map(key, a)), Counter(map(key, b))
    bm = {key(e): (i, e) for i, e in enumerate(b) if cb[key(e)] == 1}
    last_right = -1
    for i, e in enumerate(a):
        identity = key(e)
        if e.get('mode') is None or ca[identity] > 1 or cb[identity] > 1:
            base['ambiguous_events'].append({'left_line': e['line'], 'pc': e['pc'],
                                             'left_occurrences': ca[identity], 'right_occurrences': cb[identity],
                                             'reason': 'missing privilege or repeated dynamic identity'})
            continue
        match = bm.get(identity)
        if match is None:
            base['gaps'].append({'left_line': e['line'], 'pc': e['pc'], 'reason': 'no unique source-bound counterpart'})
            continue
        j, f = match
        if j <= last_right:
            base['gaps'].append({'left_line': e['line'], 'reason': 'event order conflict'})
            continue
        last_right = j
        pair = {'left_line': e['line'], 'right_line': f['line'], 'right_commit_line': f.get('commit_line'),
                'pc': e['pc'], 'bytes_hex': e['bytes_hex'], 'mode': e['mode'], 'kind': e['kind'],
                'left_phase': e.get('phase'), 'right_phase': f.get('phase'),
                'scope': 'uniquely matched source-bound event; not a global completeness proof'}
        base['pairs'].append(pair)
        ar, br = e.get('csr_instruction_read'), f.get('csr_instruction_read')
        if ar and br and ar['csr_number'] == br['csr_number'] and ar['register'] == br['register'] and ar['value'] != br['value']:
            base['csr_read_differences'].append({**pair, 'csr_number': ar['csr_number'],
                                                'register': ar['register'], 'left_value': ar['value'],
                                                'right_value': br['value'],
                                                'interpretation': 'different source-bound instruction return values; not a verified hardware deviation'})
        for field in sorted(set(e.get('csr_snapshot', {})) & set(f.get('csr_snapshot', {}))):
            av, bv = e['csr_snapshot'][field], f['csr_snapshot'][field]
            if av != bv:
                base['field_differences'].append({**pair, 'field': field, 'left_value': av, 'right_value': bv,
                                                 'interpretation': 'different recorded snapshots; causal/specification equivalence not established'})
    if not a or not b:
        base['gaps'].append('missing source-bound instruction events')
    if configurations_equivalent is not True:
        base['gaps'].append('configuration equivalence not established')
    if not trace_complete:
        base['gaps'].append('complete observation coverage not established')
    if any(e['kind'] == 'malformed' for e in left.get('events', []) + right.get('events', [])):
        base['gaps'].append('malformed record prevents global-first claims')
    base['first_comparable_snapshot_difference'] = base['field_differences'][0] if base['field_differences'] else None
    base['first_comparable_csr_read_difference'] = base['csr_read_differences'][0] if base['csr_read_differences'] else None
    by_field = {}
    for d in base['field_differences']:
        by_field.setdefault(d['field'], d)
    base['first_comparable_difference_by_field'] = by_field
    return base
