"""Tiny source-defined traces; no RTL tool, shell, network or real corpus IO."""
from hashlib import sha256
import importlib.util
from pathlib import Path
import struct

import pytest


MODULE = Path(__file__).resolve().parents[2] / 'experiments/rtl/rocket/trace_analysis.py'
spec = importlib.util.spec_from_file_location('rocket_trace_analysis', MODULE)
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)


def sha(data):
    return sha256(data).hexdigest()


def elf(instructions=(0x10002173, 0x00100193)):
    payload = b''.join(i.to_bytes(4, 'little') for i in instructions)
    data = bytearray(0x100 + len(payload))
    data[:64] = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01' + b'\0' * 9,
                            2, 243, 1, 0x80000000, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    data[64:120] = struct.pack('<IIQQQQQQ', 1, 5, 0x100, 0x80000000,
                              0x80000000, len(payload), len(payload), 4)
    data[0x100:] = payload
    return bytes(data)


def rocket_source():
    prefix = ('$fwrite(fd, "%d %d 0x%x ", core.io_hartid, core.csr_io_status_prv, core.csr_io_trace_0_iaddr);\n'
              '$fwrite(fd, "0x%x 0x%x", core.csr_io_trace_0_insn, core.coreMonitorBundle_wrenx ? core.rf_wdata : 64\'h0);\n'
              '$fwrite(fd, " %x", mstatus_wire);\n'
              '$fwrite(fd, " %x", core.csr.reg_mcause);\n'
              '$fwrite(fd, " %x", core.csr.reg_mtval);\n'
              '$fwrite(fd, " %x", core.csr.reg_misa);\n')
    normal = prefix + '$fwrite(fd, " %d", io_covSum);\n'
    exception = prefix + '$fwrite(fd, " %d EXCEPTION", io_covSum);\n'
    return ('always @(posedge clock) begin\n'
            'if (core.coreMonitorBundle_valid & ~core.reset) begin\n' + normal +
            'end else if (core.csr_io_trace_0_exception) begin\n' + exception + 'end\nend\n').encode()


PROCESSOR = b'''void processor_t::disasm(insn_t insn)
{
  s << " (0x" << bits << ") [0x" << state.mstatus->read()
    << "," << state.mcause->read() << "," << state.csrmap[CSR_MTVAL]->read()
    << "," << state.csrmap[CSR_MISA]->read() << "] " << disassembler->disassemble(insn);
}
int processor_t::paddr_bits() { return 0; }
'''
EXECUTE = b'''commit_log_stash_privilege(p);
npc = fetch.func(p, fetch.insn, pc);
commit_log_print_insn(p, pc, fetch.insn);
'''


def rocket_record(pc=0x80000000, encoding=0x10002173, value=1, status=1, exception=False):
    return f'0 3 0x{pc:x} 0x{encoding:08x} 0x{value:x} {status:x} 0 0 8000000000000000 7' + (' EXCEPTION' if exception else '') + '\n'


def spike_record(pc=0x80000000, encoding=0x10002173, value=1, status=1, exception=False):
    prefix = f'core   0: 0x{pc:016x} (0x{encoding:08x}) [0x{status:x},0,0,8000000000000000] csr instruction\n'
    if exception:
        return prefix + f'core   0: exception trap_illegal_instruction, epc 0x{pc:016x}\ncore   0:           tval 0x{encoding:x}\n'
    return prefix + f'core   0: 3 0x{pc:016x} (0x{encoding:08x}) x 2 0x{value:016x}\n'


def parse_r(data=None, source=None, image=None):
    source, image = source or rocket_source(), image or elf()
    return trace.parse_rocket_trace((data or rocket_record()).encode(), rtl_bytes=source,
                                    expected_rtl_sha256=sha(source), elf_bytes=image,
                                    expected_elf_sha256=sha(image))


def parse_s(data=None, image=None):
    image = image or elf()
    return trace.parse_spike_trace((data or spike_record()).encode(), processor_source_bytes=PROCESSOR,
                                   execute_source_bytes=EXECUTE,
                                   expected_processor_source_sha256=sha(PROCESSOR),
                                   expected_execute_source_sha256=sha(EXECUTE),
                                   elf_bytes=image, expected_elf_sha256=sha(image))


def test_source_derived_positions_and_instruction_bytes():
    result = parse_r()
    event = result['events'][0]
    assert result['recipe']['fields'][5]['expression'] == 'mstatus_wire'
    assert event['elf_binding']['status'] == 'MATCHED'
    assert event['bytes_hex'] == '73210010'
    assert event['coverage_sum'] == 7
    assert result['recipe']['coverage_is_cycle_counter'] is False
    assert event['csr_instruction_read']['value'] == 1


def test_internal_register_number_requires_source_defined_indexing():
    source = rocket_source().replace(b'$fwrite(fd, " %d',
        b'$fwrite(fd, " %x", core.rf[29]);\n$fwrite(fd, " %d')
    record = rocket_record().replace('8000000000000000 7', '8000000000000000 1234 7')
    assert parse_r(record,source)['events'][0]['integer_register_snapshot'] == {}
    source += (b'assign rf_MPORT_addr = ~rf_waddr;\n'
               b'assign rf_id_rs_MPORT_addr = ~id_raddr1;\n'
               b'assign rf_id_rs_MPORT_1_addr = ~id_raddr2;\n')
    assert parse_r(record,source)['events'][0]['integer_register_snapshot'] == {2:0x1234}


def test_reserved_system_funct3_cannot_become_csr_read_evidence():
    encoding=0x10004173
    event=parse_r(rocket_record(encoding=encoding),image=elf((encoding,)))['events'][0]
    assert 'csr_instruction_read' not in event


def test_exception_not_a_normal_retirement_or_a_post_trap_snapshot():
    result = parse_r(rocket_record(exception=True))
    event = result['events'][0]
    assert event['kind'] == 'exception'
    assert 'csr_instruction_read' not in event
    assert 'before nonblocking' in event['phase']
    assert event['csr_snapshot']['mcause'] == 0


def test_wrong_exception_marker_location_is_malformed():
    result = parse_r(rocket_record(exception=True).replace(' 7 EXCEPTION', ' EXCEPTION 7'))
    assert result['events'][0]['kind'] == 'malformed'
    assert result['binding_status'] == 'UNKNOWN'


def test_delayed_writes_keep_unresolved_instruction_association():
    result = parse_r(rocket_record() + 'DELAYED r11=0000000000000000\nDELAYED f7=fffffffffffffffe 02\n')
    assert [e['kind'] for e in result['events']] == ['instruction', 'delayed_write', 'delayed_write']
    assert result['events'][1]['instruction_association'] == 'UNKNOWN'
    assert result['events'][2]['fflags'] == 2
    assert result['events'][2]['pc'] is None


@pytest.mark.parametrize('name', ['rtl', 'elf'])
def test_byte_identity_mismatch_rejected(name):
    image, source = elf(), rocket_source()
    with pytest.raises(ValueError, match='identity mismatch'):
        trace.parse_rocket_trace(rocket_record().encode(), rtl_bytes=source,
                                 expected_rtl_sha256='0' * 64 if name == 'rtl' else sha(source),
                                 elf_bytes=image, expected_elf_sha256='0' * 64 if name == 'elf' else sha(image))


def test_different_elf_bytes_prevent_alignment_and_first_difference():
    left = parse_r(image=elf((0x100021f3, 0x00100193)))
    right = parse_s()
    assert left['binding_status'] == 'MISMATCH'
    result = trace.align_events(left, right)
    assert result['pairs'] == []
    assert result['global_first_divergence'] == 'UNKNOWN'
    assert result['verified_deviation'] is False


def test_spike_snapshot_and_integer_commit_have_distinct_phases():
    result = parse_s(spike_record(value=0x55, status=0x11))
    event = result['events'][0]
    assert event['csr_snapshot']['mstatus'] == 0x11
    assert event['csr_instruction_read']['value'] == 0x55
    assert event['commit_line'] == 2
    assert 'before execute_insn' in event['phase']


def test_trap_diagnostic_value_does_not_become_mtval_csr():
    event = parse_s(spike_record(exception=True))['events'][0]
    assert event['kind'] == 'exception'
    assert event['trap_value'] == 0x10002173
    assert event['csr_snapshot']['mtval'] == 0
    assert event['mode'] is None
    assert 'csr_instruction_read' not in event


def test_suppressed_repeated_spike_snapshot_keeps_dynamic_commits():
    commit = 'core   0: 3 0x0000000080000000 (0x10002173) x 2 0x0000000000000002\n'
    events = parse_s(spike_record() + commit)['events']
    assert len(events) == 2
    assert events[1]['snapshot_status'] == 'MISSING'
    assert events[1]['csr_snapshot'] == {}
    assert events[1]['commit_line'] == 3


def test_interleaved_hart_commit_cannot_acquire_another_harts_snapshot():
    snapshot, commit = spike_record(value=0x55, status=0x11).splitlines()
    result = parse_s(snapshot + '\n' + commit.replace('core   0:', 'core   1:') + '\n')
    events = [e for e in result['events'] if e['kind'] == 'instruction']
    assert len(events) == 2
    assert events[0]['hart'] == 0 and events[0]['mode'] is None
    assert events[0]['commit_line'] is None
    assert events[1]['hart'] == 1 and events[1]['snapshot_status'] == 'MISSING'
    assert events[1]['csr_snapshot'] == {}
    assert trace.align_events(parse_r(), result)['pairs'] == []


def test_interleaved_hart_trap_cannot_reclassify_another_harts_instruction():
    snapshot, trap_line, value_line = spike_record(exception=True).splitlines()
    result = parse_s(snapshot + '\n' + trap_line.replace('core   0:', 'core   1:') + '\n'
                     + value_line.replace('core   0:', 'core   1:') + '\n')
    assert result['events'][0]['kind'] == 'instruction'
    assert 'trap_value' not in result['events'][0]
    assert [e['kind'] for e in result['events'][1:]] == ['opaque', 'opaque']


def test_other_harts_trap_payload_does_not_overwrite_bound_trap_value():
    result = parse_s(spike_record(exception=True)
                     + 'core   1:           tval 0xabcdef\n')
    assert result['events'][0]['trap_value'] == 0x10002173
    assert result['events'][-1]['kind'] == 'opaque'


def test_commit_after_trap_is_a_new_dynamic_attempt_even_at_same_pc():
    commit = 'core   0: 3 0x0000000080000000 (0x10002173) x 2 0x0000000000000002\n'
    events = parse_s(spike_record(exception=True) + commit)['events']
    assert events[0]['kind'] == 'exception' and events[0]['commit_line'] is None
    assert events[1]['kind'] == 'instruction' and events[1]['snapshot_status'] == 'MISSING'


def test_repeated_pc_requires_explicit_dynamic_disambiguation():
    result = trace.align_events(parse_r(rocket_record() * 2), parse_s(spike_record() * 2))
    assert result['pairs'] == []
    assert len(result['ambiguous_events']) == 2
    assert result['global_first_divergence'] == 'UNKNOWN'


def test_omitted_event_does_not_change_following_instruction_alignment():
    left = parse_r(rocket_record() + rocket_record(pc=0x80000004, encoding=0x00100193))
    right = parse_s(spike_record(pc=0x80000004, encoding=0x00100193))
    result = trace.align_events(left, right)
    assert len(result['pairs']) == 1
    assert result['pairs'][0]['pc'] == 0x80000004
    assert result['gaps'][0]['left_line'] == 1
    assert result['global_first_divergence'] == 'UNKNOWN'


@pytest.mark.parametrize('configuration', [None, False, True])
def test_snapshot_difference_is_not_verified_deviation(configuration):
    result = trace.align_events(parse_r(rocket_record(status=0x60)), parse_s(spike_record(status=0x20)),
                                configurations_equivalent=configuration, trace_complete=True)
    difference = result['first_comparable_difference_by_field']['mstatus']
    assert difference['left_value'] == 0x60
    assert difference['right_value'] == 0x20
    assert result['verified_deviation'] is False
    assert result['architectural_differential'] == 'UNKNOWN'


def test_csr_read_values_compared_only_for_same_instruction_identity():
    result = trace.align_events(parse_r(rocket_record(value=0x60)), parse_s(spike_record(value=0x20)))
    difference = result['first_comparable_csr_read_difference']
    assert difference['csr_number'] == 0x100
    assert difference['register'] == 2
    assert difference['left_value'] == 0x60
    different_instruction = parse_s(spike_record(encoding=0x30002173), image=elf((0x30002173, 0x00100193)))
    assert trace.align_events(parse_r(), different_instruction)['csr_read_differences'] == []


def test_empty_trace_and_malformed_trace_do_not_claim_complete_first_difference():
    empty = trace.parse_rocket_trace(b'', rtl_bytes=rocket_source(), expected_rtl_sha256=sha(rocket_source()),
                                     elf_bytes=elf(), expected_elf_sha256=sha(elf()))
    malformed = parse_r('0 3 0x80000000 0x10002173\n')
    for source in [empty, malformed]:
        result = trace.align_events(source, parse_s())
        assert result['pairs'] == []
        assert result['global_first_divergence'] == 'UNKNOWN'


def test_outside_elf_boot_pc_kept_unbound():
    result = parse_r(rocket_record(pc=0x10000))
    assert result['events'][0]['elf_binding']['status'] == 'UNBOUND'
    assert trace.align_events(result, parse_s())['pairs'] == []


def test_malformed_source_recipe_is_rejected_even_if_hash_is_correct():
    source = rocket_source().replace(b'core.csr.reg_mtval', b'unsupported.signal')
    with pytest.raises(ValueError, match='required observable fields'):
        parse_r(source=source)


def test_commented_exception_block_end_is_not_an_actual_block_boundary():
    source = rocket_source().replace(b'else if (core.csr_io_trace_0_exception) begin\n',
                                     b'else if (core.csr_io_trace_0_exception) begin\n//end\n')
    assert parse_r(source=source)['binding_status'] == 'SOURCE_BOUND_PREFIX'


def test_spike_csr_field_count_conflict_is_malformed_not_an_empty_snapshot():
    result = parse_s(spike_record().replace(',0,0,8000000000000000]', ',0]'))
    assert result['events'][0]['kind'] == 'malformed'
    assert result['events'][1]['snapshot_status'] == 'MISSING'
    aligned = trace.align_events(parse_r(), result)
    assert aligned['global_first_divergence'] == 'UNKNOWN'
    assert 'malformed record prevents global-first claims' in aligned['gaps']


@pytest.mark.parametrize('same', [False, True])
def test_equal_or_different_observations_never_assert_vulnerability(same):
    result = trace.align_events(parse_r(), parse_s(spike_record(value=1 if same else 2)))
    assert bool(result['csr_read_differences']) is not same
    assert result['verified_deviation'] is False
    assert result['hardware_deviation'] == 'NOT_ESTABLISHED'


def test_diagnostic_text_explains_scope_and_no_case_or_signature_index_rule():
    result = trace.align_events(parse_r(rocket_record(status=2)), parse_s())
    assert 'not a global completeness proof' in result['pairs'][0]['scope']
    assert 'causal/specification equivalence not established' in result['field_differences'][0]['interpretation']
    source = MODULE.read_text()
    assert 'real_case_001' not in source
    assert 'word_index' not in source
