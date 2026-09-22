"""BRIDGE1: an attested, bounded Ibex RVFI/data-bus execution join.

No cycle-offset/ordinal join, capability, trigger or deviation interpretation.
B1 is imported unchanged; only new jointly collected runs can enter this bridge.
"""
from __future__ import annotations

from io import BytesIO
from pathlib import Path
import re
from typing import Literal

from elftools.elf.elffile import ELFFile
from pydantic import StrictBool, model_validator

from chipchain.domain.common import Contract, Identifier, Sha256
from chipchain.firmware import mmio_grounding as b1
from chipchain.firmware.mmio_grounding import Content, Count, U32, identified, require

RULE = 'ibex-rvfi-bus-semantic-bijection/v1'
COVERAGE = 'ibex-straight-line-entry-through-simctrl-stop/v1'
BASE_SHA = '030425ba50863f72ccf05051d35c198811d5248be1f79c3ce5d430968a315c5d'
APPROVED_TREES = (
    'f882b80ccd16c9de7828b399196f079ee3b982e43fc54784c3f6e015430f4e1b',
    '805480e150a838026c0b47dfe375a0548064381a4b175d79f9ea6bf02089b440')
REVIEWED_SOURCES = {
    'rtl/ibex_tracer.sv': '6241602443ec15517914fc3231e9c860229aea52dc571b5a94769a0510963925',
    'rtl/ibex_core.sv': '88b8bf3907472f1d413380f62234a7fbf53cb1de392a6660e6ef2d684a2416fd',
    'shared/rtl/bus.sv': 'b24c2cbe36cee25230c61d533258a66707ee03c7c3857cc97494c8d95a2a2953',
    'examples/simple_system/rtl/ibex_simple_system.sv': '5e3ca1b92f450fde2b2f2bdaca73d68ba1aa4c47aa072c797adf2406430446e1'}
HEADER = 'Time\tCycle\tPC\tInsn\tDecoded instruction\tRegister and memory contents'
ROW = re.compile(r'\s*(\d+)\t\s*(\d+)\t([0-9a-f]{8})\t([0-9a-f]{8})\t(lui|addi|lw|sw)\t([^\t\r\n]+)\t(.*)')
REG = re.compile(r'\s+x([0-9]|[12][0-9]|3[01])([:=])0x([0-9a-f]{8})')
MEM = re.compile(r' PA:0x([0-9a-f]{8}) (store|load):0x([0-9a-f]{8})')
Status = Literal['bound', 'unknown', 'not_same']


class BridgeArtifact(Content):
    id_field = 'artifact_id'
    prefix = 'mmio-bridge-source'
    artifact_id: Identifier
    role: Literal['processor_trace', 'bus_trace', 'platform_source', 'elf', 'stdout', 'stderr']
    sha256: Sha256
    hash_kind: Literal['file_bytes'] = 'file_bytes'


def artifact(role, data):
    return identified(BridgeArtifact, role=role, sha256=b1.bytes_sha(data))


class PlatformProof(Content):
    id_field = 'proof_id'
    prefix = 'mmio-platform-proof'
    proof_id: Identifier
    rule: Literal['reviewed-frozen-ibex-single-cored/v1'] = 'reviewed-frozen-ibex-single-cored/v1'
    rtl_tree_sha256: Sha256
    map_id: Identifier
    map_source_id: Identifier
    source_artifacts: tuple[BridgeArtifact, ...]
    single_cored_host: StrictBool
    no_other_target_master: StrictBool
    aligned_word_mask_from_instruction: StrictBool


def verify_platform(source_tree, source_manifest_bytes, map_source):
    require(map_source.rtl_tree_sha256 in APPROVED_TREES, 'UNREVIEWED_PLATFORM')
    b1.verify_source_tree(source_tree, source_manifest_bytes, map_source.rtl_tree_sha256)
    params = dict(map_source.platform_map.configuration)
    require(params.get('NrHosts') == 1 and params.get('NrDevices') == 4 and
            params.get('SecureIbex') == 0 and params.get('WritebackStage') == 0 and
            params.get('BaseIsa') == 0, 'UNSUPPORTED_PLATFORM_CONFIG')
    sources = []
    for name, expected in REVIEWED_SOURCES.items():
        raw = (Path(source_tree) / name).read_bytes()
        require(b1.bytes_sha(raw) == expected, 'PLATFORM_SOURCE_MISMATCH')
        sources.append(artifact('platform_source', raw))
    return identified(PlatformProof, rtl_tree_sha256=map_source.rtl_tree_sha256,
        map_id=map_source.platform_map.map_id, map_source_id=map_source.map_evidence_id,
        source_artifacts=tuple(sorted(sources, key=lambda s: s.artifact_id)), single_cored_host=True,
        no_other_target_master=True, aligned_word_mask_from_instruction=True)


class ProcessorRow(Contract):
    trace_sequence: Count  # derived zero-based row ordinal, not an emitted RVFI order field
    simulation_time: Count
    processor_cycle: Count
    pc: U32
    instruction_encoding: str  # bytes in file/little-endian order
    mnemonic: Literal['lui', 'addi', 'lw', 'sw']
    operation: Literal['read', 'write'] | None
    address: U32 | None
    width_bits: Literal[32] | None
    byte_mask: None = None  # numeric masks are NOT emitted in this text trace
    write_value: U32 | None
    read_value: U32 | None


def parse_processor_trace(raw: bytes):
    """Exact pinned text grammar. Instruction bits, not mnemonic prose, select semantics."""
    require(raw and len(raw) < 4_000_000 and raw.endswith(b'\n'), 'PROCESSOR_TRACE_MISSING_OR_TRUNCATED')
    lines = raw.decode('ascii').splitlines()
    require(lines[0] == HEADER and 1 < len(lines) <= 257, 'PROCESSOR_HEADER_OR_BOUND')
    result = []; previous_time = previous_cycle = -1
    for sequence, line in enumerate(lines[1:]):
        match = ROW.fullmatch(line)
        require(match is not None, 'MALFORMED_PROCESSOR_ROW')
        time, cycle, pc, word = int(match[1]), int(match[2]), int(match[3], 16), int(match[4], 16)
        require(time > previous_time and cycle > previous_cycle and pc % 4 == 0, 'PROCESSOR_SEQUENCE_OR_PC')
        previous_time, previous_cycle = time, cycle
        op, funct3 = word & 127, (word >> 12) & 7
        decoded = 'lui' if op == 0x37 else 'addi' if op == 0x13 and funct3 == 0 else (
            'lw' if op == 3 and funct3 == 2 else 'sw' if op == 0x23 and funct3 == 2 else None)
        require(decoded is not None and decoded == match[5], 'UNSUPPORTED_OR_INCONSISTENT_ENCODING')
        require(re.fullmatch(r'[x0-9a-f,()\-]+', match[6]) is not None, 'OPERAND_GRAMMAR')
        tail = match[7]; regs = {}; pos = 0
        while reg := REG.match(tail, pos):
            key = (int(reg[1]), reg[2]); require(key not in regs, 'DUPLICATE_REGISTER_FIELD')
            regs[key] = int(reg[3], 16); pos = reg.end()
        rd, rs1, rs2 = (word >> 7) & 31, (word >> 15) & 31, (word >> 20) & 31
        mem = MEM.fullmatch(tail[pos:]) if decoded in ('lw', 'sw') else None
        address = write_value = read_value = width = operation = None
        immediate = (((word >> 25) << 5) | ((word >> 7) & 31)) if decoded == 'sw' else word >> 20
        immediate = immediate - 4096 if immediate & 2048 else immediate
        if decoded in ('lw', 'sw'):
            require(mem is not None, 'UNSUPPORTED_MEMORY_RECORD')
            operation = 'write' if decoded == 'sw' else 'read'; width = 32
            require(mem[2] == ('store' if decoded == 'sw' else 'load'), 'MEMORY_DIRECTION_MISMATCH')
            required = {(rs1, ':'), (rs2, ':')} if decoded == 'sw' else {(rs1, ':'), (rd, '=')}
            require(set(regs) == required, 'PROCESSOR_REGISTER_FIELDS')
            address = int(mem[1], 16); value = int(mem[3], 16)
            require(address % 4 == 0 and address == (regs[(rs1, ':')] + immediate) & 0xffffffff, 'RVFI_ADDRESS_MISMATCH')
            if decoded == 'sw':
                require(value == regs[(rs2, ':')], 'RVFI_STORE_VALUE_MISMATCH'); write_value = value
            else:
                require(value == regs[(rd, '=')], 'RVFI_LOAD_VALUE_MISMATCH'); read_value = value
        else:
            require(tail[pos:] == '', 'UNEXPECTED_MEMORY_OR_TEXT')
            required = {(rd, '=')} if decoded == 'lui' else {(rs1, ':'), (rd, '=')}
            require(set(regs) == required, 'PROCESSOR_REGISTER_FIELDS')
            value = word & 0xfffff000 if decoded == 'lui' else (regs[(rs1, ':')] + immediate) & 0xffffffff
            require(regs[(rd, '=')] == (value if rd else 0), 'PROCESSOR_ALU_VALUE_MISMATCH')
        result.append(ProcessorRow(trace_sequence=sequence, simulation_time=time, processor_cycle=cycle,
            pc=pc, instruction_encoding=word.to_bytes(4, 'little').hex(), mnemonic=decoded,
            operation=operation, address=address, width_bits=width, write_value=write_value, read_value=read_value))
    return tuple(result)


def elf_prefix(elf_bytes, count):
    elf = ELFFile(BytesIO(elf_bytes)); entry = int(elf['e_entry']); result = []
    for i in range(count):
        pc = entry + i * 4
        sections = [s for s in elf.iter_sections() if s['sh_flags'] & 6 == 6 and
                    s['sh_type'] != 'SHT_NOBITS' and s['sh_addr'] <= pc and pc + 4 <= s['sh_addr'] + s['sh_size']]
        require(len(sections) == 1, 'ELF_PREFIX_MAPPING')
        s = sections[0]; result.append((pc, s.data()[pc-s['sh_addr']:pc-s['sh_addr']+4].hex()))
    return tuple(result)


def validate_processor_coverage(rows, elf_bytes, static, parsed_bus):
    """Complete *target execution window*, not a claim about every final CPU cycle.

    A control-flow-free ELF prefix must be fully retired from entry through the
    decoded software-stop store. Bus footer and post-stop window are complete.
    Missing/reordered/extra retirement rows fail, without guessing a cycle offset.
    """
    rebuilt = b1.extract_rv32_mmio_static_facts(elf_bytes, static.target_binding,
                                              instruction_count=static.instruction_count)
    require(b1.serialize(rebuilt) == b1.serialize(static), 'STATIC_REPLAY_MISMATCH')
    require(tuple((r.pc, r.instruction_encoding) for r in rows) == elf_prefix(elf_bytes, static.instruction_count),
            'PROCESSOR_PREFIX_INCOMPLETE')
    simctrl = [e for e in static.target_binding.entries if e.name == 'SimCtrl']
    require(len(simctrl) == 1 and rows[-1].operation == 'write' and
            rows[-1].address == simctrl[0].base + 8 and rows[-1].write_value == 1, 'NO_RETIRED_SOFTWARE_STOP')
    stop = [e for e in parsed_bus['events'] if e['phase'] == 'software_stop']
    require(len(stop) == 1 and stop[0]['address'] == rows[-1].address and stop[0]['write_data'] == 1,
            'STOP_EVIDENCE_MISMATCH')
    require(all(t['response']['cycle'] < stop[0]['cycle'] for t in parsed_bus['transactions']), 'TARGET_EVENT_AFTER_STOP')
    return {'rule': COVERAGE, 'retired_prefix_count': len(rows), 'last_pc': rows[-1].pc,
            'bus_stop_cycle': stop[0]['cycle'], 'scope': 'ELF entry through retired/accepted software stop; complete target bus window'}


class CollectionAttestation(Content):
    id_field = 'attestation_id'
    prefix = 'mmio-joint-collection'
    attestation_id: Identifier
    joint_evidence_sha256: Sha256
    stdout_sha256: Sha256
    stderr_sha256: Sha256
    process_returncode: Literal[0] = 0
    collector_version: Literal['new-process-joint-collection/v1'] = 'new-process-joint-collection/v1'


class JointRun(Content):
    id_field = 'joint_run_id'
    prefix = 'mmio-joint-run'
    excluded = frozenset({'collection'})
    joint_run_id: Identifier
    schema_version: Literal['joint-mmio-execution-run/v1'] = 'joint-mmio-execution-run/v1'
    firmware_sha256: Sha256
    rtl_tree_sha256: Sha256
    simulator_sha256: Sha256
    input_sha256: Sha256
    execution_context_sha256: Sha256
    bus_trace_sha256: Sha256
    processor_trace_sha256: Sha256
    normal_exit: StrictBool
    bus_trace_complete: StrictBool
    processor_trace_complete: StrictBool
    processor_completeness_rule: Literal['ibex-straight-line-entry-through-simctrl-stop/v1'] = COVERAGE
    platform_proof_id: Identifier
    collection: CollectionAttestation

    def evidence_payload(self):
        return {k: getattr(self, k) for k in ('firmware_sha256', 'rtl_tree_sha256', 'simulator_sha256',
            'input_sha256', 'execution_context_sha256', 'bus_trace_sha256', 'processor_trace_sha256')}

    @model_validator(mode='after')
    def complete(self):
        require(self.normal_exit and self.bus_trace_complete and self.processor_trace_complete, 'INCOMPLETE_JOINT_RUN')
        require(self.collection.joint_evidence_sha256 == b1.digest(self.evidence_payload()), 'COLLECTION_BINDING_MISMATCH')
        return self


class ProcessorMemoryObservation(Content):
    id_field = 'observation_id'
    prefix = 'mmio-processor'
    observation_id: Identifier
    schema_version: Literal['processor-memory-observation/v1'] = 'processor-memory-observation/v1'
    joint_run_id: Identifier
    firmware_sha256: Sha256
    trace_sequence: Count
    processor_cycle: Count
    pc: U32
    instruction_encoding: str
    operation: Literal['read', 'write']
    address: U32
    address_kind: Literal['rvfi_mem_addr_printed_as_PA'] = 'rvfi_mem_addr_printed_as_PA'
    width_bits: U32
    width_basis: Literal['decoded-aligned-rv32-lw-sw'] = 'decoded-aligned-rv32-lw-sw'
    byte_mask: None = None
    mask_status: Literal['not_emitted_by_text_tracer'] = 'not_emitted_by_text_tracer'
    write_value: U32 | None
    read_value: U32 | None
    processor_trace_artifact_id: Identifier
    evidence_ids: tuple[Identifier, ...]


class AttestedBusObservation(Content):
    id_field = 'observation_id'
    prefix = 'mmio-attested-bus'
    observation_id: Identifier
    joint_run_id: Identifier
    runtime_observation: b1.RuntimeMmioObservation


class AttestedMmioExecutionBinding(Content):
    id_field = 'binding_id'
    prefix = 'mmio-execution-binding'
    binding_id: Identifier
    static_fact_id: Identifier
    processor_observation_id: Identifier | None
    runtime_observation_id: Identifier | None
    joint_run_id: Identifier
    static_processor_status: Status
    processor_bus_status: Status
    overall_status: Status
    binding_rule_version: Identifier = RULE
    reason: Identifier
    bridge_evidence_ids: tuple[Identifier, ...]
    limitations: tuple[str, ...] = ('Current reviewed single-CoreD Ibex apparatus only.',
                                  'Establishes execution correspondence, not hardware trigger or value interpretation.')

    @model_validator(mode='after')
    def consistent(self):
        expected = 'bound' if self.static_processor_status == self.processor_bus_status == 'bound' else (
            'not_same' if 'not_same' in (self.static_processor_status, self.processor_bus_status) else 'unknown')
        require(self.overall_status == expected, 'BRIDGE_STATUS_MISMATCH')
        if self.processor_bus_status == 'bound':
            require(self.processor_observation_id and self.runtime_observation_id, 'STAGE_BOUND_WITHOUT_REFS')
        if expected == 'bound':
            require(self.processor_observation_id and self.runtime_observation_id and self.bridge_evidence_ids, 'BOUND_WITHOUT_EVIDENCE')
        return self


class BridgeSet(Content):
    id_field = 'set_id'
    prefix = 'mmio-execution-bridges'
    set_id: Identifier
    schema_version: Literal['attested-mmio-execution-bridge/v1'] = 'attested-mmio-execution-bridge/v1'
    joint_run: JointRun
    static_catalog_id: Identifier
    runtime_set_id: Identifier
    platform_proof: PlatformProof
    source_artifacts: tuple[BridgeArtifact, ...]
    processor_observations: tuple[ProcessorMemoryObservation, ...]
    bus_observations: tuple[AttestedBusObservation, ...]
    bindings: tuple[AttestedMmioExecutionBinding, ...]
    # Collector stdout PID/wall-time changes its own attestation, not semantic IDs.
    def semantic_payload(self):
        data = super().semantic_payload()
        data['joint_run'].pop('collection')
        return data

    @model_validator(mode='after')
    def references(self):
        jid = self.joint_run.joint_run_id
        require(self.platform_proof.proof_id == self.joint_run.platform_proof_id, 'PLATFORM_PROOF_REF')
        require(all(o.joint_run_id == jid for o in self.processor_observations + self.bus_observations + self.bindings), 'CROSS_RUN_OBSERVATION')
        ps = {p.observation_id for p in self.processor_observations}
        bs = {b.observation_id for b in self.bus_observations}
        require(all((b.processor_observation_id is None or b.processor_observation_id in ps) and
                    (b.runtime_observation_id is None or b.runtime_observation_id in bs) for b in self.bindings), 'DANGLING_BRIDGE_REF')
        return self


def static_processor_status(fact, proc):
    if fact.firmware_sha256 != proc.firmware_sha256:
        raise ValueError('WRONG_FIRMWARE_BINDING')
    for x, y in ((fact.instruction_pc, proc.pc), (fact.instruction_encoding, proc.instruction_encoding),
                 (fact.operation, proc.operation), (fact.width_bits, proc.width_bits)):
        if x != y:
            return 'not_same'
    if fact.address_status != 'resolved_exact' or (fact.operation == 'write' and fact.value_status != 'resolved_exact'):
        return 'unknown'
    if fact.address != proc.address or (fact.operation == 'write' and fact.value != proc.write_value):
        return 'not_same'
    return 'bound'


def semantic_bijection(processors, buses, joint_run_id, platform):
    """Unique full semantic bijection. No ordinal or cycle alignment is used.

    Repeated complete signatures stay ambiguous even if an order-preserving
    matching could be manufactured. All evidence must first pass materialization.
    """
    require(all(o.joint_run_id == joint_run_id for o in (*processors, *buses)), 'CROSS_RUN_OBSERVATION')
    if not (platform.single_cored_host and platform.no_other_target_master and platform.aligned_word_mask_from_instruction):
        return 'unknown', 'UNKNOWN_PLATFORM', {}
    left = {}; right = {}
    for p in processors:
        value = p.write_value if p.operation == 'write' else p.read_value
        if value is None or p.width_bits != 32 or p.address % 4:
            return 'unknown', 'UNKNOWN_INSUFFICIENT', {}
        key = (p.operation, p.address, p.width_bits, 15, value)
        left.setdefault(key, []).append(p.observation_id)
    for b in buses:
        o = b.runtime_observation; value = o.write_value if o.operation == 'write' else o.read_value
        if o.error or o.completion_status != 'completed_success' or value is None:
            return 'unknown', 'UNKNOWN_INSUFFICIENT', {}
        key = (o.operation, o.address, o.width_bits, o.byte_enable, value)
        right.setdefault(key, []).append(b.observation_id)
    if any(len(ids) > 1 for ids in (*left.values(), *right.values())):
        return 'unknown', 'UNKNOWN_AMBIGUOUS', {}
    if left.keys() != right.keys():
        return 'not_same', 'SEMANTIC_SET_MISMATCH', {}
    return 'bound', 'UNIQUE_FULL_SEMANTIC_BIJECTION', {ids[0]: right[key][0] for key, ids in left.items()}


def make_joint_run(*, inputs, static, elf_bytes, platform, bus_bytes, processor_bytes,
                   stdout_bytes, stderr_bytes, process_returncode):
    require(process_returncode == 0, 'SIMULATION_FAILED')
    require(set(inputs) == {'firmware_sha256', 'rtl_tree_sha256', 'simulator_sha256', 'input_sha256',
                           'execution_context_sha256'}, 'JOINT_INPUT_FIELDS')
    require(b1.bytes_sha(elf_bytes) == inputs['firmware_sha256'] == static.firmware_artifact.sha256, 'WRONG_FIRMWARE_BINDING')
    require(platform.rtl_tree_sha256 == inputs['rtl_tree_sha256'] and
            platform.map_id == static.target_binding.map_id, 'WRONG_PLATFORM_BINDING')
    stdout = stdout_bytes.decode('utf-8')
    require('Terminating simulation by software request.' in stdout and
            'Received $finish() from Verilog' in stdout and 'timeout' not in stdout.lower(), 'NO_NORMAL_COMPLETION')
    bus = b1.parse_apparatus_trace(bus_bytes.decode('ascii')); rows = parse_processor_trace(processor_bytes)
    validate_processor_coverage(rows, elf_bytes, static, bus)
    payload = dict(**inputs, bus_trace_sha256=b1.bytes_sha(bus_bytes), processor_trace_sha256=b1.bytes_sha(processor_bytes))
    collection = identified(CollectionAttestation, joint_evidence_sha256=b1.digest(payload),
                            stdout_sha256=b1.bytes_sha(stdout_bytes), stderr_sha256=b1.bytes_sha(stderr_bytes))
    return identified(JointRun, **payload, normal_exit=True, bus_trace_complete=True, processor_trace_complete=True,
                      platform_proof_id=platform.proof_id, collection=collection)


def materialize_bridge(*, joint, static, runtime, platform, inputs, elf_bytes, bus_bytes,
                       processor_bytes, stdout_bytes, stderr_bytes):
    joint = JointRun.model_validate(joint.model_dump(mode='json'))
    replay = make_joint_run(inputs=inputs, static=static, elf_bytes=elf_bytes, platform=platform,
        bus_bytes=bus_bytes, processor_bytes=processor_bytes, stdout_bytes=stdout_bytes,
        stderr_bytes=stderr_bytes, process_returncode=joint.collection.process_returncode)
    require(b1.serialize(replay) == b1.serialize(joint), 'JOINT_FILE_REPLAY_MISMATCH')
    runtime = b1.RuntimeMmioObservationSet.model_validate(runtime.model_dump(mode='json'))
    binding = runtime.run_binding
    require(all(getattr(binding, k) == value for k, value in inputs.items()), 'CROSS_RUN_INPUT_BINDING')
    require(binding.raw_trace_sha256 == joint.bus_trace_sha256 and
            binding.parsed_trace_sha256 == b1.digest(b1.parse_apparatus_trace(bus_bytes.decode())), 'BUS_RUNTIME_TRACE_MISMATCH')
    rows = parse_processor_trace(processor_bytes)
    pa, ba = artifact('processor_trace', processor_bytes), artifact('bus_trace', bus_bytes)
    lo, hi = static.target_binding.target_range
    processors = tuple(identified(ProcessorMemoryObservation, joint_run_id=joint.joint_run_id,
        firmware_sha256=joint.firmware_sha256, trace_sequence=r.trace_sequence, processor_cycle=r.processor_cycle,
        pc=r.pc, instruction_encoding=r.instruction_encoding, operation=r.operation, address=r.address,
        width_bits=r.width_bits, write_value=r.write_value, read_value=r.read_value,
        processor_trace_artifact_id=pa.artifact_id, evidence_ids=(pa.artifact_id, joint.joint_run_id))
        for r in rows if r.operation is not None and lo <= r.address and r.address + 3 <= hi)
    buses = tuple(identified(AttestedBusObservation, joint_run_id=joint.joint_run_id, runtime_observation=o)
                  for o in runtime.runtime_observations)
    pb_status, reason, pairing = semantic_bijection(processors, buses, joint.joint_run_id, platform)
    bindings = []
    for fact in static.static_facts + static.unresolved_accesses:
        candidates = [p for p in processors if p.pc == fact.instruction_pc]
        proc = candidates[0] if len(candidates) == 1 else None
        sp_status = static_processor_status(fact, proc) if proc else 'unknown'
        bus_id = pairing.get(proc.observation_id) if proc else None
        current_pb = pb_status if proc else 'unknown'
        overall = 'bound' if sp_status == current_pb == 'bound' else (
            'not_same' if 'not_same' in (sp_status, current_pb) else 'unknown')
        why = reason if sp_status == 'bound' else 'STATIC_PROCESSOR_' + sp_status.upper()
        refs = tuple(sorted((pa.artifact_id, ba.artifact_id, platform.proof_id, joint.joint_run_id)))
        bindings.append(identified(AttestedMmioExecutionBinding, static_fact_id=fact.fact_id,
            processor_observation_id=proc.observation_id if proc else None, runtime_observation_id=bus_id,
            joint_run_id=joint.joint_run_id, static_processor_status=sp_status,
            processor_bus_status=current_pb, overall_status=overall, reason=why, bridge_evidence_ids=refs))
    return identified(BridgeSet, joint_run=joint, static_catalog_id=static.catalog_id, runtime_set_id=runtime.set_id,
        platform_proof=platform, source_artifacts=tuple(sorted((pa, ba), key=lambda a: a.artifact_id)),
        processor_observations=processors, bus_observations=buses, bindings=tuple(bindings))


def render_report(bridge, static):
    bridge = BridgeSet.model_validate(bridge.model_dump(mode='json'))
    require(static.catalog_id == bridge.static_catalog_id, 'REPORT_STATIC_ID')
    counts = {s: sum(b.overall_status == s for b in bridge.bindings) for s in ('bound', 'unknown', 'not_same')}
    lines = ['# MMIO 执行桥接报告', '', f'固件 SHA：`{bridge.joint_run.firmware_sha256}`',
             f'Joint run：`{bridge.joint_run.joint_run_id}`', '',
             f'静态目标访问点：{len(static.static_facts)}；Processor 目标事件：{len(bridge.processor_observations)}；总线事务：{len(bridge.bus_observations)}。',
             f'PC ↔ bus：BOUND {counts["bound"]}，UNKNOWN {counts["unknown"]}，NOT_SAME {counts["not_same"]}。', '']
    if counts['bound'] == len(bridge.bindings) and bridge.bindings:
        lines.append('本次共同来源绑定的真实运行中，下列具体 MMIO 指令与已完成设备事务建立了确定对应。')
    else:
        lines.append('仅 BOUND 行建立对应；其余行保留未知或字段不一致，不补猜映射。')
    lines += ['这不证明硬件触发、异常、漏洞或跨层攻击链。', '',
              '| PC | 操作 | RVFI 地址 | 观测值 | bus 事务 | 对应状态 |', '|---|---|---|---|---|---|']
    ps = {p.observation_id:p for p in bridge.processor_observations}
    bs = {b.observation_id:b.runtime_observation for b in bridge.bus_observations}
    fs = {f.fact_id:f for f in static.static_facts + static.unresolved_accesses}
    for b in bridge.bindings:
        f=fs[b.static_fact_id];p=ps.get(b.processor_observation_id);bus=bs.get(b.runtime_observation_id)
        value=(p.write_value if p.operation=='write' else p.read_value) if p else None
        lines.append(f'| 0x{f.instruction_pc:X} | {f.operation} | {hex(p.address) if p else "未知"} | {hex(value) if value is not None else "未知"} | {bus.transaction_id if bus else "未绑定"} | {b.overall_status.upper()} |')
    lines += ['', '## 为什么与 B1 旧结果不同', '',
              '旧 A 文件 + 冻结 B1 API 仍为 12 条 UNKNOWN；没有补写旧 manifest 或修改旧结果。',
              '本报告来自新执行的进程，收集时共同绑定 processor trace 与 bus trace，重验完整目标窗口，并检查完整语义的一对一唯一映射。',
              '不按表格顺序、唯一地址或固定 cycle 偏移配对；重复语义导致 UNKNOWN_AMBIGUOUS。', '',
              '## 范围与证据', '', f'规则：`{RULE}`；集合：`{bridge.set_id}`。',
              'RVFI 地址字段为 tracer 打印的 PA（来源 rvfi_mem_addr）；不是独立观测到的设备总线地址。',
              '文本没有数值 byte mask；原始 mask 保留空值。32-bit 宽度来自指令解码，全字访问约束来自已审查的对齐 LW/SW 与单 CoreD 平台。',
              '完整性限定为 ELF 入口到 software-stop 的直线退休前缀及完整目标总线窗口，不声明退出前每一个 CPU cycle 都有 trace 行。',
              '静态 READ 仍不含运行时读值；0 和 0xDEAD 均只叫实际观测值。']
    return '\n'.join(lines)+'\n'
