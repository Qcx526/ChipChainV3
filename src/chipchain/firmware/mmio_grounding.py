"""B1: bounded ELF facts, independently bound bus observations, conservative joins.

No capability/contract matcher, model client, simulator or implicit persistence.
The RV32 backend covers a caller-bounded straight-line prefix, not reachability.
"""
from __future__ import annotations

from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import re
from typing import Annotated, ClassVar, Literal
import xml.etree.ElementTree as ET

from elftools.elf.elffile import ELFFile
from pydantic import ConfigDict, Field, model_validator

from chipchain.domain.common import Architecture, Contract, Identifier, Sha256

U32 = Annotated[int, Field(strict=True, ge=0, le=0xffffffff)]
Count = Annotated[int, Field(strict=True, ge=0)]
PRODUCER = 'bounded-mmio-grounding/v1'
BRIDGE_RULE = 'unbound-no-attested-pc-transaction-bridge/v1'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


SET_FIELDS = frozenset({'source_artifacts', 'evidence', 'source_artifact_ids', 'evidence_ids',
                        'candidate_static_fact_ids', 'bridge_evidence_ids'})


def _ordered(value, field=None):
    if isinstance(value, dict):
        return {k: _ordered(v, k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        items = [_ordered(v) for v in value]
        return sorted(items, key=lambda v: json.dumps(v, sort_keys=True, separators=(',', ':'))) if field in SET_FIELDS else items
    return value


def canonical(value):
    if isinstance(value, Contract):
        value = value.model_dump(mode='json')
    return json.dumps(_ordered(value), sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def digest(value):
    return sha256(canonical(value).encode()).hexdigest()


def bytes_sha(value):
    return sha256(value).hexdigest()


def file_sha(path):
    h = sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def read_json(raw):
    return json.loads(raw, object_pairs_hook=_unique,
                      parse_constant=lambda _: require(False, 'NONFINITE_JSON'))


class Content(Contract):
    """Semantic IDs are replay-checked, never trusted from serialized inputs."""
    model_config = ConfigDict(extra='forbid', frozen=True, allow_inf_nan=False)
    id_field: ClassVar[str] = 'content_id'
    prefix: ClassVar[str]
    hash_field: ClassVar[str | None] = None
    excluded: ClassVar[frozenset[str]] = frozenset()

    def semantic_payload(self):
        return self.model_dump(mode='json', exclude={self.id_field, self.hash_field} | self.excluded)

    @model_validator(mode='after')
    def identity(self):
        h = digest(self.semantic_payload())
        require(getattr(self, self.id_field) == self.prefix + ':' + h, 'CONTENT_ID_MISMATCH')
        if self.hash_field:
            require(getattr(self, self.hash_field) == h, 'CONTENT_SHA_MISMATCH')
        return self


def identified(cls, **fields):
    """Internal builder: defaults join the identity; final validation is mandatory."""
    draft = cls.model_construct(**fields)
    h = digest(draft.semantic_payload())
    fields[cls.id_field] = cls.prefix + ':' + h
    if cls.hash_field:
        fields[cls.hash_field] = h
    return cls.model_validate(fields)


SourceKind = Literal['elf_bytes', 'platform_address_map', 'elaboration_xml',
    'elaboration_record', 'rtl_source_manifest', 'apparatus_run_manifest',
    'apparatus_trace_binding', 'raw_bus_trace', 'parsed_bus_trace', 'simulator',
    'build_recipe', 'software_input', 'stdout', 'stderr', 'processor_trace_unattested']


class SourceArtifact(Content):
    id_field = 'artifact_id'
    prefix = 'mmio-source'
    artifact_id: Identifier
    sha256: Sha256
    hash_kind: Literal['file_bytes', 'canonical_json']
    source_kind: SourceKind


def source(kind, raw=None, payload=None):
    return identified(SourceArtifact, source_kind=kind,
                      hash_kind='file_bytes' if raw is not None else 'canonical_json',
                      sha256=bytes_sha(raw) if raw is not None else digest(payload))


class Evidence(Content):
    id_field = 'evidence_id'
    prefix = 'mmio-evidence'
    evidence_id: Identifier
    kind: Literal['elf_instruction', 'accepted_transaction', 'elaborated_map', 'run_binding']
    source_artifact_ids: tuple[Identifier, ...]
    instruction_pc: U32 | None = None
    instruction_encoding: str | None = None
    request_sequence: Count | None = None
    response_sequence: Count | None = None

    @model_validator(mode='after')
    def canonical_refs(self):
        require(self.source_artifact_ids == tuple(sorted(set(self.source_artifact_ids))), 'UNSORTED_SOURCE_REFS')
        return self


class Provenance(Contract):
    method: Literal['rv32-lui-addi-lw-sw/v1', 'syn-a-completed-bus-transaction/v1',
                    'verilator-xml-address-map/v1', 'syn-a-source-binding/v1',
                    'unbound-no-attested-pc-transaction-bridge/v1']
    source_artifact_ids: tuple[Identifier, ...]
    evidence_ids: tuple[Identifier, ...]


class FirmwareArtifact(Content):
    id_field = 'artifact_id'
    prefix = 'mmio-firmware'
    artifact_id: Identifier
    sha256: Sha256
    hash_kind: Literal['file_bytes'] = 'file_bytes'
    architecture: Architecture
    word_size_bits: Annotated[int, Field(strict=True, gt=0)]
    endianness: Literal['little', 'big']
    entry: U32


class MapEntry(Contract):
    name: Identifier
    base: U32
    mask: U32


class PlatformMap(Content):
    id_field = 'map_id'
    prefix = 'mmio-map'
    map_id: Identifier
    schema_version: Literal['mmio-platform-map/v1'] = 'mmio-platform-map/v1'
    extraction_version: Literal['verilator-xml-address-map/v1'] = 'verilator-xml-address-map/v1'
    architecture: Architecture
    entries: tuple[MapEntry, ...]
    # Config order is canonical; map provenance is kept in PlatformMapEvidence.
    configuration: tuple[tuple[str, U32], ...]
    target_device: Identifier

    @model_validator(mode='after')
    def valid_map(self):
        require(tuple(e.name for e in self.entries) == tuple(sorted({e.name for e in self.entries})), 'MAP_ORDER_OR_DUPLICATE')
        require(self.configuration == tuple(sorted(set(self.configuration))), 'CONFIG_ORDER')
        require(len(dict(self.configuration)) == len(self.configuration), 'CONFIG_DUPLICATE')
        require(sum(e.name == self.target_device for e in self.entries) == 1, 'TARGET_MAP_MISSING')
        for i, entry in enumerate(self.entries):
            size = ((~entry.mask) & 0xffffffff) + 1
            require(size & (size - 1) == 0 and entry.base & entry.mask == entry.base, 'MAP_NOT_CONTIGUOUS')
            for other in self.entries[i + 1:]:
                require((entry.base ^ other.base) & entry.mask & other.mask, 'MAP_OVERLAP')
        return self

    @property
    def target_range(self):
        e = next(e for e in self.entries if e.name == self.target_device)
        return e.base, e.base + ((~e.mask) & 0xffffffff)


class PlatformMapEvidence(Content):
    id_field = 'map_evidence_id'
    prefix = 'mmio-map-source'
    map_evidence_id: Identifier
    platform_map: PlatformMap
    rtl_tree_sha256: Sha256
    source_artifacts: tuple[SourceArtifact, ...]
    evidence: tuple[Evidence, ...]
    provenance: Provenance


class InstructionStep(Contract):
    pc: U32
    encoding: Annotated[str, Field(pattern=r'^[0-9a-f]{8}$')]
    mnemonic: Literal['lui', 'addi', 'lw', 'sw']


class StaticMmioAccessFact(Content):
    id_field = 'fact_id'
    prefix = 'mmio-static'
    fact_id: Identifier
    schema_version: Literal['mmio-static-access/v1'] = 'mmio-static-access/v1'
    firmware_artifact_id: Identifier
    firmware_sha256: Sha256
    architecture: Architecture
    instruction_pc: U32
    instruction_encoding: Annotated[str, Field(pattern=r'^[0-9a-f]{8}$')]
    instruction_width: Literal[32] = 32
    operation: Literal['read', 'write']
    address_status: Literal['resolved_exact', 'unresolved']
    address: U32 | None
    width_bits: Literal[32] = 32
    value_status: Literal['resolved_exact', 'unresolved', 'not_applicable']
    value: U32 | None
    scope_status: Literal['in_target', 'outside_target', 'unresolved']
    map_id: Identifier
    source_registers: tuple[str, ...]
    derivation: tuple[InstructionStep, ...]
    provenance: Provenance

    @model_validator(mode='after')
    def separation(self):
        require((self.address is not None) == (self.address_status == 'resolved_exact'), 'ADDRESS_STATUS')
        require((self.value is not None) == (self.value_status == 'resolved_exact'), 'VALUE_STATUS')
        require((self.operation == 'read') == (self.value_status == 'not_applicable'), 'STATIC_READ_VALUE')
        require(self.provenance.method == 'rv32-lui-addi-lw-sw/v1', 'STATIC_AUTHORITY')
        require(self.derivation and self.derivation[-1].pc == self.instruction_pc and
                self.derivation[-1].encoding == self.instruction_encoding, 'STATIC_DERIVATION')
        return self


class FirmwareMmioStaticCatalog(Content):
    id_field = 'catalog_id'
    hash_field = 'catalog_sha256'
    prefix = 'fwmmio-static'
    schema_version: Literal['firmware-mmio-static/v1'] = 'firmware-mmio-static/v1'
    catalog_id: Identifier
    catalog_sha256: Sha256
    producer_version: Literal['bounded-mmio-grounding/v1'] = PRODUCER
    architecture: Architecture
    firmware_artifact: FirmwareArtifact
    target_binding: PlatformMap
    instruction_count: Annotated[int, Field(strict=True, ge=1, le=256)]
    static_facts: tuple[StaticMmioAccessFact, ...]
    non_target_accesses: tuple[StaticMmioAccessFact, ...]
    unresolved_accesses: tuple[StaticMmioAccessFact, ...]
    static_sequence: tuple[Identifier, ...]
    source_artifacts: tuple[SourceArtifact, ...]
    evidence: tuple[Evidence, ...]
    limitations: tuple[str, ...] = ('Straight-line bounded prefix only; not execution or reachability proof.',
                                  'Static load result is never inferred; runtime is not static authority.')

    @model_validator(mode='after')
    def references(self):
        facts = self.static_facts + self.non_target_accesses + self.unresolved_accesses
        require(self.architecture == self.firmware_artifact.architecture == self.target_binding.architecture, 'ARCHITECTURE_MISMATCH')
        require({s.source_kind for s in self.source_artifacts} == {'elf_bytes', 'platform_address_map'}, 'STATIC_SOURCE_AUTHORITY')
        sources = {s.artifact_id for s in self.source_artifacts}
        ev = {e.evidence_id: e for e in self.evidence}
        require(len(ev) == len(self.evidence), 'DUPLICATE_EVIDENCE')
        require(all(e.kind == 'elf_instruction' and set(e.source_artifact_ids) <= sources for e in self.evidence), 'DANGLING_OR_NONSTATIC_EVIDENCE')
        require(next(s.sha256 for s in self.source_artifacts if s.source_kind == 'elf_bytes') == self.firmware_artifact.sha256, 'STATIC_ELF_SOURCE')
        require(next(s.sha256 for s in self.source_artifacts if s.source_kind == 'platform_address_map') == digest(self.target_binding), 'STATIC_MAP_SOURCE')
        for group, scope in ((self.static_facts, 'in_target'), (self.non_target_accesses, 'outside_target'),
                             (self.unresolved_accesses, 'unresolved')):
            require(all(f.scope_status == scope for f in group), 'SCOPE_GROUP')
        lo, hi = self.target_binding.target_range
        for f in facts:
            expected_scope = 'unresolved' if f.address is None else 'in_target' if lo <= f.address and f.address + 3 <= hi else 'outside_target'
            require(f.scope_status == expected_scope, 'STATIC_SCOPE_MISMATCH')
            require(f.firmware_sha256 == self.firmware_artifact.sha256 and
                    f.firmware_artifact_id == self.firmware_artifact.artifact_id and
                    f.architecture == self.architecture and f.map_id == self.target_binding.map_id, 'STATIC_BINDING')
            require(set(f.provenance.source_artifact_ids) == sources and
                    len(f.provenance.evidence_ids) == 1 and set(f.provenance.evidence_ids) <= ev.keys(), 'STATIC_EVIDENCE_REFS')
            e = ev[f.provenance.evidence_ids[0]]
            require(e.instruction_pc == f.instruction_pc and e.instruction_encoding == f.instruction_encoding, 'STATIC_EVIDENCE_SITE')
        ordered = sorted(facts, key=lambda f: f.instruction_pc)
        require(len({f.instruction_pc for f in facts}) == len(facts) and
                self.static_sequence == tuple(f.fact_id for f in ordered), 'STATIC_SEQUENCE')
        return self


def extract_rv32_mmio_static_facts(elf_bytes: bytes, platform_map: PlatformMap, *, instruction_count=12):
    """Decode only ELF-mapped bytes in an explicit straight-line prefix from entry.

    Only x0 is initially known. No assembly, symbols, disassembly or runtime input.
    Unresolved-address accesses remain explicit instead of being filtered away.
    """
    require(type(instruction_count) is int and 1 <= instruction_count <= 256, 'BAD_STATIC_BOUND')
    platform_map = PlatformMap.model_validate(platform_map.model_dump(mode='json'))
    elf = ELFFile(BytesIO(elf_bytes))
    require(elf.elfclass == 32 and elf.little_endian and elf['e_machine'] == 'EM_RISCV'
            and elf['e_type'] == 'ET_EXEC' and platform_map.architecture == Architecture.RISCV, 'UNSUPPORTED_ARCHITECTURE')
    entry = int(elf['e_entry']); require(entry % 4 == 0, 'UNALIGNED_ENTRY')
    firmware = identified(FirmwareArtifact, sha256=bytes_sha(elf_bytes), architecture=Architecture.RISCV,
                          word_size_bits=32, endianness='little', entry=entry)
    elf_source = source('elf_bytes', raw=elf_bytes)
    map_source = source('platform_address_map', payload=platform_map)
    refs = tuple(sorted((elf_source.artifact_id, map_source.artifact_id)))
    sections = [s for s in elf.iter_sections() if s['sh_flags'] & 2 and s['sh_flags'] & 4 and s['sh_type'] != 'SHT_NOBITS']
    segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD' and s['p_flags'] & 1]
    values = [None] * 32; values[0] = 0
    origins = [() for _ in range(32)]
    facts, evidence = [], []
    lo, hi = platform_map.target_range
    for i in range(instruction_count):
        pc = entry + i * 4
        ss = [s for s in sections if s['sh_addr'] <= pc and pc + 4 <= s['sh_addr'] + s['sh_size']]
        ps = [s for s in segments if s['p_vaddr'] <= pc and pc + 4 <= s['p_vaddr'] + s['p_filesz']]
        require(len(ss) == len(ps) == 1, 'ELF_MAPPING_NOT_UNIQUE')
        raw = ss[0].data()[pc - ss[0]['sh_addr']:pc - ss[0]['sh_addr'] + 4]
        require(raw == ps[0].data()[pc - ps[0]['p_vaddr']:pc - ps[0]['p_vaddr'] + 4], 'ELF_MAPPING_MISMATCH')
        word = int.from_bytes(raw, 'little'); op = word & 127
        rd, rs1, rs2, f3 = (word >> 7) & 31, (word >> 15) & 31, (word >> 20) & 31, (word >> 12) & 7
        mnemonic = 'lui' if op == 0x37 else 'addi' if op == 0x13 and f3 == 0 else (
            'lw' if op == 3 and f3 == 2 else 'sw' if op == 0x23 and f3 == 2 else None)
        require(mnemonic is not None, f'UNSUPPORTED_INSTRUCTION:{pc:#x}:{raw.hex()}')
        step = InstructionStep(pc=pc, encoding=raw.hex(), mnemonic=mnemonic)
        immediate = (((word >> 25) << 5) | ((word >> 7) & 31)) if mnemonic == 'sw' else word >> 20
        immediate = immediate - 4096 if immediate & 2048 else immediate
        if mnemonic == 'lui':
            values[rd], origins[rd] = word & 0xfffff000, (step,)
        elif mnemonic == 'addi':
            values[rd] = None if values[rs1] is None else (values[rs1] + immediate) & 0xffffffff
            origins[rd] = origins[rs1] + (step,)
        else:
            address = None if values[rs1] is None else (values[rs1] + immediate) & 0xffffffff
            require(address is None or address % 4 == 0, 'UNSUPPORTED_UNALIGNED_STATIC_ACCESS')
            write = mnemonic == 'sw'; value = values[rs2] if write else None
            deps = {s.pc: s for s in origins[rs1] + (origins[rs2] if write else ()) + (step,)}
            ev = identified(Evidence, kind='elf_instruction', source_artifact_ids=refs,
                            instruction_pc=pc, instruction_encoding=raw.hex())
            evidence.append(ev)
            facts.append(identified(StaticMmioAccessFact, firmware_artifact_id=firmware.artifact_id,
                firmware_sha256=firmware.sha256, architecture=Architecture.RISCV, instruction_pc=pc,
                instruction_encoding=raw.hex(), operation='write' if write else 'read',
                address_status='unresolved' if address is None else 'resolved_exact', address=address,
                value_status=('resolved_exact' if value is not None else 'unresolved') if write else 'not_applicable', value=value,
                scope_status='unresolved' if address is None else 'in_target' if lo <= address and address + 3 <= hi else 'outside_target',
                map_id=platform_map.map_id, source_registers=tuple(f'x{r}' for r in sorted({rs1, rs2} if write else {rs1})),
                derivation=tuple(deps[k] for k in sorted(deps)),
                provenance=Provenance(method='rv32-lui-addi-lw-sw/v1', source_artifact_ids=refs, evidence_ids=(ev.evidence_id,))))
            if not write:
                values[rd], origins[rd] = None, origins[rs1] + (step,)
        values[0], origins[0] = 0, ()
    return identified(FirmwareMmioStaticCatalog, architecture=Architecture.RISCV, firmware_artifact=firmware,
        target_binding=platform_map, instruction_count=instruction_count,
        static_facts=tuple(f for f in facts if f.scope_status == 'in_target'),
        non_target_accesses=tuple(f for f in facts if f.scope_status == 'outside_target'),
        unresolved_accesses=tuple(f for f in facts if f.scope_status == 'unresolved'),
        static_sequence=tuple(f.fact_id for f in facts),
        source_artifacts=tuple(sorted((elf_source, map_source), key=lambda s: s.artifact_id)),
        evidence=tuple(sorted(evidence, key=lambda e: e.evidence_id)))


def _xml_number(text):
    match = re.fullmatch(r"\d+'s?h([0-9a-fA-F]+)", text or '')
    require(match is not None, 'ELABORATION_CONSTANT')
    return int(match[1], 16)


def extract_platform_map(xml_bytes, record_bytes, source_manifest_bytes, *, rtl_tree_sha256, target_device):
    """Re-extract A's elaborated map; semantic identity excludes source tree/XML."""
    record = read_json(record_bytes)
    require(bytes_sha(xml_bytes) == record['xml_sha256'], 'XML_HASH_MISMATCH')
    require(digest(read_json(source_manifest_bytes)) == rtl_tree_sha256, 'WRONG_RTL_MAP_BINDING')
    require(len(xml_bytes) < 50_000_000 and b'<!DOCTYPE' not in xml_bytes and b'<!ENTITY' not in xml_bytes, 'UNSAFE_XML')
    tree = ET.fromstring(xml_bytes)
    tops = [n for n in tree.iter('module') if n.get('name') == 'ibex_simple_system']
    require(len(tops) == 1, 'ELABORATION_TOP')
    top = tops[0]
    require(sum(n.get('name') == 'u_synthetic_mmio' for n in top.iter('instance')) == 1, 'ELABORATION_INSTANCE')
    entries = {}
    for node in top.iter('contassign'):
        kids = list(node)
        if len(kids) != 2 or kids[0].tag != 'const' or kids[1].tag != 'arraysel':
            continue
        arr = list(kids[1]); name = arr[0].get('name') if arr else None
        if name not in ('cfg_device_addr_base', 'cfg_device_addr_mask'):
            continue
        require(len(arr) == 2 and arr[1].tag == 'const', 'ELABORATION_ARRAY')
        index = _xml_number(arr[1].get('name')); key = name.rsplit('_', 1)[1]
        require(key not in entries.setdefault(index, {}), 'DUPLICATE_MAP_ASSIGNMENT')
        entries[index][key] = _xml_number(kids[0].get('name'))
    # Device index semantics belong to the source-pinned A adapter, not generic MMIO.
    names = ('Ram', 'SimCtrl', 'Timer', 'SyntheticPeripheral')
    require(set(entries) == set(range(4)), 'ELABORATED_DEVICE_COUNT')
    actual = [dict(name=name, **entries[index]) for index, name in enumerate(names)]
    require(actual == record['address_map'], 'MAP_RECORD_XML_MISMATCH')
    parameters = {n.get('name'): list(n)[0].get('name') for n in top.findall('var')
                  if (n.get('param') == 'true' or n.get('localparam') == 'true') and len(n) and list(n)[0].tag == 'const'}
    require(parameters == record['parameters'] and _xml_number(parameters['NrDevices']) == 4, 'ELABORATION_CONFIG')
    require(record['peripheral_instance'] == 'u_synthetic_mmio', 'ELABORATION_INSTANCE')
    semantic = identified(PlatformMap, architecture=Architecture.RISCV, entries=tuple(MapEntry(**e) for e in sorted(actual, key=lambda e: e['name'])),
                         configuration=tuple(sorted((k, _xml_number(v)) for k, v in parameters.items())), target_device=target_device)
    artifacts = tuple(sorted((source('elaboration_xml', raw=xml_bytes), source('elaboration_record', raw=record_bytes),
                              source('rtl_source_manifest', payload=read_json(source_manifest_bytes))), key=lambda s: s.artifact_id))
    refs = tuple(s.artifact_id for s in artifacts)
    evidence = identified(Evidence, kind='elaborated_map', source_artifact_ids=refs)
    return identified(PlatformMapEvidence, platform_map=semantic, rtl_tree_sha256=rtl_tree_sha256,
                      source_artifacts=artifacts, evidence=(evidence,),
                      provenance=Provenance(method='verilator-xml-address-map/v1', source_artifact_ids=refs,
                                            evidence_ids=(evidence.evidence_id,)))


class RunScientificBinding(Content):
    id_field = 'run_binding_id'
    prefix = 'mmio-run'
    run_binding_id: Identifier
    schema_version: Literal['mmio-run-binding/v1'] = 'mmio-run-binding/v1'
    firmware_sha256: Sha256
    rtl_tree_sha256: Sha256
    simulator_sha256: Sha256
    input_sha256: Sha256
    execution_context_sha256: Sha256
    raw_trace_sha256: Sha256
    parsed_trace_sha256: Sha256
    map_id: Identifier


class RuntimeSourceAttestation(Content):
    id_field = 'attestation_id'
    prefix = 'mmio-runtime-attestation'
    attestation_id: Identifier
    upstream_apparatus_run_id: Identifier
    run_binding_id: Identifier
    map_source: PlatformMapEvidence
    source_artifacts: tuple[SourceArtifact, ...]
    # This evidence sidecar is fully content-addressed, but excluded from semantic
    # observation/set IDs: A manifest includes differential bookkeeping.
    provenance: Provenance


class RuntimeMmioObservation(Content):
    id_field = 'observation_id'
    prefix = 'mmio-runtime'
    observation_id: Identifier
    schema_version: Literal['mmio-runtime-observation/v1'] = 'mmio-runtime-observation/v1'
    run_binding_id: Identifier
    transaction_id: Count
    request_cycle: Count
    response_cycle: Count
    reset_epoch: Count
    operation: Literal['read', 'write']
    address: U32
    width_bits: Literal[32] = 32
    byte_enable: U32
    write_value: U32 | None
    read_value: U32 | None
    error: U32
    completion_status: Literal['completed_success'] = 'completed_success'
    raw_trace_artifact_id: Identifier
    parsed_trace_artifact_id: Identifier
    provenance: Provenance

    @model_validator(mode='after')
    def completed(self):
        require(self.error == 0 and self.byte_enable == 15 and self.address % 4 == 0 and
                self.transaction_id > 0 and self.reset_epoch > 0 and self.response_cycle == self.request_cycle + 1,
                'NOT_COMPLETED_SUCCESS')
        require((self.write_value is not None and self.read_value is None) if self.operation == 'write' else
                (self.read_value is not None and self.write_value is None), 'RUNTIME_VALUE_DIRECTION')
        require(self.provenance.method == 'syn-a-completed-bus-transaction/v1', 'RUNTIME_AUTHORITY')
        return self


class RuntimeMmioObservationSet(Content):
    id_field = 'set_id'
    hash_field = 'set_sha256'
    prefix = 'fwmmio-runtime'
    excluded = frozenset({'source_attestation'})
    schema_version: Literal['firmware-mmio-runtime/v1'] = 'firmware-mmio-runtime/v1'
    set_id: Identifier
    set_sha256: Sha256
    producer_version: Literal['bounded-mmio-grounding/v1'] = PRODUCER
    run_binding: RunScientificBinding
    runtime_observations: tuple[RuntimeMmioObservation, ...]
    runtime_sequence: tuple[Identifier, ...]
    source_artifacts: tuple[SourceArtifact, ...]
    evidence: tuple[Evidence, ...]
    source_attestation: RuntimeSourceAttestation
    limitations: tuple[str, ...] = ('Observed read values have no expected/abnormal interpretation.',
                                  'No PC or static-site identity in the bus observation.')

    @model_validator(mode='after')
    def references(self):
        require(self.source_attestation.run_binding_id == self.run_binding.run_binding_id and
                self.source_attestation.map_source.rtl_tree_sha256 == self.run_binding.rtl_tree_sha256 and
                self.source_attestation.map_source.platform_map.map_id == self.run_binding.map_id, 'RUNTIME_ATTESTATION_MISMATCH')
        require(self.runtime_sequence == tuple(o.observation_id for o in self.runtime_observations), 'RUNTIME_SEQUENCE')
        require(len(set(self.runtime_sequence)) == len(self.runtime_sequence), 'DUPLICATE_RUNTIME_OBSERVATION')
        sources = {s.artifact_id: s for s in self.source_artifacts}; ev = {e.evidence_id for e in self.evidence}
        require(all(set(e.source_artifact_ids) <= sources.keys() for e in self.evidence), 'RUNTIME_EVIDENCE_REFS')
        require({s.source_kind for s in self.source_artifacts} == {'raw_bus_trace', 'parsed_bus_trace'}, 'RUNTIME_SOURCE_AUTHORITY')
        require(all(e.kind == 'accepted_transaction' for e in self.evidence), 'RUNTIME_EVIDENCE_KIND')
        lo, hi = self.source_attestation.map_source.platform_map.target_range
        last = -1; tids = set()
        for o in self.runtime_observations:
            require(o.run_binding_id == self.run_binding.run_binding_id and o.request_cycle > last and o.transaction_id not in tids, 'RUNTIME_BINDING_ORDER')
            require(lo <= o.address and o.address + 3 <= hi, 'RUNTIME_OUTSIDE_TARGET_SCOPE')
            last = o.request_cycle; tids.add(o.transaction_id)
            require(o.raw_trace_artifact_id in sources and o.parsed_trace_artifact_id in sources and
                    sources[o.raw_trace_artifact_id].sha256 == self.run_binding.raw_trace_sha256 and
                    sources[o.parsed_trace_artifact_id].sha256 == self.run_binding.parsed_trace_sha256, 'TRACE_ARTIFACT_REF')
            require(set(o.provenance.source_artifact_ids) <= sources.keys() and set(o.provenance.evidence_ids) <= ev, 'RUNTIME_PROVENANCE_REFS')
        return self


# Narrow independent A v1 reader, ported from frozen experiments/syn_e2e1/run.py.
# No runtime import of the experiment runner and no changes to A.
EVENT_KEYS = set('schema sequence cycle reset_epoch phase transaction_id address write_enable byte_enable write_data read_data error request_valid response_valid reset_n enable_value command_value status_value'.split())
PHASES = {'request', 'response', 'status_sample', 'reset_assert', 'reset_release', 'software_stop', 'ram_write'}

def parse_apparatus_trace(text):
    require(len(text) <= 20_000_000 and text.endswith('\n'), 'TRACE_INCOMPLETE')
    try:
        rows = [json.loads(line, object_pairs_hook=_unique) for line in text.splitlines()]
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError('MALFORMED_TRACE') from exc
    require(len(rows) >= 4 and rows[0] == {'schema': 'syn-mmio-trace/v1', 'phase': 'header'}, 'TRACE_HEADER')
    footer = rows[-1]
    require(isinstance(footer, dict) and set(footer) == set('schema phase complete event_count last_cycle reset_epoch_count normal_sim_exit'.split()), 'TRACE_INCOMPLETE')
    require(footer['schema'] == 'syn-mmio-footer/v1' and footer['phase'] == 'footer', 'TRACE_INCOMPLETE')
    require(all(type(footer[k]) is int for k in ('complete','event_count','last_cycle','reset_epoch_count','normal_sim_exit')), 'BAD_FOOTER')
    require(footer['complete'] == footer['normal_sim_exit'] == 1, 'TRACE_INCOMPLETE')
    require(0 <= footer['last_cycle'] <= 100_000 and 0 <= footer['event_count'] <= 1_000_000, 'TRACE_BOUNDS')
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



def materialize_runtime(*, manifest_bytes, binding_bytes, raw_trace_bytes, parsed_trace_bytes,
                        firmware: FirmwareArtifact, map_source: PlatformMapEvidence,
                        rtl_tree_sha256, simulator_sha256, input_sha256, recipe,
                        stdout_bytes, stderr_bytes):
    """Revalidate all reproducible A bindings before creating any observation.

    File loader below supplies hashes from actual source trees/binaries. This pure
    boundary also supports small synthetic artifact tests without subprocesses.
    """
    manifest, binding = read_json(manifest_bytes), read_json(binding_bytes)
    require(manifest.get('schema_version') == 'syn-apparatus-run/v1', 'RUN_SCHEMA')
    identity = manifest['identity_inputs']
    require(manifest['run_case_neutral_id'] == 'run:' + digest(identity), 'UPSTREAM_RUN_ID_MISMATCH')
    require(isinstance(binding, dict) and set(binding) == {
        'run_case_neutral_id', 'firmware_sha256', 'rtl_tree_sha256', 'raw_trace_sha256', 'parsed_trace_sha256'}, 'INVALID_BINDING')
    require(binding['run_case_neutral_id'] == manifest['run_case_neutral_id'], 'INVALID_BINDING')
    require(identity['firmware_sha256'] == binding['firmware_sha256'] == firmware.sha256, 'WRONG_FIRMWARE_BINDING')
    require(identity['rtl_tree_sha256'] == binding['rtl_tree_sha256'] == rtl_tree_sha256 == map_source.rtl_tree_sha256, 'WRONG_RTL_BINDING')
    require(identity['simulator_sha256'] == simulator_sha256 and identity['input_sha256'] == input_sha256, 'RUN_INPUT_MISMATCH')
    require(identity['build_recipe_sha256'] == digest(recipe), 'RECIPE_MISMATCH')
    require(map_source.platform_map.architecture == firmware.architecture, 'ARCHITECTURE_MISMATCH')
    require(map_source.platform_map.target_device == 'SyntheticPeripheral' and
            map_source.platform_map.target_range == (0x40000, 0x403ff), 'UNSUPPORTED_A_MONITOR_SCOPE')
    require(bytes_sha(raw_trace_bytes) == manifest['raw_trace_sha256'] == binding['raw_trace_sha256'], 'RAW_TRACE_HASH_MISMATCH')
    parsed = parse_apparatus_trace(raw_trace_bytes.decode('utf-8'))
    require(canonical(read_json(parsed_trace_bytes)) == canonical(parsed), 'RAW_PARSED_MISMATCH')
    require(digest(parsed) == manifest['parsed_trace_sha256'] == binding['parsed_trace_sha256'], 'PARSED_TRACE_HASH_MISMATCH')
    require(manifest['normal_exit'] is True and manifest['trace_complete'] is True, 'TRACE_INCOMPLETE')
    require(bytes_sha(stdout_bytes) == manifest['stdout_sha256'] and bytes_sha(stderr_bytes) == manifest['stderr_sha256'], 'PROCESS_LOG_HASH_MISMATCH')
    stdout = stdout_bytes.decode('utf-8')
    require('Terminating simulation by software request.' in stdout and
            'Received $finish() from Verilog' in stdout and 'timeout' not in stdout.lower(), 'NORMAL_EXIT_NOT_CORROBORATED')
    # Explicit single-run execution semantics; no variant-patch or apparatus ID.
    context = {k: recipe[k] for k in ('target_config', 'clock_policy', 'reset_schedule', 'runtime_options', 'tools')}
    scientific = identified(RunScientificBinding, firmware_sha256=firmware.sha256,
        rtl_tree_sha256=rtl_tree_sha256, simulator_sha256=simulator_sha256, input_sha256=input_sha256,
        execution_context_sha256=digest(context), raw_trace_sha256=bytes_sha(raw_trace_bytes),
        parsed_trace_sha256=digest(parsed), map_id=map_source.platform_map.map_id)
    raw_source = source('raw_bus_trace', raw=raw_trace_bytes)
    parsed_source = source('parsed_bus_trace', payload=parsed)
    artifacts = tuple(sorted((raw_source, parsed_source), key=lambda s: s.artifact_id))
    refs = tuple(s.artifact_id for s in artifacts)
    observations, evidence = [], []
    for tx in parsed['transactions']:
        request, response = tx['request'], tx['response']
        require(request['error'] == response['error'] == 0 and request['byte_enable'] == 15, 'ERROR_TRANSACTION')
        ev = identified(Evidence, kind='accepted_transaction', source_artifact_ids=refs,
                        request_sequence=request['sequence'], response_sequence=response['sequence'])
        evidence.append(ev)
        write = request['write_enable'] == 1
        observations.append(identified(RuntimeMmioObservation, run_binding_id=scientific.run_binding_id,
            transaction_id=request['transaction_id'], request_cycle=request['cycle'], response_cycle=response['cycle'],
            reset_epoch=request['reset_epoch'], operation='write' if write else 'read', address=request['address'],
            byte_enable=request['byte_enable'], write_value=request['write_data'] if write else None,
            read_value=None if write else response['read_data'], error=response['error'],
            raw_trace_artifact_id=raw_source.artifact_id, parsed_trace_artifact_id=parsed_source.artifact_id,
            provenance=Provenance(method='syn-a-completed-bus-transaction/v1', source_artifact_ids=refs, evidence_ids=(ev.evidence_id,))))
    attested = tuple(sorted((source('apparatus_run_manifest', raw=manifest_bytes),
                            source('apparatus_trace_binding', raw=binding_bytes), source('stdout', raw=stdout_bytes),
                            source('stderr', raw=stderr_bytes), source('build_recipe', payload=recipe)), key=lambda s: s.artifact_id))
    attestation = identified(RuntimeSourceAttestation, upstream_apparatus_run_id=manifest['run_case_neutral_id'],
        run_binding_id=scientific.run_binding_id, map_source=map_source, source_artifacts=attested,
        provenance=Provenance(method='syn-a-source-binding/v1', source_artifact_ids=tuple(s.artifact_id for s in attested), evidence_ids=()))
    return identified(RuntimeMmioObservationSet, run_binding=scientific, runtime_observations=tuple(observations),
        runtime_sequence=tuple(o.observation_id for o in observations), source_artifacts=artifacts,
        evidence=tuple(sorted(evidence, key=lambda e: e.evidence_id)), source_attestation=attestation)


class StaticRuntimeMmioBinding(Content):
    id_field = 'binding_id'
    prefix = 'mmio-binding'
    binding_id: Identifier
    binding_rule_version: Literal['unbound-no-attested-pc-transaction-bridge/v1'] = BRIDGE_RULE
    # No bound/not_same constructor is offered before a reviewed bridge exists.
    status: Literal['unknown'] = 'unknown'
    static_catalog_id: Identifier
    runtime_set_id: Identifier
    candidate_static_fact_ids: tuple[Identifier, ...]
    runtime_observation_ids: tuple[Identifier, ...]
    bridge_evidence_ids: tuple[Identifier, ...] = ()
    reason: Literal['no_attested_pc_transaction_bridge'] = 'no_attested_pc_transaction_bridge'

    @model_validator(mode='after')
    def no_invented_bridge(self):
        require(not self.bridge_evidence_ids, 'UNSUPPORTED_BRIDGE')
        require(self.candidate_static_fact_ids == tuple(sorted(set(self.candidate_static_fact_ids))), 'CANDIDATE_SET_ORDER')
        require(len(self.runtime_observation_ids) == 1, 'BINDING_OBSERVATION_CARDINALITY')
        return self


class StaticRuntimeMmioBindingSet(Content):
    id_field = 'set_id'
    hash_field = 'set_sha256'
    prefix = 'fwmmio-binding'
    set_id: Identifier
    set_sha256: Sha256
    schema_version: Literal['firmware-mmio-binding/v1'] = 'firmware-mmio-binding/v1'
    static_catalog_id: Identifier
    runtime_set_id: Identifier
    bindings: tuple[StaticRuntimeMmioBinding, ...]
    limitations: tuple[str, ...] = ('Address equality, unique candidates and order do not establish PC-to-bus binding.',)

    @model_validator(mode='after')
    def refs(self):
        require(all(b.static_catalog_id == self.static_catalog_id and b.runtime_set_id == self.runtime_set_id for b in self.bindings), 'BINDING_SET_REFS')
        require(len({b.binding_id for b in self.bindings}) == len(self.bindings), 'DUPLICATE_BINDING')
        return self


def bind_static_runtime(static: FirmwareMmioStaticCatalog, runtime: RuntimeMmioObservationSet):
    """Return UNKNOWN independently for each runtime observation, never zip sites."""
    static = FirmwareMmioStaticCatalog.model_validate(static.model_dump(mode='json'))
    runtime = RuntimeMmioObservationSet.model_validate(runtime.model_dump(mode='json'))
    require(static.firmware_artifact.sha256 == runtime.run_binding.firmware_sha256, 'WRONG_FIRMWARE_BINDING')
    require(static.target_binding.map_id == runtime.run_binding.map_id, 'MAP_IDENTITY_MISMATCH')
    candidates = tuple(sorted(f.fact_id for f in static.static_facts + static.unresolved_accesses))
    bindings = tuple(identified(StaticRuntimeMmioBinding, static_catalog_id=static.catalog_id,
                     runtime_set_id=runtime.set_id, candidate_static_fact_ids=candidates,
                     runtime_observation_ids=(o.observation_id,)) for o in runtime.runtime_observations)
    return identified(StaticRuntimeMmioBindingSet, static_catalog_id=static.catalog_id,
                      runtime_set_id=runtime.set_id, bindings=bindings)


def _local(root, relative):
    root = Path(root).resolve(); relative = Path(relative)
    require(not relative.is_absolute() and '..' not in relative.parts, 'UNSAFE_LOCAL_PATH')
    p = root / relative
    require(p.resolve().is_relative_to(root) and p.is_file() and not p.is_symlink(), 'MISSING_OR_UNSAFE_ARTIFACT')
    return p


def verify_source_tree(tree, manifest_bytes, expected_sha):
    """Recompute the complete file set and content, not just manifest claims."""
    tree = Path(tree); require(tree.is_dir() and not tree.is_symlink(), 'SOURCE_TREE_MISSING')
    manifest = read_json(manifest_bytes)
    require(isinstance(manifest, dict) and digest(manifest) == expected_sha, 'SOURCE_MANIFEST_IDENTITY')
    files = {}
    for path in sorted(tree.rglob('*')):
        require(not path.is_symlink(), 'SYMLINK_SOURCE')
        if path.is_file():
            files[str(path.relative_to(tree))] = file_sha(path)
    require(files == manifest, 'SOURCE_TREE_MISMATCH')
    return files


def load_apparatus_run(workspace: Path, manifest_relative: str, *, base_source: Path,
                       expected_base_sha: str, expected_rtl_sha: str, expected_firmware_sha: str):
    """Explicit read-only ingestion of a source-pinned A workspace.

    Pin values are caller inputs, not inferred from path, expected outcomes or
    sibling runs. The A parser/runner and the processor trace are not imported.
    Returns three independently addressed objects and map source attestation.
    """
    root = Path(workspace).resolve(); mp = _local(root, manifest_relative)
    manifest_bytes = mp.read_bytes(); manifest = read_json(manifest_bytes)
    identity = manifest['identity_inputs']
    require(identity['base_source_tree_sha256'] == expected_base_sha and
            identity['rtl_tree_sha256'] == expected_rtl_sha, 'FROZEN_SOURCE_IDENTITY_MISMATCH')
    require(identity['firmware_sha256'] == expected_firmware_sha, 'FROZEN_FIRMWARE_IDENTITY_MISMATCH')
    verify_source_tree(base_source, _local(root, 'base-source-files.json').read_bytes(), expected_base_sha)
    matches = []
    for name in ('a', 'b'):
        raw = _local(root, name + '-source-files.json').read_bytes()
        if digest(read_json(raw)) == expected_rtl_sha:
            matches.append((name, raw))
    require(len(matches) == 1, 'AMBIGUOUS_RTL_SOURCE')
    name, source_manifest_bytes = matches[0]
    verify_source_tree(root / 'sources' / name, source_manifest_bytes, expected_rtl_sha)
    sim = _local(root, manifest['simulator_path'])
    require(sim.is_relative_to(root / 'builds' / name), 'SIMULATOR_TREE_MISMATCH')
    xmls = list(sim.parent.rglob('Vibex_simple_system.xml'))
    require(len(xmls) == 1, 'ELABORATION_XML_MISSING_OR_AMBIGUOUS')
    xml = _local(root, str(xmls[0].relative_to(root)))
    map_source = extract_platform_map(xml.read_bytes(), _local(root, name + '-elaboration.json').read_bytes(),
        source_manifest_bytes, rtl_tree_sha256=expected_rtl_sha, target_device='SyntheticPeripheral')
    elf_bytes = _local(root, manifest['firmware_path']).read_bytes()
    require(bytes_sha(elf_bytes) == expected_firmware_sha, 'ELF_BYTES_IDENTITY_MISMATCH')
    static = extract_rv32_mmio_static_facts(elf_bytes, map_source.platform_map, instruction_count=12)
    recipe = read_json(_local(root, 'build-recipe.json').read_bytes())
    require(digest(recipe) == identity['build_recipe_sha256'], 'RECIPE_MISMATCH')
    params = dict(map_source.platform_map.configuration)
    enums = {'ibex_pkg::BaseIsaRV32I': 0, 'ibex_pkg::RV32MFast': 2, 'ibex_pkg::RV32BNone': 0,
             'ibex_pkg::RV32Zca': 0, 'ibex_pkg::RegFileFF': 0}
    require(all(params.get(k) == enums.get(v, v) for k, v in recipe['target_config'].items()), 'MAP_CONFIG_RECIPE_MISMATCH')
    run_relative = mp.parent.relative_to(root)
    def record(name):
        return _local(root, str(run_relative / name)).read_bytes()
    runtime = materialize_runtime(manifest_bytes=manifest_bytes, binding_bytes=record('trace-binding.json'),
        raw_trace_bytes=record('synthetic-mmio.jsonl'), parsed_trace_bytes=record('parsed-trace.json'),
        firmware=static.firmware_artifact, map_source=map_source, rtl_tree_sha256=expected_rtl_sha,
        simulator_sha256=file_sha(sim), input_sha256=digest(read_json(_local(root, 'software-input.json').read_bytes())),
        recipe=recipe, stdout_bytes=record('process.stdout.log'), stderr_bytes=record('process.stderr.log'))
    return static, runtime, bind_static_runtime(static, runtime), map_source


def serialize(model):
    """Pure deterministic serialization; callers explicitly choose persistence."""
    checked = type(model).model_validate(model.model_dump(mode='json'))
    return canonical(checked) + '\n'


def render_report(static, runtime, bindings):
    """Small deterministic Chinese renderer kept here to avoid another module."""
    require(serialize(bind_static_runtime(static, runtime)) == serialize(bindings), 'BINDING_REPLAY_MISMATCH')
    def number(value):
        return '未知' if value is None else f'0x{value:X}'
    lines = ['# 固件 MMIO 事实报告', '',
             f'固件 SHA-256：`{static.firmware_artifact.sha256}`', '',
             f'静态：从 ELF 字节确定 {len(static.static_facts)} 个目标窗口访问点。',
             f'运行时：实际接受并成功完成 {len(runtime.runtime_observations)} 个目标窗口事务。',
             '对应关系：UNKNOWN。现有来源绑定没有提供可核验的 PC ↔ bus transaction 桥接。', '',
             '静态地址和值只来自 ELF；运行时地址和值只来自总线记录，二者没有互相补值。', '',
             '## 静态事实', '', '| PC | 操作 | 地址 | 静态写值 |', '|---|---|---|---|']
    for f in static.static_facts:
        lines.append(f'| {number(f.instruction_pc)} | {f.operation} | {number(f.address)} | {number(f.value) if f.operation == "write" else "不适用（读取）"} |')
    lines += ['', f'另保留 {len(static.non_target_accesses)} 个已解析非目标内存访问和 {len(static.unresolved_accesses)} 个地址未解析访问。',
              '', '## 运行时观察', '', '| 事务 | 请求 → 响应周期 | 操作 | 地址 | 观测值 |', '|---|---|---|---|---|']
    for o in runtime.runtime_observations:
        lines.append(f'| {o.transaction_id} | {o.request_cycle} → {o.response_cycle} | {o.operation} | {number(o.address)} | {number(o.write_value if o.operation == "write" else o.read_value)} |')
    lines += ['', '## 绑定与未知项', '',
              '每个事务保留所有候选静态访问点，全部为 UNKNOWN；不按表格行次序、唯一地址或数值相等建立对应。',
              'RVFI 文本即使存在，也不能由同目录位置自动补成来源已绑定的桥接证据。', '',
              '## 可追溯身份', '', f'- Static catalog：`{static.catalog_id}`',
              f'- Runtime set：`{runtime.set_id}`', f'- Binding set：`{bindings.set_id}`',
              f'- Map semantic ID：`{static.target_binding.map_id}`',
              f'- Map source evidence：`{runtime.source_attestation.map_source.map_evidence_id}`', '',
              '## 科学边界', '',
              '读回值只表示实际观测值，不评价正常或异常。本报告不生成 FirmwareCapability、硬件触发满足、偏差验证或跨层链。',
              '静态顺序只是受限直线指令前缀的地址顺序；实际事务顺序来自运行时 cycle/transaction 记录。']
    return '\n'.join(lines) + '\n'
