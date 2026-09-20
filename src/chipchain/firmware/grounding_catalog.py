"""Explicit ELF/trace ingestion and conservative, source-prioritized ownership."""
from io import BytesIO
import hashlib
from pathlib import Path
from elftools.elf.elffile import ELFFile
from chipchain.domain.case import TargetDescriptor
from chipchain.domain.evidence import EvidenceRef, EvidenceLocation
from chipchain.firmware.control_flow_grounding import (
    FunctionInterval, FunctionOwnershipFact, FactProvenance, FirmwareControlFlowGroundingCatalog,
    Capabilities, SourceArtifact, RuntimeRetirementObservation, identity,
)
from chipchain.firmware.riscv_control_flow import resolve_transfer
from chipchain.tools.paired.ibex import parse_trace


def resolve_ownership(*, case_id, site_pc, functions, source_id, source_sha256,
                      evidence_id, architecture, word_size_bits=32):
    # ELF first; explicit static-structure / CFG intervals are fallback sources.
    candidates = []
    for kind in ('elf_symbol', 'static_structure', 'cfg_metadata'):
        candidates = [f for f in functions if f.source_kind == kind and
            ((f.end_exclusive is not None and f.start <= site_pc < f.end_exclusive)
             or (f.end_exclusive is None and f.start == site_pc))]
        if candidates:
            # Unknown-size starts are not invented intervals; try a fallback
            # only if this level has no containing interval at all.
            if all(f.end_exclusive is None for f in candidates) and kind != 'cfg_metadata':
                continue
            break
    candidates = sorted(candidates, key=lambda f: f.function_id)
    unique = len(candidates) == 1 and candidates[0].end_exclusive is not None
    owner = candidates[0] if unique else None
    status = 'unique' if unique else 'ambiguous' if candidates else 'missing'
    data = dict(case_id=case_id, architecture=architecture, site_pc=site_pc, ownership_status=status,
        owner_function_id=owner.function_id if owner else None,
        owner_function_name=owner.function_name if owner else None,
        function_start=owner.start if owner else None, function_end_exclusive=owner.end_exclusive if owner else None,
        ownership_method='source-priority-half-open-containment/v1',
        source_ids=sorted({source_id, *(s for f in candidates for s in f.source_ids)}),
        evidence_ids=sorted({evidence_id, *(e for f in candidates for e in f.evidence_ids)}),
        candidate_function_ids=[f.function_id for f in candidates],
        provenance=FactProvenance(scope='static_function_interval', method='half-open-containment-no-nearest-symbol',
            input_sha256=source_sha256, architecture=architecture, word_size_bits=word_size_bits))
    data['fact_id'] = identity('a6-owner', {**data, 'provenance':data['provenance'].model_dump(mode='json')})
    return FunctionOwnershipFact(**data)


def build_catalog(*, case_id, elf_path: Path, trace_path: Path | None = None,
                  sites: dict[int, bytes] | None = None, artifact_id='elf', target: TargetDescriptor | None = None,
                  trace_semantics: str | None = None):
    """Use every unique trace site; all runtime encodings must match ELF bytes.

    Caller-supplied sites are explicit static sites. No implicit scan or nearest
    symbol heuristics. Runtime trace existence is provenance, not path feasibility.
    """
    raw = elf_path.read_bytes(); digest = hashlib.sha256(raw).hexdigest()
    elf = ELFFile(BytesIO(raw))
    architecture = {'EM_RISCV':'riscv', 'EM_ARM':'arm', 'EM_PPC':'powerpc', 'EM_PPC64':'powerpc', 'EM_386':'x86', 'EM_X86_64':'x86'}.get(elf['e_machine'], 'unknown')
    if target is None:
        target = TargetDescriptor(architecture=architecture, processor_id='ELF:'+elf['e_machine'],
            word_size_bits=elf.elfclass, endianness='little' if elf.little_endian else 'big')
    if (target.architecture != architecture or target.word_size_bits not in (None, elf.elfclass)
            or target.endianness not in ('unknown', 'little' if elf.little_endian else 'big')):
        raise ValueError('Target descriptor differs from ELF')
    sources = [SourceArtifact(artifact_id=artifact_id, sha256=digest, size_bytes=len(raw), format='elf')]
    evidence = []

    def ref(kind, pc, summary, function=None):
        eid = identity('a6-ev', dict(source=digest, kind=kind, pc=pc, summary=summary))
        item = EvidenceRef(evidence_id=eid, source_type='deterministic_analyzer', artifact_id=artifact_id,
            analyzer='firmware-control-flow-grounding/v1', epistemic_status='derived', summary=summary,
            location=EvidenceLocation(address=pc, function=function))
        if not any(e.evidence_id == eid for e in evidence):
            evidence.append(item)
        return eid

    symbols = elf.get_section_by_name('.symtab'); functions = []
    if symbols:
        for index, sym in enumerate(symbols.iter_symbols()):
            if sym['st_info']['type'] != 'STT_FUNC' or not isinstance(sym['st_shndx'], int):
                continue
            section = elf.get_section(sym['st_shndx'])
            if not section['sh_flags'] & 4:
                continue
            start = int(sym['st_value'])
            if architecture == 'arm':
                start &= ~1
            size = int(sym['st_size']); end = start + size if size else None
            if not section['sh_addr'] <= start < section['sh_addr'] + section['sh_size']:
                continue
            if end is not None and end > section['sh_addr'] + section['sh_size']:
                end = None  # Invalid extent cannot become authoritative containment.
            name = sym.name or None
            eid = ref('function', start, f'ELF STT_FUNC symbol index {index}, start {start:#x}, end exclusive {end}; name {name}.', name)
            fid = identity('a6-fn', dict(source=digest, symbol_index=index, start=start, end_exclusive=end))
            functions.append(FunctionInterval(function_id=fid, function_name=name, start=start,
                end_exclusive=end, source_kind='elf_symbol', source_ids=[artifact_id], evidence_ids=[eid]))
    requested = dict(sites or {}); trace_hash = None; runtime = []
    if trace_path:
        if trace_semantics not in (None, 'ibex_rvfi_retirement'):
            raise ValueError('Unsupported trace semantics')
        if trace_semantics and architecture != 'riscv':
            raise ValueError('Ibex retirement metadata requires RISC-V')
        trace_data = trace_path.read_bytes(); trace_hash = hashlib.sha256(trace_data).hexdigest()
        sources.append(SourceArtifact(artifact_id='runtime-selection-trace', sha256=trace_hash,
                                      size_bytes=len(trace_data), format='ibex-rvfi-text'))
        for row in parse_trace(trace_data.decode()):
            if row.pc in requested and requested[row.pc] != row.encoding:
                raise ValueError('Conflicting encodings at one PC')
            requested[row.pc] = row.encoding
            if trace_semantics == 'ibex_rvfi_retirement':
                data = dict(case_id=case_id, instruction_pc=row.pc, instruction_encoding=row.encoding.hex(),
                    cycle=row.cycle, line=row.line, source_artifact_id='runtime-selection-trace', source_sha256=trace_hash)
                eid = identity('a6-retired-ev', data)
                evidence.append(EvidenceRef(evidence_id=eid, source_type='deterministic_analyzer',
                    artifact_id='runtime-selection-trace', analyzer='ibex-rvfi-retirement/v1', epistemic_status='observed',
                    summary=f'RVFI retirement event at PC {row.pc:#x}, cycle {row.cycle}; no static path-feasibility claim.',
                    location=EvidenceLocation(line=row.line, address=row.pc)))
                runtime.append(RuntimeRetirementObservation(observation_id=identity('a6-retired',data),
                    evidence_ids=[eid], **data))
    segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD' and s['p_flags'] & 1]
    transfers = []
    for pc, encoding in sorted(requested.items()):
        matches = [s for s in segments if s['p_vaddr'] <= pc and pc + len(encoding) <= s['p_vaddr'] + s['p_filesz']]
        if len(matches) != 1:
            raise ValueError('Site is not uniquely file-backed executable ELF data')
        segment = matches[0]; offset = pc - segment['p_vaddr']
        if segment.data()[offset:offset+len(encoding)] != encoding:
            raise ValueError('Instruction input differs from ELF bytes')
        eid = ref('instruction', pc, f'Static instruction bytes at {pc:#x}: {encoding.hex()} in address order.')
        transfers.append(resolve_transfer(case_id=case_id, pc=pc, encoding=encoding, architecture=architecture,
            artifact_id=artifact_id, evidence_ids=[eid], source_sha256=digest, word_size_bits=elf.elfclass,
            runtime_selection_sha256=trace_hash, byteorder="little" if elf.little_endian else "big"))
    ownership = []
    owner_sites = set(requested) | {f.resolved_target_pc for f in transfers if f.resolved_target_pc is not None}
    for pc in sorted(owner_sites):
        eid = ref('ownership-query', pc, f'Static function containment query at {pc:#x}; symbol extents are half-open.')
        ownership.append(resolve_ownership(case_id=case_id, site_pc=pc, functions=functions,
            source_id=artifact_id, source_sha256=digest, evidence_id=eid, architecture=architecture,
            word_size_bits=elf.elfclass))
    return FirmwareControlFlowGroundingCatalog(case_id=case_id, architecture=architecture, target=target, runtime_observations=runtime,
        transfer_facts=transfers, ownership_facts=ownership, functions=functions, source_artifacts=sources,
        evidence_catalog=evidence, capabilities=Capabilities(
            supports_direct_target_resolution=architecture=='riscv' and elf.elfclass==32 and elf.little_endian),
        limitations=['Static target is not taken branch, runtime target, reachability, or feasibility.',
            'RV32 I+C direct JAL, B, CJ and CB only; indirect registers and return state are unresolved.',
            'Function extents require explicit sizes; overlapping candidates are never silently selected.',
            'Symbol names are presentation only; zero-size or absent functions may leave missing ownership.',
            'Trace supplies site selection, not static path feasibility.'])
