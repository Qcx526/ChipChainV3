"""Strict export validation and independent ELF/Capstone callsite cross-checks."""
import hashlib
import json
from chipchain.domain.common import Architecture
from chipchain.domain.evidence import EvidenceRef, EvidenceLocation
from chipchain.domain.provenance import ToolDescriptor
from chipchain.tools.architecture.arm import ArmThumbInstructionDecoder, MAX_FUNCTION_BYTES
from .elf import parse_elf
from .models import (GhidraExport,GhidraStaticStructureResult,ProgramIdentity,AddressRange,
                     StaticCallEdge,UnresolvedCallSite,semantic_json)
from .process import GhidraError, LANGUAGE, COMPILER, MAX_EXPORT


def evidence(identifier: str, address: int, summary: str, *, artifact_id: str='elf',
             analyzer: str='ghidra-headless + pyelftools + capstone') -> EvidenceRef:
    return EvidenceRef(evidence_id=identifier,source_type='deterministic_analyzer',artifact_id=artifact_id,
        analyzer=analyzer,location=EvidenceLocation(address=address),
        summary=summary,epistemic_status='derived')


def _pairs(items):
    result={}
    for k,v in items:
        if k in result: raise GhidraError('Duplicate JSON keys')
        result[k]=v
    return result


def normalize_export(raw: bytes, elf_bytes: bytes, *, case_id: str, expected_version: str,
                     script_sha256: str, artifact_id: str='elf') -> GhidraStaticStructureResult:
    if len(raw)>MAX_EXPORT: raise GhidraError('Oversized export')
    try:
        exported=GhidraExport.model_validate(json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs),strict=True)
    except Exception:
        raise GhidraError('Invalid Ghidra export schema') from None
    meta=parse_elf(elf_bytes)
    image=meta.image
    if (exported.ghidra_version!=expected_version or exported.executable_sha256!=hashlib.sha256(elf_bytes).hexdigest()
        or exported.language_id!=LANGUAGE or exported.compiler_spec_id!=COMPILER or exported.processor!='ARM'
        or exported.word_size_bits!=32 or exported.endianness!='little'
        or exported.image_base!=min(s.vaddr for s in image.segments)
        or image.entry & ~1 not in exported.entry_points):
        raise GhidraError('Ghidra tool/program/target identity mismatch')
    # All exported target memory must fit LOAD mappings; metadata overlays are
    # explicitly excluded by the script, never reinterpreted as target memory.
    for m in exported.memory:
        if not any(s.vaddr<=m.start<m.end<=s.vaddr+(s.filesz if m.initialized else s.memsz) for s in image.segments):
            raise GhidraError('Ghidra memory conflicts with ELF LOAD ranges')
        if m.execute and not any(s.flags&1 and s.vaddr<=m.start<m.end<=s.vaddr+s.memsz for s in image.segments):
            raise GhidraError('Ghidra executable memory conflicts with ELF')
    for segment in image.segments:
        cursor=segment.vaddr
        for block in sorted(exported.memory,key=lambda m:m.start):
            if segment.vaddr<=block.start<segment.vaddr+segment.memsz:
                if block.start!=cursor: raise GhidraError('Ghidra target memory gap/overlap')
                cursor=block.end
        if cursor!=segment.vaddr+segment.memsz: raise GhidraError('Ghidra memory does not cover ELF LOAD')
    functions=sorted((f.model_copy(deep=True) for f in exported.functions),key=lambda f:f.entry_address)
    for f in functions:
        if f.is_external: raise GhidraError('External function needs a separate unresolved representation')
        for r in f.ranges:
            image.locate(r.start,r.end-r.start)
        f.ranges.sort(key=lambda r:(r.start,r.end))
        f.symbols.sort(key=lambda s:(s.name,s.source_type))
    by_id={f.function_id:f for f in functions}
    decoder=ArmThumbInstructionDecoder()
    edges=[];unresolved=[]
    for call in sorted(exported.call_sites,key=lambda c:c.call_site_address):
        pc=call.call_site_address
        try: actual=meta.read_code(pc,call.instruction_size)
        except Exception: raise GhidraError('Callsite outside executable file-backed image') from None
        if call.instruction_size not in (2,4): raise GhidraError('Unsupported Thumb instruction size')
        if actual.hex()!=call.raw_encoding: raise GhidraError('Ghidra call bytes differ from ELF')
        refs=[evidence(f'call-{pc:x}',pc,'Static callsite from Ghidra, cross-checked against ELF bytes',artifact_id=artifact_id)]
        caller=by_id.get(call.caller_function_id);callee=by_id.get(call.callee_function_id)
        reason=None
        if call.computed or call.target_count!=1: reason='computed_or_ambiguous'
        elif caller is None: reason='missing_caller'
        elif callee is None: reason='missing_callee'
        elif call.target_address!=callee.entry_address: reason='callee_entry_conflict'
        elif (not any(r.contains(pc,call.instruction_size) for r in caller.ranges) or
              sum(any(r.contains(pc) for r in f.ranges) for f in functions)!=1):
            reason='caller_containment_conflict'
        else:
            # Independent start/bounds from ELF function symbols, not from
            # Ghidra's claimed instruction boundary. Generated-only functions stay unresolved.
            bounds={f.size for f in image.functions if f.address==caller.entry_address}
            try:
                if len(bounds)!=1: raise ValueError('No unique ELF function bound')
                size=next(iter(bounds))
                if size>MAX_FUNCTION_BYTES: raise ValueError('Bound too large')
                decoded=decoder.decode_site(function_bytes=meta.read_code(caller.entry_address,size),
                    function_address=caller.entry_address,pc=pc,observation_id=f'call-{pc:x}',evidence=refs)
                targets=[o.immediate for o in decoded.operands if o.kind=='immediate']
                if (decoded.raw_encoding!=call.raw_encoding or decoded.mnemonic!='bl'
                        or targets!=[call.target_address]): reason='decoder_disagreement'
            except ValueError: reason='instruction_boundary_unconfirmed'
        if reason:
            unresolved.append(UnresolvedCallSite(call_site_address=pc,caller_function_id=call.caller_function_id,
                target_address=call.target_address,reason=reason,evidence=refs))
        else:
            edges.append(StaticCallEdge(edge_id=f'call-{pc:x}',call_site_address=pc,
                caller_function_id=caller.function_id,callee_function_id=callee.function_id,evidence=refs))
    options=dict(sorted(exported.analysis_options.items()))
    if any(v!='false' for k,v in options.items()
           if k.lower()=='call convention id' or any(x in k.lower() for x in ('decompiler','dwarf','pdb','external'))):
        raise GhidraError('Unsupported enabled analyzer policy')
    config={'script_sha256':script_sha256,'analysis_options':options,'language':LANGUAGE,'compiler':COMPILER,
            'normalization_policy':'static-structure-normalization/v1','max_cpu':1,'analysis_timeout':240,
            'capstone_mode':'thumb-m-little','max_function_bytes':MAX_FUNCTION_BYTES}
    config_sha=hashlib.sha256(json.dumps(config,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    result=GhidraStaticStructureResult(case_id=case_id,
        tool=ToolDescriptor(tool_name='ghidra-headless',tool_version=exported.ghidra_version,
                            tool_role='firmware_static_structure',configuration_sha256=config_sha),
        decoder=decoder.descriptor,program=ProgramIdentity(artifact_id=artifact_id,sha256=exported.executable_sha256,
            size_bytes=len(elf_bytes),architecture=Architecture.ARM,word_size_bits=32,endianness='little',
            elf_entry_address=image.entry,image_base=exported.image_base,language_id=exported.language_id,
            compiler_spec_id=exported.compiler_spec_id,
            load_ranges=[AddressRange(start=s.vaddr,end=s.vaddr+s.memsz) for s in image.segments]),
        java_runtime_version=exported.java_runtime_version,java_vendor=exported.java_vendor,script_sha256=script_sha256,
        analysis_options=options,functions=functions,direct_call_edges=edges,unresolved_call_sites=unresolved,
        warnings=['Static function/call structure does not establish execution, input consumption or vulnerability.'])
    # A result has no project paths/logs. Names remain ELF/imported/analysis labels.
    semantic_json(result)
    return result
