"""Bounded Cortex-M vector metadata, never interrupt occurrence or physical input proof."""
from typing import Literal
from elftools.elf.sections import SymbolTableSection
from pydantic import Field
from chipchain.domain.common import Contract
from chipchain.domain.evidence import EvidenceRef
from chipchain.tools.firmware.ghidra.elf import ElfMetadata
from chipchain.tools.firmware.ghidra.models import AddressRange,StaticFunction
from chipchain.tools.firmware.ghidra.normalize import evidence


class VectorHandlerBinding(Contract):
    vector_index: int = Field(ge=0)
    exception_number: int | None
    external_irq_number: int | None
    core_exception_name: str | None
    raw_handler_value: int = Field(ge=0,le=0xffffffff)
    canonical_handler_address: int | None
    function_id: str | None
    symbol_names: list[str]
    binding_status: Literal['initial_stack_pointer','null_entry','non_thumb','outside_executable',
                            'function_entry','inside_function','ambiguous','no_function']
    evidence: list[EvidenceRef]


class CortexMVectorResult(Contract):
    status: Literal['bounded','unresolved']
    extent: AddressRange | None = None
    extent_sources: list[str] = Field(default_factory=list)
    bindings: list[VectorHandlerBinding] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


CORE = {1:'Reset',2:'NMI',3:'HardFault',4:'MemManage',5:'BusFault',6:'UsageFault',
        7:'Reserved',8:'Reserved',9:'Reserved',10:'Reserved',11:'SVCall',12:'DebugMonitor',
        13:'Reserved',14:'PendSV',15:'SysTick'}
VECTOR_SYMBOLS={'exception_table','__Vectors','g_pfnVectors','vector_table','__isr_vector'}
VECTOR_SECTIONS={'.isr_vector','.vectors','.vector_table'}


def vector_table(meta: ElfMetadata, functions: list[StaticFunction], *, artifact_id: str='elf') -> CortexMVectorResult:
    candidates=[]
    for section in meta.elf.iter_sections():
        if section.name in VECTOR_SECTIONS and section['sh_flags']&2:
            candidates.append((section['sh_addr'],section['sh_size'],'section:'+section.name))
        if isinstance(section,SymbolTableSection):
            for symbol in section.iter_symbols():
                if symbol.name in VECTOR_SYMBOLS and isinstance(symbol['st_shndx'],int) and symbol['st_size']:
                    candidates.append((symbol['st_value'],symbol['st_size'],'symbol:'+symbol.name))
    extents={(start,size) for start,size,_ in candidates}
    if len(extents)!=1:
        return CortexMVectorResult(status='unresolved',warnings=['No unique evidence-backed vector extent; no guessed IRQ entries.'])
    start,size=next(iter(extents))
    if start%4 or size%4 or not 8<=size<=4*512:
        return CortexMVectorResult(status='unresolved',warnings=['Unsupported vector alignment/extent.'])
    # A table can be in a non-executable LOAD; handlers must be executable.
    segments=[s for s in meta.image.segments if s.vaddr<=start and start+size<=s.vaddr+s.filesz]
    if len(segments)!=1:
        return CortexMVectorResult(status='unresolved',warnings=['Vector extent is not file-backed LOAD data.'])
    segment=segments[0];offset=segment.offset+start-segment.vaddr
    data=meta.data[offset:offset+size]
    words=[int.from_bytes(data[i:i+4],'little') for i in range(0,size,4)]
    if words[0]%4 or words[1]!=meta.image.entry:
        return CortexMVectorResult(status='unresolved',warnings=['Vector stack/reset metadata conflicts with ELF.'])
    bindings=[]
    for i,raw in enumerate(words):
        address=raw & ~1 if i and raw else None
        matches=[];symbol_names=[]
        status='no_function'
        if i==0: status='initial_stack_pointer'
        elif raw==0: status='null_entry'
        elif not raw&1: status='non_thumb'
        else:
            try: meta.image.locate(address,2)
            except ValueError: status='outside_executable'
            else:
                matches=[f for f in functions if any(r.contains(address) for r in f.ranges)]
                if len(matches)>1: status='ambiguous'
                elif len(matches)==1:
                    status='function_entry' if matches[0].entry_address==address else 'inside_function'
                symbol_names=sorted({f.name for f in meta.image.functions if f.address==address})
        bindings.append(VectorHandlerBinding(vector_index=i,exception_number=i if i else None,
            external_irq_number=i-16 if i>=16 else None,core_exception_name=CORE.get(i),
            raw_handler_value=raw,canonical_handler_address=address,
            function_id=matches[0].function_id if len(matches)==1 else None,symbol_names=symbol_names,
            binding_status=status,evidence=[evidence(f'vector-{i}',start+i*4,
                'Bounded ELF vector word; symbolic static dispatch only, not interrupt occurrence.',artifact_id=artifact_id,
                analyzer='pyelftools + Cortex-M vector policy/v1')]))
    return CortexMVectorResult(status='bounded',extent=AddressRange(start=start,end=start+size),
        extent_sources=sorted(source for _,_,source in candidates),bindings=bindings,
        warnings=['Handler symbols are labels, not verified peripheral or physical-input semantics.',
                  'No evidence connects environment interrupt configuration to these static dispatch entries.'])
