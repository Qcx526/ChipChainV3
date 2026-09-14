"""Architecture-neutral static structures; separate from agent observations/IR."""
from typing import Annotated, Literal, Self
from pydantic import Field, model_validator
from chipchain.domain.common import Architecture, Contract, Sha256
from chipchain.domain.evidence import EvidenceRef
from chipchain.domain.provenance import ToolDescriptor

Address = Annotated[int, Field(strict=True, ge=0, lt=2**64)]
Count = Annotated[int, Field(strict=True, ge=0)]


class AddressRange(Contract):
    """Half-open address interval."""
    start: Address
    end: Address

    @model_validator(mode='after')
    def valid(self) -> Self:
        if self.end <= self.start: raise ValueError('Empty or reversed address range')
        return self

    def contains(self, address: int, size: int = 1) -> bool:
        return self.start <= address and address+size <= self.end


class StaticSymbol(Contract):
    name: str = Field(min_length=1, max_length=1024)
    source_type: Literal['DEFAULT', 'ANALYSIS', 'IMPORTED', 'USER_DEFINED', 'UNKNOWN']


class StaticFunction(Contract):
    function_id: str = Field(pattern=r'^f[0-9a-f]+$')
    entry_address: Address
    name: str | None = Field(default=None, max_length=1024)
    ranges: list[AddressRange] = Field(min_length=1, max_length=4096)
    size_bytes: Count
    source_type: Literal['DEFAULT', 'ANALYSIS', 'IMPORTED', 'USER_DEFINED', 'UNKNOWN']
    symbols: list[StaticSymbol] = Field(max_length=256)
    is_thunk: bool
    is_external: bool

    @model_validator(mode='after')
    def consistent(self) -> Self:
        ranges=sorted(self.ranges,key=lambda r:r.start)
        if (self.function_id != f'f{self.entry_address:x}' or
            not any(r.contains(self.entry_address) for r in ranges) or
            self.size_bytes != sum(r.end-r.start for r in ranges) or
            any(a.end>b.start for a,b in zip(ranges,ranges[1:]))):
            raise ValueError('Inconsistent function identity/body')
        return self


class MemoryRange(AddressRange):
    name: str
    initialized: bool
    execute: bool


class ExportCallSite(Contract):
    call_site_address: Address
    caller_function_id: str | None
    callee_function_id: str | None
    target_address: Address | None
    computed: bool
    target_count: Count
    raw_encoding: str = Field(pattern=r'^(?:[0-9a-f]{2}){1,32}$')
    instruction_size: int = Field(strict=True, ge=1, le=32)

    @model_validator(mode='after')
    def byte_count(self) -> Self:
        if len(self.raw_encoding)!=2*self.instruction_size:
            raise ValueError('Instruction byte count mismatch')
        return self


class GhidraExport(Contract):
    schema_version: Literal['ghidra-export/v1']
    ghidra_version: str = Field(min_length=1,max_length=64)
    java_runtime_version: str = Field(min_length=1,max_length=256)
    java_vendor: str = Field(min_length=1,max_length=128)
    language_id: str
    compiler_spec_id: str
    processor: str
    word_size_bits: Literal[32,64]
    endianness: Literal['little','big']
    image_base: Address
    executable_sha256: Sha256
    entry_points: list[Address] = Field(max_length=10000)
    analysis_options: dict[str, Literal['true','false']]
    memory: list[MemoryRange] = Field(min_length=1,max_length=256)
    functions: list[StaticFunction] = Field(max_length=10000)
    call_sites: list[ExportCallSite] = Field(max_length=50000)

    @model_validator(mode='after')
    def unique(self) -> Self:
        for ids in ([f.function_id for f in self.functions],[c.call_site_address for c in self.call_sites]):
            if len(ids)!=len(set(ids)): raise ValueError('Duplicate function/call identity')
        return self


class StaticCallEdge(Contract):
    edge_id: str
    call_site_address: Address
    caller_function_id: str
    callee_function_id: str
    call_kind: Literal['resolved_direct'] = 'resolved_direct'
    evidence: list[EvidenceRef] = Field(min_length=1)


class UnresolvedCallSite(Contract):
    call_site_address: Address
    caller_function_id: str | None
    target_address: Address | None
    reason: Literal['computed_or_ambiguous','missing_caller','missing_callee','callee_entry_conflict',
                    'caller_containment_conflict','instruction_boundary_unconfirmed','decoder_disagreement']
    evidence: list[EvidenceRef] = Field(min_length=1)


class ProgramIdentity(Contract):
    artifact_id: str
    sha256: Sha256
    size_bytes: Count
    architecture: Architecture
    word_size_bits: Literal[32,64]
    endianness: Literal['little','big']
    elf_entry_address: Address
    image_base: Address
    language_id: str
    compiler_spec_id: str
    load_ranges: list[AddressRange]


class GhidraStaticStructureResult(Contract):
    schema_version: Literal['static-structure/v1'] = 'static-structure/v1'
    case_id: str
    tool: ToolDescriptor
    decoder: ToolDescriptor
    program: ProgramIdentity
    java_runtime_version: str
    java_vendor: str
    script_sha256: Sha256
    analysis_options: dict[str,str]
    normalization_policy: Literal['static-structure-normalization/v1'] = 'static-structure-normalization/v1'
    functions: list[StaticFunction]
    direct_call_edges: list[StaticCallEdge]
    unresolved_call_sites: list[UnresolvedCallSite]
    warnings: list[str]

    @model_validator(mode='after')
    def references(self) -> Self:
        functions={f.function_id:f for f in self.functions}
        ids=[e.edge_id for e in self.direct_call_edges]
        sites=[e.call_site_address for e in self.direct_call_edges]+[e.call_site_address for e in self.unresolved_call_sites]
        if len(functions)!=len(self.functions) or len(ids)!=len(set(ids)) or len(sites)!=len(set(sites)):
            raise ValueError('Duplicate static structure identity')
        for e in self.direct_call_edges:
            if e.caller_function_id not in functions or e.callee_function_id not in functions:
                raise ValueError('Unresolved direct edge reference')
            if not any(r.contains(e.call_site_address) for r in functions[e.caller_function_id].ranges):
                raise ValueError('Callsite outside caller')
        return self


def semantic_json(result: GhidraStaticStructureResult) -> str:
    import json
    return json.dumps(result.model_dump(mode='json'),sort_keys=True,separators=(',',':'),ensure_ascii=False)
