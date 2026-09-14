"""Existing A1 sites related to static functions without altering observations or IR."""
from typing import Literal
from pydantic import Field
from chipchain.domain.common import Contract
from chipchain.domain.evidence import EvidenceRef
from chipchain.tools.contracts import FirmwareObservations,StaticInstructionSiteDetails,MmioModelDetails
from .models import GhidraStaticStructureResult,StaticFunction
from .normalize import evidence


class SiteFunctionComparison(Contract):
    pc: int
    observation_id: str
    a1_name: str | None
    a1_entry_address: int | None
    function_ids: list[str]
    containment: Literal['missing','unique','ambiguous']
    entry_match: bool | None
    name_match: bool | None
    mnemonic: str | None
    directions: list[str]


class MmioFunctionBinding(Contract):
    mmio_behavior_id: str
    pc: int
    function_id: str | None
    candidate_function_ids: list[str]
    binding_status: Literal['missing','unique','ambiguous']
    binding_basis: Literal['static address containment'] = 'static address containment'
    evidence: list[EvidenceRef]


class DirectCallNeighborhood(Contract):
    function_id: str
    name: str | None
    direct_callers: list[str]
    direct_callees: list[str]
    incoming_edge_count: int
    outgoing_edge_count: int


class MmioStructureAssociations(Contract):
    sites: list[SiteFunctionComparison]
    bindings: list[MmioFunctionBinding]
    neighborhoods: list[DirectCallNeighborhood]
    warnings: list[str] = Field(default_factory=list)


def containing(functions: list[StaticFunction],pc: int) -> list[StaticFunction]:
    return sorted((f for f in functions if any(r.contains(pc) for r in f.ranges)),key=lambda f:f.function_id)


def associate_mmio(result: GhidraStaticStructureResult, observations: FirmwareObservations) -> MmioStructureAssociations:
    if result.case_id!=observations.case_id: raise ValueError('Structure and observations case mismatch')
    before=observations.model_dump_json()
    sites=[];bindings=[];used=set()
    directions={}
    for o in observations.observations:
        if isinstance(getattr(o,'details',None),MmioModelDetails):
            directions.setdefault(o.details.pc,set()).update(b.attributes.get('direction','unknown') for b in o.behaviors)
    for o in observations.observations:
        d=getattr(o,'details',None)
        if isinstance(d,StaticInstructionSiteDetails):
            matches=containing(result.functions,d.address)
            f=matches[0] if len(matches)==1 else None
            status='unique' if f else 'ambiguous' if matches else 'missing'
            decoded=next((b.decoded_instruction for b in o.behaviors if b.decoded_instruction),None)
            sites.append(SiteFunctionComparison(pc=d.address,observation_id=o.observation_id,a1_name=d.function,
                a1_entry_address=d.canonical_function_address,function_ids=[m.function_id for m in matches],containment=status,
                entry_match=f.entry_address==d.canonical_function_address if f and d.canonical_function_address is not None else None,
                name_match=f.name==d.function if f and d.function else None,mnemonic=decoded.mnemonic if decoded else None,
                directions=sorted(directions.get(d.address,set()))))
        if isinstance(d,MmioModelDetails):
            matches=containing(result.functions,d.pc);f=matches[0] if len(matches)==1 else None
            if f: used.add(f.function_id)
            for b in o.behaviors:
                bindings.append(MmioFunctionBinding(mmio_behavior_id=b.behavior_id,pc=d.pc,
                    function_id=f.function_id if f else None,candidate_function_ids=[m.function_id for m in matches],
                    binding_status='unique' if f else 'ambiguous' if matches else 'missing',
                    evidence=[*o.evidence,evidence(f'containment-{b.behavior_id}',d.pc,
                        'Static address containment in Ghidra function body; no execution/reachability assertion.',
                        artifact_id=result.program.artifact_id)]))
    neighborhoods=[]
    for fid in sorted(used):
        f=next(f for f in result.functions if f.function_id==fid)
        ins=[e for e in result.direct_call_edges if e.callee_function_id==fid]
        outs=[e for e in result.direct_call_edges if e.caller_function_id==fid]
        neighborhoods.append(DirectCallNeighborhood(function_id=fid,name=f.name,
            direct_callers=sorted({e.caller_function_id for e in ins}),direct_callees=sorted({e.callee_function_id for e in outs}),
            incoming_edge_count=len(ins),outgoing_edge_count=len(outs)))
    assert observations.model_dump_json()==before
    return MmioStructureAssociations(sites=sorted(sites,key=lambda s:s.pc),
        bindings=sorted(bindings,key=lambda b:b.mmio_behavior_id),neighborhoods=neighborhoods,
        warnings=(['Ambiguous containment or unequal function entries are explicit structural conflicts.']
            if any(s.containment=='ambiguous' or s.entry_match is False for s in sites) else [])
            + (['Some A1 sites have no containing Ghidra function; original A1 facts remain authoritative.']
               if any(s.containment=='missing' for s in sites) else []))
