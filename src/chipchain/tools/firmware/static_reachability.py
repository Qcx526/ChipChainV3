"""Architecture-neutral static graph contracts and deterministic bounded witnesses."""
from collections import deque
import hashlib
import json
from typing import Literal
from pydantic import Field, model_validator
from chipchain.domain.common import Contract, Sha256

MAX_FUNCTION_PATH_EDGES = 16
MAX_SITE_PATH_EDGES = 256


class CFGConfiguration(Contract):
    normalize: Literal[True] = True
    resolve_indirect_jumps: Literal[True] = True
    force_complete_scan: Literal[False] = False
    force_smart_scan: Literal[False] = False
    function_prologues: Literal[False] = False
    symbols: Literal[False] = False
    start_at_entry: Literal[False] = False
    eh_frame: Literal[False] = False
    exceptions: Literal[False] = False
    function_starts: list[int]


class SourceIdentities(Contract):
    case_id: str
    elf_artifact_id: str
    elf_sha256: Sha256
    elf_size: int
    a2_sha256: Sha256
    a3_sha256: Sha256
    a4_sha256: Sha256
    analyzer: Literal['angr CFGFast'] = 'angr CFGFast'
    versions: dict[str, str]
    configuration: CFGConfiguration
    address_policy: Literal['cortex-m-thumb-lsb-validated/v1', 'identity/v1']


class StaticFunctionBinding(Contract):
    function_id: str
    expected_entry_address: int
    angr_raw_address: int | None
    angr_canonical_address: int | None
    binding_status: Literal['exact', 'missing', 'conflict']

    @model_validator(mode='after')
    def binding(self):
        if self.binding_status == 'exact' and (self.angr_raw_address is None or self.angr_canonical_address != self.expected_entry_address):
            raise ValueError('Exact binding requires matching entry')
        if self.binding_status != 'exact' and (self.angr_raw_address is not None or self.angr_canonical_address is not None):
            raise ValueError('Missing/conflicting binding cannot select an entry')
        return self


class CFGNodeFact(Contract):
    node_id: str
    raw_address: int
    canonical_address: int
    size: int = Field(ge=0)
    function_canonical_address: int | None
    instruction_addresses: list[int]


class CFGEdgeFact(Contract):
    edge_id: str
    source_node_id: str
    target_node_id: str
    source_address: int
    target_address: int
    instruction_address: int | None
    jumpkind: str
    edge_kind: Literal['call', 'branch', 'return', 'fakeret', 'syscall', 'unknown']


class FunctionEdge(Contract):
    edge_id: str
    source_address: int
    target_address: int
    basis: Literal['angr_recovered_callgraph'] = 'angr_recovered_callgraph'


class A4TransferComparison(Contract):
    relation_id: str
    site_address: int
    a4_kind: str
    a4_status: str
    angr_successor_addresses: list[int]
    angr_jumpkinds: list[str]
    successor_edge_ids: list[str]
    comparison_status: Literal['agree', 'disagree', 'angr_unresolved', 'site_not_mapped']


class FirmwareAngrCFGResult(Contract):
    schema_version: Literal['firmware-angr-cfg/v1'] = 'firmware-angr-cfg/v1'
    identities: SourceIdentities
    loader: dict[str, str | int | bool]
    loader_diagnostics: dict[str, int]
    total_function_count: int
    total_node_count: int
    total_edge_count: int
    function_bindings: list[StaticFunctionBinding]
    nodes: list[CFGNodeFact]
    edges: list[CFGEdgeFact]
    function_edges: list[FunctionEdge]
    transfer_comparisons: list[A4TransferComparison]

    @model_validator(mode='after')
    def references(self):
        nodes = {n.node_id: n for n in self.nodes}
        for objects, key in [(self.nodes,'node_id'),(self.edges,'edge_id'),(self.function_edges,'edge_id'),
                             (self.function_bindings,'function_id'),(self.transfer_comparisons,'relation_id')]:
            if len({getattr(o,key) for o in objects}) != len(objects):
                raise ValueError('Duplicate graph identity')
        for edge in self.edges:
            if edge.source_node_id not in nodes or edge.target_node_id not in nodes:
                raise ValueError('Edge node missing')
            if (edge.source_address,edge.target_address)!=(nodes[edge.source_node_id].canonical_address,nodes[edge.target_node_id].canonical_address):
                raise ValueError('Edge address mismatch')
            if edge.edge_kind != normalize_jumpkind(edge.jumpkind):
                raise ValueError('Jumpkind mismatch')
        edges = {e.edge_id for e in self.edges}
        if any(not set(c.successor_edge_ids)<=edges for c in self.transfer_comparisons):
            raise ValueError('Comparison references missing edge')
        return self


class StaticCapabilities(Contract):
    supports_static_reachability: bool
    supports_runtime_reachability: Literal[False] = False
    supports_path_feasibility: Literal[False] = False
    supports_input_reachability: Literal[False] = False
    supports_interrupt_occurrence: Literal[False] = False
    supports_hardware_trigger: Literal[False] = False


class StaticFunctionReachabilityFact(Contract):
    source_function_id: str
    target_function_id: str
    status: Literal['reachable_static','not_found_within_bound','source_mapping_missing','target_mapping_missing']
    witness_function_addresses: list[int]
    witness_edge_ids: list[str]
    path_edge_count: int
    capabilities: StaticCapabilities
    limitations: list[Literal['static_only','not_negative_proof']]

    @model_validator(mode='after')
    def witness(self):
        positive=self.status=='reachable_static'
        if self.capabilities.supports_static_reachability!=positive:
            raise ValueError('Static capability mismatch')
        if positive:
            if self.path_edge_count<1 or self.path_edge_count!=len(self.witness_edge_ids) or len(self.witness_function_addresses)!=self.path_edge_count+1:
                raise ValueError('Invalid function witness')
        elif self.witness_function_addresses or self.witness_edge_ids or self.path_edge_count:
            raise ValueError('Negative/missing query cannot carry witness')
        if 'static_only' not in self.limitations or (not positive and 'not_negative_proof' not in self.limitations):
            raise ValueError('Static query limitations missing')
        return self


class StaticSiteReachabilityFact(Contract):
    site_id: str
    site_address: int
    site_kind: Literal['mmio','transfer']
    owner_function_id: str | None
    status: Literal['owner_mapping_missing','source_mapping_missing','reachable_static_no_fakeret',
                    'reachable_static_with_fakeret','not_found_in_cfg']
    witness_node_ids: list[str]
    witness_edge_ids: list[str]
    uses_fakeret: bool
    angr_owner_addresses: list[int]
    capabilities: StaticCapabilities
    limitations: list[Literal['static_only','not_negative_proof','assumes_callee_returns']]

    @model_validator(mode='after')
    def witness(self):
        positive=self.status.startswith('reachable_static_')
        if self.capabilities.supports_static_reachability!=positive or self.uses_fakeret!=(self.status=='reachable_static_with_fakeret'):
            raise ValueError('Site capability/status mismatch')
        if positive and (not self.witness_node_ids or len(self.witness_node_ids)!=len(self.witness_edge_ids)+1):
            raise ValueError('Invalid site witness')
        if not positive and (self.witness_node_ids or self.witness_edge_ids):
            raise ValueError('Non-positive site has witness')
        if ('static_only' not in self.limitations or (self.uses_fakeret and 'assumes_callee_returns' not in self.limitations)
            or (not positive and 'not_negative_proof' not in self.limitations)):
            raise ValueError('Site limitations missing')
        return self


class FirmwareStaticReachabilityCatalog(Contract):
    schema_version: Literal['firmware-static-reachability/v1'] = 'firmware-static-reachability/v1'
    identities: SourceIdentities
    cfg_sha256: Sha256
    max_function_path_edges: int = Field(default=MAX_FUNCTION_PATH_EDGES,ge=1,le=16)
    max_site_path_edges: int = Field(default=MAX_SITE_PATH_EDGES,ge=1,le=256)
    function_reachability: list[StaticFunctionReachabilityFact]
    site_reachability: list[StaticSiteReachabilityFact]


def normalize_jumpkind(jumpkind):
    return {'Ijk_Call':'call','Ijk_Boring':'branch','Ijk_Ret':'return','Ijk_FakeRet':'fakeret'}.get(
        jumpkind,'syscall' if jumpkind.startswith('Ijk_Sys') else 'unknown')


def bounded_bfs(adjacency, source, targets, max_edges):
    """Deterministic shortest witness, neighbors sorted by stable identity."""
    queue=deque([(source,[source],[])])
    visited={source}
    while queue:
        node,path,edges=queue.popleft()
        if node in targets:
            return path,edges
        if len(edges)>=max_edges:
            continue
        for neighbor,eid in sorted(adjacency.get(node,[])):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor,path+[neighbor],edges+[eid]))
    return [],[]


def _canonical(model):
    value=model.model_dump(mode='json')
    if isinstance(model,FirmwareAngrCFGResult):
        value['function_bindings'].sort(key=lambda x:(x['expected_entry_address'],x['function_id']))
        value['nodes'].sort(key=lambda x:(x['canonical_address'],x['node_id']))
        value['edges'].sort(key=lambda x:(x['source_address'],x['target_address'],x['edge_kind'],x['edge_id']))
        value['function_edges'].sort(key=lambda x:(x['source_address'],x['target_address'],x['edge_id']))
        value['transfer_comparisons'].sort(key=lambda x:(x['site_address'],x['relation_id']))
    else:
        value['function_reachability'].sort(key=lambda x:(x['source_function_id'],x['target_function_id']))
        value['site_reachability'].sort(key=lambda x:(x['owner_function_id'] or '',x['site_address'],x['site_id']))
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)


def serialize_firmware_angr_cfg(result):
    return _canonical(FirmwareAngrCFGResult.model_validate(result.model_dump()))


def firmware_angr_cfg_sha256(result):
    return hashlib.sha256(serialize_firmware_angr_cfg(result).encode()).hexdigest()


def parse_firmware_angr_cfg(text):
    return FirmwareAngrCFGResult.model_validate_json(text)


def serialize_firmware_static_reachability(result):
    return _canonical(FirmwareStaticReachabilityCatalog.model_validate(result.model_dump()))


def firmware_static_reachability_sha256(result):
    return hashlib.sha256(serialize_firmware_static_reachability(result).encode()).hexdigest()


def parse_firmware_static_reachability(text, *, cfg):
    result=FirmwareStaticReachabilityCatalog.model_validate_json(text)
    validate_reachability_witnesses(result,cfg)
    return result


def build_static_reachability(cfg, sites):
    cfg=FirmwareAngrCFGResult.model_validate(cfg.model_dump())
    bindings={b.function_id:b for b in cfg.function_bindings}
    adjacency={}
    for e in cfg.function_edges:adjacency.setdefault(e.source_address,[]).append((e.target_address,e.edge_id))
    facts=[]
    for source in sorted(bindings):
        for target in sorted(bindings):
            if source==target:continue
            a,b=bindings[source],bindings[target]
            path,edges=[],[]
            if a.binding_status!='exact':status='source_mapping_missing'
            elif b.binding_status!='exact':status='target_mapping_missing'
            else:
                path,edges=bounded_bfs(adjacency,a.expected_entry_address,{b.expected_entry_address},MAX_FUNCTION_PATH_EDGES)
                status='reachable_static' if path else 'not_found_within_bound'
            facts.append(StaticFunctionReachabilityFact(source_function_id=source,target_function_id=target,status=status,
                witness_function_addresses=path,witness_edge_ids=edges,path_edge_count=len(edges),
                capabilities=StaticCapabilities(supports_static_reachability=bool(path)),
                limitations=['static_only'] if path else ['static_only','not_negative_proof']))
    sitefacts=[]
    for sid,pc,kind,owner in sites:
        binding=bindings.get(owner)
        candidates=[n for n in cfg.nodes if pc in n.instruction_addresses]
        angr_owners=sorted({n.function_canonical_address for n in candidates if n.function_canonical_address is not None})
        path,edges=[],[];uses=False
        if owner is None:status='owner_mapping_missing'
        elif binding is None or binding.binding_status!='exact':status='source_mapping_missing'
        else:
            owned={n.node_id:n for n in cfg.nodes if n.function_canonical_address==binding.expected_entry_address}
            starts=sorted(n.node_id for n in owned.values() if n.canonical_address==binding.expected_entry_address)
            targets={n.node_id for n in candidates if n.node_id in owned}
            status='not_found_in_cfg'
            if len(starts)==1:
                for allow_fake in (False,True):
                    local={}
                    for e in cfg.edges:
                        if e.source_node_id in owned and e.target_node_id in owned and e.edge_kind in (('branch','fakeret') if allow_fake else ('branch',)):
                            local.setdefault(e.source_node_id,[]).append((e.target_node_id,e.edge_id))
                    path,edges=bounded_bfs(local,starts[0],targets,MAX_SITE_PATH_EDGES)
                    if path:
                        uses=any(e.edge_kind=='fakeret' and e.edge_id in edges for e in cfg.edges)
                        status='reachable_static_with_fakeret' if uses else 'reachable_static_no_fakeret'
                        break
        limits=['static_only']+(['assumes_callee_returns'] if uses else [])+([] if path else ['not_negative_proof'])
        sitefacts.append(StaticSiteReachabilityFact(site_id=sid,site_address=pc,site_kind=kind,owner_function_id=owner,
            status=status,witness_node_ids=path,witness_edge_ids=edges,uses_fakeret=uses,angr_owner_addresses=angr_owners,
            capabilities=StaticCapabilities(supports_static_reachability=bool(path)),limitations=limits))
    result=FirmwareStaticReachabilityCatalog(identities=cfg.identities,cfg_sha256=firmware_angr_cfg_sha256(cfg),
        function_reachability=facts,site_reachability=sitefacts)
    result=FirmwareStaticReachabilityCatalog.model_validate_json(serialize_firmware_static_reachability(result))
    validate_reachability_witnesses(result,cfg)
    return result


def validate_reachability_witnesses(result,cfg):
    if result.identities!=cfg.identities or result.cfg_sha256!=firmware_angr_cfg_sha256(cfg):
        raise ValueError('Reachability/CFG source identity mismatch')
    bindings={b.function_id:b for b in cfg.function_bindings}
    expected={(s,t) for s in bindings for t in bindings if s!=t}
    actual=[(f.source_function_id,f.target_function_id) for f in result.function_reachability]
    if set(actual)!=expected or len(actual)!=len(expected):raise ValueError('Pair coverage mismatch')
    function_edges={e.edge_id:e for e in cfg.function_edges};edges={e.edge_id:e for e in cfg.edges};nodes={n.node_id:n for n in cfg.nodes}
    for f in result.function_reachability:
        if f.status=='reachable_static':
            path=f.witness_function_addresses
            if len(f.witness_edge_ids)>result.max_function_path_edges:raise ValueError('Function path exceeds bound')
            if (path[0],path[-1])!=(bindings[f.source_function_id].expected_entry_address,bindings[f.target_function_id].expected_entry_address):raise ValueError('Wrong witness endpoints')
            for a,b,eid in zip(path,path[1:],f.witness_edge_ids):
                e=function_edges.get(eid)
                if e is None or (e.source_address,e.target_address)!=(a,b):raise ValueError('Broken function witness')
    if len({s.site_id for s in result.site_reachability})!=len(result.site_reachability):raise ValueError('Duplicate site')
    for s in result.site_reachability:
        if not s.witness_node_ids:continue
        path=s.witness_node_ids
        owner=bindings[s.owner_function_id].expected_entry_address
        if len(s.witness_edge_ids)>result.max_site_path_edges:raise ValueError('Site bound exceeded')
        if any(n not in nodes or nodes[n].function_canonical_address!=owner for n in path):raise ValueError('Site witness leaves owner')
        if nodes[path[0]].canonical_address!=owner or s.site_address not in nodes[path[-1]].instruction_addresses:raise ValueError('Site endpoint mismatch')
        for a,b,eid in zip(path,path[1:],s.witness_edge_ids):
            e=edges.get(eid)
            if e is None or (e.source_node_id,e.target_node_id)!=(a,b) or e.edge_kind not in ('branch','fakeret'):raise ValueError('Invalid site edge')
        if s.uses_fakeret!=any(edges[eid].edge_kind=='fakeret' for eid in s.witness_edge_ids):raise ValueError('FakeRet mismatch')
