"""Explicit bounded CFGFast adapter. Optional angr is imported only by the worker."""
import hashlib
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from collections import Counter
from importlib.metadata import version

from chipchain.agents.contracts import FirmwareAgentInput
from chipchain.tools.firmware.ghidra.models import GhidraStaticStructureResult
from chipchain.tools.firmware.structure_projection import FirmwareRelevantStaticStructure, relevant_structure_sha256, _hash
from chipchain.tools.firmware.relations import FirmwareStaticRelationCatalog, firmware_static_relations_sha256
from chipchain.tools.firmware.static_reachability import (
    CFGConfiguration, SourceIdentities, StaticFunctionBinding, CFGNodeFact, CFGEdgeFact, FunctionEdge,
    A4TransferComparison, FirmwareAngrCFGResult, normalize_jumpkind, serialize_firmware_angr_cfg,
    parse_firmware_angr_cfg, build_static_reachability,
)

ANGR_VERSION = '9.3.4'
TIMEOUT_SECONDS = 60
MAX_NODES = 20000
MAX_FUNCTIONS = 4096


class ThumbAddressAdapter:
    """LSB applies only to validated Cortex-M code ranges, never arbitrary data."""
    def __init__(self, architecture, ranges, probes):
        if architecture != 'ARMCortexM' or len(probes)<3:
            raise ValueError('Thumb policy requires Cortex-M loader and three known probes')
        self.ranges=ranges
        for canonical,raw,thumb in probes:
            if not thumb or canonical%2 or raw!=canonical+1 or not self.is_code(canonical):
                raise ValueError('Thumb address probe failed')

    def is_code(self,address):
        return any(start<=address<end for start,end in self.ranges)

    def canonical(self,raw):
        return raw & ~1 if self.is_code(raw & ~1) else raw


def bind_functions(selected, raw_functions, adapter):
    by_address={}
    for raw in raw_functions:by_address.setdefault(adapter.canonical(raw),[]).append(raw)
    bindings=[]
    for f in selected:
        candidates=by_address.get(f.entry_address,[])
        status='exact' if len(candidates)==1 else 'conflict' if candidates else 'missing'
        bindings.append(StaticFunctionBinding(function_id=f.function_id,expected_entry_address=f.entry_address,
            angr_raw_address=candidates[0] if status=='exact' else None,
            angr_canonical_address=f.entry_address if status=='exact' else None,binding_status=status))
    return bindings


def relevant_sites(a4):
    sites=[]
    for r in a4.relations:
        if r.kind=='mmio_function_containment':
            sites.append((r.relation_id,r.site_address,'mmio',r.target.entity_id if r.target and r.status=='confirmed_static' else None))
        elif r.kind in ('direct_call','direct_branch','control_transfer_unresolved'):
            sites.append((r.relation_id,r.site_address,'transfer',r.source.entity_id if r.source.entity_type=='function' else None))
    return sorted(sites,key=lambda s:(s[1],s[0]))


def compare_transfers(a4,nodes,edges,code_ranges):
    comparisons=[]
    for r in a4.relations:
        if r.kind not in ('direct_call','direct_branch','control_transfer_unresolved'):continue
        mapped=any(r.site_address in n.instruction_addresses for n in nodes)
        candidates=sorted((e for e in edges if e.instruction_address==r.site_address and e.edge_kind not in ('fakeret','return')),
                          key=lambda e:(e.target_address,e.jumpkind,e.edge_id))
        known=[e for e in candidates if any(start<=e.target_address<end for start,end in code_ranges) and e.edge_kind in ('call','branch')]
        if not mapped:status='site_not_mapped'
        elif not known:status='angr_unresolved'
        elif r.kind=='control_transfer_unresolved':status='disagree'  # recovery vs unresolved: preserve both
        else:
            expected_kind='call' if r.kind=='direct_call' else 'branch'
            status='agree' if r.target is not None and {(e.target_address,e.edge_kind) for e in candidates}=={(r.target.address,expected_kind)} else 'disagree'
        comparisons.append(A4TransferComparison(relation_id=r.relation_id,site_address=r.site_address,
            a4_kind=r.kind,a4_status=r.status,angr_successor_addresses=[e.target_address for e in candidates],
            angr_jumpkinds=[e.jumpkind for e in candidates],successor_edge_ids=[e.edge_id for e in candidates],comparison_status=status))
    return comparisons


def validate_inputs(inputs,source,relevant,a4,elf_path):
    inputs=FirmwareAgentInput.model_validate(inputs.model_dump())
    source=GhidraStaticStructureResult.model_validate(source.model_dump())
    relevant=FirmwareRelevantStaticStructure.model_validate(relevant.model_dump())
    a4=FirmwareStaticRelationCatalog.model_validate(a4.model_dump())
    if len({inputs.case.case_id,inputs.deterministic_observations.case_id,source.case_id,relevant.case_id,a4.case_id})!=1:
        raise ValueError('A5 case identity mismatch')
    data=Path(elf_path).read_bytes();digest=hashlib.sha256(data).hexdigest()
    artifact=next((a for a in inputs.case.firmware_artifacts if a.artifact_id==source.program.artifact_id),None)
    sid=a4.source_identities
    if artifact is None or not Path(artifact.path).samefile(elf_path):raise ValueError('A5 explicit ELF artifact mismatch')
    if not (digest==artifact.sha256==source.program.sha256==sid.elf_sha256 and
            len(data)==artifact.size_bytes==source.program.size_bytes==sid.elf_size_bytes and artifact.artifact_id==sid.elf_artifact_id):
        raise ValueError('A5 ELF identity mismatch')
    a2hash=_hash(source.model_dump(mode='json'))
    if a2hash!=sid.a2_sha256 or a2hash!=relevant.source_structure.structure_sha256 or relevant_structure_sha256(relevant)!=sid.a3_sha256:
        raise ValueError('A5 A2/A3 identity mismatch')
    if inputs.case.case_id=='fuzzware:heat-press:scenario-13':
        if (digest,sid.a3_sha256,firmware_static_relations_sha256(a4))!=(
            '73f667524ed0ff8f24b460d4678b74f15eec13d954b93cdc92c839c2c3f1044e',
            '4685e8fbc41fffd90a32bc550fc122955b329c24043dd860abecf55970056304',
            'fc4f1af1737813210ae58daa80b258813eb9e13591024d936c31fd6fe6634902'):
            raise ValueError('A5 frozen Heat_Press identity mismatch')
    return inputs,source,relevant,a4,data


def _recover(inputs,source,relevant,a4,elf_path):
    """Worker only: synchronous CFGFast; the public API enforces process timeout."""
    from chipchain.tools.firmware.ghidra.elf import parse_elf
    inputs,source,relevant,a4,data=validate_inputs(inputs,source,relevant,a4,elf_path)
    versions={p:version(p) for p in ('angr','cle','pyvex','archinfo','capstone','pyelftools')}
    versions['python']='.'.join(map(str,sys.version_info[:3]))
    if any(versions[p]!=ANGR_VERSION for p in ('angr','cle','pyvex','archinfo')):raise ValueError('A5 requires exact angr stack 9.3.4')
    counts=Counter()
    class Capture(logging.Handler):
        def emit(self,record):counts[record.name+':'+record.levelname]+=1
    logging.root.handlers=[Capture()];logging.root.setLevel(logging.WARNING)
    import angr
    project=angr.Project(str(elf_path),auto_load_libs=False)
    meta=parse_elf(data)
    ranges=[]
    for sec in meta.elf.iter_sections():
        if int(sec['sh_flags'])&4 and sec['sh_type']!='SHT_NOBITS':
            raw=sec.data()
            if project.loader.memory.load(sec['sh_addr'],len(raw))!=raw:raise ValueError('Loader changed executable bytes')
            ranges.append((int(sec['sh_addr']),int(sec['sh_addr'])+len(raw)))
    probes=[]
    addresses=(0x80f34,0x80eac,0x80af4) if inputs.case.case_id=='fuzzware:heat-press:scenario-13' else tuple(f.entry_address for f in relevant.functions[:3])
    for addr in addresses:
        symbols=[s for s in project.loader.main_object.symbols if s.is_function and s.rebased_addr in (addr,addr+1)]
        raw=sorted({s.rebased_addr for s in symbols})
        if len(raw)!=1:raise ValueError('Missing or conflicting Thumb loader probe')
        block=project.factory.block(raw[0],size=4)
        probes.append((addr,raw[0],bool(block.thumb)))
    adapter=ThumbAddressAdapter(project.arch.name,ranges,probes)
    starts=sorted({f.entry_address+1 for f in relevant.functions})
    options=CFGConfiguration(function_starts=starts)
    cfg=project.analyses.CFGFast(**options.model_dump())
    if len(cfg.graph)>MAX_NODES or len(cfg.kb.functions)>MAX_FUNCTIONS:raise ValueError('CFG recovery exceeds serialization bounds')
    bindings=bind_functions(relevant.functions,list(cfg.kb.functions),adapter)
    selected={b.expected_entry_address for b in bindings}
    all_nodes={}
    for n in cfg.graph.nodes:
        raw=int(n.addr);addr=adapter.canonical(raw);size=int(n.size or 0)
        fid=adapter.canonical(n.function_address) if n.function_address is not None else None
        nid=f'n{addr:016x}-{raw:016x}-{size:x}'
        fact=CFGNodeFact(node_id=nid,raw_address=raw,canonical_address=addr,size=size,
            function_canonical_address=fid,instruction_addresses=sorted({adapter.canonical(x) for x in (n.instruction_addrs or [])}))
        if nid in [v.node_id for v in all_nodes.values()]:raise ValueError('Ambiguous canonical CFG node')
        all_nodes[n]=fact
    all_edges=[]
    for a,b,d in cfg.graph.edges(data=True):
        src,tgt=all_nodes[a],all_nodes[b]
        jump=d.get('jumpkind','unknown');pc=d.get('ins_addr')
        pc=adapter.canonical(pc) if isinstance(pc,int) else None
        eid='e-'+hashlib.sha256(f'{src.node_id}/{tgt.node_id}/{jump}/{pc}'.encode()).hexdigest()[:24]
        all_edges.append(CFGEdgeFact(edge_id=eid,source_node_id=src.node_id,target_node_id=tgt.node_id,
            source_address=src.canonical_address,target_address=tgt.canonical_address,instruction_address=pc,
            jumpkind=jump,edge_kind=normalize_jumpkind(jump)))
    sites=relevant_sites(a4);pcs={s[1] for s in sites}
    keep={n.node_id for n in all_nodes.values() if n.function_canonical_address in selected or pcs.intersection(n.instruction_addresses)}
    # Include successor endpoints needed by transfer comparisons, no recursive expansion.
    for e in all_edges:
        if e.instruction_address in pcs:keep.update((e.source_node_id,e.target_node_id))
    nodes=[n for n in all_nodes.values() if n.node_id in keep]
    edges=[e for e in all_edges if e.source_node_id in keep and e.target_node_id in keep]
    function_edges=[]
    pairs=sorted({(adapter.canonical(a),adapter.canonical(b)) for a,b in cfg.kb.functions.callgraph.edges()
                  if adapter.is_code(adapter.canonical(a)) and adapter.is_code(adapter.canonical(b))})
    for a,b in pairs:function_edges.append(FunctionEdge(edge_id=f'fc-{a:x}-{b:x}',source_address=a,target_address=b))
    sid=a4.source_identities
    identities=SourceIdentities(case_id=inputs.case.case_id,elf_artifact_id=sid.elf_artifact_id,elf_sha256=sid.elf_sha256,
        elf_size=sid.elf_size_bytes,a2_sha256=sid.a2_sha256,a3_sha256=sid.a3_sha256,a4_sha256=firmware_static_relations_sha256(a4),
        versions=versions,configuration=options,address_policy='cortex-m-thumb-lsb-validated/v1')
    obj=project.loader.main_object
    return FirmwareAngrCFGResult(identities=identities,
        loader=dict(architecture=project.arch.name,endianness=str(project.arch.memory_endness),entry_point=project.entry,
            mapped_min=obj.min_addr,mapped_max=obj.max_addr,executable_bytes_equal=True,thumb_probe_count=len(probes)),
        loader_diagnostics=dict(counts),total_function_count=len(cfg.kb.functions),total_node_count=len(cfg.graph),
        total_edge_count=cfg.graph.number_of_edges(),function_bindings=bindings,nodes=nodes,edges=edges,function_edges=function_edges,
        transfer_comparisons=compare_transfers(a4,nodes,edges,ranges))


def recover_firmware_angr_cfg(inputs,source,relevant,a4,*,elf_path,timeout=TIMEOUT_SECONDS):
    if not 0<timeout<=120:raise ValueError('CFGFast requires a timeout <=120 seconds')
    validate_inputs(inputs,source,relevant,a4,elf_path)
    with tempfile.TemporaryDirectory(prefix='chipchain-a5-') as work:
        request=Path(work)/'request.json';response=Path(work)/'cfg.json'
        request.write_text(json.dumps(dict(inputs=inputs.model_dump(mode='json'),source=source.model_dump(mode='json'),
            relevant=relevant.model_dump(mode='json'),a4=a4.model_dump(mode='json'),elf_path=str(Path(elf_path).resolve()))))
        env={k:v for k,v in os.environ.items() if not any(word in k.upper() for word in ('KEY','TOKEN','SECRET','PASSWORD'))}
        env.update(PYTHONHASHSEED='0',LANGSMITH_TRACING='false',LANGCHAIN_TRACING='false',LANGCHAIN_TRACING_V2='false')
        result=subprocess.run([sys.executable,'-m','chipchain.tools.firmware.angr_cfg',str(request),str(response)],
            timeout=timeout,check=False,capture_output=True,env=env,shell=False)
        if result.returncode:raise ValueError('CFGFast worker failed: '+result.stderr.decode(errors='replace')[-1500:])
        cfg=parse_firmware_angr_cfg(response.read_text())
        validate_inputs(inputs,source,relevant,a4,elf_path)
        return cfg


def main():
    # Worker must not call network, external models, or external processes.
    import socket
    def forbidden(*a,**k):raise RuntimeError('A5 worker network disabled')
    socket.socket.connect=forbidden;socket.create_connection=forbidden;socket.getaddrinfo=forbidden
    request=json.loads(Path(sys.argv[1]).read_text())
    cfg=_recover(FirmwareAgentInput.model_validate(request['inputs']),GhidraStaticStructureResult.model_validate(request['source']),
        FirmwareRelevantStaticStructure.model_validate(request['relevant']),FirmwareStaticRelationCatalog.model_validate(request['a4']),request['elf_path'])
    Path(sys.argv[2]).write_text(serialize_firmware_angr_cfg(cfg))


if __name__=='__main__':main()
