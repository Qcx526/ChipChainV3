"""A5 pure graph tests; no angr import or external tool execution."""
from types import SimpleNamespace as NS
import json
import pytest
from pydantic import ValidationError
from chipchain.tools.firmware.static_reachability import *
from chipchain.tools.firmware.angr_cfg import ThumbAddressAdapter,bind_functions,compare_transfers,relevant_sites


@pytest.fixture
def cfg():
    identities=SourceIdentities(case_id='synthetic',elf_artifact_id='elf',elf_sha256='1'*64,elf_size=128,
        a2_sha256='2'*64,a3_sha256='3'*64,a4_sha256='4'*64,versions={'angr':'synthetic'},
        configuration=CFGConfiguration(function_starts=[0x101,0x201,0x301]),address_policy='identity/v1')
    nodes=[CFGNodeFact(node_id=f'n{pc:016x}',raw_address=pc,canonical_address=pc,size=4,
        function_canonical_address=owner,instruction_addresses=[pc]) for pc,owner in [(0x100,0x100),(0x104,0x100),(0x108,0x100),(0x200,0x200),(0x300,0x300)]]
    edges=[]
    for a,b,j in [(0x100,0x104,'Ijk_Boring'),(0x104,0x108,'Ijk_FakeRet'),(0x104,0x200,'Ijk_Call')]:
        edges.append(CFGEdgeFact(edge_id=f'e{a:x}-{b:x}',source_node_id=f'n{a:016x}',target_node_id=f'n{b:016x}',
            source_address=a,target_address=b,instruction_address=a,jumpkind=j,edge_kind=normalize_jumpkind(j)))
    bindings=[StaticFunctionBinding(function_id=f'f{x:x}',expected_entry_address=x,angr_raw_address=x,
        angr_canonical_address=x,binding_status='exact') for x in [0x100,0x200,0x300]]
    return FirmwareAngrCFGResult(identities=identities,loader={},loader_diagnostics={},total_function_count=4,
        total_node_count=len(nodes),total_edge_count=len(edges),function_bindings=bindings,nodes=nodes,edges=edges,
        function_edges=[FunctionEdge(edge_id=f'fc-{a:x}-{b:x}',source_address=a,target_address=b) for a,b in [(0x100,0x400),(0x400,0x200)]],transfer_comparisons=[])


@pytest.mark.parametrize('jump,kind',[('Ijk_Call','call'),('Ijk_Boring','branch'),('Ijk_Ret','return'),
    ('Ijk_FakeRet','fakeret'),('Ijk_Sys_syscall','syscall'),('Ijk_NoDecode','unknown')])
def test_jump_normalization(jump,kind):assert normalize_jumpkind(jump)==kind


def test_verified_thumb_mapping_and_binding():
    adapter=ThumbAddressAdapter('ARMCortexM',[(0x100,0x400)],[(0x100,0x101,True),(0x200,0x201,True),(0x300,0x301,True)])
    assert adapter.canonical(0x101)==0x100 and adapter.canonical(0x200001)==0x200001
    selected=[NS(function_id=f'f{x:x}',entry_address=x) for x in (0x100,0x200,0x300)]
    bindings=bind_functions(selected,[0x101,0x300,0x301],adapter)
    assert [b.binding_status for b in bindings]==['exact','missing','conflict']
    with pytest.raises(ValueError):ThumbAddressAdapter('ARMEL',[(0x100,0x400)],[(0x100,0x101,True)]*3)
    with pytest.raises(ValueError):ThumbAddressAdapter('ARMCortexM',[(0x100,0x400)],[(0x100,0x100,False)]*3)


def test_sorted_bfs_cutoff_and_cycle():
    graph={1:[(3,'13'),(2,'12')],2:[(1,'21'),(4,'24')],3:[(4,'34')]}
    assert bounded_bfs(graph,1,{4},2)==([1,2,4],['12','24'])
    assert bounded_bfs(graph,1,{4},1)==([],[])
    graph[1].reverse()
    assert bounded_bfs(graph,1,{4},2)==([1,2,4],['12','24'])


def test_function_intermediate_and_site_fakeret(cfg):
    result=build_static_reachability(cfg,[('entry',0x100,'mmio','f100'),('before',0x104,'transfer','f100'),
        ('after',0x108,'mmio','f100'),('missing',0x110,'mmio',None),('absent',0x120,'mmio','f100')])
    f=next(f for f in result.function_reachability if (f.source_function_id,f.target_function_id)==('f100','f200'))
    assert f.witness_function_addresses==[0x100,0x400,0x200] and f.path_edge_count==2
    assert len(result.function_reachability)==6
    assert any(f.status=='not_found_within_bound' and 'not_negative_proof' in f.limitations for f in result.function_reachability)
    sites={s.site_id:s for s in result.site_reachability}
    assert sites['before'].status=='reachable_static_no_fakeret'
    assert sites['after'].status=='reachable_static_with_fakeret' and sites['after'].uses_fakeret
    assert 'assumes_callee_returns' in sites['after'].limitations
    assert sites['missing'].status=='owner_mapping_missing' and sites['absent'].status=='not_found_in_cfg'
    for f in [*result.function_reachability,*result.site_reachability]:
        assert not any(v for k,v in f.capabilities.model_dump().items() if k!='supports_static_reachability')


def test_mapping_missing(cfg):
    cfg.function_bindings[0]=StaticFunctionBinding(function_id='f100',expected_entry_address=0x100,
        angr_raw_address=None,angr_canonical_address=None,binding_status='missing')
    r=build_static_reachability(cfg,[('site',0x104,'mmio','f100')])
    assert sum(f.status=='source_mapping_missing' for f in r.function_reachability)==2
    assert sum(f.status=='target_mapping_missing' for f in r.function_reachability)==2
    assert r.site_reachability[0].status=='source_mapping_missing'


def test_codec_order_and_witness_corruption(cfg):
    r=build_static_reachability(cfg,[('site',0x108,'mmio','f100')])
    wire=serialize_firmware_static_reachability(r);cg=serialize_firmware_angr_cfg(cfg)
    assert serialize_firmware_static_reachability(parse_firmware_static_reachability(wire,cfg=cfg))==wire
    assert serialize_firmware_angr_cfg(parse_firmware_angr_cfg(cg))==cg
    cfg.nodes.reverse();cfg.edges.reverse();cfg.function_bindings.reverse()
    r.function_reachability.reverse()
    assert serialize_firmware_angr_cfg(cfg)==cg and serialize_firmware_static_reachability(r)==wire
    value=json.loads(wire);value['site_reachability'][0]['witness_edge_ids'][0]='unknown'
    with pytest.raises(ValueError):parse_firmware_static_reachability(json.dumps(value),cfg=cfg)
    value=json.loads(wire);value['site_reachability'][0]['uses_fakeret']=False
    with pytest.raises(ValueError):parse_firmware_static_reachability(json.dumps(value),cfg=cfg)


@pytest.mark.parametrize('kind,status,target,expected',[
    ('direct_call','confirmed_static',0x200,'agree'),('direct_call','confirmed_static',0x300,'disagree'),
    ('direct_branch','confirmed_static',0x200,'disagree'),('control_transfer_unresolved','unresolved',0x200,'disagree')])
def test_comparison_preserves_a4(cfg,kind,status,target,expected):
    r=NS(relation_id='call-site',site_address=0x104,kind=kind,status=status,target=NS(address=target))
    result=compare_transfers(NS(relations=[r]),cfg.nodes,cfg.edges,[(0x100,0x500)])[0]
    assert result.comparison_status==expected and r.kind==kind and r.status==status
    assert result.angr_jumpkinds==['Ijk_Call']  # FakeRet explicitly excluded from transfer target evidence


def test_unknown_indirect_and_unmapped(cfg):
    r=NS(relation_id='call-site',site_address=0x104,kind='control_transfer_unresolved',status='unresolved',target=None)
    assert compare_transfers(NS(relations=[r]),cfg.nodes,[],[(0x100,0x500)])[0].comparison_status=='angr_unresolved'
    r.site_address=0x999
    assert compare_transfers(NS(relations=[r]),cfg.nodes,[],[(0x100,0x500)])[0].comparison_status=='site_not_mapped'


def test_no_unreachable_or_runtime_claim(cfg):
    r=build_static_reachability(cfg,[]).model_dump()
    r['function_reachability'][0]['status']='unreachable'
    with pytest.raises(ValidationError):FirmwareStaticReachabilityCatalog.model_validate(r)
    r=build_static_reachability(cfg,[]).model_dump();r['function_reachability'][0]['capabilities']['supports_runtime_reachability']=True
    with pytest.raises(ValidationError):FirmwareStaticReachabilityCatalog.model_validate(r)


def test_function_depth_sixteen_cutoff(cfg):
    cfg.function_edges=[FunctionEdge(edge_id=f'd{i}',source_address=0x100+i,target_address=0x101+i) for i in range(16)]
    cfg.function_edges.append(FunctionEdge(edge_id='last',source_address=0x110,target_address=0x200))
    r=build_static_reachability(cfg,[])
    assert next(f for f in r.function_reachability if (f.source_function_id,f.target_function_id)==('f100','f200')).status=='not_found_within_bound'


def test_missing_owner_is_not_inferred_from_angr(cfg):
    r=build_static_reachability(cfg,[('missing-owner',0x104,'mmio',None)])
    s=r.site_reachability[0]
    assert s.angr_owner_addresses==[0x100] and s.owner_function_id is None
    assert s.status=='owner_mapping_missing'


def test_real_constructor_returns_canonical_site_order(cfg):
    r=build_static_reachability(cfg,[('z',0x200,'mmio','f200'),('a',0x100,'mmio','f100')])
    assert parse_firmware_static_reachability(serialize_firmware_static_reachability(r),cfg=cfg)==r


def test_cfg_edges_require_exact_addresses_and_kind(cfg):
    value=cfg.model_dump();value['edges'][0]['edge_kind']='call'
    with pytest.raises(ValueError):FirmwareAngrCFGResult.model_validate(value)
    value=cfg.model_dump();value['edges'][0]['source_address']=999
    with pytest.raises(ValueError):FirmwareAngrCFGResult.model_validate(value)


@pytest.mark.parametrize('defect',['case','elf_hash','elf_size','a2','a3'])
def test_input_identity_mismatch(tmp_path,defect):
    from tests.test_static_relations import canonical,build
    from chipchain.tools.firmware.angr_cfg import validate_inputs
    from pathlib import Path
    data=canonical(tmp_path/'inputs');inputs,source,_,relevant,_=data;a4=build(data)
    path=Path(inputs.case.firmware_artifacts[0].path)
    validate_inputs(inputs,source,relevant,a4,path)
    if defect=='case':relevant.case_id='different'
    elif defect=='elf_hash':a4.source_identities.elf_sha256='0'*64
    elif defect=='elf_size':a4.source_identities.elf_size_bytes+=1
    elif defect=='a2':a4.source_identities.a2_sha256='0'*64
    else:a4.source_identities.a3_sha256='0'*64
    with pytest.raises(ValueError):validate_inputs(inputs,source,relevant,a4,path)


def test_explicit_timeout_and_worker_failure(tmp_path,monkeypatch):
    from tests.test_static_relations import canonical,build
    from chipchain.tools.firmware import angr_cfg
    from pathlib import Path
    data=canonical(tmp_path/'inputs');inputs,source,_,relevant,_=data;a4=build(data)
    path=Path(inputs.case.firmware_artifacts[0].path)
    with pytest.raises(ValueError):angr_cfg.recover_firmware_angr_cfg(inputs,source,relevant,a4,elf_path=path,timeout=121)
    def timed_out(argv,**kwargs):
        assert kwargs['timeout']==60 and kwargs['shell'] is False
        raise angr_cfg.subprocess.TimeoutExpired(argv,60)
    monkeypatch.setattr(angr_cfg.subprocess,'run',timed_out)
    with pytest.raises(angr_cfg.subprocess.TimeoutExpired):
        angr_cfg.recover_firmware_angr_cfg(inputs,source,relevant,a4,elf_path=path)
