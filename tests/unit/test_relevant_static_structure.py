"""A3 complete relevance selection and reversible compact serialization, all offline."""
import hashlib
import json
import random

import pytest

from chipchain.agents.firmware_evidence import collect_firmware_evidence
from chipchain.tools.firmware.ghidra.associations import associate_mmio
from chipchain.tools.firmware.structure_projection import (
    StructureProjectionError, build_relevant_static_structure, parse_relevant_static_structure,
    relevant_structure_sha256, serialize_relevant_static_structure,
)
from tests.firmware_fakes import BASE
from tests.structure_projection_fakes import projection_inputs


@pytest.fixture
def source(tmp_path):
    return projection_inputs(tmp_path)


def test_seed_union_dedup_overlap(source):
    r=build_relevant_static_structure(*source)
    seeds={f.function_id:f.seed_reasons for f in r.functions if f.seed_reasons}
    assert seeds=={f'f{BASE:x}':['mmio_site','vector_handler'],f'f{BASE+32:x}':['vector_handler']}
    assert len(r.mmio_sites)==1 and len(r.mmio_sites[0].mmio_behavior_ids)==5


def test_complete_one_hop_callers_callees_no_two_hop(source):
    r=build_relevant_static_structure(*source)
    assert {f.function_id for f in r.functions}=={f'f{BASE+i:x}' for i in (0,8,16,32)}
    assert {e.call_site_address for e in r.direct_call_edges}=={BASE,BASE+8}
    assert {f.function_id for f in r.functions if f.role=='one_hop_neighbor'}=={f'f{BASE+8:x}',f'f{BASE+16:x}'}
    seed=next(n for n in r.seed_neighborhoods if n.function_id==f'f{BASE:x}')
    assert (seed.incoming_edge_count,seed.outgoing_edge_count,seed.unresolved_outgoing_count)==(1,1,1)


def test_only_confirmed_edges_and_caller_seed_unresolved_policy(source):
    r=build_relevant_static_structure(*source)
    assert len(r.unresolved_call_sites)==1
    u=r.unresolved_call_sites[0]
    assert u.call_site_address==BASE+2 and u.reason=='decoder_disagreement' and u.target_address==BASE+40
    assert not any(f.entry_address==BASE+40 for f in r.functions)
    # Target-only and unrelated unresolved sites do not satisfy the frozen v1 policy.
    assert not {BASE+18,BASE+42}&{c.call_site_address for c in r.unresolved_call_sites}


def test_missing_mmio_site_preserved(source):
    i,s,v=source
    # Shrink the existing seed body; the site falls outside it, keep the A1 fact.
    s.functions[0].ranges[0].end=BASE+2
    s.functions[0].size_bytes=2
    r=build_relevant_static_structure(i,s,v)
    assert r.mmio_sites[0].function_id is None
    assert r.mmio_sites[0].containment_status=='missing'
    assert next(c for c in r.unresolved_constraints if c.constraint_id=='missing_mmio_containment').pcs==[BASE+2]


@pytest.mark.parametrize('direction',['read','write','unknown'])
def test_direction_is_copied_from_a1_only(source,direction):
    for o in source[0].deterministic_observations.observations:
        if o.kind=='mmio_model':
            for b in o.behaviors:b.attributes['direction']=direction
    assert build_relevant_static_structure(*source).mmio_sites[0].direction==direction


def test_conflicting_direction_fails(source):
    observation=next(o for o in source[0].deterministic_observations.observations if o.kind=='mmio_model')
    observation.behaviors[0].attributes['direction']='write'
    with pytest.raises(StructureProjectionError,match='directions'):build_relevant_static_structure(*source)


def test_vector_grouping_shared_aliases_all_dispatches(source):
    r=build_relevant_static_structure(*source)
    assert len(r.vector_handler_groups)==2
    assert {index:g.handler_address for g in r.vector_handler_groups for index in g.vector_indices}=={1:BASE,2:BASE+32,3:BASE+32}
    shared=r.vector_handler_groups[1]
    assert shared.shared_handler and shared.symbol_names==['ADC_Handler','Default_Handler']
    assert shared.core_exception_names==['HardFault','NMI']


def test_no_interface_or_runtime_claims(source):
    r=build_relevant_static_structure(*source)
    assert r.functions[0].name=='UARTClass::write'
    constraints={c.constraint_id:c for c in r.unresolved_constraints}
    assert constraints['trigger_handler_relation'].status=='missing_relation'
    assert constraints['opaque_input_relation'].status=='missing_relation'
    assert constraints['symbol_semantics'].status=='not_established'
    fields=set(r.model_dump())
    assert not fields & {'behaviors','reachable_behaviors','findings','external_input_paths','issue_anchors'}
    for function in r.functions:
        assert not {'physical_interface','peripheral','input_source','ranges'} & set(function.model_dump())


def test_evidence_exactness_including_reversible_wire(source):
    i,s,v=source;r=build_relevant_static_structure(*source)
    original=collect_firmware_evidence(i)
    for fact in [*s.direct_call_edges,*s.unresolved_call_sites,*v.bindings,*associate_mmio(s,i.deterministic_observations).bindings]:
        for ref in fact.evidence:original[ref.evidence_id]=ref
    assert all(original[ref.evidence_id]==ref for ref in r.evidence_catalog)
    assert len({ref.evidence_id for ref in r.evidence_catalog})==len(r.evidence_catalog)
    restored=parse_relevant_static_structure(serialize_relevant_static_structure(r))
    assert restored==r
    assert [ref.model_dump() for ref in restored.evidence_catalog]==[ref.model_dump() for ref in r.evidence_catalog]


@pytest.mark.parametrize('selected',[True,False])
def test_a1_a2_id_collision_even_if_unselected(source,selected):
    i,s,v=source
    existing=next(iter(collect_firmware_evidence(i).values()))
    target=s.direct_call_edges[0 if selected else -1]
    target.evidence=[existing.model_copy(update={'summary':'conflicting exact object'})]
    with pytest.raises(StructureProjectionError,match='evidence identity'):build_relevant_static_structure(i,s,v)


def test_equal_id_equal_object_deduplicates(source):
    i,s,v=source
    ref=next(iter(collect_firmware_evidence(i).values()))
    s.direct_call_edges[0].evidence=[ref,ref]
    r=build_relevant_static_structure(i,s,v)
    assert len([e for e in r.evidence_catalog if e.evidence_id==ref.evidence_id])==1


def test_source_inputs_unchanged_and_order_independent(source):
    before=[x.model_dump_json() for x in source]
    r=build_relevant_static_structure(*source)
    assert [x.model_dump_json() for x in source]==before
    expected=serialize_relevant_static_structure(r)
    i,s,v=[x.model_copy(deep=True) for x in source]
    for items in (i.deterministic_observations.observations,s.functions,s.direct_call_edges,s.unresolved_call_sites,v.bindings):
        random.Random(73).shuffle(items)
    assert serialize_relevant_static_structure(build_relevant_static_structure(i,s,v))==expected
    assert relevant_structure_sha256(r)==hashlib.sha256(expected.encode('utf-8')).hexdigest()
    assert relevant_structure_sha256(build_relevant_static_structure(*source))==relevant_structure_sha256(r)
    assert [f.entry_address for f in r.functions]==sorted(f.entry_address for f in r.functions)
    assert [e.evidence_id for e in r.evidence_catalog]==sorted(e.evidence_id for e in r.evidence_catalog)


def test_hard_size_cap_no_truncation(source,monkeypatch):
    import chipchain.tools.firmware.structure_projection as module
    r=build_relevant_static_structure(*source);before=r.model_dump_json()
    monkeypatch.setattr(module,'MAX_STRUCTURE_CHARS',100)
    with pytest.raises(StructureProjectionError,match='exceeds 18000'):serialize_relevant_static_structure(r)
    with pytest.raises(StructureProjectionError,match='exceeds 18000'):build_relevant_static_structure(*source)
    assert r.model_dump_json()==before


@pytest.mark.parametrize('problem',['case','artifact','vector_entry','vector_duplicate','vector_unbounded'])
def test_source_conflicts_rejected(source,problem):
    i,s,v=source
    if problem=='case':s.case_id='other'
    if problem=='artifact':s.program.sha256='0'*64
    if problem=='vector_entry':v.bindings[1].function_id=f'f{BASE+8:x}'
    if problem=='vector_duplicate':v.bindings.append(v.bindings[1])
    if problem=='vector_unbounded':v.status='unresolved'
    with pytest.raises(StructureProjectionError):build_relevant_static_structure(i,s,v)


@pytest.mark.parametrize('problem',['wire','duplicate_column','row_size','dictionary','profile','evidence_ref'])
def test_wire_corruption_rejected(source,problem):
    wire=json.loads(serialize_relevant_static_structure(build_relevant_static_structure(*source)))
    if problem=='wire':wire['wire_format']='other'
    if problem=='duplicate_column':wire['functions']['columns'].append(wire['functions']['columns'][0])
    if problem=='row_size':wire['functions']['rows'][0].append(None)
    if problem=='dictionary':
        wire['functions'].setdefault('dictionaries',{})['entry_address']=[1]
    if problem=='profile':wire['evidence_catalog']['profiles']['rows']=[]
    if problem=='evidence_ref':wire['evidence_catalog']['entries']['rows']=[]
    with pytest.raises(StructureProjectionError):parse_relevant_static_structure(json.dumps(wire,separators=(',',':'),sort_keys=True))


def test_duplicate_json_keys_rejected():
    with pytest.raises(StructureProjectionError,match='Duplicate'):parse_relevant_static_structure('{"x":1,"x":2}')


def test_23_synthetic_pc_records_complete(tmp_path):
    import yaml
    from chipchain.tools.firmware.fuzzware import FuzzwareHeatPressScenarioAnalyzer
    from chipchain.agents.contracts import FirmwareAgentInput
    from tests.firmware_fakes import make_case, reference
    _,structure,vectors=projection_inputs(tmp_path/'graph')
    case=make_case(tmp_path/'23-sites',code=bytes.fromhex('9969')*23,pc=BASE)
    config_path=tmp_path/'23-sites/config.yml'
    config=yaml.safe_load(config_path.read_text())
    config['mmio_models']={'constant':{f'site-{n}':dict(pc=BASE+n*2,addr=0x40000018,access_size=4,val=0) for n in range(23)}}
    config_path.write_text(yaml.safe_dump(config))
    case.firmware_artifacts=[reference(config_path,'firmware_config','yaml') if ref.format=='yaml' else ref for ref in case.firmware_artifacts]
    batch=FuzzwareHeatPressScenarioAnalyzer().analyze(case_id=case.case_id,target=case.target,artifacts=case.firmware_artifacts)
    elf=case.firmware_artifacts[0]
    structure.program=structure.program.model_copy(update={'sha256':elf.sha256,'size_bytes':elf.size_bytes})
    r=build_relevant_static_structure(FirmwareAgentInput(case=case,deterministic_observations=batch),structure,vectors)
    assert [s.pc for s in r.mmio_sites]==[BASE+n*2 for n in range(23)]
    assert all(s.direction=='read' for s in r.mmio_sites)


def test_external_vector_indices_and_null_summary(source):
    i,s,v=source
    from chipchain.tools.firmware.ghidra.normalize import evidence
    for index in range(4,17):
        b=v.bindings[2].model_copy(deep=True)
        b.vector_index=index;b.exception_number=index;b.core_exception_name=None
        b.external_irq_number=0 if index==16 else None
        b.evidence=[evidence(f'vector-{index}',BASE+4*index,'Synthetic vector')]
        if index!=16:
            b.binding_status='null_entry';b.raw_handler_value=0;b.canonical_handler_address=None
            b.function_id=None;b.symbol_names=[]
        v.bindings.append(b)
    v.extent.end=BASE+17*4
    r=build_relevant_static_structure(i,s,v)
    assert r.null_vector_indices==list(range(4,16))
    group=next(g for g in r.vector_handler_groups if g.handler_address==BASE+32)
    assert group.vector_indices==[2,3,16] and group.external_irq_numbers==[0]
