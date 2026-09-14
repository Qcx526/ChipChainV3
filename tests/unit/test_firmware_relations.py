"""B3 lossless wire, fake-provider support gates, and safe persistence."""
import hashlib
import json

import pytest
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_deepseek import ChatDeepSeek

from chipchain.agents.firmware import FirmwareSecurityAgent
from chipchain.agents.model_outputs.firmware_v2 import ModelFirmwareAnalysisReportV2
from chipchain.agents.projections.firmware import build_firmware_analysis_projection
from chipchain.agents.projections.firmware_relations import (
    build_firmware_relation_projection, serialize_firmware_relation_projection,
    parse_firmware_relation_projection, firmware_relation_projection_sha256, projection_registry,
)
from chipchain.agents.projections.firmware_envelope_v3 import (
    build_firmware_envelope_v3, serialize_firmware_envelope_v3, parse_firmware_envelope_v3,
    envelope_v3_metadata,
)
from chipchain.agents.relation_support import validate_support_artifact
from chipchain.agents.runtime import AgentExecutionError, AgentStructuredOutputError
from chipchain.agents.firmware_evidence import collect_firmware_reasoning_evidence
from chipchain.integrations import deepseek_firmware as real
from chipchain.execution.reviewed_output import _validate, export_reviewed_output
from tests.test_static_relations import canonical, build
from tests.fakes import fake_model
from tests.unit.test_deepseek_firmware import config


@pytest.fixture
def components(tmp_path):
    data = canonical(tmp_path/'inputs')
    catalog = build(data)
    projection = build_firmware_relation_projection(data[0],data[3],catalog)
    return data,catalog,projection


def fact_claim(r, sid='support-1'):
    d = r.attributes
    return dict(support_claim_id=sid,claim_type='relation_fact',relation_id=r.relation_id,
        expected_kind=r.kind.value,expected_status=r.status.value,expected_source_entity_id=r.source.entity_id,
        expected_target_entity_id=r.target.entity_id if r.target else None,
        expected_direction=getattr(d,'direction',None),expected_transfer_kind=getattr(d,'transfer_kind',None),
        expected_vector_index=getattr(d,'vector_index',None),expected_binding_status=getattr(d,'binding_status',None))


def payload_for(components, rid='edge-80000'):
    data,catalog,_ = components
    r = next(r for r in catalog.relations if r.relation_id==rid)
    return dict(case_id=data[0].case.case_id,
        findings=[dict(finding_id='finding-1',summary='A supplied static relation, with no runtime proof.',
            evidence_ids=r.evidence_ids,processor_behavior_ids=[],epistemic_status='derived',support_claim_ids=['support-1'])],
        support_claims=[fact_claim(r)])


def invoke(components,payload):
    data,catalog,projection = components
    model = fake_model(ModelFirmwareAnalysisReportV2,payload)
    agent = FirmwareSecurityAgent(model=model)
    output,audit = agent.invoke_supported(data[0],static_relation_catalog=catalog,
        relation_projection=projection,relevant_static_structure=data[3])
    return output,audit,model


def test_projection_lossless_exact_union(components):
    data,catalog,p = components
    base = build_firmware_analysis_projection(data[0])
    text = serialize_firmware_relation_projection(p)
    restored = parse_firmware_relation_projection(text,base=base)
    assert restored.catalog == catalog
    assert serialize_firmware_relation_projection(restored)==text
    assert firmware_relation_projection_sha256(p)==hashlib.sha256(text.encode()).hexdigest()
    assert projection_registry(p,base)==collect_firmware_reasoning_evidence(data[0],data[3])
    assert {r.evidence_id for r in p.evidence_delta}.isdisjoint({r.evidence_id for r in base.evidence_catalog})
    assert len(p.catalog.relations)==len(catalog.relations)
    assert text==serialize_firmware_relation_projection(build_firmware_relation_projection(data[0],data[3],catalog))


def test_envelope_exact_base_and_binding(components):
    from chipchain.agents.context import firmware_context
    data,catalog,p = components
    e=build_firmware_envelope_v3(data[0],p,static_relation_catalog=catalog)
    text=serialize_firmware_envelope_v3(e)
    assert parse_firmware_envelope_v3(text)==e
    assert json.dumps(e.base_firmware_projection,sort_keys=True,separators=(',',':'),ensure_ascii=False)==firmware_context(data[0])
    assert 'relevant_static_structure' not in json.loads(text)


@pytest.mark.parametrize('defect',['hash','kind','evidence_delta','base','labels','oversize','envelope_oversize'])
def test_projection_corruption_and_budget_refused(components,monkeypatch,defect):
    data,catalog,p=components;base=build_firmware_analysis_projection(data[0])
    value=json.loads(serialize_firmware_relation_projection(p))
    if defect=='hash':value['catalog_sha256']='0'*64
    elif defect=='kind':value['catalog']['relations']['direct_branch']['table']['common']['kind']='direct_call'
    elif defect=='evidence_delta':value['evidence_delta']['entries']['rows']=[]
    elif defect=='base':base.case.case_id='other'
    elif defect=='labels':value['function_labels']['rows'].append(value['function_labels']['rows'][0])
    elif defect=='oversize':
        monkeypatch.setattr('chipchain.agents.projections.firmware_relations.MAX_RELATION_CHARS',10)
    else:
        monkeypatch.setattr('chipchain.agents.projections.firmware_envelope_v3.MAX_V3_CHARS',10)
        with pytest.raises(ValueError):build_firmware_envelope_v3(data[0],p,static_relation_catalog=catalog)
        return
    with pytest.raises((ValueError,KeyError)):
        parse_firmware_relation_projection(json.dumps(value,sort_keys=True,separators=(',',':')),base=base)


@pytest.mark.parametrize('rid',['edge-80000','call-80004','mmio-direction-80002','vector-1','mmio-containment-80002'])
def test_valid_fact_fake_model(components,rid):
    output,audit,model=invoke(components,payload_for(components,rid))
    assert audit.support_claims[0].result=='supported'
    assert len(model.seen_messages)==1
    assert 'support_claim_ids' not in output.report.model_dump_json()
    assert output.processor_behavior_ir==FirmwareSecurityAgent().invoke(components[0][0]).processor_behavior_ir
    assert json.loads(model.seen_messages[0][1].content)['envelope_version']=='firmware-analysis-envelope/v3'
    assert 'Typed relations are authoritative' in model.seen_messages[0][0].content
    validate_support_artifact(audit,output.report,components[1])


@pytest.mark.parametrize('missing',[False,True])
def test_valid_unresolved_and_missing_facts(tmp_path,missing):
    data=canonical(tmp_path/'inputs',missing=missing,reason='computed_or_ambiguous')
    catalog=build(data);p=build_firmware_relation_projection(data[0],data[3],catalog)
    c=(data,catalog,p)
    _,audit,_=invoke(c,payload_for(c,'mmio-containment-80002' if missing else 'call-80004'))
    assert audit.support_claims[0].reason_code=='exact_relation_fact'


def test_valid_explicit_path(components):
    p=payload_for(components)
    p['support_claims']=[dict(support_claim_id='support-1',claim_type='static_call_path',
        source_function_id='f80008',target_function_id='f80010',edge_relation_ids=['edge-80008','edge-80000'])]
    _,audit,_=invoke(components,p)
    assert audit.support_claims[0].reason_code=='exact_static_call_path'


@pytest.mark.parametrize('defect',['branch_call','read_write','vector_call','unknown_relation','endpoint','status',
    'direction_missing','transfer_missing','vector_index','trigger_to_handler','physical_input_path','runtime_reachability',
    'broken_path','unknown_support','unused','duplicate','missing_support','evidence','ir'])
def test_fake_model_rejects_invalid_support(components,defect):
    rid={'branch_call':'call-80004','read_write':'mmio-direction-80002','vector_call':'vector-1',
         'direction_missing':'mmio-direction-80002','vector_index':'vector-1'}.get(defect,'edge-80000')
    p=payload_for(components,rid);claim=p['support_claims'][0]
    if defect in ('branch_call','vector_call'):claim.update(expected_kind='direct_call',expected_transfer_kind='direct_call')
    elif defect=='read_write':claim['expected_direction']='write'
    elif defect=='unknown_relation':claim['relation_id']='invented'
    elif defect=='endpoint':claim['expected_target_entity_id']='f80008'
    elif defect=='status':claim['expected_status']='unresolved'
    elif defect=='direction_missing':claim['expected_direction']=None
    elif defect=='transfer_missing':claim['expected_transfer_kind']=None
    elif defect=='vector_index':claim['expected_vector_index']=99
    elif defect in ('trigger_to_handler','physical_input_path','runtime_reachability'):
        p['support_claims']=[dict(support_claim_id='support-1',claim_type=defect,source_entity_id='f80008',
            target_entity_id='f80010',relation_ids=['edge-80008','edge-80000'])]
    elif defect=='broken_path':
        p['support_claims']=[dict(support_claim_id='support-1',claim_type='static_call_path',source_function_id='f80008',
            target_function_id='f80010',edge_relation_ids=['edge-80000','edge-80008'])]
    elif defect=='unknown_support':p['findings'][0]['support_claim_ids']=['invented']
    elif defect=='unused':p['findings']=[]
    elif defect=='duplicate':p['support_claims'].append(dict(claim))
    elif defect=='missing_support':p['findings'][0]['support_claim_ids']=[]
    elif defect=='evidence':p['findings'][0]['evidence_ids']=['invented']
    elif defect=='ir':p['findings'][0]['processor_behavior_ids']=['invented']
    with pytest.raises(AgentStructuredOutputError):invoke(components,p)


def test_shared_support_all_four_collections_and_no_prose_parsing(components):
    p=payload_for(components);base=p['findings'][0]
    bid=components[0][0].deterministic_observations.observations[0].behaviors[0].behavior_id
    p['external_input_paths']=[dict(path_id='path-1',entry_point='static label',summary='Static only',
        evidence_ids=base['evidence_ids'],support_claim_ids=['support-1'])]
    p['reachable_behaviors']=[dict(reachability_id='reach-1',processor_behavior_id=bid,
        evidence_ids=base['evidence_ids'],support_claim_ids=['support-1'],reachability_kind='unknown')]
    p['issue_anchors']=[dict(anchor_id='anchor-1',summary='Static anchor',firmware_finding_ids=['finding-1'],
        evidence_ids=base['evidence_ids'],support_claim_ids=['support-1'])]
    p['findings'][0]['summary']='Unsupported prose about runtime and physical input is not parsed by the support gate.'
    output,audit,_=invoke(components,p)
    assert len(audit.support_claims[0].referencing_firmware_claims)==4
    assert output.report.findings[0].summary==p['findings'][0]['summary']


def patch_run(components,monkeypatch,payload,*,transport=False):
    data,catalog,projection=components
    e=build_firmware_envelope_v3(data[0],projection,static_relation_catalog=catalog)
    text=serialize_firmware_envelope_v3(e)
    monkeypatch.setattr(real,'prepare_firmware_input',lambda _:data[0])
    monkeypatch.setattr(real,'validate_firmware_baseline',lambda *a:None)
    monkeypatch.setattr(real,'prepare_relation_context',lambda *a:(data[3],data[1],catalog,projection,text,envelope_v3_metadata(e)))
    seen=[]
    def generate(self,messages,**kwargs):
        seen.append(messages)
        if transport:raise RuntimeError('RAW PROVIDER BODY')
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content='RAW PROVIDER BODY',
            tool_calls=[dict(name='ModelFirmwareAnalysisReportV2',args=payload,id='synthetic')],
            usage_metadata=dict(input_tokens=10,output_tokens=20,total_tokens=30)))])
    monkeypatch.setattr(ChatDeepSeek,'_generate',generate)
    return seen,text


@pytest.fixture
def persisted(components,config,monkeypatch,tmp_path):
    seen,text=patch_run(components,monkeypatch,payload_for(components))
    path=real.run_real_firmware(tmp_path,config=config,enabled=True,output_root=tmp_path/'output',
        context_mode='relation_v3',ghidra_home=tmp_path/'explicit')
    assert len(seen)==1 and seen[0][1].content==text
    return path


def test_persistence_and_exporter_revalidation(persisted,config,tmp_path):
    files={p.name:p.read_bytes() for p in persisted.iterdir()}
    assert set(files)=={'analysis_run.json','firmware_analysis_report.json','firmware_relation_support.json',
                       'analysis_input.json','invocation.json','invocation_attempts.jsonl'}
    _,inv,_=_validate(files,config.api_key.get_secret_value())
    assert inv.prompt_version=='v2' and inv.model_output_schema=='ModelFirmwareAnalysisReportV2'
    assert inv.structured_support_claim_count==inv.supported_support_claim_count==1
    assert all(b'RAW PROVIDER BODY' not in content for content in files.values())
    dest=export_reviewed_output(persisted,phase='synthetic-b3',accepted=True,reviewed_root=tmp_path/'reviewed')
    assert all((dest/name).read_bytes()==content for name,content in files.items())


@pytest.mark.parametrize('defect',['support_status','support_kind','support_reference','support_missing','support_raw','projection_hash','catalog_hash','count','report_evidence'])
def test_exporter_refuses_corruption(persisted,config,defect):
    files={p.name:p.read_bytes() for p in persisted.iterdir()}
    def edit(name,fn):
        d=json.loads(files[name]);fn(d);files[name]=json.dumps(d).encode()
    if defect=='support_status':edit('firmware_relation_support.json',lambda d:d['support_claims'][0].update(result='unsupported'))
    elif defect=='support_kind':edit('firmware_relation_support.json',lambda d:d['support_claims'][0]['support_claim'].update(expected_kind='direct_branch'))
    elif defect=='support_reference':edit('firmware_relation_support.json',lambda d:d['support_claims'][0]['referencing_firmware_claims'][0].update(claim_id='invented'))
    elif defect=='support_missing':files.pop('firmware_relation_support.json')
    elif defect=='support_raw':edit('firmware_relation_support.json',lambda d:d.update(raw_response='BODY'))
    elif defect=='projection_hash':edit('invocation.json',lambda d:d.update(relation_projection_sha256='0'*64))
    elif defect=='catalog_hash':edit('invocation.json',lambda d:d.update(a4_catalog_sha256='0'*64))
    elif defect=='count':edit('invocation.json',lambda d:d.update(supported_support_claim_count=9))
    else:
        def change(d):d['findings'][0]['evidence'][0]['summary']='rewritten'
        edit('firmware_analysis_report.json',change);edit('analysis_run.json',lambda d:change(d['firmware_report']))
    with pytest.raises((ValueError,KeyError,AgentStructuredOutputError)):_validate(files,config.api_key.get_secret_value())


@pytest.mark.parametrize('failure',['support','transport'])
def test_failed_run_is_safe_and_single_call(components,config,monkeypatch,tmp_path,failure):
    p=payload_for(components);p['support_claims'][0]['expected_kind']='direct_branch'
    seen,_=patch_run(components,monkeypatch,p,transport=failure=='transport')
    root=tmp_path/'output'
    with pytest.raises(AgentExecutionError):real.run_real_firmware(tmp_path,config=config,enabled=True,
        output_root=root,context_mode='relation_v3',ghidra_home=tmp_path/'explicit')
    assert len(seen)==1
    directory=next(root.glob('*/*'))
    assert {p.name for p in directory.iterdir()}=={'failure.json','invocation_attempts.jsonl'}
    detail=json.loads((directory/'failure.json').read_text())
    if failure=='support':assert detail['failure_category']=='relation_support_validation'
    assert 'RAW PROVIDER BODY' not in (directory/'failure.json').read_text()


def test_preflight_rejects_synthetic_catalog(components):
    from chipchain.integrations.firmware_relations import validate_relation_baseline
    with pytest.raises(AgentExecutionError,match='baseline'):
        validate_relation_baseline(components[1])


def test_every_referenced_support_must_pass(components):
    p=payload_for(components)
    bad=dict(p['support_claims'][0],support_claim_id='bad',expected_status='unresolved')
    p['support_claims'].append(bad)
    p['findings'][0]['support_claim_ids'].append('bad')
    with pytest.raises(AgentStructuredOutputError):invoke(components,p)


def test_explicit_model_required_and_legacy_reusable(components):
    from chipchain.agents.model_outputs.firmware import ModelFirmwareAnalysisReport
    data,catalog,projection=components
    with pytest.raises(ValueError,match='explicit model'):
        FirmwareSecurityAgent().invoke_supported(data[0],static_relation_catalog=catalog,
            relation_projection=projection,relevant_static_structure=data[3])
    model=fake_model(ModelFirmwareAnalysisReport,{'case_id':data[0].case.case_id})
    agent=FirmwareSecurityAgent(model=model)
    agent.invoke(data[0]);agent.invoke(data[0],relevant_static_structure=data[3],static_source=data[1])
    assert len(model.seen_messages)==2
    assert 'envelope_version' not in json.loads(model.seen_messages[0][1].content)
    assert json.loads(model.seen_messages[1][1].content)['envelope_version']=='firmware-analysis-envelope/v2'


def test_wrong_canonical_elf_refuses_before_model(components):
    data,catalog,p=components
    data[0].case.firmware_artifacts[0].sha256='0'*64
    with pytest.raises(ValueError,match='ELF fingerprint'):
        build_firmware_envelope_v3(data[0],p,static_relation_catalog=catalog)
