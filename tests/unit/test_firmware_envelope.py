"""Synthetic envelope, exact union, explicit agent path and persistence regression."""
import hashlib
import json
from pathlib import Path

import pytest

from chipchain.agents.context import MAX_CONTEXT_ITEMS, MAX_CONTEXT_CHARS, firmware_context
from chipchain.agents.firmware import FirmwareSecurityAgent, validate_firmware_evidence
from chipchain.agents.firmware_evidence import collect_firmware_evidence, collect_firmware_reasoning_evidence
from chipchain.agents.model_outputs.firmware import ModelFirmwareAnalysisReport
from chipchain.agents.projections.firmware_envelope import (
    build_firmware_envelope, serialize_firmware_envelope, parse_firmware_envelope,
    envelope_components, firmware_envelope_sha256, envelope_metadata, compact,
)
from chipchain.tools.firmware.structure_projection import build_relevant_static_structure, serialize_relevant_static_structure
from chipchain.integrations import deepseek_firmware as real, deepseek
from chipchain.execution.reviewed_output import _validate, export_reviewed_output
from chipchain.agents.runtime import AgentExecutionError, AgentStructuredOutputError
from tests.structure_projection_fakes import projection_inputs
from tests.fakes import fake_model
from tests.firmware_fakes import model_report_fixture
from tests.unit.test_firmware_grounding import report_with_all_objects
from tests.unit.test_deepseek_firmware import config, script_provider


@pytest.fixture
def components(tmp_path):
    i,s,v=projection_inputs(tmp_path/'inputs')
    r=build_relevant_static_structure(i,s,v)
    return i,s,r


def test_envelope_exact_components_determinism_limits(components):
    i,s,r=components;before=[x.model_dump_json() for x in components]
    e=build_firmware_envelope(i,r,s);text=serialize_firmware_envelope(e)
    assert isinstance(json.loads(text)['relevant_static_structure'],dict)
    assert compact(e.firmware_projection)==firmware_context(i)
    assert compact(e.relevant_static_structure)==serialize_relevant_static_structure(r)
    assert parse_firmware_envelope(text)==e
    assert text==serialize_firmware_envelope(build_firmware_envelope(i,r,s))
    assert firmware_envelope_sha256(e)==hashlib.sha256(text.encode()).hexdigest()
    assert MAX_CONTEXT_ITEMS==128 and MAX_CONTEXT_CHARS==64000
    assert [x.model_dump_json() for x in components]==before


@pytest.mark.parametrize('marker',['/home/qcx/private','/tmp/private','04-crash-analysis','crashing_input','README','CVE-123','known root cause','expected crash','exploitability'])
def test_neutrality_rejected(components,marker):
    i,s,r=components;r.functions[0].name=marker
    with pytest.raises(ValueError):build_firmware_envelope(i,r,s)


@pytest.mark.parametrize('limit',[58000,64000])
def test_context_size_refuses_no_truncation(components,monkeypatch,limit):
    import chipchain.agents.projections.firmware_envelope as mod
    e=build_firmware_envelope(components[0],components[2],components[1]);before=e.model_dump_json()
    monkeypatch.setattr(mod,'MAX_ENRICHED_CONTEXT_CHARS' if limit==58000 else 'MAX_CONTEXT_CHARS',100)
    with pytest.raises(ValueError,match='budget'):serialize_firmware_envelope(e)
    assert e.model_dump_json()==before


@pytest.mark.parametrize('defect',['case','elf','source_hash','arbitrary_source'])
def test_identity_before_agent_call(components,defect):
    i,s,r=components
    if defect=='case':r.case_id='other'
    if defect=='elf':i.case.firmware_artifacts[0].sha256='0'*64
    if defect=='source_hash':r.source_structure.structure_sha256='0'*64
    if defect=='arbitrary_source':s={}
    with pytest.raises(ValueError):build_firmware_envelope(i,r,s)


def test_union_equal_shared_and_collision(components):
    i,s,r=components;a1=collect_firmware_evidence(i)
    assert collect_firmware_reasoning_evidence(i)==a1
    union=collect_firmware_reasoning_evidence(i,r)
    a3={e.evidence_id:e for e in r.evidence_catalog}
    assert union==a1|a3
    key=next(iter(a1.keys()&a3.keys()))
    ref=next(e for e in r.evidence_catalog if e.evidence_id==key);ref.summary='altered'
    with pytest.raises(AgentStructuredOutputError,match='Conflicting'):collect_firmware_reasoning_evidence(i,r)


def test_reasoning_safety_bound_independent(components,monkeypatch):
    import chipchain.agents.firmware_evidence as mod
    monkeypatch.setattr(mod,'MAX_REASONING_EVIDENCE',1)
    assert mod.collect_firmware_reasoning_evidence(components[0])==mod.collect_firmware_evidence(components[0])
    with pytest.raises(AgentStructuredOutputError,match='safety limit'):mod.collect_firmware_reasoning_evidence(components[0],components[2])
    assert MAX_CONTEXT_ITEMS==128


@pytest.mark.parametrize('kind',['a1_only','a3_only','shared','unknown'])
def test_model_evidence_hydration_all_classes(components,kind):
    i,s,r=components;a1=collect_firmware_evidence(i);a3={e.evidence_id:e for e in r.evidence_catalog}
    ids={'a1_only':a1.keys()-a3.keys(),'a3_only':a3.keys()-a1.keys(),'shared':a1.keys()&a3.keys()}
    key='invented' if kind=='unknown' else sorted(ids[kind])[0]
    payload=model_report_fixture(report_with_all_objects(i))
    payload.findings[0].evidence_ids=[key]
    model=fake_model(ModelFirmwareAnalysisReport,payload)
    agent=FirmwareSecurityAgent(model=model)
    if kind=='unknown':
        with pytest.raises(AgentStructuredOutputError):agent.invoke(i,relevant_static_structure=r,static_source=s)
        return
    output=agent.invoke(i,relevant_static_structure=r,static_source=s)
    assert output.report.findings[0].evidence==[(a1|a3)[key]]
    assert 'evidence_ids' not in output.report.model_dump_json()
    assert output.processor_behavior_ir==FirmwareSecurityAgent().invoke(i).processor_behavior_ir
    assert json.loads(model.seen_messages[0][1].content)['envelope_version']=='firmware-analysis-envelope/v2'
    validate_firmware_evidence(output.report,i,relevant_static_structure=r)
    real.validate_real_firmware_report(output,i)


def test_v1_agent_context_unchanged_and_a3_static_not_runtime(components):
    i,s,r=components
    payload=model_report_fixture(report_with_all_objects(i))
    model=fake_model(ModelFirmwareAnalysisReport,payload)
    FirmwareSecurityAgent(model=model).invoke(i)
    assert model.seen_messages[0][1].content==firmware_context(i)
    a1=collect_firmware_evidence(i)
    ref=next(e for e in r.evidence_catalog if e.evidence_id not in a1)
    payload.reachable_behaviors[0].evidence_ids=[ref.evidence_id]
    payload.reachable_behaviors[0].reachability_kind='runtime'
    output=FirmwareSecurityAgent(model=fake_model(ModelFirmwareAnalysisReport,payload)).invoke(i,relevant_static_structure=r,static_source=s)
    with pytest.raises(AgentStructuredOutputError,match='Runtime reachability'):real.validate_real_firmware_report(output,i)


@pytest.fixture
def persisted(components,config,tmp_path,monkeypatch):
    i,s,r=components;e=build_firmware_envelope(i,r,s);text=serialize_firmware_envelope(e)
    monkeypatch.setattr(real,'prepare_firmware_input',lambda _:i)
    monkeypatch.setattr(real,'validate_firmware_baseline',lambda *a:None)
    monkeypatch.setattr(real,'prepare_enriched_context',lambda *a:(r,s,text,envelope_metadata(e)))
    report=report_with_all_objects(i)
    a1=collect_firmware_evidence(i)
    report.findings[0].evidence=[next(ref for ref in r.evidence_catalog if ref.evidence_id not in a1)]
    seen=script_provider(monkeypatch,report)
    directory=real.run_real_firmware(tmp_path,config=config,enabled=True,output_root=tmp_path/'runtime',context_mode='enriched_v2',ghidra_home=tmp_path/'explicit')
    assert len(seen)==1 and seen[0][0][1].content==text
    return directory


def blobs(path):return {p.name:p.read_bytes() for p in path.iterdir()}


def test_enriched_persistence_export_and_no_overwrite(persisted,components,config,tmp_path,monkeypatch):
    files=blobs(persisted);run,inv,_=_validate(files,config.api_key.get_secret_value())
    assert files['analysis_input.json'].decode().rstrip('\n')==serialize_firmware_envelope(build_firmware_envelope(components[0],components[2],components[1]))
    assert inv.context_mode=='enriched_v2' and len(run.provenance.tools)==6
    assert all('RAW PROVIDER' not in v.decode() and config.api_key.get_secret_value() not in v.decode() for v in files.values())
    # Synthetic exporter compatibility only; never accepts any real output.
    exported=export_reviewed_output(persisted,phase='synthetic-b2',accepted=True,reviewed_root=tmp_path/'reviewed')
    for name,value in files.items():assert (exported/name).read_bytes()==value
    monkeypatch.setattr(real,'build_deepseek_chat_model',lambda *_:pytest.fail('No second call'))
    with pytest.raises(FileExistsError):real.run_real_firmware(tmp_path,config=config,enabled=True,output_root=persisted.parent.parent,run_id=run.run_id,context_mode='enriched_v2',ghidra_home=tmp_path)


@pytest.mark.parametrize('defect',['component_hash','a3_hash','a3_evidence','report_evidence','ir','raw','secret','elf'])
def test_enriched_persistence_corruption_rejected(persisted,config,defect):
    files=blobs(persisted)
    def edit(name,fn):
        d=json.loads(files[name]);fn(d);files[name]=json.dumps(d).encode()
    if defect=='component_hash':edit('invocation.json',lambda d:d.update(base_projection_sha256='0'*64))
    if defect=='a3_hash':edit('invocation.json',lambda d:d.update(relevant_structure_sha256='0'*64))
    if defect=='a3_evidence':
        edit('analysis_input.json',lambda d:d['relevant_static_structure']['evidence_catalog']['entries'].update(rows=[]))
    if defect=='report_evidence':
        def corrupt(d):d['findings'][0]['evidence'][0]['summary']='rewritten'
        edit('firmware_analysis_report.json',corrupt);edit('analysis_run.json',lambda d:corrupt(d['firmware_report']))
    if defect=='ir':edit('analysis_run.json',lambda d:d['processor_behavior_ir']['behaviors'][0].update(summary='changed'))
    if defect=='raw':edit('invocation.json',lambda d:d.update(raw_response='body'))
    if defect=='secret':edit('invocation.json',lambda d:d.update(password=config.api_key.get_secret_value()))
    if defect=='elf':edit('analysis_run.json',lambda d:d['artifacts'][0].update(sha256='0'*64))
    with pytest.raises(ValueError):_validate(files,config.api_key.get_secret_value())


def test_b2_settings_refused_before_io(config,tmp_path,monkeypatch):
    from dataclasses import replace
    monkeypatch.setattr(real,'prepare_firmware_input',lambda *_:pytest.fail('No input IO'))
    with pytest.raises(ValueError):real.run_real_firmware(tmp_path,config=replace(config,temperature=0.1),enabled=True,output_root=tmp_path/'out',context_mode='enriched_v2')


def test_frozen_baseline_pins_fail_closed(components):
    i,s,r=components
    with pytest.raises(AgentExecutionError,match='identity/count'):real.validate_enriched_baseline(r,envelope_metadata(build_firmware_envelope(i,r,s)))


def test_existing_machine_gate_does_not_correct_semantic_prose(components):
    i,s,r=components
    report=report_with_all_objects(i)
    report.findings[0].summary='SystemInit performs configuration writes; UART symbols imply input.'
    model=fake_model(ModelFirmwareAnalysisReport,model_report_fixture(report))
    output=FirmwareSecurityAgent(model=model).invoke(i,relevant_static_structure=r,static_source=s)
    real.validate_real_firmware_report(output,i)
    assert output.report.findings[0].summary==report.findings[0].summary
