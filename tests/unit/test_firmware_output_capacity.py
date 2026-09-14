"""R1 output capacity and safe completion telemetry; frozen B3 semantics reused."""
import json
from dataclasses import replace

import pytest
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import RunnableLambda
from langchain_deepseek import ChatDeepSeek
from pydantic import ValidationError

from chipchain.agents.runtime import StructuredReportRuntime, AgentStructuredOutputError, AgentExecutionError
from chipchain.agents.model_outputs.firmware import ModelFirmwareAnalysisReport
from chipchain.agents.model_outputs.firmware_v2 import ModelFirmwareAnalysisReportV2
from chipchain.agents.relation_support import validate_support_artifact
from chipchain.integrations import deepseek_firmware as real
from chipchain.integrations.deepseek import DeepSeekConfig
from chipchain.integrations.firmware_relations import validate_b3_semantic_pins
from tests.unit.test_deepseek_firmware import config
from tests.unit.test_firmware_relations import components, payload_for, invoke, patch_run
from tests.fakes import fake_model


def test_large_valid_response_end_to_end_shared_support(components):
    data,catalog,_=components
    payload=payload_for(components)
    original=payload['findings'][0]
    payload['support_claims'].append(dict(support_claim_id='support-path',claim_type='static_call_path',
        source_function_id='f80008',target_function_id='f80010',edge_relation_ids=['edge-80008','edge-80000']))
    bid=next(b.behavior_id for o in data[0].deterministic_observations.observations for b in o.behaviors)
    shared=dict(evidence_ids=original['evidence_ids'],support_claim_ids=['support-1','support-path'],epistemic_status='derived')
    summary='Static relation evidence with no execution or physical interface proof. '*8
    payload['findings']=[dict(**shared,finding_id=f'finding-{n}',summary=summary) for n in range(40)]
    payload['external_input_paths']=[dict(**shared,path_id=f'path-{n}',entry_point='static endpoint',summary=summary) for n in range(40)]
    payload['reachable_behaviors']=[dict(**shared,reachability_id=f'reach-{n}',processor_behavior_id=bid,
        external_input_path_ids=[f'path-{n}'],reachability_kind='unknown') for n in range(40)]
    payload['issue_anchors']=[dict(**shared,anchor_id=f'anchor-{n}',summary=summary,
        firmware_finding_ids=[f'finding-{n}']) for n in range(40)]
    typed=ModelFirmwareAnalysisReportV2.model_validate(payload)
    text=typed.model_dump_json()
    assert len(text)>100000
    output,audit,model=invoke(components,json.loads(text))
    assert len(model.seen_messages)==1
    assert [len(getattr(output.report,k)) for k in ('findings','external_input_paths','reachable_behaviors','issue_anchors')]==[40]*4
    assert len(audit.support_claims)==2
    assert all(len(s.referencing_firmware_claims)==160 for s in audit.support_claims)
    assert output.report.findings[-1].summary==summary.strip()
    validate_support_artifact(audit,output.report,catalog)
    print('Large valid model output characters:',len(text))


@pytest.mark.parametrize('mode,budget',[('v1',8192),('enriched_v2',8192),('relation_v3',16384)])
def test_effective_runner_budget(components,config,monkeypatch,tmp_path,mode,budget):
    from chipchain.agents.projections.firmware_envelope import build_firmware_envelope, serialize_firmware_envelope, envelope_metadata
    data,_,_=components
    seen,_=patch_run(components,monkeypatch,payload_for(components))
    e=build_firmware_envelope(data[0],data[3],data[1])
    monkeypatch.setattr(real,'prepare_enriched_context',lambda *a:(data[3],data[1],serialize_firmware_envelope(e),envelope_metadata(e)))
    original_factory=real.build_deepseek_chat_model
    observed=[]
    def factory(c):
        observed.append(c)
        return original_factory(c)
    monkeypatch.setattr(real,'build_deepseek_chat_model',factory)
    def generate(self,messages,**kwargs):
        assert self.max_tokens==budget
        seen.append(messages)
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content='',
            tool_calls=[dict(name='ModelFirmwareAnalysisReportV2' if mode=='relation_v3' else 'ModelFirmwareAnalysisReport',
                args={'case_id':data[0].case.case_id},id='synthetic')],response_metadata={'finish_reason':'tool_calls'}))])
    monkeypatch.setattr(ChatDeepSeek,'_generate',generate)
    path=real.run_real_firmware(tmp_path,config=config,enabled=True,output_root=tmp_path/'out',context_mode=mode,ghidra_home=tmp_path)
    invocation=json.loads((path/'invocation.json').read_text())
    assert invocation['max_tokens']==budget and observed[0].max_tokens==budget and len(seen)==1
    assert invocation['response_metadata']['finish_reason']=='tool_calls'
    assert config.max_tokens==8192 and DeepSeekConfig.__dataclass_fields__['max_tokens'].default==8192


@pytest.mark.parametrize('finish,expected',[('stop','stop'),('length','length'),('tool_calls','tool_calls'),
    ('content_filter','content_filter'),('unknown','unknown'),('PRIVATE RESPONSE TEXT','unknown'),({'headers':'secret'},'unknown'),(None,None)])
def test_finish_reason_allowlist(finish,expected):
    model=fake_model(ModelFirmwareAnalysisReport,AIMessage(content='',tool_calls=[dict(
        name='ModelFirmwareAnalysisReport',args={'case_id':'synthetic'},id='fake')],response_metadata={'finish_reason':finish,'headers':'PRIVATE'}))
    runtime=StructuredReportRuntime(model,ModelFirmwareAnalysisReport,'synthetic prompt')
    runtime.invoke('{}')
    assert runtime.last_response_metadata==({'finish_reason':expected} if expected else {})
    assert runtime.last_parse_stage is None


@pytest.mark.parametrize('stage',['pydantic_validation','malformed_tool_arguments','missing_structured_result','unknown'])
def test_safe_parse_classification(stage):
    model=fake_model(ModelFirmwareAnalysisReport,{'case_id':'synthetic'})
    runtime=StructuredReportRuntime(model,ModelFirmwareAnalysisReport,'synthetic prompt')
    error=None;raw=AIMessage(content='PRIVATE RAW BODY',response_metadata={'finish_reason':'length','headers':'PRIVATE'})
    if stage=='pydantic_validation':
        try:ModelFirmwareAnalysisReport.model_validate({'case_id':[]})
        except ValidationError as exc:error=exc
    elif stage=='malformed_tool_arguments':
        raw=AIMessage(content='PRIVATE',invalid_tool_calls=[{'name':'ModelFirmwareAnalysisReport','args':'{PRIVATE PARTIAL',
            'id':'fake','error':'PRIVATE ERROR','type':'invalid_tool_call'}],response_metadata={'finish_reason':'length'})
    elif stage=='unknown':error=ValueError('PRIVATE ERROR')
    runtime.runnable=RunnableLambda(lambda _:dict(raw=raw,parsed=None,parsing_error=error))
    with pytest.raises(AgentStructuredOutputError):runtime.invoke('{}')
    assert runtime.last_parse_stage==stage
    assert runtime.last_response_metadata=={'finish_reason':'length'}
    safe=json.dumps(dict(usage=runtime.last_usage,metadata=runtime.last_response_metadata,stage=runtime.last_parse_stage))
    assert 'PRIVATE' not in safe


def test_failure_records_effective_budget_and_safe_parse_stage(components,config,monkeypatch,tmp_path):
    seen,_=patch_run(components,monkeypatch,payload_for(components))
    def generate(self,messages,**kwargs):
        seen.append(messages)
        assert self.max_tokens==16384
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content='PRIVATE RAW BODY',
            invalid_tool_calls=[dict(name='ModelFirmwareAnalysisReportV2',args='{PRIVATE PARTIAL',id='fake',error='PRIVATE',type='invalid_tool_call')],
            usage_metadata=dict(input_tokens=10,output_tokens=16384,total_tokens=16394),response_metadata={'finish_reason':'length','headers':'PRIVATE'}))])
    monkeypatch.setattr(ChatDeepSeek,'_generate',generate)
    with pytest.raises(AgentExecutionError):real.run_real_firmware(tmp_path,config=config,enabled=True,
        output_root=tmp_path/'out',context_mode='relation_v3',ghidra_home=tmp_path)
    directory=next((tmp_path/'out').glob('*/*'))
    assert {p.name for p in directory.iterdir()}=={'failure.json','invocation_attempts.jsonl'}
    failure=json.loads((directory/'failure.json').read_text())
    assert failure['max_tokens']==16384
    assert failure['response_metadata']['finish_reason']=='length'
    assert failure['structured_output_parse_stage']=='malformed_tool_arguments'
    assert len(seen)==1
    assert all('PRIVATE' not in p.read_text() for p in directory.iterdir())


def test_semantic_pins_refuse_changed_payload(components):
    with pytest.raises(AgentExecutionError,match='identity changed'):
        validate_b3_semantic_pins('changed',{})
