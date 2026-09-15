"""Synthetic supported Hardware reports, real LangChain parser, offline transport."""
import json
from pathlib import Path

import pytest
from pydantic import ValidationError, SecretStr
from langchain_core.messages import AIMessage

from chipchain.agents.hardware import HardwareSecurityAgent
from chipchain.agents.hardware_support import (
    HardwareSupportError, validate_supported_hardware_report, revalidate_hardware_support_artifact,
    evaluate_model_support, HardwareRelationSupportReportV1, collect_hardware_evidence,
)
from chipchain.agents.hardware_support_diagnostics import serialize_hardware_support_failure
from chipchain.agents.model_outputs.hardware_v2 import (
    ModelHardwareAnalysisReportV2, ModelHardwareRelationFactSupport, ModelHardwareSemanticSupport,
)
from chipchain.agents.projections.hardware_relations import (
    build_hardware_relation_projection, serialize_hardware_relation_projection,
    compact_attributes, validate_hardware_relation_projection,
)
from chipchain.agents.projections.hardware_envelope import build_hardware_envelope, serialize_hardware_envelope
from chipchain.agents.runtime import AgentStructuredOutputError
from chipchain.integrations.deepseek import DeepSeekConfig
from chipchain.integrations.deepseek_hardware_supported import PreparedHardwareB2, run_supported_hardware
from chipchain.tools.hardware.relation_claims import HardwareClaimKind, CAPABILITY_FOR_CLAIM
from chipchain.tools.hardware.relations import HardwareRelationKind as Kind, serialize_hardware_relation_catalog
from tests.fakes import fake_model
from tests.unit.test_hardware_typed_relations import sample, inputs, catalog, build, change_hidden_oracle, enriched


def fact_support(relation, sid='support-1'):
    return ModelHardwareRelationFactSupport(support_claim_id=sid, relation_id=relation.relation_id,
        expected_kind=relation.kind, expected_status=relation.status, expected_attributes=compact_attributes(relation.attributes))


def semantic_support(kind, relations, sid='support-1'):
    return ModelHardwareSemanticSupport(support_claim_id=sid, semantic_kind=kind,
        relation_ids=[r.relation_id for r in relations],
        expected_attributes=compact_attributes(relations[0].attributes) if relations else None,
        expected_status=relations[0].status if relations else 'observed',
        start={'value': 50, 'unit': 'ns'} if kind == HardwareClaimKind.INTERVAL else None,
        end={'value': 70, 'unit': 'ns'} if kind == HardwareClaimKind.INTERVAL else None)


def grounded_report(inputs, catalog, *, relation=None, support=None):
    r = relation or next(r for r in catalog.relations if r.kind == Kind.INSTRUCTION)
    support = support or fact_support(r)
    behavior_ids = [b.behavior_id for o in inputs.deterministic_observations.observations
                    if o.observation_id == r.source_observation_id for b in o.behaviors]
    return ModelHardwareAnalysisReportV2(case_id=inputs.case.case_id,
        findings=[dict(finding_id='finding-1', summary='Synthetic sampled fact only.',
            evidence_ids=r.evidence_ids, processor_behavior_ids=behavior_ids, epistemic_status='derived',
            support_claim_ids=[support.support_claim_id])], trigger_hypotheses=[], abnormal_states=[],
        processor_behavior_ids=[b.behavior_id for o in inputs.deterministic_observations.observations for b in o.behaviors],
        unresolved_questions=[], support_claims=[support])


def prepared(inputs, catalog):
    p = build_hardware_relation_projection(catalog)
    return PreparedHardwareB2(inputs, catalog, p, build_hardware_envelope(inputs, catalog, p))


def scripted(report):
    return fake_model(ModelHardwareAnalysisReportV2, AIMessage(content='', tool_calls=[dict(
        name='ModelHardwareAnalysisReportV2', args=report.model_dump(mode='json') if hasattr(report,'model_dump') else report,
        id='synthetic-response')], usage_metadata=dict(input_tokens=100, output_tokens=200, total_tokens=300),
        response_metadata=dict(model_name='deepseek-flash', finish_reason='tool_calls')))


@pytest.mark.parametrize('kind', list(Kind))
def test_exact_fact_hydration_and_audit_revalidation(inputs, catalog, kind):
    r = next(r for r in catalog.relations if r.kind == kind)
    report = grounded_report(inputs, catalog, relation=r)
    output, audit = validate_supported_hardware_report(report, inputs, catalog)
    registry = collect_hardware_evidence(inputs)
    assert output.report.findings[0].evidence == [registry[e] for e in r.evidence_ids]
    assert audit.referenced_supported_count == 1 and audit.orphan_support_count == 0
    assert output.processor_behavior_ir == HardwareSecurityAgent().invoke(inputs).processor_behavior_ir
    assert revalidate_hardware_support_artifact(audit, output.report, inputs, catalog) == audit


def test_real_langchain_parser_supported_and_legacy_path(inputs, catalog):
    report = grounded_report(inputs, catalog)
    model = scripted(report)
    agent = HardwareSecurityAgent(model=model)
    p = build_hardware_relation_projection(catalog)
    output, audit = agent.invoke_supported(inputs, relation_catalog=catalog, relation_projection=p)
    assert model.bound_schema_names == ['HardwareAnalysisReport', 'ModelHardwareAnalysisReportV2']
    assert len(model.seen_messages) == 1
    assert 'sampled point' in model.seen_messages[0][0].content
    assert agent.last_usage == {'input_tokens':100,'output_tokens':200,'total_tokens':300}
    assert audit.referenced_supported_count == 1
    legacy = fake_model(type(output.report), output.report)
    assert HardwareSecurityAgent(model=legacy).invoke(inputs).report == output.report


@pytest.mark.parametrize('kind', [k for k in HardwareClaimKind if k not in CAPABILITY_FOR_CLAIM])
def test_referenced_semantic_promotions_rejected(inputs, catalog, kind):
    r = next(r for r in catalog.relations if r.kind == Kind.REGISTER)
    report = grounded_report(inputs, catalog, relation=r, support=semantic_support(kind,[r]))
    with pytest.raises(HardwareSupportError) as caught:
        validate_supported_hardware_report(report, inputs, catalog)
    assert caught.value.failed_count == 1
    assert caught.value.failure_diagnostic.failed_referenced_supports[0].result == 'unsupported'


@pytest.mark.parametrize('kind', list(CAPABILITY_FOR_CLAIM))
def test_positive_semantic_claim_supported(inputs, catalog, kind):
    r = next(r for r in catalog.relations if r.kind == CAPABILITY_FOR_CLAIM[kind][0])
    report = grounded_report(inputs, catalog, relation=r, support=semantic_support(kind,[r]))
    assert validate_supported_hardware_report(report, inputs, catalog)[1].referenced_supported_count == 1


@pytest.mark.parametrize('status', ['supported','unsupported','incompatible'])
def test_orphan_all_results_do_not_reject(inputs, catalog, status):
    report = grounded_report(inputs, catalog)
    r = next(r for r in catalog.relations if r.kind == Kind.REGISTER)
    orphan = semantic_support(HardwareClaimKind.TRIGGER,[r],sid='orphan') if status == 'unsupported' else fact_support(r,'orphan')
    if status == 'incompatible':
        a = orphan.expected_attributes.model_dump()
        a['host_value'],a['reference_value']=a['reference_value'],a['host_value']
        orphan.expected_attributes=type(orphan.expected_attributes).model_validate(a)
    report.support_claims.append(orphan)
    output,audit=validate_supported_hardware_report(report,inputs,catalog)
    assert len(output.report.findings)==1 and audit.orphan_support_count==1
    e=audit.support_claims[1]
    assert e.result==status and e.usage_status=='orphaned' and e.referencing_hardware_claims==[]
    assert revalidate_hardware_support_artifact(audit,output.report,inputs,catalog)==audit


@pytest.mark.parametrize('error', ['missing_support','unknown_support','duplicate_support','duplicate_reference',
    'unknown_evidence','unknown_behavior','unknown_finding','duplicate_finding','case_id','unrelated_evidence'])
def test_bad_wiring_rejected(inputs,catalog,error):
    report=grounded_report(inputs,catalog).model_dump(mode='json')
    f=report['findings'][0]
    if error=='missing_support': f['support_claim_ids']=[]
    elif error=='unknown_support': f['support_claim_ids']=['missing']
    elif error=='duplicate_support': report['support_claims'].append(report['support_claims'][0])
    elif error=='duplicate_reference': f['support_claim_ids']*=2
    elif error=='unknown_evidence': f['evidence_ids']=['missing']
    elif error=='unknown_behavior': f['processor_behavior_ids']=['missing']
    elif error=='duplicate_finding': report['findings'].append(dict(f))
    elif error=='case_id': report['case_id']='other'
    elif error=='unrelated_evidence':
        r=next(r for r in catalog.relations if r.kind==Kind.COVER)
        f['evidence_ids']=r.evidence_ids
    else:
        report['abnormal_states']=[dict(state_id='state-1',summary='Synthetic state',
            hardware_finding_ids=['missing'],processor_behavior_ids=[],evidence_ids=f['evidence_ids'],
            epistemic_status='hypothesized',support_claim_ids=f['support_claim_ids'])]
    with pytest.raises((ValueError,AgentStructuredOutputError)):
        validate_supported_hardware_report(ModelHardwareAnalysisReportV2.model_validate(report),inputs,catalog)


@pytest.mark.parametrize('collection', ['findings','abnormal_states','trigger_hypotheses'])
def test_verified_post_gate_rejects(inputs,catalog,collection):
    report=grounded_report(inputs,catalog)
    f=report.findings[0].model_dump()
    if collection=='findings': report.findings[0].epistemic_status='verified'
    else:
        f.pop('finding_id'); f['hardware_finding_ids']=['finding-1']; f['epistemic_status']='verified'
        if collection=='abnormal_states': f['state_id']='state-1'
        else: f.update(hypothesis_id='hypothesis-1',constraints=[])
        data=report.model_dump(); data[collection]=[f]
        report=ModelHardwareAnalysisReportV2.model_validate(data)
    with pytest.raises(HardwareSupportError,match='rejected') as caught:
        validate_supported_hardware_report(report,inputs,catalog)
    assert caught.value.reason_code=='unsupported_verified_status'


def test_hypothesized_association_of_three_facts_allowed(inputs,catalog):
    selected=[next(r for r in catalog.relations if r.kind==k) for k in [Kind.INSTRUCTION,Kind.LOCAL,Kind.REGISTER]]
    report=grounded_report(inputs,catalog)
    report.support_claims=[fact_support(r,f's-{i}') for i,r in enumerate(selected)]
    report.findings[0].support_claim_ids=['s-0']
    data=report.model_dump()
    data['trigger_hypotheses']=[dict(hypothesis_id='hypothesis-1',summary='These sampled facts may be related; causality is unverified.',
        hardware_finding_ids=['finding-1'],processor_behavior_ids=report.processor_behavior_ids,
        evidence_ids=sorted({e for r in selected for e in r.evidence_ids}),constraints=[],
        epistemic_status='hypothesized',support_claim_ids=['s-0','s-1','s-2'])]
    output,audit=validate_supported_hardware_report(ModelHardwareAnalysisReportV2.model_validate(data),inputs,catalog)
    assert output.report.trigger_hypotheses[0].epistemic_status=='hypothesized'
    assert audit.referenced_supported_count==3


def multi_failure(inputs,catalog):
    r=next(r for r in catalog.relations if r.kind==Kind.REGISTER)
    claims=[semantic_support(HardwareClaimKind.EXECUTED,[r],'execution'),
            semantic_support(HardwareClaimKind.INTERVAL,[r],'interval'),fact_support(r,'wrong-values')]
    a=claims[-1].expected_attributes.model_dump()
    a['host_value'],a['reference_value']=a['reference_value'],a['host_value']
    claims[-1].expected_attributes=type(claims[-1].expected_attributes).model_validate(a)
    report=grounded_report(inputs,catalog,relation=r,support=claims[0])
    report.findings[0].summary='PRIVATE SECRET RAW MODEL TEXT'
    report.findings[0].support_claim_ids=[c.support_claim_id for c in claims]
    report.support_claims=claims+[semantic_support(HardwareClaimKind.CAUSAL,[r],'orphan-causal')]
    return report


def test_all_failures_diagnostic_no_prose(inputs,catalog):
    with pytest.raises(HardwareSupportError) as caught:
        validate_supported_hardware_report(multi_failure(inputs,catalog),inputs,catalog)
    diagnostic=caught.value.failure_diagnostic
    assert diagnostic.referenced_unsupported_count==2 and diagnostic.referenced_incompatible_count==1
    assert diagnostic.orphan_unsupported_count==1
    assert len(diagnostic.failed_referenced_supports)==3
    assert all(e.support_claim_id!='orphan-causal' for e in diagnostic.failed_referenced_supports)
    text=serialize_hardware_support_failure(diagnostic)
    for token in ['PRIVATE SECRET','summary','unresolved_questions','tool_calls','AIMessage']:
        assert token not in text


def test_diagnostic_redacts_unrecognized_attribute_prose(inputs,catalog):
    r=next(r for r in catalog.relations if r.kind==Kind.LOCAL)
    claim=fact_support(r)
    claim.expected_attributes.host_signal='PRIVATE SECRET RAW MODEL TEXT'
    report=grounded_report(inputs,catalog,relation=r,support=claim)
    with pytest.raises(HardwareSupportError) as caught:
        validate_supported_hardware_report(report,inputs,catalog)
    text=serialize_hardware_support_failure(caught.value.failure_diagnostic)
    assert 'PRIVATE SECRET' not in text and 'unrecognized_text_sha256' in text


def test_diagnostic_over_cap_omitted_without_changing_rejection(inputs,catalog,monkeypatch):
    import chipchain.agents.hardware_support_diagnostics as diagnostics
    monkeypatch.setattr(diagnostics,'MAX_HARDWARE_SUPPORT_FAILURE_BYTES',1)
    with pytest.raises(HardwareSupportError) as caught:
        validate_supported_hardware_report(multi_failure(inputs,catalog),inputs,catalog)
    assert caught.value.failed_count==3 and caught.value.failure_diagnostic is None


@pytest.mark.parametrize('failure', [False,True])
def test_runner_success_or_safe_failure_files(inputs,catalog,tmp_path,monkeypatch,failure):
    import chipchain.integrations.deepseek_hardware_supported as runner
    report=multi_failure(inputs,catalog) if failure else grounded_report(inputs,catalog)
    model=scripted(report)
    seen=[]
    def factory(config):
        seen.append(config)
        return model
    monkeypatch.setattr(runner,'build_deepseek_chat_model',factory)
    config=DeepSeekConfig(api_key=SecretStr('synthetic-api-key'))
    result=run_supported_hardware(prepared(inputs,catalog),config=config,enabled=True,output_root=tmp_path)
    assert len(seen)==1 and seen[0].max_tokens==16384 and config.max_tokens==8192
    assert len(model.seen_messages)==1
    directory=Path(result['directory'])
    files={p.name for p in directory.iterdir()}
    if failure:
        assert files=={'failure.json','invocation_attempts.jsonl','hardware_relation_support_failure.json'}
        assert json.loads((directory/'failure.json').read_text())['failed_referenced_count']==3
    else:
        assert files=={'analysis_run.json','hardware_analysis_report.json','hardware_relation_support.json',
                      'analysis_input.json','invocation.json','invocation_attempts.jsonl'}
        assert json.loads((directory/'invocation.json').read_text())['returned_model']=='deepseek-flash'
    assert 'PRIVATE SECRET' not in ''.join(p.read_text() for p in directory.iterdir())
    assert not result['stop_experiment']
    assert len((directory/'invocation_attempts.jsonl').read_text().splitlines())==2


def test_projection_envelope_determinism_capabilities_and_no_io(inputs,catalog,monkeypatch):
    before=serialize_hardware_relation_catalog(catalog)
    p=build_hardware_relation_projection(catalog)
    rows={r.relation_id:r for r in p.relations}
    for r in catalog.relations:
        assert {**p.capability_defaults.model_dump(),**rows[r.relation_id].capabilities}==r.capabilities.model_dump()
    def forbidden(*args,**kwargs): raise AssertionError('No projection IO')
    monkeypatch.setattr(Path,'open',forbidden)
    assert serialize_hardware_relation_projection(p)==serialize_hardware_relation_projection(build_hardware_relation_projection(catalog))
    a=build_hardware_envelope(inputs,catalog,p)
    assert serialize_hardware_envelope(a)==serialize_hardware_envelope(build_hardware_envelope(inputs,catalog,p))
    assert before==serialize_hardware_relation_catalog(catalog)


def test_caps_fail_closed_and_projection_tampering(inputs,catalog,monkeypatch):
    import chipchain.agents.projections.hardware_relations as projection
    import chipchain.agents.projections.hardware_envelope as envelope
    p=build_hardware_relation_projection(catalog)
    changed=p.model_copy(deep=True); changed.relations.pop()
    with pytest.raises(ValueError): validate_hardware_relation_projection(changed,catalog)
    changed=p.model_copy(deep=True); changed.relations[0].capabilities['supports_instruction_execution']=True
    with pytest.raises(ValueError): validate_hardware_relation_projection(changed,catalog)
    monkeypatch.setattr(projection,'MAX_HARDWARE_RELATION_CHARS',1)
    with pytest.raises(ValueError): build_hardware_relation_projection(catalog)
    monkeypatch.setattr(projection,'MAX_HARDWARE_RELATION_CHARS',20000)
    monkeypatch.setattr(envelope,'MAX_HARDWARE_B2_CONTEXT_CHARS',1)
    with pytest.raises(ValueError): build_hardware_envelope(inputs,catalog,p)


def test_oracle_independence_projection_envelope(sample):
    from chipchain.tools.hardware.encorpus import EnCorpusIbexDriverAnalyzer
    original=EnCorpusIbexDriverAnalyzer().ingest(sample)
    results=[prepared(i,build(i)) for i in [enriched(original),enriched(change_hidden_oracle(original))]]
    assert serialize_hardware_relation_projection(results[0].projection)==serialize_hardware_relation_projection(results[1].projection)
    assert serialize_hardware_envelope(results[0].envelope)==serialize_hardware_envelope(results[1].envelope)


def test_future_audit_revalidation_rejects_status_tamper(inputs,catalog):
    report=grounded_report(inputs,catalog)
    output,audit=validate_supported_hardware_report(report,inputs,catalog)
    audit.support_claims[0].support_claim.expected_status='observed'
    with pytest.raises(HardwareSupportError): revalidate_hardware_support_artifact(audit,output.report,inputs,catalog)
    data=audit.model_dump();data['generated_support_count']=99
    with pytest.raises(ValidationError): HardwareRelationSupportReportV1.model_validate(data)


@pytest.mark.parametrize('defect', ['none','schema','transport','wrong_model','secret_success'])
def test_official_deepseek_binding_and_safe_terminal_records(inputs,catalog,tmp_path,monkeypatch,defect):
    from langchain_deepseek import ChatDeepSeek
    from langchain_core.outputs import ChatGeneration, ChatResult
    seen=[]
    config=DeepSeekConfig(api_key=SecretStr('synthetic-sensitive-credential'))
    report=grounded_report(inputs,catalog)
    if defect=='secret_success': report.findings[0].summary=config.api_key.get_secret_value()
    def generate(self,messages,**kwargs):
        seen.append(kwargs)
        assert self.max_tokens==16384 and self.temperature==0 and self.request_timeout==180
        assert self.max_retries==0 and self.extra_body=={'thinking':{'type':'disabled'}}
        assert kwargs['tools'][0]['function']['name']=='ModelHardwareAnalysisReportV2'
        assert kwargs['tools'][0]['function']['strict'] is False
        if defect=='transport': raise RuntimeError('PRIVATE RAW PROVIDER BODY '+config.api_key.get_secret_value())
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content='PRIVATE RAW PROVIDER BODY',
            tool_calls=[dict(name='ModelHardwareAnalysisReportV2',args={} if defect=='schema' else report.model_dump(mode='json'),id='fake')],
            usage_metadata=dict(input_tokens=100,output_tokens=200,total_tokens=300),
            response_metadata=dict(model_name='wrong-model' if defect=='wrong_model' else 'deepseek-flash',finish_reason='tool_calls')))])
    monkeypatch.setattr(ChatDeepSeek,'_generate',generate)
    result=run_supported_hardware(prepared(inputs,catalog),config=config,enabled=True,output_root=tmp_path)
    assert len(seen)==1
    directory=Path(result['directory'])
    assert result['status']==('succeeded' if defect=='none' else 'failed')
    assert result['stop_experiment']==(defect in ['wrong_model','secret_success'])
    if defect!='none':
        assert {p.name for p in directory.iterdir()}=={'failure.json','invocation_attempts.jsonl'}
    text=''.join(p.read_text() for p in directory.iterdir())
    assert 'PRIVATE RAW PROVIDER BODY' not in text and config.api_key.get_secret_value() not in text


def test_persistence_failure_rolls_back_accepted_files(inputs,catalog,tmp_path,monkeypatch):
    import chipchain.integrations.deepseek_hardware_supported as runner
    model=scripted(grounded_report(inputs,catalog))
    monkeypatch.setattr(runner,'build_deepseek_chat_model',lambda _:model)
    original=Path.open
    def fail(self,*args,**kwargs):
        if self.name=='hardware_relation_support.json': raise OSError('synthetic disk failure')
        return original(self,*args,**kwargs)
    monkeypatch.setattr(Path,'open',fail)
    result=run_supported_hardware(prepared(inputs,catalog),config=DeepSeekConfig(api_key=SecretStr('key')),
        enabled=True,output_root=tmp_path)
    assert result['stop_experiment']
    assert {p.name for p in Path(result['directory']).iterdir()}=={'failure.json','invocation_attempts.jsonl'}


def test_missing_opt_in_and_wrong_model_do_not_call(inputs,catalog,tmp_path,monkeypatch):
    import chipchain.integrations.deepseek_hardware_supported as runner
    from chipchain.integrations.deepseek import DeepSeekConfigurationError
    monkeypatch.setattr(runner,'build_deepseek_chat_model',lambda _:pytest.fail('No provider construction'))
    config=DeepSeekConfig(api_key=SecretStr('key'))
    for enabled,c in [(False,config),(True,DeepSeekConfig(api_key=SecretStr('key'),model='deepseek-v4-pro'))]:
        with pytest.raises(DeepSeekConfigurationError):
            run_supported_hardware(prepared(inputs,catalog),config=c,enabled=enabled,output_root=tmp_path/'out')
    assert not (tmp_path/'out').exists()


def test_conflicting_input_evidence_fails_before_invocation(inputs,catalog):
    ref=inputs.deterministic_observations.observations[0].evidence[0].model_copy(deep=True)
    ref.summary='different under same evidence identity'
    inputs.deterministic_observations.observations[0].evidence.append(ref)
    model=scripted(grounded_report(inputs,catalog))
    with pytest.raises(HardwareSupportError):
        HardwareSecurityAgent(model=model).invoke_supported(inputs,relation_catalog=catalog,
            relation_projection=build_hardware_relation_projection(catalog))
    assert not model.seen_messages


def test_model_schema_requires_all_top_level_collections(inputs,catalog):
    report=grounded_report(inputs,catalog).model_dump(mode='json')
    for key in ['findings','trigger_hypotheses','abnormal_states','support_claims','unresolved_questions']:
        incomplete=dict(report);incomplete.pop(key)
        with pytest.raises(ValidationError): ModelHardwareAnalysisReportV2.model_validate(incomplete)


def test_empty_complete_report_allowed_without_invented_findings(inputs,catalog):
    report=ModelHardwareAnalysisReportV2(case_id=inputs.case.case_id,findings=[],trigger_hypotheses=[],abnormal_states=[],
        processor_behavior_ids=[],unresolved_questions=['Insufficient support for additional claims.'],support_claims=[])
    output,audit=validate_supported_hardware_report(report,inputs,catalog)
    assert output.report.findings==[] and audit.generated_support_count==0


@pytest.mark.parametrize('kind,summary', [
    (HardwareClaimKind.INTERVAL,'LSU held across 50–70ns'),
    (HardwareClaimKind.SAME_CONFIGURATION,'Both formal events share a configuration'),
    (HardwareClaimKind.READ,'x10 was read'),
])
def test_historical_prose_rejection_comes_from_typed_support(inputs,catalog,kind,summary):
    r=next(r for r in catalog.relations if r.kind==Kind.REGISTER)
    report=grounded_report(inputs,catalog,relation=r,support=semantic_support(kind,[r]))
    report.findings[0].summary=summary
    with pytest.raises(HardwareSupportError) as caught:
        validate_supported_hardware_report(report,inputs,catalog)
    assert caught.value.failure_diagnostic.failed_referenced_supports[0].result=='unsupported'
    # Changing prose does not change typed support verdict.
    report.findings[0].summary='Neutral synthetic text.'
    with pytest.raises(HardwareSupportError): validate_supported_hardware_report(report,inputs,catalog)


@pytest.mark.parametrize('field', ['time','signal_id','mnemonic','encoding_bits'])
def test_compact_instruction_wrong_expectation_not_repaired(inputs,catalog,field):
    r=next(r for r in catalog.relations if r.kind==Kind.INSTRUCTION)
    support=fact_support(r)
    if field=='time': support.expected_attributes.time.value+=1
    elif field=='signal_id': support.expected_attributes.signal_id='different.signal'
    elif field=='mnemonic': support.expected_attributes.decoded_instruction.mnemonic='different_mnemonic'
    else: support.expected_attributes.encoding_bits='1'*32
    result=evaluate_model_support(support,catalog)
    assert result.status=='incompatible'


@pytest.mark.parametrize('stop_first', [False,True])
def test_predetermined_two_case_policy_no_retry(inputs,catalog,tmp_path,monkeypatch,stop_first):
    import chipchain.integrations.deepseek_hardware_supported as runner
    p=prepared(inputs,catalog)
    manifest=tmp_path/'freeze.json'
    manifest.write_text(json.dumps({'source':{'synthetic.py':'frozen'},'identities':[p.identities(),p.identities()]}))
    monkeypatch.setenv('CHIPCHAIN_ENABLE_REAL_LLM','1')
    monkeypatch.setattr('sys.argv',['runner','--corpus-root',str(tmp_path),'--env-file',str(tmp_path/'unused.env'),
                                  '--freeze-manifest',str(manifest)])
    monkeypatch.setattr(runner,'source_snapshot',lambda _: {'synthetic.py':'frozen'})
    seen=[]
    monkeypatch.setattr(runner,'prepare_supported_hardware',lambda path:p)
    monkeypatch.setattr(runner,'load_deepseek_config',lambda *a,**kw:DeepSeekConfig(api_key=SecretStr('key')))
    def run(item,**kwargs):
        seen.append(item)
        return dict(directory='synthetic',status='failed',stop_experiment=stop_first)
    monkeypatch.setattr(runner,'run_supported_hardware',run)
    if stop_first:
        with pytest.raises(ValueError,match='stopped'): runner.main()
    else: runner.main()
    assert len(seen)==(1 if stop_first else 2)


def test_no_prose_entailment_claim_is_made(inputs,catalog):
    report=grounded_report(inputs,catalog)
    report.findings[0].summary='This free text is not parsed by the typed checker.'
    assert validate_supported_hardware_report(report,inputs,catalog)[1].referenced_supported_count==1
