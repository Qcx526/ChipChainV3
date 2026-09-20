"""A6 rejection stays out of the existing cross-layer workflow input."""
import json
from chipchain.agents.hardware import HardwareSecurityAgent
from chipchain.agents.cross_layer import CrossLayerSecurityAgent
from chipchain.domain.hardware import HardwareAnalysisReport
from chipchain.domain.cross_layer import CrossLayerAnalysisReport
from chipchain.firmware.grounded_agent import GroundedFirmwareAgent
from chipchain.firmware.grounding_catalog import build_catalog
from chipchain.firmware.grounding_support import GroundedFirmwareModelReport
from chipchain.tools.paired.ibex import prepare_inputs
from chipchain.workflows.case import build_case_workflow
from chipchain.workflows.state import CaseWorkflowState
from tests.fakes import fake_model
from tests.integration.test_paired_baseline import prepared


def test_rejected_target_and_raw_prose_do_not_reach_cross_layer(prepared):
    elf=prepared['elf_path'];raw=bytearray(elf.read_bytes());raw[84:88]=bytes.fromhex('6f004000');elf.write_bytes(raw)
    trace=prepared['trace_path'];trace.write_text(trace.read_text().replace('00000013','0040006f').replace('addi\tx0,x0,0','jal\tx0,4'))
    case,hw,fw,_=prepare_inputs(**prepared)
    cat=build_catalog(case_id=case.case_id,elf_path=elf,trace_path=trace)
    fact=next(f for f in cat.transfer_facts if f.resolution_status=='resolved_direct')
    assert fact.resolved_target_pc==0x100004
    raw_report=GroundedFirmwareModelReport.model_validate(dict(case_id=case.case_id,claims=[
        dict(claim_id='bad-target',claim_type='control_transfer_target',fact_id=fact.fact_id,
             instruction_pc=fact.instruction_pc,claimed_target_pc=0x100008,raw_model_summary='REJECTED_RAW_PROSE'),
        dict(claim_id='correct-target',claim_type='control_transfer_target',fact_id=fact.fact_id,
             instruction_pc=fact.instruction_pc,claimed_target_pc=0x100004,raw_model_summary='UNTRUSTED_SUPPORTED_PROSE')],
        diagnostic_questions=['UNTRUSTED_MODEL_QUESTION']))
    docs={}
    agent=GroundedFirmwareAgent(model=fake_model(GroundedFirmwareModelReport,raw_report),catalog=cat,
        selected_sites={0x100000,0x100004},write=lambda n,v:docs.update({n:v}))
    hm=fake_model(HardwareAnalysisReport,HardwareAnalysisReport(case_id=case.case_id))
    cm=fake_model(CrossLayerAnalysisReport,CrossLayerAnalysisReport(case_id=case.case_id))
    state=CaseWorkflowState.model_validate(build_case_workflow(
        hardware_agent=HardwareSecurityAgent(model=hm),firmware_agent=agent,cross_layer_agent=CrossLayerSecurityAgent(model=cm),
        hardware_observer=lambda _:hw,firmware_observer=lambda _:fw).invoke({'case':case}))
    assert state.firmware_status=='completed' and state.cross_layer_status=='completed'
    assert len(state.firmware_report.findings)==1
    audit=json.loads(docs['firmware_support_validation.json'])
    assert audit['rejected_claim_ids']==['bad-target'] and audit['accepted_claim_ids']==['correct-target']
    context=cm.seen_messages[0][-1].content
    assert all(text not in context for text in ['REJECTED_RAW_PROSE','UNTRUSTED_SUPPORTED_PROSE','UNTRUSTED_MODEL_QUESTION','bad-target'])
    assert 'REJECTED_RAW_PROSE' in docs['firmware_model_claims.diagnostic.json']
    assert '0x100004' in state.firmware_report.findings[0].summary


def test_retirement_is_explicit_separate_and_cannot_resolve_jalr(prepared):
    from chipchain.firmware.control_flow_grounding import serialize_catalog,parse_catalog
    elf=prepared['elf_path'];raw=bytearray(elf.read_bytes());raw[84:88]=bytes.fromhex('67800000');elf.write_bytes(raw)
    trace=prepared['trace_path'];trace.write_text(trace.read_text().replace('00000013','00008067'))
    args=dict(case_id='synthetic-pair',elf_path=elf,trace_path=trace)
    selection=build_catalog(**args)
    c=build_catalog(**args,trace_semantics='ibex_rvfi_retirement')
    assert selection.runtime_observations==[]
    assert len(c.runtime_observations)==2 and all(e.retired is True for e in c.runtime_observations)
    assert [f.model_dump() for f in c.transfer_facts]==[f.model_dump() for f in selection.transfer_facts]
    indirect=next(f for f in c.transfer_facts if f.instruction_pc==0x100000)
    assert indirect.resolution_status=='indirect' and indirect.resolved_target_pc is None
    assert all(e.source_stage=='ibex_rvfi_retirement' for e in c.runtime_observations)
    registry={e.evidence_id:e for e in c.evidence_catalog}
    assert all(registry[i].epistemic_status=='observed' for e in c.runtime_observations for i in e.evidence_ids)
    assert all(registry[i].epistemic_status=='derived' for f in c.transfer_facts for i in f.evidence_ids)
    assert serialize_catalog(parse_catalog(serialize_catalog(c)))==serialize_catalog(c)


def test_retirement_source_mismatch_is_rejected(prepared):
    import pytest
    from pydantic import ValidationError
    c=build_catalog(case_id='synthetic-pair',elf_path=prepared['elf_path'],trace_path=prepared['trace_path'],
                    trace_semantics='ibex_rvfi_retirement')
    data=c.model_dump(exclude={'catalog_sha256'});data['runtime_observations'][0]['source_sha256']='b'*64
    with pytest.raises(ValidationError,match='Runtime event source'):
        type(c).model_validate(data)
    data=c.model_dump(exclude={'catalog_sha256'});data['runtime_observations'][0]['retired']=False
    with pytest.raises(ValidationError):type(c).model_validate(data)


def test_elf_x86_architecture_is_preserved_without_fake_riscv_decode(prepared):
    elf=prepared['elf_path'];raw=bytearray(elf.read_bytes());raw[18:20]=(3).to_bytes(2,'little');elf.write_bytes(raw)
    c=build_catalog(case_id='x86-synthetic',elf_path=elf,sites={0x100000:bytes(raw[84:88])})
    assert c.architecture=='x86' and c.target.architecture=='x86'
    assert c.transfer_facts[0].resolution_status=='unsupported'
    assert not c.capabilities.supports_direct_target_resolution
