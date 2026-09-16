"""Synthetic artifacts exercise real ingestion and LangGraph without network."""

import struct
from pathlib import Path

import pytest

from chipchain.agents.contracts import CrossLayerAgentInput, FirmwareAgentInput
from chipchain.agents.context import firmware_context
from chipchain.agents.cross_layer import CrossLayerSecurityAgent
from chipchain.agents.firmware import FirmwareSecurityAgent
from chipchain.agents.hardware import HardwareSecurityAgent
from chipchain.agents.model_outputs.firmware import ModelFirmwareAnalysisReport
from chipchain.agents.runtime import AgentStructuredOutputError
from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.case import ArtifactRef, CaseBundle, TargetDescriptor
from chipchain.domain.cross_layer import CrossLayerAnalysisReport, CrossLayerCandidate
from chipchain.domain.firmware import FirmwareAnalysisReport
from chipchain.domain.hardware import HardwareAnalysisReport
from chipchain.integrations.paired_baseline import validate_cross_references
from chipchain.tools.paired.ibex import parse_trace, prepare_inputs
from chipchain.workflows.case import build_case_workflow
from chipchain.workflows.state import CaseWorkflowState
from tests.fakes import fake_model


@pytest.fixture
def prepared(tmp_path):
    # Minimal real ELF layout: header, executable PT_LOAD, ADDI then C.NOP.
    code = bytes.fromhex('130000000100')
    ident = b'\x7fELF\x01\x01\x01' + bytes(9)
    header = struct.pack('<16sHHIIIIIHHHHHH',ident,2,243,1,0x100000,52,0,1,52,32,1,40,0,0)
    ph = struct.pack('<IIIIIIII',1,84,0x100000,0x100000,len(code),len(code),5,4)
    elf = tmp_path/'firmware.elf'; elf.write_bytes(header+ph+code)
    trace = tmp_path/'trace.log'
    trace.write_text('Time\tCycle\tPC\tInsn\tDecoded instruction\tRegister and memory contents\n'
                     '20\t6\t00100000\t00000013\taddi\tx0,x0,0\n'
                     '24\t8\t00100004\t0001\tc.nop\n')
    stdout = tmp_path/'stdout.log'; stdout.write_text('Terminating simulation by software request.\nExecuted cycles: 9\n')
    ascii_path=tmp_path/'ascii.log'; ascii_path.write_text('synthetic console\n')
    case=CaseBundle(case_id='synthetic-pair',name='synthetic paired ELF trace',
        target=TargetDescriptor(architecture='riscv',processor_id='synthetic',word_size_bits=32,endianness='little'),
        hardware_artifacts=[ArtifactRef(artifact_id='trace',artifact_type='hardware_trace',path=str(trace),format='text')],
        firmware_artifacts=[ArtifactRef(artifact_id='elf',artifact_type='firmware_binary',path=str(elf),format='elf')])
    args=dict(template=case,elf_path=elf,trace_path=trace,stdout_path=stdout,ascii_path=ascii_path)
    return args


def test_trace_elf_binding_and_neutral_projection(prepared):
    case,hw,fw,audit=prepare_inputs(**prepared)
    assert audit['byte_matched_records']==2
    assert [o.observation_id for o in hw.observations][-2:]==['hw-o-row-2','hw-o-row-3']
    context=firmware_context(FirmwareAgentInput(case=case,deterministic_observations=fw))
    assert str(prepared['elf_path']) not in context
    assert 'static ELF' in context or 'Static ELF' in context
    assert case.firmware_artifacts[0].artifact_id=='elf'


def test_mismatched_elf_is_rejected(prepared):
    path=prepared['elf_path'];data=bytearray(path.read_bytes());data[84]=0x93;path.write_bytes(data)
    with pytest.raises(ValueError,match='differ from ELF'):
        prepare_inputs(**prepared)


@pytest.mark.parametrize('bad', ['garbage', '20\t6\t00100000\t0001ffff\tbad',
    '20\t6\t00100000\t00000013\taddi\n24\t5\t00100004\t0001\tc.nop'])
def test_invalid_trace_rejected(bad):
    with pytest.raises(ValueError):
        parse_trace('Time\tCycle\tPC\tInsn\tDecoded instruction\n'+bad+'\n')


def test_three_agents_receive_real_observations_in_order(prepared):
    case,hw,fw,_=prepare_inputs(**prepared)
    h=fake_model(HardwareAnalysisReport,HardwareAnalysisReport(case_id=case.case_id))
    f=fake_model(ModelFirmwareAnalysisReport,{'case_id':case.case_id})
    x=fake_model(CrossLayerAnalysisReport,CrossLayerAnalysisReport(case_id=case.case_id))
    order=[]
    def observe_h(c):
        order.append('hardware');return hw
    def observe_f(c):
        assert len(h.seen_messages)==1;order.append('firmware');return fw
    state=CaseWorkflowState.model_validate(build_case_workflow(
        hardware_agent=HardwareSecurityAgent(model=h),firmware_agent=FirmwareSecurityAgent(model=f),
        cross_layer_agent=CrossLayerSecurityAgent(model=x),hardware_observer=observe_h,firmware_observer=observe_f,
    ).invoke({'case':case}))
    assert state.errors==[] and state.cross_layer_status=='completed'
    assert order==['hardware','firmware']
    assert 'Observed RVFI text row' in h.seen_messages[0][-1].content
    assert 'Static ELF site' in f.seen_messages[0][-1].content
    assert 'hw-b-row-2' in x.seen_messages[0][-1].content
    assert len(state.processor_behavior_ir.behaviors)==4


def test_observer_failure_isolated_before_model(prepared):
    case,hw,fw,_=prepare_inputs(**prepared)
    h=fake_model(HardwareAnalysisReport,HardwareAnalysisReport(case_id=case.case_id))
    def fail(c):raise ValueError('sensitive-local-detail')
    state=CaseWorkflowState.model_validate(build_case_workflow(
        hardware_agent=HardwareSecurityAgent(model=h),hardware_observer=fail,firmware_observer=lambda _:fw,
    ).invoke({'case':case}))
    assert not h.seen_messages
    assert state.hardware_status=='failed' and state.firmware_status=='completed' and state.cross_layer_status=='blocked'
    assert 'sensitive-local-detail' not in state.model_dump_json()


def test_cross_layer_gate_rejects_invented_findings(prepared):
    case,hw,fw,_=prepare_inputs(**prepared)
    behaviors=[b for o in [*hw.observations,*fw.observations] for b in o.behaviors]
    inputs=CrossLayerAgentInput(case=case,hardware_report=HardwareAnalysisReport(case_id=case.case_id),
        firmware_report=FirmwareAnalysisReport(case_id=case.case_id),
        processor_behavior_ir=ProcessorBehaviorIR(case_id=case.case_id,behaviors=behaviors))
    report=CrossLayerAnalysisReport(case_id=case.case_id,candidates=[CrossLayerCandidate(
        candidate_id='candidate',candidate_type='TYPE_I',summary='Synthetic hypothesis',
        hardware_finding_ids=['invented'],evidence=behaviors[0].evidence)])
    with pytest.raises(AgentStructuredOutputError,match='finding'):
        validate_cross_references(report,inputs)


def test_bound_hardware_hydrates_exact_evidence(prepared):
    from chipchain.integrations.paired_agents import BoundHardwareAgent, HardwareBinding
    from chipchain.agents.contracts import HardwareAgentInput
    case,hw,_,_=prepare_inputs(**prepared)
    payload=dict(case_id=case.case_id,findings=[dict(finding_id='f1',summary='Synthetic observed baseline',
        evidence_ids=[hw.observations[0].evidence[0].evidence_id],processor_behavior_ids=[],epistemic_status='derived')],
        trigger_hypotheses=[],abnormal_states=[],processor_behavior_ids=[],unresolved_questions=[])
    agent=BoundHardwareAgent(model=fake_model(HardwareBinding,payload))
    before=hw.model_dump_json()
    out=agent.invoke(HardwareAgentInput(case=case,deterministic_observations=hw))
    assert out.report.findings[0].evidence==hw.observations[0].evidence
    out.report.findings[0].evidence[0].summary='changed copy'
    assert hw.model_dump_json()==before


@pytest.mark.parametrize('ids',[['unknown'],['hw-ev-trace','hw-ev-trace']])
def test_bound_hardware_rejects_unbound_evidence(prepared,ids):
    from chipchain.integrations.paired_agents import BoundHardwareAgent, HardwareBinding
    from chipchain.agents.contracts import HardwareAgentInput
    case,hw,_,_=prepare_inputs(**prepared)
    payload=dict(case_id=case.case_id,findings=[dict(finding_id='f1',summary='Synthetic',evidence_ids=ids,
        processor_behavior_ids=[],epistemic_status='derived')],trigger_hypotheses=[],abnormal_states=[],
        processor_behavior_ids=[],unresolved_questions=[])
    with pytest.raises(AgentStructuredOutputError,match='Unknown or duplicate'):
        BoundHardwareAgent(model=fake_model(HardwareBinding,payload)).invoke(
            HardwareAgentInput(case=case,deterministic_observations=hw))


def test_bound_report_requires_all_top_level_fields():
    from chipchain.integrations.paired_agents import HardwareBinding, CrossLayerBinding
    from pydantic import ValidationError
    for schema in (HardwareBinding,CrossLayerBinding):
        with pytest.raises(ValidationError):
            schema.model_validate({'case_id':'synthetic'})
