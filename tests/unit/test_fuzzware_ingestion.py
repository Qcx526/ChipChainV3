"""Offline semantic and malformed-input regressions, all bytes synthetic."""

import json
import os
import struct

import pytest
from pydantic import ValidationError
import yaml

from chipchain.agents.context import firmware_context
from chipchain.agents.contracts import FirmwareAgentInput
from chipchain.agents.firmware import FirmwareSecurityAgent
from chipchain.domain.behavior import BehaviorKind
from chipchain.domain.instruction import EncodingRepresentation
from chipchain.tools.contracts import (
    FirmwareObservation, FirmwareObservations, FirmwareObservationKind as Kind,
    ObservationRole, ObservationScope, MmioModelDetails,
)
from chipchain.tools.firmware.fuzzware import FuzzwareHeatPressScenarioAnalyzer
from chipchain.tools.firmware.fuzzware.readers import (
    FirmwareIngestionError, parse_configuration, parse_image, read_artifact,
)
from tests.firmware_fakes import BASE, make_case, reference, synthetic_config, synthetic_elf


def ingest(case):
    return FuzzwareHeatPressScenarioAnalyzer().analyze(case_id=case.case_id,target=case.target,artifacts=case.firmware_artifacts)


def config_read(data):
    return parse_configuration(data,'/virtual/config.yml','/virtual/image.bin')


def image_read(elf,binary):
    config=config_read(yaml.safe_dump(synthetic_config()).encode())
    return parse_image(elf,binary,config.regions['text'])


def test_ingestion_facts_and_offline_stub(tmp_path):
    case=make_case(tmp_path);batch=ingest(case)
    assert len(batch.observations)==8
    sites=[o for o in batch.observations if o.kind==Kind.STATIC_INSTRUCTION_SITE]
    assert len(sites)==1
    site=sites[0]
    assert site.details.raw_symbol_value==BASE|1
    assert site.details.canonical_function_address==BASE
    assert site.details.address==BASE+2 and site.details.elf_offset==0x102 and site.details.image_offset==2
    assert site.details.raw_bytes=='9969' and site.details.width_bits==16
    assert site.behaviors[0].decoded_instruction.representation==EncodingRepresentation.MEMORY_BYTES
    models=[o for o in batch.observations if o.kind==Kind.MMIO_MODEL]
    assert len(models)==5 and all(o.scope==ObservationScope.CONFIGURATION for o in models)
    assert {o.behaviors[0].attributes['direction'] for o in models}=={'read'}
    assert next(o for o in models if o.details.model_kind=='constant').details.parameters=={'val':123}
    assert all(o.role==ObservationRole.ANALYSIS_INPUT and o.scope!=ObservationScope.RUNTIME for o in batch.observations)
    inputs=FirmwareAgentInput(case=case,deterministic_observations=batch)
    result=FirmwareSecurityAgent().invoke(inputs)
    assert result.processor_behavior_ir.case_id==case.case_id
    assert len(result.processor_behavior_ir.behaviors)==6
    assert {b.kind for b in result.processor_behavior_ir.behaviors}=={BehaviorKind.INSTRUCTION,BehaviorKind.MMIO_ACCESS}
    assert not result.report.findings and not result.report.external_input_paths and not result.report.reachable_behaviors and not result.report.issue_anchors
    text=firmware_context(inputs)
    assert len(text)<64000 and 'OPAQUE_INPUT_MUST_NOT_ENTER_CONTEXT' not in text
    assert '4f50415155455f494e505554' not in text
    assert 'crash_observed' not in text and 'HardFault' not in text
    assert 'observed_value' not in text
    trigger=next(o for o in batch.observations if o.details.kind=='interrupt_trigger')
    assert not trigger.behaviors and trigger.details.tick_unit=='emulator_tick'


def test_typed_roundtrip_context_and_evidence_resolution(tmp_path):
    case=make_case(tmp_path);batch=ingest(case)
    copy_batch=FirmwareObservations.model_validate_json(batch.model_dump_json())
    assert copy_batch==batch and all(isinstance(o,FirmwareObservation) for o in copy_batch.observations)
    inputs=FirmwareAgentInput(case=case,deterministic_observations=copy_batch)
    assert FirmwareAgentInput.model_validate_json(inputs.model_dump_json())==inputs
    context=json.loads(firmware_context(inputs))
    refs={r['evidence_id']:r for o in context['observations'] for r in o['evidence']}
    for original, rendered in zip(batch.observations,context['observations']):
        for field in ['kind','role','scope','details']:
            assert rendered[field]==original.model_dump(mode='json',exclude_none=True)[field]
        for behavior in rendered['behaviors']:
            for item in [behavior,behavior.get('decoded_instruction')]:
                if item and 'evidence_ids' in item:
                    assert item['evidence_ids'] and all(key in refs for key in item['evidence_ids'])
    assert inputs.deterministic_observations==batch  # context did not mutate contracts


def test_oracle_default_and_rejection(tmp_path):
    case=make_case(tmp_path);batch=ingest(case)
    raw=batch.observations[0].model_dump();raw.pop('role')
    oracle=FirmwareObservation.model_validate(raw)
    assert oracle.role==ObservationRole.BENCHMARK_ORACLE
    batch.observations[0]=oracle
    with pytest.raises(ValueError,match='oracle'):
        FirmwareAgentInput(case=case,deterministic_observations=batch)


@pytest.mark.parametrize('field,value',[('scope','runtime'),('scope','artifact'),('kind','environment_input')])
def test_kind_scope_details_incompatible(tmp_path,field,value):
    raw=ingest(make_case(tmp_path)).observations[0].model_dump()
    raw[field]=value
    with pytest.raises(ValidationError):FirmwareObservation.model_validate(raw)


@pytest.mark.parametrize('parameters',[{'val':{'nested':1}},{'val':True},{'val':'123'},{'val':[1]},{'surprise':1}])
def test_parameters_reject_wrong_types(parameters):
    with pytest.raises(ValueError):
        MmioModelDetails(pc=BASE,mmio_address=0x40000000,access_size_bytes=4,
                         model_kind='constant',config_key='x',parameters=parameters)


def test_evidence_membership(tmp_path):
    case=make_case(tmp_path);batch=ingest(case)
    batch.observations[0].evidence[0].artifact_id='undeclared'
    with pytest.raises(ValueError,match='artifact'):
        FirmwareAgentInput(case=case,deterministic_observations=batch)


def test_nested_decoded_evidence_membership(tmp_path):
    case=make_case(tmp_path);batch=ingest(case)
    decoded=batch.observations[0].behaviors[0].decoded_instruction
    decoded.evidence=[decoded.evidence[0].model_copy(update={'artifact_id':'undeclared'})]
    with pytest.raises(ValueError,match='artifact'):
        FirmwareAgentInput(case=case,deterministic_observations=batch)


def test_literal_access_size_does_not_accept_bool():
    with pytest.raises(ValueError):
        MmioModelDetails(pc=BASE,mmio_address=0x40000000,access_size_bytes=True,
                         model_kind='unmodeled',config_key='x')


def test_context_compaction_rejects_conflicting_evidence(tmp_path):
    from chipchain.agents.runtime import AgentExecutionError
    case=make_case(tmp_path);batch=ingest(case)
    batch.observations[-1].evidence[0].evidence_id=batch.observations[-2].evidence[0].evidence_id
    inputs=FirmwareAgentInput(case=case,deterministic_observations=batch)
    with pytest.raises(AgentExecutionError,match='Conflicting'):
        firmware_context(inputs)


@pytest.mark.parametrize('data',[
    b'a: 1\na: 2\n',b'!Custom {a: 1}',b'!!python/object/apply:os.system [echo]',
    b'[1,2,3]',b'null',b'a: &x [1]\nb: *x',b'1: value',b'a: '+b'x'*513,
    b'['*14+b'0'+b']'*14,b'a: ['+b'0,'*257+b']',b'\xff',
])
def test_invalid_yaml(data):
    with pytest.raises(FirmwareIngestionError):config_read(data)


@pytest.mark.parametrize('mutation',[
    lambda c:c.update(handlers={}),
    lambda c:c['memory_map']['text'].update(ivt_offset=0),
    lambda c:c['memory_map']['text'].update(size=True),
    lambda c:c['interrupt_triggers']['trigger'].update(every_nth_tick='1000'),
    lambda c:c['interrupt_triggers']['trigger'].update(fuzz_mode='fuzzed'),
    lambda c:c['mmio_models']['constant']['constant_site'].update(access_size=True),
    lambda c:c['mmio_models']['constant']['constant_site'].update(pc=BASE+1),
    lambda c:c['mmio_models']['constant']['constant_site'].update(addr=0),
    lambda c:c['mmio_models'].update(custom={}),
    lambda c:c['memory_map']['ram'].update(base_addr=BASE),
])
def test_unsupported_yaml_subset(mutation):
    c=synthetic_config();mutation(c)
    with pytest.raises(FirmwareIngestionError):config_read(yaml.safe_dump(c).encode())


def test_model_bound_and_duplicate_identifier():
    c=synthetic_config()
    c['mmio_models']={'constant':{f'key{i}':{'pc':BASE,'addr':0x40000000,'access_size':4,'val':0} for i in range(129)}}
    with pytest.raises(FirmwareIngestionError,match='bound'):config_read(yaml.safe_dump(c).encode())
    c=synthetic_config();c['mmio_models']['set']['constant_site']=c['mmio_models']['set'].pop('set_site')
    with pytest.raises(FirmwareIngestionError,match='Duplicate'):config_read(yaml.safe_dump(c).encode())


def test_only_explicit_files_read_and_oracle_independence(tmp_path,monkeypatch):
    case=make_case(tmp_path);first=ingest(case)
    for name in ['README.md','run.sh','syms.yml','valid_basic_blocks.txt','bug-details']:
        (tmp_path/name).write_text('KNOWN ROOT CAUSE: injected oracle answer')
    opened=[];original=os.open
    def audited(path,*args,**kwargs):
        opened.append(str(path));return original(path,*args,**kwargs)
    monkeypatch.setattr(os,'open',audited)
    assert ingest(case)==first
    assert set(opened)=={a.path for a in case.firmware_artifacts} and len(opened)==4


def test_config_path_is_never_opened(tmp_path,monkeypatch):
    case=make_case(tmp_path);path=tmp_path/'config.yml'
    c=synthetic_config();c['memory_map']['text']['file']='undeclared.bin'
    path.write_text(yaml.safe_dump(c));case.firmware_artifacts[2]=reference(path,'firmware_config','yaml')
    opened=[];original=os.open
    def audited(path,*args,**kwargs):opened.append(str(path));return original(path,*args,**kwargs)
    monkeypatch.setattr(os,'open',audited)
    with pytest.raises(FirmwareIngestionError,match='reference'):ingest(case)
    assert opened==[str(path)]


def test_file_fingerprints_caps_and_roles(tmp_path):
    case=make_case(tmp_path);ref=case.firmware_artifacts[0]
    with pytest.raises(FirmwareIngestionError,match='bounded'):read_artifact(ref,10)
    ref.sha256='0'*64
    with pytest.raises(FirmwareIngestionError,match='fingerprint'):ingest(case)
    ref.sha256=None
    with pytest.raises(FirmwareIngestionError,match='require'):ingest(case)
    case.firmware_artifacts.pop()
    with pytest.raises(FirmwareIngestionError,match='four'):ingest(case)


def test_elf_load_lma_bss_and_symbols():
    elf,binary=synthetic_elf();image=image_read(elf,binary)
    assert len(image.segments)==3 and image.segments[-1].filesz==0
    assert image.segments[1].vaddr!=image.segments[1].paddr
    assert image.functions[0].raw_value==BASE|1 and image.functions[0].address==BASE
    assert image.entry==BASE|1


@pytest.mark.parametrize('offset,fmt,value',[
    (4,'B',2),(5,'B',2),(18,'H',243),(0,'I',0),(28,'I',0xfffffff0),
    (32,'I',0xfffffff0),(52+16,'I',0xfffffff0),(52+20,'I',0),
    (52+8,'I',0xfffffff0),(0x300+2*40+24,'I',200),
    (0x300+2*40+36,'I',8),(24,'I',BASE),
])
def test_unsupported_or_malformed_elf(offset,fmt,value):
    elf,binary=synthetic_elf();data=bytearray(elf);struct.pack_into('<'+fmt,data,offset,value)
    with pytest.raises(FirmwareIngestionError):image_read(bytes(data),binary)


def test_mismatching_and_truncated_bin():
    elf,binary=synthetic_elf()
    for bad in [b'wrong'+binary,binary[:-1]]:
        with pytest.raises(FirmwareIngestionError):image_read(elf,bad)


@pytest.mark.parametrize('code,pc,size',[
    (bytes.fromhex('d3f8841000bf'),BASE+2,None), # mid 32-bit instruction
    (bytes.fromhex('ffff'),BASE,None), # incomplete 32-bit prefix
    (bytes.fromhex('00bf9969'),BASE+2,0), # no sized function
    (bytes.fromhex('00bf9969'),BASE+2,5000), # function bound
])
def test_unresolved_site_retains_all_models(tmp_path,code,pc,size):
    case=make_case(tmp_path,code=code,pc=pc,symbol_size=size);batch=ingest(case)
    assert not any(o.kind==Kind.STATIC_INSTRUCTION_SITE for o in batch.observations)
    assert len([o for o in batch.observations if o.kind==Kind.MMIO_MODEL])==5
    assert any('configuration retained' in q for q in batch.unresolved_questions)
    assert {b.attributes['direction'] for o in batch.observations for b in o.behaviors}=={'unknown'}
