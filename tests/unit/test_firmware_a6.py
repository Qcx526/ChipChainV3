"""A6 semantics and binding tests; only tiny structured real-regression values."""
import json
from pathlib import Path
import pytest
from pydantic import ValidationError
from chipchain.domain.evidence import EvidenceRef
from chipchain.firmware.control_flow_grounding import (
    FunctionInterval, SourceArtifact, FirmwareControlFlowGroundingCatalog, Capabilities, canonical, sha256, parse_catalog)
from chipchain.firmware.riscv_control_flow import resolve_transfer
from chipchain.firmware.grounding_catalog import resolve_ownership
from chipchain.firmware.grounding_support import (
    TargetClaim, OwnershipClaim, GroundedFirmwareModelReport, evaluate_claim, validate_claims, build_projection)

SHA='a'*64
EV=EvidenceRef(evidence_id='ev',artifact_id='elf',source_type='deterministic_analyzer',summary='Synthetic static bytes and intervals',epistemic_status='derived')


def resolve(word,pc=0x1000,width=4,architecture='riscv'):
    return resolve_transfer(case_id='case',pc=pc,encoding=word.to_bytes(width,'little'),architecture=architecture,
                            artifact_id='elf',evidence_ids=['ev'],source_sha256=SHA)


def jal(offset,rd=0):
    n=offset&0x1fffff
    return ((n>>20)<<31)|(((n>>1)&1023)<<21)|(((n>>11)&1)<<20)|(((n>>12)&255)<<12)|(rd<<7)|0x6f


def branch(offset,funct3=0):
    n=offset&0x1fff
    return ((n>>12)<<31)|(((n>>5)&63)<<25)|(2<<20)|(1<<15)|(funct3<<12)|(((n>>1)&15)<<8)|(((n>>11)&1)<<7)|0x63


@pytest.mark.parametrize('offset',[-1048576,-4,0,2,710,1048574])
@pytest.mark.parametrize('rd,kind',[(0,'direct_jump'),(1,'direct_call'),(5,'direct_call')])
def test_jal_signed_targets(offset,rd,kind):
    f=resolve(jal(offset,rd))
    assert f.resolution_status=='resolved_direct' and f.resolved_target_pc==(0x1000+offset)&0xffffffff
    assert f.transfer_kind==kind and f.fallthrough_pc == 0x1004
    assert f.decoded_immediate == offset and f.destination_register == f'x{rd}'
    assert f.fallthrough_semantics == 'sequential_address_not_branch_alternative'


@pytest.mark.parametrize('funct3',[0,1,4,5,6,7])
@pytest.mark.parametrize('offset',[-4096,-2,0,4094])
def test_conditional_branch(offset,funct3):
    f=resolve(branch(offset,funct3))
    assert f.resolved_target_pc==(0x1000+offset)&0xffffffff and f.fallthrough_pc==0x1004
    assert f.transfer_kind=='conditional_branch'


@pytest.mark.parametrize('word,width,kind',[(0x00008067,4,'return'),(0x000280e7,4,'indirect_call'),
    (0x00030067,4,'indirect_jump'),(0x8082,2,'return'),(0x9282,2,'indirect_call'),(0x30200073,4,'return')])
def test_indirect_never_has_concrete_target(word,width,kind):
    f=resolve(word,width=width)
    assert f.transfer_kind==kind and f.resolution_status=='indirect' and f.resolved_target_pc is None


@pytest.mark.parametrize('word,width,target,kind',[(0xa009,2,0x1002,'direct_jump'),(0x2009,2,0x1002,'direct_call'),
    (0xc009,2,0x1002,'conditional_branch'),(0xe009,2,0x1002,'conditional_branch'),
    (0xbffd,2,0x0ffe,'direct_jump'),(0xdc7d,2,0x0ffe,'conditional_branch')])
def test_compressed_control_transfers(word,width,target,kind):
    f=resolve(word,width=width);assert f.resolved_target_pc==target and f.transfer_kind==kind


def test_invalid_unsupported_and_powerpc():
    assert resolve(0).resolution_status=='invalid'
    assert resolve(0x13,pc=1).resolution_status=='invalid'
    assert resolve(0x13).resolution_status=='unsupported'
    f=resolve(0x48000004,architecture='powerpc')
    assert f.resolution_status=='unsupported' and f.provenance.architecture=='powerpc'


def interval(identifier,start,end,name='same',kind='elf_symbol'):
    return FunctionInterval(function_id=identifier,function_name=name,start=start,end_exclusive=end,
        source_kind=kind,source_ids=['elf'],evidence_ids=['ev'])


def own(pc,functions):
    return resolve_ownership(case_id='case',site_pc=pc,functions=functions,source_id='elf',source_sha256=SHA,
                             evidence_id='ev',architecture='riscv')


@pytest.mark.parametrize('pc,status',[(0x1000,'unique'),(0x100f,'unique'),(0x1010,'missing'),(0xfff,'missing')])
def test_half_open_ownership(pc,status):
    assert own(pc,[interval('f',0x1000,0x1010)]).ownership_status==status


def test_overlap_unknown_size_and_source_priority():
    assert own(12,[interval('a',10,20),interval('b',11,25)]).ownership_status=='ambiguous'
    assert own(12,[interval('unknown',10,None)]).ownership_status=='missing'
    assert own(10,[interval('unknown',10,None)]).owner_function_id is None
    assert own(12,[interval('a',10,20),interval('b',11,25,kind='cfg_metadata')]).owner_function_id=='a'
    assert own(12,[interval('unknown',10,None),interval('b',11,25,kind='static_structure')]).owner_function_id=='b'


def catalog(transfers=(),owners=(),functions=()):
    return FirmwareControlFlowGroundingCatalog(case_id='case',architecture='riscv',transfer_facts=list(transfers),
        ownership_facts=list(owners),functions=list(functions),source_artifacts=[SourceArtifact(artifact_id='elf',sha256=SHA,size_bytes=4,format='elf')],
        evidence_catalog=[EV],capabilities=Capabilities(supports_direct_target_resolution=True),limitations=['static only'])


@pytest.fixture
def known_failure():
    data=json.loads(Path('tests/data/firmware_a6/paired_regression.json').read_text())
    t=data['target'];f=resolve(int.from_bytes(bytes.fromhex(t['encoding_little_endian']),'little'),pc=t['pc'])
    functions=[interval(d['name'],d['start'],d['start']+d['size'],d['name']) for d in data['ownership']['intervals']]
    owner=own(data['ownership']['site_pc'],functions)
    return data,catalog([f],[owner],functions)


def test_actual_wrong_target_rejected_and_right_target_accepted(known_failure):
    data,c=known_failure;fact=c.transfer_facts[0]
    assert fact.resolved_target_pc==data['target']['correct_target']
    for target,status in [(data['target']['wrong_target'],'incompatible'),(data['target']['correct_target'],'supported')]:
        result=evaluate_claim(TargetClaim(claim_id='target',claim_type='control_transfer_target',fact_id=fact.fact_id,
            instruction_pc=fact.instruction_pc,claimed_target_pc=target,raw_model_summary='diagnostic only'),c)
        assert result.status==status and result.evidence
        if status=='incompatible':assert result.reason_code=='control_transfer_target_mismatch'


def test_actual_wrong_owner_rejected_and_right_owner_accepted(known_failure):
    data,c=known_failure;fact=c.ownership_facts[0]
    assert fact.owner_function_name==data['ownership']['correct_function']
    for owner,status in [('puthex','incompatible'),('puts','supported')]:
        result=evaluate_claim(OwnershipClaim(claim_id='owner',claim_type='function_ownership',fact_id=fact.fact_id,
            site_pc=fact.site_pc,owner_function_id=owner,raw_model_summary='diagnostic only'),c)
        assert result.status==status and result.evidence
        if status=='incompatible':assert result.reason_code=='function_ownership_mismatch'


def test_indirect_ambiguous_missing_unsupported():
    f=resolve(0x00008067);c=catalog([f])
    r=evaluate_claim(TargetClaim(claim_id='t',claim_type='control_transfer_target',fact_id=f.fact_id,
        instruction_pc=f.instruction_pc,claimed_target_pc=123,raw_model_summary=''),c)
    assert r.status=='unsupported' and r.reason_code=='indirect_target_not_deterministically_resolved'
    functions=[interval('a',10,20),interval('b',11,21)]
    for pc in (12,30):
        o=own(pc,functions);c=catalog(owners=[o],functions=functions)
        assert evaluate_claim(OwnershipClaim(claim_id='o',claim_type='function_ownership',fact_id=o.fact_id,
            site_pc=pc,owner_function_id='a',raw_model_summary=''),c).status=='unsupported'


def test_generic_evidence_id_cannot_support_target(known_failure):
    _,c=known_failure
    claim=TargetClaim(claim_id='x',claim_type='control_transfer_target',fact_id='ev',instruction_pc=0x100080,
        claimed_target_pc=0x100346,raw_model_summary='')
    assert evaluate_claim(claim,c).status=='unsupported'


def test_serialization_determinism(known_failure):
    _,c=known_failure
    text=canonical(c);clone=parse_catalog(text)
    clone.functions.reverse();clone.ownership_facts.reverse();clone.transfer_facts.reverse()
    assert canonical(clone)==text and sha256(clone)==sha256(c)
    for fact in [*c.transfer_facts,*c.ownership_facts]:
        assert canonical(type(fact).model_validate_json(canonical(fact)))==canonical(fact)


def test_no_raw_prose_or_rejected_claims_enter_canonical(known_failure):
    _,c=known_failure;t=c.transfer_facts[0];o=c.ownership_facts[0]
    model=GroundedFirmwareModelReport(case_id='case',claims=[
        TargetClaim(claim_id='bad',claim_type='control_transfer_target',fact_id=t.fact_id,instruction_pc=t.instruction_pc,
                    claimed_target_pc=0x1002c6,raw_model_summary='RAW WRONG TARGET'),
        OwnershipClaim(claim_id='good',claim_type='function_ownership',fact_id=o.fact_id,site_pc=o.site_pc,
                       owner_function_id=o.owner_function_id,raw_model_summary='EVEN ACCEPTED RAW PROSE STAYS DIAGNOSTIC')],
        diagnostic_questions=['UNTRUSTED QUESTION'])
    before=model.model_dump_json()
    report,audit=validate_claims(model,c,allowed_fact_ids={t.fact_id,o.fact_id})
    assert len(report.findings)==1 and audit.accepted_claim_ids==['good'] and audit.rejected_claim_ids==['bad']
    assert 'RAW' not in report.model_dump_json() and 'UNTRUSTED' not in report.model_dump_json()
    assert model.model_dump_json()==before
    report2,audit2=validate_claims(model,c,allowed_fact_ids=set())
    assert not report2.findings and not audit2.accepted_claim_ids


def test_projection_is_bounded_and_not_authority(known_failure):
    _,c=known_failure;p=build_projection(c,{0x100080,0x1000a0})
    p['transfer_facts'][0]['resolved_target_pc']=123
    assert c.transfer_facts[0].resolved_target_pc==0x100346
    with pytest.raises(ValueError,match='budget'):build_projection(c,{0x100080,0x1000a0},max_facts=0)
    with pytest.raises(ValidationError):Capabilities(supports_direct_target_resolution=True,supports_path_feasibility=True)


def test_invalid_reserved_branch_and_endianness():
    assert resolve(branch(4,2)).resolution_status=='invalid'
    f=resolve_transfer(case_id='case',pc=0x1000,encoding=bytes.fromhex('0040006f'),architecture='riscv',
        artifact_id='elf',evidence_ids=['ev'],source_sha256=SHA,byteorder='big')
    assert f.resolution_status=='unsupported'


def test_ownership_names_are_not_identity():
    functions=[interval('left',0,10,'duplicate'),interval('right',10,20,'duplicate')]
    assert own(12,functions).owner_function_id=='right'
    functions=[interval('anonymous',0,10,None)]
    assert own(0,functions).owner_function_id=='anonymous'


def test_provenance_and_evidence_are_mandatory(known_failure):
    _,c=known_failure
    data=c.model_dump();data['transfer_facts'][0]['evidence_ids']=['invented']
    with pytest.raises(ValidationError):FirmwareControlFlowGroundingCatalog.model_validate(data)
    data=c.model_dump();data['transfer_facts'][0]['provenance']['input_sha256']='b'*64
    with pytest.raises(ValidationError):FirmwareControlFlowGroundingCatalog.model_validate(data)


def test_a4_overlap_detects_mismatch_without_modifying_old_catalog(tmp_path):
    from tests.test_static_relations import canonical as arm_fixture,build
    from chipchain.firmware.grounding_compatibility import compare_a4
    data=arm_fixture(tmp_path);a4=build(data)
    relation=next(r for r in a4.relations if r.kind=='mmio_function_containment' and r.status=='confirmed_static')
    c=catalog(owners=[own(relation.site_address,[interval('owner',relation.target.address,relation.target.address+100)])],
              functions=[interval('owner',relation.target.address,relation.target.address+100)])
    # This test checks structural comparison; synthetic evidence/source is rebound
    # to the exact independently built A4 synthetic artifact identity.
    values=c.model_dump(exclude={'catalog_sha256'});values['case_id']=a4.case_id
    values['source_artifacts'][0]['sha256']=a4.source_identities.elf_sha256
    values['ownership_facts'][0]['case_id']=a4.case_id
    values['ownership_facts'][0]['provenance']['input_sha256']=a4.source_identities.elf_sha256
    c=FirmwareControlFlowGroundingCatalog.model_validate(values)
    old=a4.model_dump_json()
    checks=compare_a4(c,a4)
    assert next(r for r in checks if r.source_id==relation.relation_id).status=='agree'
    # Different but containing interval, with the same source identity, must be diagnosed.
    c.functions[0].start-=2;c.ownership_facts[0].function_start-=2
    assert next(r for r in compare_a4(c,a4) if r.source_id==relation.relation_id).status=='conflict'
    assert a4.model_dump_json()==old
