"""Evidence contracts, canonical replay and fail-closed compatibility boundaries."""
import hashlib
import json
import pytest
from pydantic import ValidationError
from chipchain.firmware.control_flow_grounding import canonical, parse_catalog, serialize_catalog
from chipchain.firmware.grounding_support import build_projection
from chipchain.firmware.grounding_compatibility import compatibility_preflight, GroundingCompatibilityConflict
from tests.unit.test_firmware_a6 import catalog, resolve, jal, own, interval


def test_catalog_embedded_hash_excludes_itself_and_detects_tampering():
    c=catalog([resolve(jal(4))])
    assert c.catalog_sha256 == hashlib.sha256(canonical(c.model_dump(mode='json',exclude={'catalog_sha256'})).encode()).hexdigest()
    changed=json.loads(serialize_catalog(c));changed['limitations'].append('tampered')
    with pytest.raises(ValidationError,match='Catalog SHA'):
        parse_catalog(json.dumps(changed))
    assert serialize_catalog(parse_catalog(serialize_catalog(c))) == serialize_catalog(c)


def test_projection_order_and_hash_are_deterministic():
    functions=[interval('one',0x1000,0x1004),interval('two',0x1004,0x1010)]
    c=catalog([resolve(jal(4)),resolve(jal(-4),pc=0x1004)],
              [own(0x1000,functions),own(0x1004,functions)],functions)
    reordered=c.model_dump()
    for key in ('transfer_facts','ownership_facts','functions','source_artifacts','evidence_catalog','limitations'):
        reordered[key].reverse()
    other=type(c).model_validate(reordered)
    first=build_projection(c,[0x1000,0x1004]);second=build_projection(other,[0x1004,0x1000])
    assert json.dumps(first)==json.dumps(second)
    assert canonical(c)==canonical(other) and c.catalog_sha256==other.catalog_sha256
    assert len(first['transfer_facts'])==2 and first['target']['architecture']=='riscv'


@pytest.mark.parametrize('architecture',['arm','riscv','powerpc','x86','unknown'])
def test_fact_preserves_architecture_and_decoder_context(architecture):
    f=resolve(jal(4),architecture=architecture)
    assert f.architecture.value==architecture==f.provenance.architecture.value
    assert f.resolution_method==f.provenance.method
    assert f.source_artifact_ids==[f.source_artifact_id]
    assert f.decoder_mode.startswith(architecture+':32:little:')
    if architecture!='riscv':assert f.resolution_status=='unsupported'


def test_conflict_is_persisted_and_blocks_regression(monkeypatch):
    import chipchain.firmware.grounding_compatibility as module
    c=catalog();written={};calls=[]
    monkeypatch.setattr(module,'compare_a4',lambda *_:[module.CompatibilityDiagnostic(
        source='A4',source_id='frozen-relation',status='conflict',reason='direct_target_mismatch')])
    with pytest.raises(GroundingCompatibilityConflict,match='before model invocation'):
        compatibility_preflight(c,write=lambda k,v:written.update({k:v}),a4=object())
        calls.append('model invocation')
    assert calls==[]
    assert written['firmware_grounding_compatibility.json']['blocked'] is True
    assert written['firmware_grounding_compatibility.json']['results'][0]['status']=='conflict'


def test_absent_overlap_is_not_agreement():
    result=compatibility_preflight(catalog(),write=lambda *_:None)
    assert not result['blocked']
    assert {r['status'] for r in result['results']}=={'not_comparable'}


def test_capabilities_do_not_invent_target_input_control():
    caps=catalog().capabilities.model_dump()
    for key in ('supports_indirect_runtime_resolution','supports_path_feasibility',
                'supports_external_input_controllability','supports_runtime_reachability_from_interface','supports_security_impact'):
        assert caps[key] is False
        with pytest.raises(ValidationError):type(catalog().capabilities).model_validate({**caps,key:True})


def test_chinese_report_separates_claim_fact_evidence_and_unknowns(tmp_path):
    from chipchain.firmware.grounding_report import render_report
    from chipchain.firmware.grounding_support import TargetClaim,evaluate_claim
    fact=resolve(jal(4));c=catalog([fact])
    claim=TargetClaim(claim_id='wrong',claim_type='control_transfer_target',fact_id=fact.fact_id,
                     instruction_pc=0x1000,claimed_target_pc=0x1008,raw_model_summary='原始错误叙述')
    result=evaluate_claim(claim,c)
    artifacts={'analysis_run.json':dict(status='completed',stages=[]),
        'research_validation.json':dict(validation_context='paired_rtl_runtime_regression'),
        'firmware_model_claims.diagnostic.json':dict(claims=[claim.model_dump()]),
        'firmware_support_validation.json':dict(results=[result.model_dump(mode='json')],accepted_claim_ids=[],rejected_claim_ids=['wrong']),
        'cross_layer_analysis_report.json':dict(candidates=[])}
    for name,data in artifacts.items():(tmp_path/name).write_text(json.dumps(data,ensure_ascii=False))
    text=render_report(tmp_path)
    for expected in ('0x1008','0x1004','incompatible','control_transfer_target_mismatch','证据来源','elf / ev',
                     '原始错误叙述','paired_rtl_runtime_regression','未知 / 缺少证据','不能据此声称平台安全'):
        assert expected in text


def test_projection_character_budget_is_enforced():
    c=catalog([resolve(jal(4))])
    with pytest.raises(ValueError,match='character budget'):
        build_projection(c,{0x1000},max_chars=100)
