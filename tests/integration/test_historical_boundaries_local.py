"""Read-only real artifact integration. Missing local data is an explicit skip.

No Verilator rebuild, network, subprocess, LLM, or implicit output persistence.
"""
import json
from pathlib import Path

import pytest

from chipchain.firmware import mmio_grounding as m

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = ROOT / 'output/syn-e2e1-a/experiment-tn2kt3tu'
BASE = '030425ba50863f72ccf05051d35c198811d5248be1f79c3ce5d430968a315c5d'
TREES = ('f882b80ccd16c9de7828b399196f079ee3b982e43fc54784c3f6e015430f4e1b',
         '805480e150a838026c0b47dfe375a0548064381a4b175d79f9ea6bf02089b440')
ELFS = ('42fe38fb5c106242c81797ece513b5ef86fc453d2ef63299514d1e98e9c06641',
        'd2d845e6b0395ae28e156d6e9b60d1afc32ac99124fb84d4b17741edfa1af920')


@pytest.fixture(scope='module')
def real_records():
    if not (WORKSPACE / 'apparatus-result.json').is_file():
        pytest.skip('BLOCKED local dependency: frozen SYN-E2E1-A experiment-tn2kt3tu absent; not real acceptance')
    result=json.loads((WORKSPACE/'apparatus-result.json').read_text())
    assert result['controlled_source_delta']['reference_tree_sha256']==TREES[0]
    assert result['controlled_source_delta']['variant_tree_sha256']==TREES[1]
    by_pair={}
    for item in result['runs']:
        manifest=json.loads((WORKSPACE/item['manifest']).read_text())
        pair=(manifest['identity_inputs']['firmware_sha256'],manifest['identity_inputs']['rtl_tree_sha256'])
        assert pair in {(f,t) for f in ELFS for t in TREES} and pair not in by_pair
        by_pair[pair]=(item['manifest'],m.load_apparatus_run(WORKSPACE,item['manifest'],
            base_source=ROOT/'samples/hardware/ibex-simple-system/source',expected_base_sha=BASE,
            expected_rtl_sha=pair[1],expected_firmware_sha=pair[0]))
    assert len(by_pair)==4
    return by_pair


@pytest.mark.parametrize('firmware,rtl,command,read_value',[
    (0,0,0xa5,0),(0,1,0xa5,0xdead),(1,0,0xa4,0),(1,1,0xa4,0)])
def test_real_static_and_runtime_observations(real_records,firmware,rtl,command,read_value):
    _,(s,r,b,map_source)=real_records[(ELFS[firmware],TREES[rtl])]
    assert [(f.instruction_pc,f.address,f.operation,f.value) for f in s.static_facts]==[
        (0x100088,0x40000,'write',1),(0x100090,0x40004,'write',command),(0x100094,0x40008,'read',None)]
    assert [(o.request_cycle,o.response_cycle,o.address,o.operation,o.write_value,o.read_value) for o in r.runtime_observations]==[
        (11,12,0x40000,'write',1,None),(14,15,0x40004,'write',command,None),(16,17,0x40008,'read',None,read_value)]
    assert all(o.error==0 and o.completion_status=='completed_success' for o in r.runtime_observations)
    assert len(s.non_target_accesses)==2 and not s.unresolved_accesses
    assert [f.address for f in s.non_target_accesses]==[0x101000,0x20008]
    assert len(b.bindings)==3 and all(x.status=='unknown' for x in b.bindings)
    assert m.serialize(b)==m.serialize(m.bind_static_runtime(s,r))
    for obj in (s,r,b,map_source):
        assert type(obj).model_validate_json(m.serialize(obj))==obj


def test_real_shared_static_distinct_runtime_and_map_provenance(real_records):
    for firmware in ELFS:
        _,a=real_records[(firmware,TREES[0])];_,b=real_records[(firmware,TREES[1])]
        assert m.serialize(a[0])==m.serialize(b[0])
        assert a[1].set_id!=b[1].set_id
        assert a[0].static_facts[-1].fact_id==b[0].static_facts[-1].fact_id
        assert a[3].platform_map.map_id==b[3].platform_map.map_id
        assert a[3].map_evidence_id!=b[3].map_evidence_id
    assert real_records[(ELFS[0],TREES[0])][1][0].catalog_id!=real_records[(ELFS[1],TREES[0])][1][0].catalog_id


def test_existing_rvfi_is_diagnostic_not_automatic_bridge(real_records):
    for manifest_path,(s,r,b,_) in real_records.values():
        folder=(WORKSPACE/manifest_path).parent
        log=(folder/'trace_core_00000000.log').read_text()
        rows=[line.split() for line in log.splitlines()[1:]]
        # Actual PC/cycle records exist, but they carry neither monitor transaction
        # IDs nor an A manifest hash attachment. No guessed offset/order join.
        sites={int(row[2],16):int(row[1]) for row in rows}
        assert [sites[pc] for pc in (0x100088,0x100090,0x100094)]==[8,11,13]
        manifest=json.loads((folder/'manifest.json').read_text())
        assert 'processor_trace_sha256' not in manifest
        assert 'processor_trace_sha256' not in manifest['identity_inputs']
        assert all(x.status=='unknown' and not x.bridge_evidence_ids and len(x.candidate_static_fact_ids)==3 for x in b.bindings)
        assert r.runtime_observations[1].request_cycle==14


def test_real_xl2_unknown_byte_replay():
    from chipchain.firmware.capability import parse_firmware_capability
    from chipchain.hardware.behavior_contract import parse_hardware_behavior_contract
    from chipchain.cross_layer.capability_compatibility import (
        compare_capability_contract,serialize_compatibility_result,validate_compatibility_replay)
    base=ROOT/'output/ibex-simple-system:hello-test:paired-workspace'
    paths=(base/'fw-cap0-a7d884ec659e96b6/firmware_capability.json',
           ROOT/'output/encorpus:ibex:driver:743/xl1-48dba3c5ba26c30d/hardware_behavior_contract.json',
           base/'xl2-34bfee41ac1fc6b4/compatibility_result.json')
    if not all(p.is_file() for p in paths):
        pytest.skip('BLOCKED local XL2 artifacts missing; not a successful UNKNOWN replay')
    before=[m.file_sha(p) for p in paths]
    fw=parse_firmware_capability(paths[0].read_text());hw=parse_hardware_behavior_contract(paths[1].read_text())
    result=compare_capability_contract(fw,hw);validate_compatibility_replay(result,fw,hw)
    assert result.overall_result=='unknown'
    assert result.result_id=='xlcompat:34bfee41ac1fc6b44fe6233bfaae8c540f8fdce5deb6ffbaf37fd80f71538ded'
    assert serialize_compatibility_result(result)==paths[2].read_text()
    assert before==[m.file_sha(p) for p in paths]
