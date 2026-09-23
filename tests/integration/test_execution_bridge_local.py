"""Read-only replay of local frozen execution bridges and historical boundary."""
import importlib.util
import json
from pathlib import Path
import shutil

import pytest

from chipchain.firmware import mmio_grounding as b1
from chipchain.firmware import mmio_execution_bridge as b
from tests.integration.test_historical_boundaries_local import real_records

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('bridge_collector',ROOT/'experiments/syn_e2e1/bridge_run.py')
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)


def evaluate(out):
    local=json.loads((out/'local-reproduction-manifest.json').read_text())
    assert local['real_simulations']==4 and local['simulator_builds']==local['llm_calls']==0
    assert len(local['records'])==4
    static_by_firmware={};outcomes=[]
    for rec in local['records']:
        p=runner.prepare(ROOT,rec['upstream_manifest']);folder=out/rec['directory']
        joint,runtime,result=runner.consume_run(p,folder)
        assert joint.joint_run_id==rec['joint_run_id'] and result.set_id==rec['bridge_set_id']
        assert b1.serialize(result)==(folder/'execution-bridges.json').read_text()
        assert b.render_report(result,p['static'])==(folder/'report-bridge1-zh.md').read_text()
        assert len(result.processor_observations)==len(result.bus_observations)==len(result.bindings)==3
        assert [x.overall_status for x in result.bindings]==['bound']*3
        assert [o.pc for o in result.processor_observations]==[0x100088,0x100090,0x100094]
        assert [o.address for o in result.processor_observations]==[0x40000,0x40004,0x40008]
        assert all(o.byte_mask is None for o in result.processor_observations)
        assert result.processor_observations[0].write_value==1
        key=(runner.FIRMWARE_SHAS.index(joint.firmware_sha256),b.APPROVED_TREES.index(joint.rtl_tree_sha256))
        command=(0xa5,0xa4)[key[0]];read_value=0xdead if key==(0,1) else 0
        assert result.processor_observations[1].write_value==command
        assert result.processor_observations[2].read_value==runtime.runtime_observations[2].read_value==read_value
        assert p['static'].static_facts[-1].value is None
        previous=static_by_firmware.setdefault(joint.firmware_sha256,b1.serialize(p['static']))
        assert previous==b1.serialize(p['static'])
        outcomes.append(key)
    assert set(outcomes)=={(0,0),(0,1),(1,0),(1,1)}


@pytest.fixture(scope='module')
def collected():
    parent=ROOT/'output/syn-e2e1-bridge1'
    candidates=[]
    for p in parent.glob('joint-*/local-reproduction-manifest.json'):
        local=json.loads(p.read_text())
        # Historical collector/producer hashes describe collection, not a reason
        # to skip byte-verified replay after a validation-only code correction.
        if local.get('schema_version')=='bridge1-local-reproduction/v1' and len(local.get('records',[]))==4:
            candidates.append(p.parent)
    if not candidates:pytest.skip('BLOCKED local dependency: no collected BRIDGE1 joint run')
    return sorted(candidates)[-1]


def test_collected_joint_run_replay(collected):
    evaluate(collected)


def test_real_processor_file_tamper_rejected(collected,tmp_path):
    local=json.loads((collected/'local-reproduction-manifest.json').read_text());rec=local['records'][0]
    source=collected/rec['directory'];copy=tmp_path/'altered';shutil.copytree(source,copy)
    processor=copy/'trace_core_00000000.log';processor.write_bytes(processor.read_bytes()+b'bad line\n')
    with pytest.raises(ValueError):runner.consume_run(runner.prepare(ROOT,rec['upstream_manifest']),copy)


def test_old_b1_twelve_unknown_preserved(real_records):
    bindings=[x for _,(_,_,binding,_) in real_records.values() for x in binding.bindings]
    assert len(bindings)==12 and all(x.status=='unknown' for x in bindings)
    preview=ROOT/'output/syn-e2e1-b1/preview-x2hq53at'
    local=json.loads((preview/'local-reproduction-manifest.json').read_text())
    by_input={path:values for path,values in real_records.values()}
    for rec in local['records']:
        s,r,binding,_=by_input[rec['input_manifest']]
        assert (preview/rec['static_path']).read_text()==b1.serialize(s)
        directory=preview/rec['runtime_directory']
        assert (directory/'runtime-observations.json').read_text()==b1.serialize(r)
        assert (directory/'static-runtime-bindings.json').read_text()==b1.serialize(binding)
