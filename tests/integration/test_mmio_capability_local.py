"""Read-only integration over the frozen BRIDGE1 collection; no simulator calls."""
from pathlib import Path

import pytest

from chipchain.firmware import capability as cap
from chipchain.firmware import mmio_grounding as grounding
from chipchain.firmware.mmio_capability import materialize_mmio
from tests.integration import test_execution_bridge_local as frozen_bridge
from tests.integration import test_historical_boundaries_local as frozen_b1

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = ROOT / 'output/syn-e2e1-bridge1/joint-e358hh72'


def replay_local():
    manifest = WORKSPACE / 'local-reproduction-manifest.json'
    if not manifest.is_file():
        pytest.skip('BLOCKED: frozen BRIDGE1 collection unavailable locally')
    local = grounding.read_json(manifest.read_bytes())
    assert len(local['records']) == 4
    result = []
    for record in local['records']:
        folder = WORKSPACE / record['directory']
        prepared = frozen_bridge.runner.prepare(ROOT, record['upstream_manifest'])
        joint, runtime, bridge = frozen_bridge.runner.consume_run(prepared, folder)
        assert grounding.serialize(bridge) == (folder / 'execution-bridges.json').read_text()
        assert joint.joint_run_id == record['joint_run_id']
        assert len(bridge.bindings) == 3 and all(b.overall_status == 'bound' for b in bridge.bindings)
        kwargs = dict(elf_bytes=prepared['elf'].read_bytes(), bridge=bridge, replay_inputs=dict(
            runtime=runtime, platform=prepared['platform'], inputs=prepared['inputs'],
            bus_bytes=(folder/'synthetic-mmio.jsonl').read_bytes(),
            processor_bytes=(folder/'trace_core_00000000.log').read_bytes(),
            stdout_bytes=(folder/'process.stdout.log').read_bytes(),
            stderr_bytes=(folder/'process.stderr.log').read_bytes()))
        capabilities = materialize_mmio(prepared['static'], **kwargs)
        static_caps = materialize_mmio(prepared['static'], elf_bytes=kwargs['elf_bytes'])
        result.append(dict(joint=joint, static=prepared['static'], bridge=bridge,
                           capabilities=capabilities, static_capabilities=static_caps, kwargs=kwargs))
    return result


@pytest.fixture(scope='module')
def real_capabilities():
    return replay_local()


def test_real_four_contexts_twelve_executed_capabilities(real_capabilities):
    static_by_elf = {}
    context_ids = set()
    combinations = set()
    for record in real_capabilities:
        joint = record['joint'];bridge = record['bridge'];capabilities = record['capabilities']
        fw_index = frozen_bridge.runner.FIRMWARE_SHAS.index(joint.firmware_sha256)
        rtl_index = frozen_b1.TREES.index(joint.rtl_tree_sha256)
        combinations.add((fw_index, rtl_index))
        command = (0xa5,0xa4)[fw_index]
        assert len(capabilities) == 3
        for capability, address, value in zip(capabilities,(0x40000,0x40004,0x40008),(1,command,None)):
            numeric = {c.kind:c.domain.exact for c in capability.constraints if isinstance(c,cap.NumericConstraint)}
            assert numeric['address'] == address and numeric['access_width'] == 32
            assert numeric.get('value') == value
            assert ('value' in numeric) == (value is not None)
            assert capability.entry.execution_status == 'source_instruction_retired'
            assert len(capability.retirement_evidence) == 1
            assert capability.origin.kind == 'normal_behavior'
            assert capability.primitives[0].control.status == 'not_established'
            assert capability.primitives[0].basis == 'static_instruction'
            assert joint.joint_run_id in capability.evidence_ids
            assert cap.parse_firmware_capability(cap.serialize_firmware_capability(capability)) == capability
            context_ids.add(capability.capability_id)
        primitive_static = [(c.primitives,c.constraints,c.origin,c.scope) for c in capabilities]
        assert primitive_static == [(c.primitives,c.constraints,c.origin,c.scope) for c in record['static_capabilities']]
        serialized = tuple(cap.serialize_firmware_capability(c) for c in record['static_capabilities'])
        previous = static_by_elf.setdefault(joint.firmware_sha256,serialized)
        assert previous == serialized
        assert bridge.processor_observations[-1].read_value == (0xdead if (fw_index,rtl_index)==(0,1) else 0)
    assert combinations == {(0,0),(0,1),(1,0),(1,1)}
    assert len(context_ids) == 12 and len(static_by_elf) == 2


def test_real_processor_copy_tamper_fails(real_capabilities):
    rec=real_capabilities[0];kwargs={**rec['kwargs'],'replay_inputs':dict(rec['kwargs']['replay_inputs'])}
    kwargs['replay_inputs']['processor_bytes'] += b'corruption\n'
    with pytest.raises(ValueError):materialize_mmio(rec['static'],**kwargs)


def test_frozen_b1_and_xl2_results_unchanged(real_capabilities):
    # Reuse the frozen read-only replay assertions without starting tools.
    manifests=grounding.read_json((ROOT/'output/syn-e2e1-a/experiment-tn2kt3tu/apparatus-result.json').read_bytes())['runs']
    records={}
    for item in manifests:
        p=frozen_bridge.runner.prepare(ROOT,item['manifest'])
        identity=p['inputs']
        loaded=grounding.load_apparatus_run(p['workspace'],item['manifest'],
            base_source=ROOT/'samples/hardware/ibex-simple-system/source',
            expected_base_sha=frozen_bridge.runner.bridge.BASE_SHA,
            expected_rtl_sha=identity['rtl_tree_sha256'],expected_firmware_sha=identity['firmware_sha256'])
        records[(identity['firmware_sha256'],identity['rtl_tree_sha256'])]=(item['manifest'],loaded)
    frozen_bridge.test_old_b1_twelve_unknown_preserved(records)
    frozen_b1.test_real_xl2_unknown_byte_replay()
