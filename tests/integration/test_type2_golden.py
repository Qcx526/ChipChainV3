"""Four frozen joint runs, one controlled Variant contract and four golden outcomes."""
from dataclasses import replace
from functools import lru_cache
from pathlib import Path
import json

import pytest

from chipchain.firmware import capability as cap
from chipchain.firmware import mmio_grounding as b1
from chipchain.firmware.mmio_capability import materialize_mmio
from chipchain.hardware import behavior_contract as hw
from chipchain.cross_layer import type2_verifier as v
from tests.integration import test_execution_bridge_local as frozen_bridge
from tests.integration import test_historical_boundaries_local as frozen_b1

ROOT=Path(__file__).resolve().parents[2]
A=ROOT/'output/syn-e2e1-a/experiment-tn2kt3tu'
BRIDGE=ROOT/'output/syn-e2e1-bridge1/joint-e358hh72'
CAPS=ROOT/'output/mmio-capability/adapter-l2ix1eun'


def contract_and_source(variant_run):
    ref_manifest=(A/'a-source-files.json').read_bytes()
    var_manifest=(A/'b-source-files.json').read_bytes()
    ref_peripheral=(A/'sources/a'/v.PERIPHERAL).read_bytes()
    var_peripheral=(A/'sources/b'/v.PERIPHERAL).read_bytes()
    source=v.ControlledSourceEvidence(
        delta_bytes=(A/'controlled-source-delta.json').read_bytes(),
        reference_manifest_bytes=ref_manifest,variant_manifest_bytes=var_manifest,
        reference_peripheral_bytes=ref_peripheral,variant_peripheral_bytes=var_peripheral,
        variant_patch_bytes=(ROOT/'experiments/syn_e2e1/variant.patch').read_bytes())
    proof=v.verify_controlled_source(source)
    source_id='synthetic-spec:'+b1.bytes_sha(ref_peripheral)
    bind=dict(source_artifact_ids=[source_id],evidence_ids=[source_id+':definition'],
        provenance=[dict(source_kind='synthetic_fixture',source_artifact_ids=[source_id])])
    formal=dict(formalization_status='formalized',**bind)
    enable='SyntheticPeripheral.ENABLE';status='SyntheticPeripheral.STATUS'
    contract=hw.build_hardware_behavior_contract(hw.HardwareBehaviorContractInput.model_validate(dict(
        architecture='riscv',
        platform=dict(target=dict(architecture='riscv',processor_id=variant_run.bridge.platform_proof.rule,
                word_size_bits=32),platform_id=variant_run.static.target_binding.map_id,
                rtl_identity='rtl-tree:'+v.VAR_TREE,rtl_revision='rtl-tree:'+v.VAR_TREE,**bind),
        preconditions=[dict(condition_id='type2:enable-prestate',condition_kind='hardware_mode',
                description='ENABLE is 1 immediately before accepted COMMAND',
                required_relation=dict(subject=enable,operator='eq',operands=[1]),**formal)],
        trigger=[
            dict(condition_id='type2:enable-write',condition_kind='MMIO_access',
                description='Accepted ENABLE=1 full-word write',access=dict(atom_id='type2:enable-atom',
                    address=0x40000,access='write',width_bits=32,value_constraint=dict(operator='eq',value=1)),**formal),
            dict(condition_id='type2:command-write',condition_kind='MMIO_access',
                description='Accepted COMMAND=A5 full-word write',access=dict(atom_id='type2:command-atom',
                    address=0x40004,access='write',width_bits=32,value_constraint=dict(operator='eq',value=0xa5)),**formal),
            dict(condition_id='type2:write-order',condition_kind='ordering',
                description='ENABLE write precedes COMMAND in same reset epoch',
                ordering=dict(atom_id='type2:order-atom',before_atom_id='type2:enable-write',
                    after_atom_id='type2:command-write'),**formal)],
        deviation=[dict(condition_id='type2:status-deviation',deviation_kind='wrong_value',
            description='Controlled STATUS wrong value after A5 trigger',affected_component=status,
            expected_behavior=dict(subject=status,operator='eq',operands=[0]),
            deviating_behavior=dict(subject=status,operator='eq',operands=[0xdead]),
            specification_ref=source_id,hardware_constraint_status='specified',**formal)],
        observation=[dict(condition_id='type2:status-observation',observable_kind='register_value',
            description='Post-update internal STATUS sample and bus-visible response must agree',
            deviation_ids=['type2:status-deviation'],observable_target=status,
            judgement_kind='comparison',required_backend='controlled-syn-mmio-postupdate+busread/v1',
            expected_observation=dict(subject=status,operator='eq',operands=[0]),
            deviation_observation=dict(subject=status,operator='eq',operands=[0xdead]),
            evidence_requirement='same joint run, post-update internal sample and completed STATUS read',**formal)],
        scope=dict(applicable_architectures=['riscv'],applicable_platforms=[variant_run.static.target_binding.map_id],
            rtl_revisions=['rtl-tree:'+v.VAR_TREE],applicability='synthetic_only',
            source_authority='synthetic_fixture',silicon_applicability='unknown',
            assumptions=['reviewed single-CoreD controlled apparatus'],unmodeled_aspects=['silicon','attacker_control'],**formal),
        source_artifacts=[dict(artifact_id=source_id,sha256=b1.bytes_sha(ref_peripheral),source_kind='synthetic_fixture')],
        evidence=[dict(evidence_id=source_id+':definition',source_type='synthetic',artifact_id=source_id,
            summary='Frozen Reference RTL source as the controlled synthetic STATUS specification')],
        limitations=['Synthetic controlled differential only; no silicon or exploit claim'],**bind)))
    state=v.identified(v.StateBinding,source_artifact_id=source_id,source_sha256=b1.bytes_sha(ref_peripheral),
        enable_subject=enable,enable_address=0x40000,enable_reset_value=0,
        status_subject=status,status_address=0x40008,status_reset_value=0)
    assert proof
    return contract,state,source


@lru_cache(maxsize=1)
def golden_inputs():
    if not (BRIDGE/'local-reproduction-manifest.json').is_file() or not (CAPS/'local-manifest.json').is_file():
        pytest.skip('BLOCKED: frozen BRIDGE1/capability local artifacts unavailable')
    bridge_manifest=b1.read_json((BRIDGE/'local-reproduction-manifest.json').read_bytes())
    cap_manifest=b1.read_json((CAPS/'local-manifest.json').read_bytes())
    assert len(bridge_manifest['records'])==len(cap_manifest['records'])==4
    runs={}
    for rec in bridge_manifest['records']:
        p=frozen_bridge.runner.prepare(ROOT,rec['upstream_manifest'])
        folder=BRIDGE/rec['directory']
        joint,runtime,bridge=frozen_bridge.runner.consume_run(p,folder)
        assert rec['joint_run_id']==joint.joint_run_id and rec['bridge_set_id']==bridge.set_id
        cap_record=next(x for x in cap_manifest['records'] if x['joint_run_id']==joint.joint_run_id)
        static_caps=materialize_mmio(p['static'],elf_bytes=p['elf'].read_bytes())
        assert [c.capability_id for c in static_caps]==cap_record['static_capability_ids']
        for identity,c in zip(cap_record['static_capability_ids'],static_caps):
            assert (CAPS/'static'/(identity.removeprefix('fwcap:')+'.json')).read_text()==cap.serialize_firmware_capability(c)
        caps=tuple(cap.parse_firmware_capability((CAPS/'execution'/
            (identity.removeprefix('fwcap:')+'.json')).read_text()) for identity in cap_record['execution_capability_ids'])
        assert [c.capability_id for c in caps]==cap_record['execution_capability_ids']
        run=v.RunEvidence(static=p['static'],bridge=bridge,runtime=runtime,platform=p['platform'],
            capabilities=caps,inputs=p['inputs'],elf_bytes=p['elf'].read_bytes(),
            bus_bytes=(folder/'synthetic-mmio.jsonl').read_bytes(),
            processor_bytes=(folder/'trace_core_00000000.log').read_bytes(),
            stdout_bytes=(folder/'process.stdout.log').read_bytes(),
            stderr_bytes=(folder/'process.stderr.log').read_bytes())
        run=replace(run,observation_binding=v.observation_binding_for(run))
        key=(joint.firmware_sha256,joint.rtl_tree_sha256)
        runs[key]=run
    assert len(runs)==4
    contract,state,source=contract_and_source(next(x for x in runs.values() if x.bridge.joint_run.rtl_tree_sha256==v.VAR_TREE))
    return runs,contract,state,source


def evaluate():
    runs,contract,state,source=golden_inputs()
    a5,a4=frozen_bridge.runner.FIRMWARE_SHAS
    p1=v.verify_type2(contract=contract,target=runs[(a5,v.VAR_TREE)],
        reference=runs[(a5,v.REF_TREE)],state_binding=state,controlled_source=source)
    n1=v.verify_type2(contract=contract,target=runs[(a4,v.VAR_TREE)],
        reference=runs[(a4,v.REF_TREE)],state_binding=state,controlled_source=source)
    u1=v.verify_type2(contract=contract,target=replace(runs[(a5,v.VAR_TREE)],observation_binding=None),
        reference=runs[(a5,v.REF_TREE)],state_binding=state,controlled_source=source)
    return p1,n1,u1


def test_real_golden_p1_n1_n2_u1():
    p1,n1,u1=evaluate()
    assert (p1.result_id,n1.result_id,p1.reference_control.verification_id,u1.result_id)==(
        'type2-verification:9c7ef89582f89727fcacdb6b8bb7334ba79733c4182a6e7b341ba324e2fa6b82',
        'type2-verification:7dc13746b7067f7ce4adf6cc11ba8eeeb01a3b2582b7a2456b005704772477e7',
        'type2-reference-control:2d1ae9b25f06e6009e54b2081253ad93da1b3f8c1d91e942fd4ef6ed7dea28ab',
        'type2-verification:21db55b0e4ddb2f545e57ebb731f09bd7bd1b6b465dbe4c63f4c49bd07dd526a')
    assert (p1.trigger.status,p1.deviation.status,p1.observation.status,p1.differential.status,p1.final_status)==(
        'supported','supported','supported','supported','verified_controlled_type2_chain')
    assert {x.status for x in p1.trigger.conditions}=={'supported'}
    assert n1.final_status=='trigger_contradicted'
    assert next(x for x in n1.trigger.conditions if x.requirement_id=='type2:command-write').status=='contradicted'
    assert p1.reference_control.trigger_status=='supported'
    assert p1.reference_control.expected_behavior_status=='supported'
    assert p1.reference_control.deviation_observed is False
    assert u1.final_status=='unknown' and u1.observation.status=='unknown'
    assert u1.differential.status=='unknown'
    for name,result in (('P1',p1),('N1',n1),('U1',u1)):
        print(name, 'trigger='+result.trigger.status, 'deviation='+result.deviation.status,
              'observation='+result.observation.status, 'differential='+result.differential.status,
              'final='+result.final_status)
    print('N2/reference-control', 'trigger='+p1.reference_control.trigger_status,
          'expected='+p1.reference_control.expected_behavior_status,
          'deviation_observed='+str(p1.reference_control.deviation_observed))


def test_frozen_regression_and_identity():
    runs,_,_,_=golden_inputs()
    assert sum(b.overall_status=='bound' for r in runs.values() for b in r.bridge.bindings)==12
    for r in runs.values():
        assert len(r.capabilities)==3
        assert all(cap.parse_firmware_capability(cap.serialize_firmware_capability(c))==c for c in r.capabilities)
    frozen_b1.test_real_xl2_unknown_byte_replay()
    # The old B1 replay assertion checks all twelve UNKNOWN and preview bytes.
    a_manifest=b1.read_json((A/'apparatus-result.json').read_bytes())
    old={}
    for record in a_manifest['runs']:
        p=frozen_bridge.runner.prepare(ROOT,record['manifest'])
        loaded=b1.load_apparatus_run(p['workspace'],record['manifest'],
            base_source=ROOT/'samples/hardware/ibex-simple-system/source',
            expected_base_sha=v.bridge_api.BASE_SHA,
            expected_rtl_sha=p['inputs']['rtl_tree_sha256'],
            expected_firmware_sha=p['inputs']['firmware_sha256'])
        old[(p['inputs']['firmware_sha256'],p['inputs']['rtl_tree_sha256'])]=(record['manifest'],loaded)
    frozen_bridge.test_old_b1_twelve_unknown_preserved(old)


def test_valid_missing_sources_remain_unknown():
    runs,contract,state,source=golden_inputs()
    a5=frozen_bridge.runner.FIRMWARE_SHAS[0]
    target=runs[(a5,v.VAR_TREE)];reference=runs[(a5,v.REF_TREE)]
    without_reference=v.verify_type2(contract=contract,target=target,reference=None,
        state_binding=state,controlled_source=source)
    assert without_reference.trigger.status=='supported'
    assert without_reference.differential.status==without_reference.final_status=='unknown'
    without_source=v.verify_type2(contract=contract,target=target,reference=reference,
        state_binding=state,controlled_source=None)
    assert without_source.final_status=='unknown'
    wrong_link=v.identified(v.ObservationBinding,joint_run_id=target.bridge.joint_run.joint_run_id,
        runtime_attestation_id=target.runtime.source_attestation.attestation_id,
        raw_trace_sha256=target.bridge.joint_run.bus_trace_sha256,
        rtl_tree_sha256='f'*64,map_id=target.static.target_binding.map_id)
    unresolved=v.verify_type2(contract=contract,target=replace(target,observation_binding=wrong_link),
        reference=reference,state_binding=state,controlled_source=source)
    assert unresolved.observation.status=='unknown' and unresolved.final_status=='unknown'


def test_scope_differential_and_label_firewall():
    runs,contract,state,source=golden_inputs()
    a5,a4=frozen_bridge.runner.FIRMWARE_SHAS
    target=runs[(a5,v.VAR_TREE)];reference=runs[(a5,v.REF_TREE)]
    original=v.verify_type2(contract=contract,target=target,reference=reference,
        state_binding=state,controlled_source=source)
    shuffled=v.verify_type2(contract=contract,target=replace(target,capabilities=tuple(reversed(target.capabilities))),
        reference=reference,state_binding=state,controlled_source=source)
    assert original.result_id==shuffled.result_id
    wrong_reference=v.verify_type2(contract=contract,target=target,reference=runs[(a4,v.REF_TREE)],
        state_binding=state,controlled_source=source)
    assert wrong_reference.differential.status=='unknown' and wrong_reference.final_status=='unknown'
    invalid_revision=contract.model_dump(mode='json')
    invalid_revision['platform']['rtl_revision']='rtl-tree:'+v.REF_TREE
    invalid_revision['scope']['rtl_revisions']=['rtl-tree:'+v.REF_TREE]
    from chipchain.hardware.behavior_contract import HardwareBehaviorContractInput
    wrong_contract=hw.build_hardware_behavior_contract(HardwareBehaviorContractInput.model_validate(
        {k:x for k,x in invalid_revision.items() if k in HardwareBehaviorContractInput.model_fields}))
    unknown=v.verify_type2(contract=wrong_contract,target=target,reference=reference,
        state_binding=state,controlled_source=source)
    assert unknown.final_status=='unknown'
    n1_wrong_scope=v.verify_type2(contract=wrong_contract,target=runs[(a4,v.VAR_TREE)],
        reference=runs[(a4,v.REF_TREE)],state_binding=state,controlled_source=source)
    assert n1_wrong_scope.final_status=='unknown'
    with pytest.raises(TypeError):
        v.verify_type2(contract=contract,target=target,reference=reference,
            state_binding=state,controlled_source=source,evaluation_label='P1')


def test_invalid_bytes_or_source_patch_rejected():
    runs,contract,state,source=golden_inputs()
    a5=frozen_bridge.runner.FIRMWARE_SHAS[0]
    target=runs[(a5,v.VAR_TREE)];reference=runs[(a5,v.REF_TREE)]
    with pytest.raises(ValueError):
        v.verify_type2(contract=contract,target=replace(target,bus_bytes=target.bus_bytes[:-1]),
            reference=reference,state_binding=state,controlled_source=source)
    with pytest.raises(ValueError,match='VARIANT_PATCH_IDENTITY'):
        v.verify_type2(contract=contract,target=target,reference=reference,state_binding=state,
            controlled_source=replace(source,variant_patch_bytes=source.variant_patch_bytes+b' '))


def test_incomplete_valid_contract_does_not_verify_chain():
    runs,contract,state,source=golden_inputs()
    a5=frozen_bridge.runner.FIRMWARE_SHAS[0]
    target=runs[(a5,v.VAR_TREE)];reference=runs[(a5,v.REF_TREE)]
    from chipchain.hardware.behavior_contract import HardwareBehaviorContractInput
    incomplete=contract.model_dump(mode='json')
    incomplete['trigger']=[r for r in incomplete['trigger'] if r['condition_kind']!='ordering']
    authored=hw.build_hardware_behavior_contract(HardwareBehaviorContractInput.model_validate(
        {k:x for k,x in incomplete.items() if k in HardwareBehaviorContractInput.model_fields}))
    result=v.verify_type2(contract=authored,target=target,reference=reference,
        state_binding=state,controlled_source=source)
    assert result.final_status=='unknown'
    assert next(c for c in result.trigger.conditions if c.requirement_id=='type2:target-scope').status=='unknown'
