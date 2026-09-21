import hashlib

import pytest

from chipchain.cross_layer.trigger import (
    HardwareTriggerConditionInput, build_hardware_trigger_condition,
    hardware_trigger_condition_sha256, serialize_hardware_trigger_condition,
)
from chipchain.hardware.behavior_contract import Platform, Provenance, SourceArtifact
from chipchain.hardware.behavior_contract_materialization import materialize_xl0


def xl0():
    return build_hardware_trigger_condition(HardwareTriggerConditionInput(
        hardware_case_id='synthetic:xl0', architecture='riscv', source_kind='synthetic_fixture',
        source_ids=['synthetic:spec'], epistemic_status='derived', all_of_atoms=[
            dict(atom_id='i', kind='instruction', architecture='riscv', mnemonic='addi'),
            dict(atom_id='r', kind='register_state', register='x1', operator='eq', value=0),
            dict(atom_id='p', kind='privilege_state', architecture='riscv', required_mode='M'),
            dict(atom_id='h', kind='hardware_state', state_identity='busy', operator='eq', value=0),
            dict(atom_id='m', kind='mmio_access', address=4096, access='read'),
            dict(atom_id='c', kind='csr_access', csr_identity='synthetic-csr', access='write'),
            dict(atom_id='o', kind='ordering', before_atom_id='i', after_atom_id='m', max_gap_events=2),
            dict(atom_id='u', kind='ordering', before_atom_id='i', after_atom_id='r'),
            dict(atom_id='v', kind='instruction', architecture='riscv', mnemonic='metadata', purpose='verification_only_metadata'),
        ]))


def arguments(value):
    source = SourceArtifact(artifact_id='xl0:source', source_kind='xl0_trigger',
                            sha256=hardware_trigger_condition_sha256(value))
    provenance = Provenance(source_kind='xl0_trigger', source_artifact_ids=[source.artifact_id])
    return dict(platform=Platform(target=dict(architecture='riscv', processor_id='synthetic-core'),
                                  source_artifact_ids=[source.artifact_id], provenance=[provenance]),
                source_artifacts=[source], evidence=[], xl0_artifact_id=source.artifact_id)


def test_partial_mapping_is_conservative_and_xl0_immutable():
    value = xl0()
    before = serialize_hardware_trigger_condition(value)
    result = materialize_xl0(value, **arguments(value))
    assert serialize_hardware_trigger_condition(value) == before
    assert not result.preconditions
    assert not result.deviation and not result.observation
    assert {t.condition_id: t.condition_kind for t in result.trigger} == {
        'i': 'instruction', 'm': 'MMIO_access', 'c': 'CSR_access', 'o': 'ordering'}
    assert {a.atom.atom_id for a in result.unclassified_atoms} == {'r', 'p', 'h', 'u', 'v'}
    assert all(t.formalization_status == 'partially_formalized' for t in result.trigger)
    assert result.provenance[0].transformation == 'xl0_partial_v1'
    assert value.condition_id in result.provenance[0].source_ids
    assert materialize_xl0(value, **arguments(value)).contract_id == result.contract_id


def test_explicit_state_roles_require_manual_source():
    value = xl0()
    args = arguments(value)
    with pytest.raises(ValueError, match='manual research'):
        materialize_xl0(value, state_roles={'p': 'precondition'}, **args)
    manual = SourceArtifact(artifact_id='manual:roles', source_kind='manual_research_input',
                            sha256=hashlib.sha256(b'explicit temporal role declaration').hexdigest())
    args['source_artifacts'].append(manual)
    result = materialize_xl0(value, state_roles={'p': 'precondition', 'h': 'precondition', 'r': 'trigger'},
        role_provenance=Provenance(source_kind='manual_research_input', source_artifact_ids=[manual.artifact_id]), **args)
    assert {p.condition_kind for p in result.preconditions} == {'privilege', 'microarchitectural_state'}
    assert {t.condition_id for t in result.trigger} >= {'r', 'u'}
    assert not result.deviation and not result.observation


def test_wrong_digest_and_architecture_rejected():
    value = xl0()
    args = arguments(value)
    args['source_artifacts'][0].sha256 = '0' * 64
    with pytest.raises(ValueError, match='digest mismatch'):
        materialize_xl0(value, **args)
    args = arguments(value)
    args['platform'].target.architecture = 'arm'
    with pytest.raises(ValueError, match='architecture differ'):
        materialize_xl0(value, **args)


def test_state_role_cannot_reclassify_instruction():
    value = xl0()
    with pytest.raises(ValueError, match='Only required state'):
        materialize_xl0(value, state_roles={'i': 'precondition'}, **arguments(value))


def test_hypothesis_not_silently_promoted_to_deterministic_source():
    value = xl0()
    data = value.model_dump(exclude={'schema_version', 'condition_id'})
    data.update(source_kind='hardware_trigger_hypothesis', epistemic_status='hypothesized')
    value = build_hardware_trigger_condition(HardwareTriggerConditionInput(**data))
    with pytest.raises(ValueError, match='Hypothesis'):
        materialize_xl0(value, **arguments(value))
