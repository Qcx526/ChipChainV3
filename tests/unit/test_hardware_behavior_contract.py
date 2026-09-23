"""Synthetic requirements only: no real processor deviation is asserted."""
import copy
import hashlib
import json

import pytest
from pydantic import ValidationError

from chipchain.hardware.behavior_contract import (
    HardwareBehaviorContractInput, build_hardware_behavior_contract, canonical_payload,
    formalization_summary, parse_hardware_behavior_contract,
    serialize_hardware_behavior_contract,
)


def complete_input():
    """Toy wrapping adder specification, explicitly synthetic and test-only."""
    binding = dict(source_artifact_ids=['synthetic:adder-spec'], evidence_ids=['synthetic:e1'],
                   provenance=[dict(source_kind='synthetic_fixture', source_artifact_ids=['synthetic:adder-spec'])])
    common = dict(formalization_status='formalized', **binding)
    expected = dict(subject='result', operator='eq', operands=[0])
    deviation = dict(subject='result', operator='neq', operands=[0])
    return dict(
        architecture='riscv', source_case_id='synthetic:wrapping-adder:test-only',
        platform=dict(target=dict(architecture='riscv', processor_id='synthetic-core',
                                  word_size_bits=32), platform_id='synthetic-platform', **binding),
        preconditions=[dict(condition_id='pre:mode', condition_kind='execution_context',
            description='合成测试执行模式', required_relation=dict(subject='mode', operator='eq', operands=['test']), **common)],
        trigger=[dict(condition_id='trigger:add', condition_kind='instruction_sequence',
            description='合成的设值和加法序列；不是已知真实缺陷',
            instructions=[dict(atom_id='step:set', architecture='riscv', mnemonic='synthetic_set',
                               operand_pattern=dict(destination_register='x1', immediate_exact=4294967295)),
                          dict(atom_id='step:add', architecture='riscv', mnemonic='synthetic_add',
                               operand_pattern=dict(destination_register='x1', source_registers=['x1'], immediate_exact=1))], **common)],
        deviation=[dict(condition_id='deviation:result', deviation_kind='wrong_value',
            description='按合成规格，32 位无符号最大值加一应回绕为零', affected_component='synthetic_adder',
            expected_behavior=expected, deviating_behavior=deviation,
            specification_ref='synthetic:adder-spec', hardware_constraint_status='specified', **common)],
        observation=[dict(condition_id='observation:result', observable_kind='register_value',
            description='比较合成后端输出的结果寄存器', deviation_ids=['deviation:result'],
            observable_target='result', judgement_kind='comparison', required_backend='synthetic_test_backend',
            expected_observation=expected, deviation_observation=deviation,
            evidence_requirement='测试后端的结果值及其可追溯位置；本 fixture 没有执行记录', **common)],
        scope=dict(applicable_architectures=['riscv'], applicable_platforms=['synthetic-platform'],
                   applicability='synthetic_only', source_authority='synthetic_fixture',
                   assumptions=['test-only'], unmodeled_aspects=['real_silicon'], **common),
        source_artifacts=[dict(artifact_id='synthetic:adder-spec', source_kind='synthetic_fixture',
                               sha256=hashlib.sha256(b'synthetic wrapping adder specification; test-only').hexdigest())],
        evidence=[dict(evidence_id='synthetic:e1', artifact_id='synthetic:adder-spec', source_type='synthetic',
                       summary='Synthetic specification definition, not execution evidence.')],
        limitations=['仅用于 schema 与 renderer 测试'], **binding,
    )


def build(data=None):
    return build_hardware_behavior_contract(HardwareBehaviorContractInput.model_validate(data or complete_input()))


def test_complete_contract_round_trip_and_identity():
    value = build()
    assert parse_hardware_behavior_contract(serialize_hardware_behavior_contract(value)) == value
    assert value.contract_id == 'hwbehavior:' + hashlib.sha256(canonical_payload(value)).hexdigest()
    assert value.contract_sha256 == hashlib.sha256(canonical_payload(value)).hexdigest()
    assert build().contract_id == value.contract_id
    assert value.scope.applicability == 'synthetic_only'
    counts = formalization_summary(value)
    assert all(counts[k].formalized == 1 for k in ('preconditions', 'trigger', 'deviation', 'observation', 'scope'))
    assert not counts['observation'].missing
    assert counts['unclassified_atoms'].missing


def test_set_order_normalization_and_instruction_order_preservation():
    data = complete_input()
    data['scope']['assumptions'] = ['b', 'a']
    extra = copy.deepcopy(data['preconditions'][0])
    extra['condition_id'] = 'pre:another'
    data['preconditions'].append(extra)
    first = build(data)
    data['scope']['assumptions'].reverse()
    data['preconditions'].reverse()
    second = build(data)
    assert canonical_payload(first) == canonical_payload(second)
    assert serialize_hardware_behavior_contract(first) == serialize_hardware_behavior_contract(second)
    data['trigger'][0]['instructions'].reverse()
    third = build(data)
    assert third.contract_id != second.contract_id
    assert [a.atom_id for a in third.trigger[0].instructions] == ['step:add', 'step:set']


@pytest.mark.parametrize('architecture', ['arm', 'riscv', 'powerpc', 'x86', 'unknown'])
def test_architecture_neutral_without_platform_inference(architecture):
    data = complete_input()
    data['architecture'] = data['platform']['target']['architecture'] = architecture
    data['scope']['applicable_architectures'] = [architecture]
    data['scope']['formalization_status'] = 'partially_formalized'
    data['trigger'][0]['formalization_status'] = 'partially_formalized'
    for atom in data['trigger'][0]['instructions']:
        atom['architecture'] = architecture
    value = build(data)
    assert value.platform.rtl_revision is None
    assert value.platform.silicon_revision is None
    assert value.platform.target.processor_id == 'synthetic-core'


@pytest.mark.parametrize('mutation', [
    lambda d: d.update(architecture='arm'),
    lambda d: d['trigger'][0]['instructions'][0].update(architecture='arm'),
    lambda d: d['preconditions'].append(copy.deepcopy(d['preconditions'][0])),
    lambda d: d['source_artifacts'].append(copy.deepcopy(d['source_artifacts'][0])),
    lambda d: d['evidence'].append(copy.deepcopy(d['evidence'][0])),
    lambda d: d['preconditions'][0].update(evidence_ids=['missing']),
    lambda d: d['preconditions'][0].update(source_artifact_ids=['missing']),
    lambda d: d['evidence'][0].update(artifact_id='missing'),
    lambda d: d['provenance'][0].update(source_kind='manual_research_input'),
    lambda d: d['observation'][0].update(actual_observed=True, evidence_ids=[]),
    lambda d: d['observation'][0].update(actual_observed=True),
    lambda d: d['deviation'][0].update(deviation_observed=True),
    lambda d: d['deviation'][0].update(hardware_constraint_status='verified'),
    lambda d: d['preconditions'][0].update(required_relation=None),
    lambda d: d['deviation'][0].update(expected_behavior=None),
    lambda d: d['observation'][0].update(required_backend=None),
    lambda d: d['scope'].update(applicability='unknown'),
    lambda d: d['scope'].update(applicable_platforms=['different']),
    lambda d: d['scope'].update(silicon_applicability='specified_revisions'),
    lambda d: d['source_artifacts'][0].update(path='/tmp/host-specific'),
    lambda d: d.update(timestamp='2026-09-20'),
    lambda d: d.update(run_uuid='runtime'),
    lambda d: d.update(llm_confidence=0.8),
    lambda d: d.update(llm_text='untrusted'),
    lambda d: d['source_artifacts'][0].update(source_kind='llm'),
])
def test_fail_closed(mutation):
    data = complete_input()
    mutation(data)
    with pytest.raises((ValidationError, ValueError)):
        build(data)


def test_digest_tampering_and_duplicate_json_key_rejected():
    value = build()
    data = json.loads(serialize_hardware_behavior_contract(value))
    data['contract_sha256'] = '0' * 64
    with pytest.raises(ValueError):
        parse_hardware_behavior_contract(json.dumps(data))
    text = serialize_hardware_behavior_contract(value).replace('{', '{"contract_id":"duplicate",', 1)
    with pytest.raises(ValueError, match='Duplicate JSON key'):
        parse_hardware_behavior_contract(text)


def test_revalidate_nested_mutation_at_public_boundaries():
    value = build()
    value.trigger[0].instructions.reverse()
    with pytest.raises(ValueError, match='identity mismatch'):
        serialize_hardware_behavior_contract(value)


def test_empty_sections_mean_missing_not_absent_requirement():
    data = complete_input()
    for key in ('preconditions', 'trigger', 'deviation', 'observation'):
        data[key] = []
    summary = formalization_summary(build(data))
    assert all(summary[key].missing and summary[key].total == 0 for key in ('preconditions', 'trigger', 'deviation', 'observation'))


def test_partial_and_unknown_have_separate_counts():
    data = complete_input()
    data['preconditions'][0]['formalization_status'] = 'unformalized'
    data['trigger'][0]['formalization_status'] = 'partially_formalized'
    data['deviation'][0]['formalization_status'] = 'unknown'
    result = formalization_summary(build(data))
    assert result['preconditions'].unformalized == 1
    assert result['trigger'].partially_formalized == 1
    assert result['deviation'].unknown == 1
    assert not hasattr(result['trigger'], 'confidence')


@pytest.mark.parametrize('mutation', [
    lambda d: d['deviation'][0].update(specification_ref='unbound-spec'),
    lambda d: d['evidence'][0].update(source_type='deterministic_analyzer', analyzer='fake-analyzer'),
    lambda d: d['observation'][0].update(deviation_ids=['unbound-deviation']),
    lambda d: d['trigger'][0].update(condition_kind='MMIO_access'),
    lambda d: d['trigger'][0]['instructions'][0].update(purpose='verification_only_metadata'),
])
def test_specific_binding_and_payload_rejections(mutation):
    data = complete_input()
    mutation(data)
    with pytest.raises(ValueError):
        build(data)


def test_preserve_ordering_constraints_and_predicate_operands():
    data = complete_input()
    first = copy.deepcopy(data['trigger'][0])
    first['condition_id'] = 'event:second'
    for atom in first['instructions']:
        atom['atom_id'] += ':second'
    data['trigger'].append(first)
    common = {k: data['trigger'][0][k] for k in ('source_artifact_ids', 'evidence_ids', 'provenance')}
    for name, before, after in [('order:a', 'trigger:add', 'event:second'),
                                 ('order:b', 'event:second', 'trigger:add')]:
        data['trigger'].append(dict(condition_id=name, description='要求顺序', condition_kind='ordering',
            formalization_status='formalized', ordering=dict(atom_id=name, kind='ordering',
                before_atom_id=before, after_atom_id=after), **common))
    original = build(data)
    # The model records declared requirements, not satisfiability (even conflicting orders).
    data['trigger'][-2:] = reversed(data['trigger'][-2:])
    swapped = build(data)
    assert original.contract_id != swapped.contract_id
    assert [c.condition_id for c in swapped.trigger][-2:] == ['order:b', 'order:a']
    data['trigger'][-1]['ordering']['after_atom_id'] = 'missing'
    with pytest.raises(ValueError, match='Ordering must reference'):
        build(data)


def test_source_and_evidence_registry_order_is_set_like():
    data = complete_input()
    source = copy.deepcopy(data['source_artifacts'][0])
    source['artifact_id'] = 'synthetic:second-source'
    data['source_artifacts'].append(source)
    ref = copy.deepcopy(data['evidence'][0])
    ref.update(evidence_id='synthetic:e2', artifact_id=source['artifact_id'])
    data['evidence'].append(ref)
    # The fixture deliberately shares these bindings among its requirements.
    data['source_artifact_ids'].append(source['artifact_id'])
    data['evidence_ids'].append(ref['evidence_id'])
    data['provenance'].append(dict(source_kind='synthetic_fixture', source_artifact_ids=[source['artifact_id']]))
    original = build(data)
    for key in ('source_artifacts', 'evidence', 'source_artifact_ids', 'evidence_ids', 'provenance'):
        data[key].reverse()
    reordered = build(data)
    assert canonical_payload(original) == canonical_payload(reordered)
    assert serialize_hardware_behavior_contract(original) == serialize_hardware_behavior_contract(reordered)
    data['source_artifacts'][0]['sha256'] = '0' * 64
    assert build(data).contract_id != original.contract_id


def test_unclassified_identity_cannot_duplicate_trigger_identity():
    data = complete_input()
    atom = copy.deepcopy(data['trigger'][0]['instructions'][0])
    atom['atom_id'] = data['trigger'][0]['condition_id']
    atom['kind'] = 'instruction'
    data['unclassified_atoms'] = [dict(
        atom=atom, reason='verification_metadata', formalization_status='unknown',
        source_artifact_ids=data['source_artifact_ids'], evidence_ids=data['evidence_ids'],
        provenance=data['provenance'],
    )]
    with pytest.raises(ValueError, match='Duplicate'):
        HardwareBehaviorContractInput.model_validate(data)


@pytest.mark.parametrize('mutation', [
    lambda d: d['provenance'].append(copy.deepcopy(d['provenance'][0])),
    lambda d: d['scope']['applicable_architectures'].append('riscv'),
])
def test_duplicate_set_members_rejected(mutation):
    data = complete_input()
    mutation(data)
    with pytest.raises(ValueError, match='Duplicate'):
        build(data)
