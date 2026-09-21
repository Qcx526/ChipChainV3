"""CAP0 synthetic declarations; no provider output or real vulnerability fixture."""
import copy
import hashlib
import json

import pytest

from chipchain.firmware.capability import (
    FirmwareCapabilityInput, build_firmware_capability, canonical_payload,
    formalization_summary, parse_firmware_capability, serialize_firmware_capability,
)


def synthetic_input():
    binding = dict(source_artifact_ids=['synthetic:spec'], evidence_ids=['synthetic:e'],
        provenance=[dict(source_kind='synthetic_fixture', source_artifact_ids=['synthetic:spec'])])
    common = dict(formalization_status='formalized', **binding)
    return dict(architecture='arm', source_case_id='synthetic:bounded-write:test-only',
        origin=dict(kind='synthetic_fixture', **binding),
        entry=dict(entry_id='entry:callback', entry_kind='callback', pc=0x1000, **common),
        conditions=[dict(condition_id='condition:length', condition_kind='input',
            description='合成定义：输入长度恰为 1 字节',
            predicate=dict(subject='input_length', operator='eq', operands=[1]), **common)],
        primitives=[dict(primitive_id='primitive:write', architecture='arm', kind='WRITE_BOUNDED',
            entry_id='entry:callback', source_pc=0x1000, basis='explicit_definition',
            condition_ids=['condition:length'], constraint_ids=['resource', 'address', 'value', 'width', 'length'],
            instruction_sequence=['select-address', 'write-byte'], source_registers=['base', 'value'],
            control=dict(status='bounded_external_control', dimensions=['value'], support_basis='synthetic_definition', **binding),
            **common)],
        constraints=[dict(constraint_id='resource', kind='target_resource', resource_kind='memory', identity='synthetic-SRAM', **common),
            dict(constraint_id='address', kind='address', domain=dict(minimum=0x20000000, maximum=0x2000000f), **common),
            dict(constraint_id='value', kind='value', domain=dict(minimum=0, maximum=255, controlled_bits=255, bit_width=32), **common),
            dict(constraint_id='width', kind='access_width', domain=dict(exact=8), **common),
            dict(constraint_id='length', kind='length', domain=dict(exact=1), **common)],
        scope=dict(target=dict(architecture='arm', processor_id='synthetic-core'), origin_kind='synthetic_fixture',
            firmware_artifact_ids=['synthetic:spec'], site_pcs=[0x1000], applicability='synthetic_only',
            assumptions=['test-only'], **common),
        source_artifacts=[dict(artifact_id='synthetic:spec', source_kind='synthetic_fixture', sha256=hashlib.sha256(b'synthetic bounded write specification').hexdigest())],
        evidence=[dict(evidence_id='synthetic:e', artifact_id='synthetic:spec', source_type='synthetic',
            summary='Synthetic definition of bounded write, not a real exploit or execution.')],
        limitations=['合成定义只用于 schema 测试，不是真实固件漏洞'], **binding)


def build(data=None):
    return build_firmware_capability(FirmwareCapabilityInput.model_validate(data or synthetic_input()))


def test_identity_round_trip_and_complete_synthetic():
    value = build()
    assert parse_firmware_capability(serialize_firmware_capability(value)) == value
    assert value.capability_id == 'fwcap:' + hashlib.sha256(canonical_payload(value)).hexdigest()
    assert value.capability_sha256 == hashlib.sha256(canonical_payload(value)).hexdigest()
    assert build().capability_id == value.capability_id
    assert value.origin.kind == 'synthetic_fixture' and value.scope.applicability == 'synthetic_only'
    summary = formalization_summary(value)
    assert all(x.formalized == x.total and not x.missing for x in summary.values())
    assert summary['constraints'].total == 5


def test_set_order_and_ordered_semantics():
    data = synthetic_input()
    data['scope']['assumptions'] = ['z', 'a']
    first = build(data)
    data['scope']['assumptions'].reverse()
    data['primitives'][0]['constraint_ids'].reverse()
    assert serialize_firmware_capability(build(data)) == serialize_firmware_capability(first)
    data['primitives'][0]['instruction_sequence'].reverse()
    assert build(data).capability_id != first.capability_id
    second = build(data)
    data['primitives'][0]['source_registers'].reverse()
    assert build(data).capability_id != second.capability_id
    second = build(data)
    data['constraints'].reverse()  # Ordered constraints are NOT mechanically sorted.
    assert build(data).capability_id != second.capability_id


@pytest.mark.parametrize('arch', ['arm', 'riscv', 'powerpc', 'x86', 'unknown'])
def test_architecture_neutral(arch):
    data = synthetic_input()
    data['architecture'] = data['scope']['target']['architecture'] = data['primitives'][0]['architecture'] = arch
    if arch == 'unknown':
        data['scope']['formalization_status'] = data['primitives'][0]['formalization_status'] = 'partially_formalized'
    assert build(data).architecture == arch


@pytest.mark.parametrize('mutation', [
    lambda d: d['source_artifacts'].append(copy.deepcopy(d['source_artifacts'][0])),
    lambda d: d['evidence'].append(copy.deepcopy(d['evidence'][0])),
    lambda d: d['conditions'].append(copy.deepcopy(d['conditions'][0])),
    lambda d: d['primitives'].append(copy.deepcopy(d['primitives'][0])),
    lambda d: d['constraints'].append(copy.deepcopy(d['constraints'][0])),
    lambda d: d['provenance'].append(copy.deepcopy(d['provenance'][0])),
    lambda d: d['primitives'][0].update(architecture='x86'),
    lambda d: d['scope']['target'].update(architecture='x86'),
    lambda d: d['primitives'][0].update(evidence_ids=['missing']),
    lambda d: d['entry'].update(source_artifact_ids=['missing']),
    lambda d: d['evidence'][0].update(artifact_id='missing'),
    lambda d: d['provenance'][0].update(source_kind='runtime_trace'),
    lambda d: d['conditions'][0].update(predicate=None),
    lambda d: d['scope'].update(applicability='unknown'),
    lambda d: d['primitives'][0].update(kind='UNKNOWN'),
    lambda d: d['primitives'][0].update(kind='ARBITRARY_WRITE'),
    lambda d: d['primitives'][0]['control'].update(controllable=True),
    lambda d: d['primitives'][0]['control'].update(status='full_external_control'),
    lambda d: d['primitives'][0]['control'].update(evidence_ids=[]),
    lambda d: d['primitives'][0]['control'].update(status='vulnerability_derived_control'),
    lambda d: d['constraints'][0].update(resource_kind='csr'),
    lambda d: d['constraints'][1].update(kind='value'),
    lambda d: d['constraints'][1]['domain'].update(minimum=0x20000010),
    lambda d: d['constraints'][2]['domain'].update(controlled_bits=1<<32),
    lambda d: d['constraints'][3]['domain'].update(exact=0),
    lambda d: d['entry'].update(execution_status='runtime_reachable_from_interface'),
    lambda d: d['entry'].update(execution_status='source_instruction_retired'),
    lambda d: d['entry'].update(ownership_status='ambiguous', function_id='guessed'),
    lambda d: d.update(timestamp='today'),
    lambda d: d.update(run_uuid='run'),
    lambda d: d.update(raw_llm_summary='arbitrary write'),
    lambda d: d.update(confidence=0.9),
    lambda d: d['source_artifacts'][0].update(path='/tmp/host/input'),
    lambda d: d['source_artifacts'][0].update(source_kind='llm'),
])
def test_fail_closed(mutation):
    data = synthetic_input()
    mutation(data)
    with pytest.raises(ValueError):
        build(data)


def test_duplicate_json_and_stale_identity():
    text = serialize_firmware_capability(build())
    with pytest.raises(ValueError, match='Duplicate JSON key'):
        parse_firmware_capability(text.replace('{', '{"architecture":"arm",', 1))
    data = json.loads(text)
    data['capability_sha256'] = '0'*64
    with pytest.raises(ValueError, match='identity mismatch'):
        parse_firmware_capability(json.dumps(data))
    value = build()
    value.primitives[0].instruction_sequence.reverse()
    with pytest.raises(ValueError, match='identity mismatch'):
        serialize_firmware_capability(value)


def test_input_influence_is_retained_without_external_control_upgrade():
    data = synthetic_input()
    data['primitives'][0]['control']['status'] = 'input_influenced'
    value = build(data)
    assert value.primitives[0].control.status == 'input_influenced'
    assert 'full_external_control' not in serialize_firmware_capability(value)


def test_csr_write_distinct_from_bounded_memory_write():
    data = synthetic_input()
    p = data['primitives'][0]
    p.update(kind='CSR_WRITE', constraint_ids=['resource', 'csr', 'value', 'width'])
    data['constraints'][0].update(resource_kind='csr', identity='synthetic-csr-bank')
    base = {k:data['constraints'][0][k] for k in ('source_artifact_ids','evidence_ids','provenance')}
    data['constraints'] = [data['constraints'][0], dict(constraint_id='csr', kind='CSR', identity='synthetic-privileged-control', **base),
        dict(constraint_id='value', kind='value', domain=dict(minimum=0, maximum=0xffffffff, bit_width=32, controlled_bits=0xffffffff), **base),
        dict(constraint_id='width', kind='access_width', domain=dict(exact=32), **base)]
    p['control']['status'] = 'full_external_control'
    csr = build(data)
    assert csr.capability_id != build().capability_id
    assert csr.primitives[0].kind == 'CSR_WRITE'
    data['primitives'][0]['kind'] = 'WRITE_BOUNDED'
    with pytest.raises(ValueError, match='incompatible'):
        build(data)


def test_normal_and_vulnerability_origin_separate_and_finding_is_not_capability():
    data = synthetic_input()
    data['origin'].update(kind='normal_behavior')
    data['scope'].update(origin_kind='normal_behavior', applicability='specified_firmware_sites')
    data['primitives'][0]['control'].update(status='not_established', dimensions=[], support_basis='not_established')
    normal = build(data)
    assert normal.origin.kind == 'normal_behavior'
    data['primitives'][0]['kind'] = 'WRITE_OOB'
    with pytest.raises(ValueError, match='Normal behavior'):
        build(data)
    data['origin'].update(kind='vulnerability_derived', finding_ids=['crash:1'])
    data['scope']['origin_kind'] = 'vulnerability_derived'
    data['source_artifacts'][0]['source_kind'] = 'firmware_vulnerability_record'
    data['provenance'][0]['source_kind'] = 'firmware_vulnerability_record'
    data['provenance'][0]['source_ids'] = ['crash:1']
    data['evidence'][0]['source_type'] = 'artifact'
    with pytest.raises(ValueError, match='Finding alone'):
        build(data)
    # A crash reference alone also cannot support hijack, even if renamed.
    data['primitives'][0].update(kind='CONTROL_FLOW_HIJACK', constraint_ids=[])
    data['primitives'][0]['formalization_status'] = 'partially_formalized'
    with pytest.raises(ValueError, match='Finding alone'):
        build(data)


def test_missing_and_unknown_formalization_are_not_complete():
    data = synthetic_input()
    data['conditions'] = []
    data['primitives'] = []
    data['constraints'] = []
    data['entry']['formalization_status'] = 'unknown'
    result = formalization_summary(build(data))
    assert result['conditions'].missing and result['primitives'].missing
    assert result['entry'].unknown == 1
    assert not hasattr(result['entry'], 'confidence')


def test_vulnerability_origin_can_bind_separate_explicit_capability_definition():
    data = build().model_dump(exclude={'schema_version', 'capability_id', 'capability_sha256'})
    # This is still synthetic test data: simulate distinct manual definition + finding sources.
    def relabel(value):
        if isinstance(value, dict):
            if value.get('source_kind') == 'synthetic_fixture':
                value['source_kind'] = 'manual_research_input'
            for child in value.values():
                relabel(child)
        elif isinstance(value, list):
            for child in value:
                relabel(child)
    relabel(data)
    data['evidence'][0]['source_type'] = 'manual'
    record = dict(artifact_id='synthetic:finding', sha256='c'*64, source_kind='firmware_vulnerability_record')
    origin = dict(source_kind='firmware_vulnerability_record', source_artifact_ids=[record['artifact_id']], source_ids=['finding:test-only'])
    data['source_artifacts'].append(record)
    data['source_artifact_ids'].append(record['artifact_id'])
    data['provenance'].append(origin)
    data['origin'] = dict(kind='vulnerability_derived', finding_ids=['finding:test-only'],
                         source_artifact_ids=[record['artifact_id']], evidence_ids=[], provenance=[origin])
    data['scope'].update(origin_kind='vulnerability_derived', applicability='specified_firmware_sites')
    data['primitives'][0].update(kind='WRITE_OOB')
    data['primitives'][0]['control'].update(status='vulnerability_derived_control', support_basis='explicit_research_definition')
    value = build(data)
    assert value.origin.finding_ids == ['finding:test-only']
    assert value.primitives[0].control.status == 'vulnerability_derived_control'
    # This validates a declared model, not whether the manual definition is scientifically true.


def test_evidence_cannot_bind_to_a_different_existing_source():
    data = synthetic_input()
    data['source_artifacts'].append(dict(artifact_id='second', source_kind='synthetic_fixture', sha256='c'*64))
    # Replacing the top-level lists avoids changing the shared component bindings.
    data['source_artifact_ids'] = [*data['source_artifact_ids'], 'second']
    data['provenance'] = [*data['provenance'], dict(source_kind='synthetic_fixture', source_artifact_ids=['second'])]
    data['evidence'][0]['artifact_id'] = 'second'
    with pytest.raises(ValueError, match='Evidence artifact/source mismatch'):
        build(data)


def test_ordering_directions_preserved_and_unknown_endpoints_rejected():
    data = synthetic_input()
    second = copy.deepcopy(data['primitives'][0]); second['primitive_id'] = 'primitive:second'
    data['primitives'].append(second)
    base = {k:data['constraints'][0][k] for k in ('source_artifact_ids', 'evidence_ids', 'provenance')}
    data['constraints'].append(dict(kind='ordering', constraint_id='order:1',
        before_primitive_id='primitive:write', after_primitive_id='primitive:second', **base))
    first = build(data)
    data['constraints'][-1].update(before_primitive_id='primitive:second', after_primitive_id='primitive:write')
    assert build(data).capability_id != first.capability_id
    data['constraints'][-1]['after_primitive_id'] = 'missing'
    with pytest.raises(ValueError, match='Ordering references'):
        build(data)


def test_catalog_set_reordering_and_mutating_source_hash():
    data = synthetic_input()
    data['source_artifacts'].append(dict(artifact_id='second', source_kind='synthetic_fixture', sha256='c'*64))
    data['source_artifact_ids'] = [*data['source_artifact_ids'], 'second']
    data['provenance'] = [*data['provenance'], dict(source_kind='synthetic_fixture', source_artifact_ids=['second'])]
    data['evidence_ids'] = [*data['evidence_ids'], 'second:e']
    data['evidence'].append(dict(evidence_id='second:e', artifact_id='second', source_type='synthetic', summary='test'))
    before = build(data)
    for key in ('source_artifacts', 'source_artifact_ids', 'provenance', 'evidence', 'evidence_ids'):
        data[key].reverse()
    assert canonical_payload(build(data)) == canonical_payload(before)
    data['source_artifacts'][0]['sha256'] = 'd'*64
    assert build(data).capability_id != before.capability_id


@pytest.mark.parametrize('source_kind', ['firmware_a4', 'firmware_a5', 'fuzzware_observation', 'runtime_trace'])
def test_analyzer_source_category_is_not_external_control_evidence(source_kind):
    data = build().model_dump(exclude={'schema_version', 'capability_id', 'capability_sha256'})
    def relabel(obj):
        if isinstance(obj, dict):
            if obj.get('source_kind') == 'synthetic_fixture':
                obj['source_kind'] = source_kind
            for v in obj.values():
                relabel(v)
        elif isinstance(obj, list):
            for v in obj:
                relabel(v)
    relabel(data)
    data['evidence'][0]['source_type'] = 'deterministic_analyzer'
    data['origin']['kind'] = 'normal_behavior'
    data['scope'].update(origin_kind='normal_behavior', applicability='specified_firmware_sites')
    data['primitives'][0]['control']['support_basis'] = 'independent_capability_evidence'
    with pytest.raises(ValueError, match='Control cannot be established'):
        build(data)
