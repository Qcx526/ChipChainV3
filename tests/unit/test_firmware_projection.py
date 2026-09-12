"""Projection invariants, operational sensitivity and explicit identity policy."""

import hashlib
import json

import pytest

from chipchain.agents.context import firmware_context, hardware_context, MAX_CONTEXT_CHARS
from chipchain.agents.contracts import FirmwareAgentInput, HardwareAgentInput
from chipchain.agents.projections.firmware import (
    PROJECTION_VERSION, build_firmware_analysis_projection,
    serialize_firmware_analysis_projection, firmware_projection_sha256,
)
from chipchain.agents.runtime import AgentExecutionError
from chipchain.domain.evidence import EvidenceRef
from chipchain.tools.contracts import DeterministicObservation, HardwareObservations
from chipchain.tools.firmware.fuzzware import FuzzwareHeatPressScenarioAnalyzer
from tests.firmware_fakes import make_case


@pytest.fixture
def inputs(tmp_path):
    case = make_case(tmp_path)
    batch = FuzzwareHeatPressScenarioAnalyzer().analyze(
        case_id=case.case_id, target=case.target, artifacts=case.firmware_artifacts,
    )
    return FirmwareAgentInput(case=case, deterministic_observations=batch)


def all_refs(inputs):
    refs = []
    for o in inputs.deterministic_observations.observations:
        refs.extend(o.evidence)
        for b in o.behaviors:
            refs.extend(b.evidence)
            if b.decoded_instruction:
                refs.extend(b.decoded_instruction.evidence)
    return refs


def test_projection_deterministic_nonmutating_and_hash(inputs):
    before = inputs.model_dump_json()
    projection = build_firmware_analysis_projection(inputs)
    text = serialize_firmware_analysis_projection(projection)
    assert text == firmware_context(inputs) == firmware_context(inputs)
    assert inputs.model_dump_json() == before
    assert firmware_projection_sha256(projection) == hashlib.sha256(text.encode()).hexdigest()
    assert projection.projection_version == PROJECTION_VERSION
    projection.evidence_catalog[0].summary = 'Changed returned projection only'
    assert inputs.model_dump_json() == before


def test_catalogs_cover_all_canonical_ids_exactly_once(inputs):
    projection = build_firmware_analysis_projection(inputs)
    batch = inputs.deterministic_observations
    assert {o.observation_id for o in batch.observations} == {o.observation_id for o in projection.observations}
    assert {b.behavior_id for o in batch.observations for b in o.behaviors} == {b.behavior_id for b in projection.behaviors}
    canonical = {e.evidence_id: e for e in all_refs(inputs)}
    assert len(projection.evidence_catalog) == len(canonical)
    assert {e.evidence_id: e for e in projection.evidence_catalog} == canonical
    data = json.loads(serialize_firmware_analysis_projection(projection))
    complete_refs = []
    def walk(value):
        if isinstance(value, dict):
            if 'evidence_id' in value and 'source_type' in value:
                complete_refs.append(EvidenceRef.model_validate(value))
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(data)
    assert complete_refs == projection.evidence_catalog
    assert all('behaviors' not in o and 'evidence' not in o for o in data['observations'])
    assert all('evidence' not in b for b in data['behaviors'])


def test_paths_display_and_hidden_metadata_do_not_influence_context(inputs):
    baseline = firmware_context(inputs)
    for artifact in inputs.case.firmware_artifacts:
        artifact.path = '/home/qcx/known root cause/04-crash-analysis/crashing_input'
        artifact.metadata['oracle'] = 'CVE-2026-0001 expected crash exploitability'
    inputs.case.name = 'CVE-2026-0001 known root cause'
    inputs.case.metadata['oracle'] = 'expected crash'
    text = firmware_context(inputs)
    assert text == baseline
    for marker in ('CVE-', 'known root cause', 'expected crash', 'exploitability', 'crash-analysis', 'crashing_input', '/home/'):
        assert marker not in text
    assert all(set(a) == {'artifact_id', 'artifact_type', 'format'} for a in json.loads(text)['artifacts'])
    assert 'name' not in json.loads(text)['case']


@pytest.mark.parametrize('unsafe_id', ['CVE-2026-001', 'artifact-root-cause', '/home/qcx/input',
                                      'crashing_input', 'ordinary-unreviewed-caller-label'])
def test_arbitrary_artifact_ids_are_not_presumed_neutral(inputs, unsafe_id):
    artifact = inputs.case.firmware_artifacts[0]
    old = artifact.artifact_id
    artifact.artifact_id = unsafe_id
    for ref in all_refs(inputs):
        if ref.artifact_id == old:
            ref.artifact_id = unsafe_id
    with pytest.raises(AgentExecutionError, match='neutral artifact'):
        firmware_context(inputs)


@pytest.mark.parametrize('where', ['case_id', 'target', 'format', 'evidence', 'generic_summary'])
def test_path_or_answer_in_forwarded_fields_is_rejected_without_sanitizing(inputs, where):
    value = '/home/qcx/expected crash'
    if where == 'case_id':
        inputs.case.case_id = value
    elif where == 'target':
        inputs.case.target.processor_id = value
    elif where == 'format':
        inputs.case.firmware_artifacts[0].format = value
    elif where == 'evidence':
        for ref in all_refs(inputs):
            ref.summary = value
    else:
        inputs.deterministic_observations.observations.append(DeterministicObservation(
            observation_id='generic', summary=value, evidence=[all_refs(inputs)[0]],
        ))
    before = inputs.model_dump_json()
    with pytest.raises(AgentExecutionError):
        firmware_context(inputs)
    assert inputs.model_dump_json() == before


@pytest.mark.parametrize('fact', ['mmio_address', 'pc', 'access_size', 'parameter', 'mnemonic', 'operand',
                                 'instruction_address', 'raw_bytes', 'input_size', 'input_hash', 'trigger'])
def test_operational_changes_change_projection(inputs, fact):
    before = firmware_context(inputs)
    observations = inputs.deterministic_observations.observations
    model = next(o for o in observations if o.kind == 'mmio_model' and o.details.model_kind == 'constant')
    site = next(o for o in observations if o.kind == 'static_instruction_site')
    opaque = next(o for o in observations if o.details.kind == 'opaque_input')
    trigger = next(o for o in observations if o.details.kind == 'interrupt_trigger')
    if fact == 'mmio_address':
        model.details.mmio_address += 4
    elif fact == 'pc':
        model.details.pc += 2
    elif fact == 'access_size':
        model.details.access_size_bytes = 1
    elif fact == 'parameter':
        model.details.parameters['val'] += 1
    elif fact == 'mnemonic':
        site.behaviors[0].decoded_instruction.mnemonic = 'str'
    elif fact == 'operand':
        site.behaviors[0].decoded_instruction.operand_text = 'r2, [r3, #0x18]'
    elif fact == 'instruction_address':
        site.details.address += 2
    elif fact == 'raw_bytes':
        site.details.raw_bytes = '00bf'
    elif fact == 'input_size':
        opaque.details.size_bytes += 1
    elif fact == 'input_hash':
        opaque.details.sha256 = '0' * 64
    else:
        trigger.details.every_nth_tick += 1
    assert firmware_context(inputs) != before


def test_instruction_and_mmio_equivalent_facts_not_repeated(inputs):
    p = build_firmware_analysis_projection(inputs)
    site = next(o for o in p.observations if o.kind == 'static_instruction_site')
    assert set(site.details) == {'address', 'function'}
    behavior = next(b for b in p.behaviors if b.behavior_id in site.behavior_ids)
    assert behavior.decoded_instruction['raw_encoding'] == '9969'
    assert behavior.decoded_instruction['mnemonic'] == 'ldr'
    for observation in p.observations:
        if observation.kind == 'mmio_model':
            b = next(b for b in p.behaviors if b.behavior_id in observation.behavior_ids)
            assert set(b.attributes) == {'direction'}
            assert {'pc', 'mmio_address', 'access_size_bytes', 'model_kind', 'parameters'} <= observation.details.keys()
            assert observation.scope == 'configuration'


@pytest.mark.parametrize('location', ['observation', 'behavior', 'decoded'])
def test_conflicting_nested_evidence_rejected(inputs, location):
    site = inputs.deterministic_observations.observations[0]
    conflict = site.evidence[0].model_copy(update={'summary': 'Different exact evidence'})
    if location == 'observation':
        inputs.deterministic_observations.observations[-1].evidence.append(conflict)
    elif location == 'behavior':
        site.behaviors[0].evidence.append(conflict)
    else:
        site.behaviors[0].decoded_instruction.evidence.append(conflict)
    with pytest.raises(AgentExecutionError, match='Conflicting'):
        firmware_context(inputs)


def test_generic_nested_only_evidence_is_cataloged(inputs):
    site = inputs.deterministic_observations.observations[0]
    b = site.behaviors[0].model_copy(deep=True)
    b.behavior_id = 'generic-behavior'
    b.evidence[0].evidence_id = 'behavior-only'
    b.decoded_instruction.evidence = [b.evidence[0].model_copy(update={'evidence_id': 'decoded-only'})]
    inputs.deterministic_observations.observations.append(DeterministicObservation(
        observation_id='generic', summary='Generic operational fact', evidence=site.evidence, behaviors=[b],
    ))
    p = build_firmware_analysis_projection(inputs)
    assert {'behavior-only', 'decoded-only'} <= {e.evidence_id for e in p.evidence_catalog}
    assert next(o for o in p.observations if o.kind == 'generic').summary == 'Generic operational fact'


def test_size_limits_fail_without_truncation(inputs):
    inputs.deterministic_observations.unresolved_questions = ['x' * MAX_CONTEXT_CHARS]
    before = inputs.model_dump_json()
    with pytest.raises(AgentExecutionError, match='64000'):
        firmware_context(inputs)
    assert inputs.model_dump_json() == before
    inputs.deterministic_observations.unresolved_questions = ['q'] * 129
    with pytest.raises(AgentExecutionError, match='item'):
        firmware_context(inputs)


def test_hardware_context_matches_unchanged_baseline(load_case):
    # Literal baseline JSON shape for a generic hardware case; firmware catalog
    # changes must not route hardware through the new serializer or identity gate.
    case = load_case('hardware_only')
    batch = HardwareObservations(case_id=case.case_id)
    actual = hardware_context(HardwareAgentInput(case=case, deterministic_observations=batch))
    expected = {
        'case': {'case_id': case.case_id, 'name': case.name,
                 'target': case.target.model_dump(mode='json', exclude_none=True), 'synthetic': True},
        'artifacts': [{k: a.model_dump(mode='json')[k] for k in ('artifact_id','artifact_type','path','format')}
                      for a in case.hardware_artifacts],
        'observations': [], 'unresolved_questions': [],
    }
    assert actual == json.dumps(expected, separators=(',', ':'), ensure_ascii=False)
