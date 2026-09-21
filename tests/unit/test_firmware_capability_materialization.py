import pytest

from chipchain.domain.evidence import EvidenceRef
from chipchain.firmware.control_flow_grounding import (
    Capabilities, FirmwareControlFlowGroundingCatalog, FunctionInterval,
    RuntimeRetirementObservation, SourceArtifact, identity, serialize_catalog,
)
from chipchain.firmware.grounding_catalog import resolve_ownership
from chipchain.firmware.riscv_control_flow import resolve_transfer
from chipchain.firmware.capability_materialization import materialize_a6
from chipchain.firmware.capability import FirmwareCapabilityInput, build_firmware_capability, serialize_firmware_capability


def catalog(*, indirect=False, runtime=True, owner='missing'):
    fact = resolve_transfer(case_id='synthetic:a6', pc=0x100080,
        encoding=bytes.fromhex('67800000' if indirect else '6f00602c'),
        architecture='riscv', artifact_id='elf', source_sha256='a'*64, evidence_ids=['ev:static'])
    sources = [SourceArtifact(artifact_id='elf', sha256='a'*64, size_bytes=4, format='elf')]
    evidence = [EvidenceRef(evidence_id='ev:static', artifact_id='elf', source_type='deterministic_analyzer',
                            summary='Synthetic A6 static instruction definition', epistemic_status='derived')]
    functions = []
    if owner != 'missing':
        functions.append(FunctionInterval(function_id='function:one', function_name='synthetic_fn',
            start=0x100080, end_exclusive=0x100090, source_kind='elf_symbol', source_ids=['elf'], evidence_ids=['ev:static']))
    if owner == 'ambiguous':
        functions.append(FunctionInterval(function_id='function:two', function_name='overlap',
            start=0x100070, end_exclusive=0x100100, source_kind='elf_symbol', source_ids=['elf'], evidence_ids=['ev:static']))
    ownership = resolve_ownership(case_id='synthetic:a6', site_pc=fact.instruction_pc, functions=functions,
        source_id='elf', source_sha256='a'*64, evidence_id='ev:static', architecture='riscv')
    events = []
    if runtime:
        sources.append(SourceArtifact(artifact_id='trace', sha256='b'*64, size_bytes=128, format='ibex-rvfi-text'))
        evidence.append(EvidenceRef(evidence_id='ev:trace', artifact_id='trace', source_type='deterministic_analyzer',
                                    summary='Synthetic retirement event', epistemic_status='observed'))
        events.append(RuntimeRetirementObservation(observation_id='retired:1', case_id='synthetic:a6',
            instruction_pc=fact.instruction_pc, instruction_encoding=fact.instruction_encoding,
            cycle=6, line=2, source_artifact_id='trace', source_sha256='b'*64, evidence_ids=['ev:trace']))
    return FirmwareControlFlowGroundingCatalog(case_id='synthetic:a6', architecture='riscv',
        transfer_facts=[fact], ownership_facts=[ownership], functions=functions,
        source_artifacts=sources, evidence_catalog=evidence, runtime_observations=events,
        capabilities=Capabilities(supports_direct_target_resolution=True), limitations=['synthetic fixture'])


def convert(value):
    return materialize_a6(value, fact_id=value.transfer_facts[0].fact_id)


def test_direct_target_retirement_and_immutability():
    source = catalog()
    before = serialize_catalog(source)
    value = convert(source)
    assert serialize_catalog(source) == before
    assert value.origin.kind == 'normal_behavior'
    assert value.primitives[0].kind == 'DIRECT_CONTROL_TRANSFER'
    assert next(c.targets for c in value.constraints if c.kind == 'target_set') == [0x100346]
    assert value.entry.execution_status == 'source_instruction_retired'
    assert value.entry.reachability_status == 'unknown'
    assert value.primitives[0].control.status == 'not_established'
    assert value.retirement_evidence[0].interpretation == 'source_instruction_retired_only'
    assert convert(source).capability_id == value.capability_id
    assert 'raw_model_summary' not in serialize_firmware_capability(value)
    assert 'CONTROL_FLOW_HIJACK' not in serialize_firmware_capability(value)
    assert 'WRITE_OOB' not in serialize_firmware_capability(value)


def test_indirect_has_no_concrete_target():
    value = convert(catalog(indirect=True))
    assert value.primitives[0].kind == 'INDIRECT_CONTROL_TRANSFER'
    assert value.primitives[0].target_status == 'indirect_unknown'
    assert not any(c.kind == 'target_set' for c in value.constraints)
    assert value.primitives[0].control.status == 'not_established'


@pytest.mark.parametrize('status', ['unique', 'ambiguous', 'missing'])
def test_ownership_only_supplies_context(status):
    value = convert(catalog(owner=status, runtime=False))
    assert value.entry.ownership_status == status
    assert value.entry.function_id == ('function:one' if status == 'unique' else None)
    assert value.entry.execution_status == 'static_only'
    assert value.entry.reachability_status == 'unknown'
    assert value.entry.interface_id is None
    assert value.primitives[0].control.status == 'not_established'


def test_wrong_target_rejected_even_if_attacker_recomputes_catalog_and_fact_hash():
    source = catalog(runtime=False)
    data = source.model_dump(mode='json')
    data['transfer_facts'][0]['resolved_target_pc'] = 0x1002c6
    with pytest.raises(ValueError, match='Catalog SHA'):
        FirmwareControlFlowGroundingCatalog.model_validate(data)
    data['catalog_sha256'] = None
    fact = data['transfer_facts'][0]
    fact['fact_id'] = identity('a6-transfer', {k:v for k,v in fact.items() if k != 'fact_id'})
    forged = FirmwareControlFlowGroundingCatalog.model_validate(data)
    with pytest.raises(ValueError, match='disagree with static instruction bytes'):
        convert(forged)


@pytest.mark.parametrize('status', ['input_influenced', 'bounded_external_control', 'full_external_control'])
def test_retirement_cannot_establish_control(status):
    value = convert(catalog())
    data = value.model_dump(exclude={'schema_version', 'capability_id', 'capability_sha256'})
    authority = data['primitives'][0]['control']
    authority.update(status=status, dimensions=['target'], support_basis='independent_capability_evidence',
                     evidence_ids=['ev:trace'])
    authority['source_artifact_ids'].append('trace')
    authority['provenance'].append(dict(source_kind='runtime_trace', source_artifact_ids=['trace']))
    with pytest.raises(ValueError, match='Control cannot be established'):
        build_firmware_capability(FirmwareCapabilityInput.model_validate(data))


def test_indirect_target_injection_and_runtime_observation_mismatch_rejected():
    value = convert(catalog(indirect=True))
    data = value.model_dump(exclude={'schema_version', 'capability_id', 'capability_sha256'})
    base = {k:data['constraints'][0][k] for k in ('source_artifact_ids', 'evidence_ids', 'provenance')}
    data['constraints'].append(dict(kind='target_set', constraint_id='guessed-target', targets=[0x1234], **base))
    data['primitives'][0]['constraint_ids'].append('guessed-target')
    with pytest.raises(ValueError, match='Indirect target'):
        FirmwareCapabilityInput.model_validate(data)
    data = value.model_dump(exclude={'schema_version', 'capability_id', 'capability_sha256'})
    data['retirement_evidence'][0]['pc'] += 4
    with pytest.raises(ValueError, match='site/evidence mismatch'):
        FirmwareCapabilityInput.model_validate(data)
