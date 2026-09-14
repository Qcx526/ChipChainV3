"""Synthetic A4 semantics and explicitly cited claim proofs; no real corpus or model."""
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.agents.contracts import FirmwareAgentInput
from chipchain.agents.firmware_evidence import collect_firmware_reasoning_evidence
from chipchain.tools.firmware.fuzzware import FuzzwareHeatPressScenarioAnalyzer
from chipchain.tools.firmware.ghidra.elf import parse_elf
from chipchain.tools.firmware.ghidra.models import StaticFunction, UnresolvedCallSite
from chipchain.tools.firmware.ghidra.normalize import evidence
from chipchain.tools.firmware.structure_projection import build_relevant_static_structure
from chipchain.tools.architecture.arm import ArmThumbInstructionDecoder
from chipchain.tools.firmware.relation_builder import build_firmware_static_relations, classify_thumb_transfer
from chipchain.tools.firmware.relation_claims import ClaimKind, StaticRelationClaim, StaticCallPathClaim, check_claim_support
from chipchain.tools.firmware.relations import (
    FirmwareStaticRelationCatalog, RelationEndpoint, StaticRelationFact,
    serialize_firmware_static_relations, parse_firmware_static_relations, firmware_static_relations_sha256,
)
from tests.firmware_fakes import BASE, make_case, synthetic_elf
from tests.ghidra_fakes import function
from tests.structure_projection_fakes import projection_inputs


def canonical(tmp_path, *, memory='9969', missing=False, reason='decoder_disagreement'):
    _, structure, vectors = projection_inputs(tmp_path)
    # NOP; LDR/STR MMIO; B #BASE+16; padding. A2 confirmed edges are synthetic facts.
    case = make_case(tmp_path, code=bytes.fromhex('00bf'+memory+'04e0'+'00bf'*29))
    batch = FuzzwareHeatPressScenarioAnalyzer().analyze(case_id=case.case_id, target=case.target, artifacts=case.firmware_artifacts)
    inputs = FirmwareAgentInput(case=case, deterministic_observations=batch)
    ref = case.firmware_artifacts[0]
    structure.program = structure.program.model_copy(update={'sha256': ref.sha256, 'size_bytes': ref.size_bytes})
    structure.functions[0] = StaticFunction(**function(BASE, 2 if missing else 8, 'UARTClass::write'))
    site = structure.unresolved_call_sites[0].model_dump()
    site.update(call_site_address=BASE+4, target_address=BASE+16, reason=reason)
    structure.unresolved_call_sites[0] = UnresolvedCallSite(**site)
    relevant = build_relevant_static_structure(inputs, structure, vectors)
    return inputs, structure, vectors, relevant, Path(ref.path).read_bytes()


def build(data):
    return build_firmware_static_relations(*data[:4], elf_bytes=data[4])


@pytest.fixture
def data(tmp_path):
    return canonical(tmp_path)


@pytest.fixture
def catalog(data):
    return build(data)


def claim_for(relation, kind, **updates):
    values = dict(claim_id='synthetic-claim', claim_kind=kind, source=relation.source,
                  target=relation.target, relation_ids=[relation.relation_id])
    values.update(updates)
    return StaticRelationClaim(**values)


def fact(catalog, rid):
    return next(r for r in catalog.relations if r.relation_id == rid)


def test_confirmed_mapping_and_branch(data, catalog):
    for edge in data[3].direct_call_edges:
        r = fact(catalog, edge.edge_id)
        assert (r.kind, r.status, r.source.entity_id, r.target.entity_id) == (
            'direct_call', 'confirmed_static', edge.caller_function_id, edge.callee_function_id)
        assert r.evidence_ids == edge.evidence_ids
    branch = fact(catalog, 'call-80004')
    assert (branch.kind, branch.status, branch.attributes.transfer_kind) == ('direct_branch', 'confirmed_static', 'direct_branch')
    assert branch.source.entity_id == 'f80000' and branch.target.entity_id == 'f80010'
    assert branch.attributes.original_reason == 'decoder_disagreement'
    assert branch.attributes.decoded_target_address == BASE+16
    assert not branch.attributes.call_semantics
    assert check_claim_support(catalog, claim_for(branch, 'direct_branch')).status == 'supported'
    assert check_claim_support(catalog, claim_for(branch, 'direct_call')).status == 'incompatible'


def test_exact_roundtrip_and_order(data, catalog):
    registry = collect_firmware_reasoning_evidence(data[0], data[3])
    text = serialize_firmware_static_relations(catalog)
    assert parse_firmware_static_relations(text, evidence_registry=registry) == catalog
    assert text == serialize_firmware_static_relations(build(data))
    shuffled = catalog.model_copy(deep=True)
    shuffled.relations.reverse()
    shuffled.function_endpoints.reverse()
    shuffled.evidence_ids.reverse()
    for r in shuffled.relations:
        r.evidence_ids.reverse()
        r.limitations.reverse()
    assert serialize_firmware_static_relations(shuffled) == text
    assert firmware_static_relations_sha256(shuffled) == firmware_static_relations_sha256(catalog)
    # Exact source data and canonical artifact bytes remain unchanged.
    before = [o.model_dump_json() for o in data[:4]]
    build(data)
    assert [o.model_dump_json() for o in data[:4]] == before
    assert all('summary' not in r for r in json.loads(text)['relations'])


@pytest.mark.parametrize('mutation', ['duplicate', 'evidence', 'function', 'function_address'])
def test_catalog_rejects_invalid_references(catalog, mutation):
    value = catalog.model_dump()
    r = next(r for r in value['relations'] if r['kind'] == 'direct_call')
    if mutation == 'duplicate':
        value['relations'].append(r)
    elif mutation == 'evidence':
        r['evidence_ids'] = ['unknown-evidence']
    elif mutation == 'function':
        r['target']['entity_id'] = 'unknown-function'
    else:
        r['target']['address'] += 2
    with pytest.raises(ValidationError):
        FirmwareStaticRelationCatalog.model_validate(value)


def test_parse_requires_exact_external_registry(data, catalog):
    registry = collect_firmware_reasoning_evidence(data[0], data[3])
    registry.pop(next(iter(registry)))
    with pytest.raises(ValueError, match='exact reasoning registry'):
        parse_firmware_static_relations(serialize_firmware_static_relations(catalog), evidence_registry=registry)


@pytest.mark.parametrize('mutation', ['kind', 'call_semantics', 'runtime', 'physical', 'status', 'attributes', 'reason'])
def test_typed_relation_rejects_false_semantics(catalog, mutation):
    value = fact(catalog, 'call-80004').model_dump()
    if mutation == 'kind':
        value['kind'] = 'direct_call'
    elif mutation == 'call_semantics':
        value['attributes']['call_semantics'] = True
    elif mutation == 'runtime':
        value['capabilities']['supports_runtime_execution'] = True
    elif mutation == 'physical':
        value['capabilities']['supports_physical_interface'] = True
    elif mutation == 'status':
        value['status'] = 'verified'
    elif mutation == 'attributes':
        value['attributes']['invented_proof'] = True
    else:
        value['attributes']['original_reason'] = 'computed_or_ambiguous'
    with pytest.raises(ValidationError):
        StaticRelationFact.model_validate(value)


def test_computed_keeps_original_target_and_is_unresolved(tmp_path):
    data = canonical(tmp_path, reason='computed_or_ambiguous')
    catalog = build(data)
    r = fact(catalog, 'call-80004')
    # Even a decoded immediate does not erase an original computed/ambiguous conflict.
    assert r.attributes.original_target_address == BASE+16
    assert r.attributes.original_reason == 'computed_or_ambiguous'
    assert (r.kind, r.status, r.attributes.call_semantics) == ('control_transfer_unresolved', 'unresolved', False)
    assert check_claim_support(catalog, claim_for(r, 'direct_call')).status == 'incompatible'


@pytest.mark.parametrize('reason', ['instruction_boundary_unconfirmed', 'missing_caller', 'missing_callee',
                                   'callee_entry_conflict', 'caller_containment_conflict'])
def test_unresolved_original_reason_is_not_collapsed(tmp_path, reason):
    r = fact(build(canonical(tmp_path, reason=reason)), 'call-80004')
    assert r.attributes.original_reason == reason
    if reason != 'instruction_boundary_unconfirmed':
        assert r.status == 'unresolved'


@pytest.mark.parametrize('memory,direction,kind,opposite', [
    ('9969', 'read', 'mmio_read', 'mmio_write'), ('9961', 'write', 'mmio_write', 'mmio_read'),
    ('00bf', 'unknown', 'mmio_read', 'mmio_write')])
def test_mmio_direction_from_a1(tmp_path, memory, direction, kind, opposite):
    catalog = build(canonical(tmp_path, memory=memory))
    r = fact(catalog, 'mmio-direction-80002')
    assert r.attributes.direction == direction and r.attributes.origin == 'A1'
    assert check_claim_support(catalog, claim_for(r, kind)).status == ('unsupported' if direction == 'unknown' else 'supported')
    assert check_claim_support(catalog, claim_for(r, opposite)).status == ('unsupported' if direction == 'unknown' else 'incompatible')


def test_conflicting_a1_directions_rejected(data):
    observations = data[0].deterministic_observations.observations
    # Use the typed details class rather than interpreting observation text.
    from chipchain.tools.contracts import MmioModelDetails
    models = [o for o in observations if isinstance(o.details, MmioModelDetails)]
    assert len(models) > 1
    models[0].behaviors[0].attributes['direction'] = 'write'
    with pytest.raises(ValueError, match='directions'):
        build(data)


def test_missing_containment_remains_missing(tmp_path):
    catalog = build(canonical(tmp_path, missing=True))
    r = fact(catalog, 'mmio-containment-80002')
    assert r.status == 'missing' and r.target is None
    claim = claim_for(r, 'mmio_containment', target=RelationEndpoint(entity_type='function', entity_id='f80000'))
    assert check_claim_support(catalog, claim).status == 'unsupported'
    assert fact(catalog, 'call-80004').attributes.transfer_kind == 'boundary_unconfirmed'


def test_vector_dispatch_is_not_call_or_symbol_interface(catalog):
    r = fact(catalog, 'vector-1')
    assert r.kind == 'vector_dispatch' and r.status == 'confirmed_static'
    assert r.target.entity_id == 'f80000'
    assert r.capabilities.supports_static_dispatch
    assert not r.capabilities.supports_interrupt_occurrence
    assert not r.capabilities.supports_handler_execution
    assert check_claim_support(catalog, claim_for(r, 'vector_dispatch')).status == 'supported'
    assert check_claim_support(catalog, claim_for(r, 'direct_call')).status == 'incompatible'
    assert 'UARTClass' not in serialize_firmware_static_relations(catalog)
    for kind in ('physical_input_path', 'trigger_to_handler', 'runtime_reachability'):
        assert check_claim_support(catalog, claim_for(r, kind)).status == 'unsupported'


@pytest.mark.parametrize('kind', ['runtime_reachability', 'physical_input_path', 'trigger_to_handler'])
def test_all_static_facts_lack_runtime_capability(catalog, kind):
    for r in catalog.relations:
        assert not r.capabilities.supports_runtime_execution
        assert not r.capabilities.supports_input_consumption
        assert not r.capabilities.supports_physical_interface
        assert check_claim_support(catalog, claim_for(r, kind)).status == 'unsupported'


def test_direct_call_exact_endpoint_and_supplied_ids(catalog):
    r = fact(catalog, 'edge-80000')
    assert check_claim_support(catalog, claim_for(r, 'direct_call')).status == 'supported'
    wrong = RelationEndpoint(entity_type='function', entity_id='f80008')
    assert check_claim_support(catalog, claim_for(r, 'direct_call', source=wrong)).status == 'incompatible'
    wrong_address = r.target.model_copy(update={'address': BASE+18})
    assert check_claim_support(catalog, claim_for(r, 'direct_call', target=wrong_address)).status == 'incompatible'
    assert check_claim_support(catalog, claim_for(r, 'direct_call', relation_ids=['absent'])).status == 'incompatible'
    assert check_claim_support(catalog, claim_for(r, 'direct_call', relation_ids=[])).status == 'unsupported'


def test_explicit_path_only_and_no_runtime_inference(catalog):
    # f80008 -> f80000 -> f80010. The checker may not substitute a valid path.
    claim = StaticCallPathClaim(claim_id='path', source_function_id='f80008', target_function_id='f80010',
                               edge_relation_ids=['edge-80008', 'edge-80000'])
    assert check_claim_support(catalog, claim).status == 'supported'
    for ids in (['edge-80000', 'edge-80008'], ['edge-80008'], ['call-80004'], ['absent']):
        broken = claim.model_copy(update={'edge_relation_ids': ids})
        assert check_claim_support(catalog, broken).status == 'incompatible'
    runtime = StaticRelationClaim(claim_id='runtime', claim_kind='runtime_reachability',
        source=RelationEndpoint(entity_type='function', entity_id='f80008'),
        target=RelationEndpoint(entity_type='function', entity_id='f80010'), relation_ids=claim.edge_relation_ids)
    assert check_claim_support(catalog, runtime).status == 'unsupported'
    typed = runtime.model_copy(update={'claim_kind': ClaimKind.STATIC_CALL_PATH})
    assert check_claim_support(catalog, typed).status == 'supported'


def test_stale_a3_and_wrong_elf_rejected(data):
    relevant = data[3]
    relevant.mmio_sites[0].direction = 'write'
    with pytest.raises(ValueError, match='A3 does not match'):
        build(data)
    relevant.mmio_sites[0].direction = 'read'
    with pytest.raises(ValueError, match='fingerprint'):
        build_firmware_static_relations(*data[:4], elf_bytes=b'wrong')


@pytest.mark.parametrize('code,pc,kind,target', [
    ('00f002f8704770477047', BASE, 'direct_call', BASE+8),
    ('04e0'+'00bf'*8, BASE, 'direct_branch', BASE+12),
    ('9847', BASE, 'indirect_call', None),
    ('1847', BASE, 'indirect_branch', None),
    ('00bf', BASE, 'decoder_unknown', None),
    ('00f002f87047', BASE+2, 'boundary_unconfirmed', None),
])
def test_decoder_classification_uses_bytes_and_boundary(code, pc, kind, target):
    elf, _ = synthetic_elf(code=bytes.fromhex(code))
    caller = StaticFunction(**function(BASE, len(bytes.fromhex(code))))
    site = UnresolvedCallSite(call_site_address=pc, caller_function_id=caller.function_id,
        target_address=0x99999, reason='computed_or_ambiguous',
        evidence=[evidence('synthetic-transfer', pc, 'Synthetic control transfer')])
    result = classify_thumb_transfer(parse_elf(elf), caller, site, ArmThumbInstructionDecoder(), site.evidence)
    assert result.transfer_kind == kind
    assert result.decoded_target_address == target
    assert result.original_target_address == 0x99999
    assert not result.call_semantics
