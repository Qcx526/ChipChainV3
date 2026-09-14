"""Opt-in four real artifacts -> A1 -> fresh Ghidra A2 -> A3 -> A4, no agent."""
from collections import Counter
import json
import os
from pathlib import Path
import subprocess

import pytest

from chipchain.agents.contracts import FirmwareAgentInput
from chipchain.agents.firmware_evidence import collect_firmware_reasoning_evidence
from chipchain.agents.projections.firmware import build_firmware_analysis_projection, firmware_projection_sha256
from chipchain.agents.projections.firmware_envelope import build_firmware_envelope, firmware_envelope_sha256
from chipchain.tools.firmware.relation_builder import build_firmware_static_relations
from chipchain.tools.firmware.relation_claims import StaticRelationClaim, check_claim_support
from chipchain.tools.firmware.relations import (
    RelationEndpoint, serialize_firmware_static_relations, parse_firmware_static_relations,
    firmware_static_relations_sha256,
)
from chipchain.domain.case import CaseBundle, TargetDescriptor
from chipchain.tools.firmware.fuzzware import FuzzwareHeatPressScenarioAnalyzer
from chipchain.tools.firmware.ghidra.api import extract_heat_press_structure
from chipchain.tools.firmware.structure_projection import build_relevant_static_structure, relevant_structure_sha256
from tests.firmware_fakes import reference
from tests.integration.test_fuzzware_local import ARTIFACTS

_POPEN = subprocess.Popen


def test_real_static_relations(tmp_path, monkeypatch):
    ghidra = os.environ.get('CHIPCHAIN_GHIDRA_HOME')
    root = os.environ.get('CHIPCHAIN_FUZZWARE_ROOT')
    if not ghidra or not root:
        pytest.skip('Set both CHIPCHAIN_GHIDRA_HOME and CHIPCHAIN_FUZZWARE_ROOT explicitly')
    ghidra, root = Path(ghidra), Path(root)
    refs = [reference(root/p, k, f) for p, k, f, _, _ in ARTIFACTS]
    for ref, (_, _, _, size, sha) in zip(refs, ARTIFACTS):
        assert (ref.size_bytes, ref.sha256) == (size, sha)
    case = CaseBundle(case_id='fuzzware:heat-press:scenario-13', name='Heat_Press scenario 13', firmware_artifacts=refs,
        target=TargetDescriptor(processor_id='sam3x', firmware_id='heat-press', architecture='arm',
            word_size_bits=32, endianness='little', isa_variant='ARMv7-M Thumb'))
    batch = FuzzwareHeatPressScenarioAnalyzer().analyze(case_id=case.case_id, target=case.target, artifacts=refs)
    inputs = FirmwareAgentInput(case=case, deterministic_observations=batch)
    assert firmware_projection_sha256(build_firmware_analysis_projection(inputs)) == '48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803'

    def explicit_headless(argv, **settings):
        assert argv[0] == str((ghidra/'support/analyzeHeadless').resolve())
        assert settings['shell'] is False and settings['cwd'].is_relative_to(tmp_path)
        return _POPEN(argv, **settings)

    monkeypatch.setattr(subprocess, 'Popen', explicit_headless)
    temporary = tmp_path/'projects'
    temporary.mkdir()
    structure, vectors = extract_heat_press_structure(Path(refs[0].path), ghidra_home=ghidra,
        script_path=Path(__file__).resolve().parents[2]/'scripts/ghidra/ExportFirmwareStructure.java', temporary_parent=temporary)
    assert not list(temporary.iterdir())
    relevant = build_relevant_static_structure(inputs, structure, vectors)
    assert relevant_structure_sha256(relevant) == '4685e8fbc41fffd90a32bc550fc122955b329c24043dd860abecf55970056304'
    envelope = build_firmware_envelope(inputs, relevant, structure)
    assert firmware_envelope_sha256(envelope) == '6afef3295f8c54ee7fef65446db0a91169ee833d3ede4314e38e45ca0d7c5016'
    registry = collect_firmware_reasoning_evidence(inputs, relevant)
    assert len(registry) == 174
    before = [o.model_dump_json() for o in (inputs, structure, vectors, relevant)]
    elf = Path(refs[0].path).read_bytes()
    catalog = build_firmware_static_relations(inputs, structure, vectors, relevant, elf_bytes=elf)
    second = build_firmware_static_relations(inputs, structure, vectors, relevant, elf_bytes=elf)
    text = serialize_firmware_static_relations(catalog)
    assert text == serialize_firmware_static_relations(second)
    assert parse_firmware_static_relations(text, evidence_registry=registry) == catalog
    assert [o.model_dump_json() for o in (inputs, structure, vectors, relevant)] == before
    assert set(catalog.evidence_ids) == set(registry)
    assert all(set(r.evidence_ids) <= set(registry) for r in catalog.relations)
    facts = {r.relation_id: r for r in catalog.relations}
    counts = Counter(r.kind.value for r in catalog.relations)
    assert counts == {'direct_call': 22, 'direct_branch': 6, 'control_transfer_unresolved': 6,
                      'mmio_function_containment': 23, 'mmio_access_direction': 23, 'vector_dispatch': 51}
    assert len(catalog.relations) == 131
    for edge in relevant.direct_call_edges:
        r = facts[edge.edge_id]
        assert (r.kind, r.status, r.source.entity_id, r.target.entity_id, r.site_address, r.evidence_ids) == (
            'direct_call', 'confirmed_static', edge.caller_function_id, edge.callee_function_id,
            edge.call_site_address, edge.evidence_ids)
    table = []
    for site in relevant.unresolved_call_sites:
        r = facts[f'call-{site.call_site_address:x}']
        assert r.attributes.original_reason == site.reason
        assert r.attributes.original_target_address == site.target_address
        table.append(dict(site=hex(r.site_address), caller=r.source.entity_id, a2_reason=site.reason,
            mnemonic=r.attributes.mnemonic, decoded_target=(hex(r.attributes.decoded_target_address)
                if r.attributes.decoded_target_address is not None else None),
            transfer_kind=r.attributes.transfer_kind.value, kind=r.kind.value, status=r.status.value))
    assert len(table) == 12
    reset = facts['call-80f88']
    assert reset.kind == 'control_transfer_unresolved' and reset.status == 'unresolved'
    assert reset.attributes.original_reason == 'computed_or_ambiguous'
    assert reset.attributes.decoded_target_address is None
    assert reset.attributes.transfer_kind == 'indirect_call' and reset.attributes.mnemonic == 'blx'
    assert reset.attributes.original_target_address == 0x816cc
    correct = facts['call-80afa']
    assert (correct.source.entity_id, correct.target.entity_id, correct.site_address) == ('f80af4', 'f80eac', 0x80afa)
    outcomes = Counter()

    def check(rid, kind, expected, source=None, target=None):
        relation = facts[rid]
        claim = StaticRelationClaim(claim_id=f'regression-{rid}-{kind}', claim_kind=kind,
            source=source or relation.source, target=target if target is not None else relation.target, relation_ids=[rid])
        outcome = check_claim_support(catalog, claim)
        assert outcome.status == expected
        outcomes[outcome.status.value] += 1

    def function(fid):
        return RelationEndpoint(entity_type='function', entity_id=fid)

    check('call-80afa', 'direct_call', 'supported')
    check('call-80f88', 'direct_call', 'incompatible', function('f80f34'), function('f80eac'))
    for pc in (0x80abe, 0x80ad2, 0x80ade, 0x80aea):
        r = facts[f'call-{pc:x}']
        assert r.attributes.mnemonic == 'b.w' and r.target.entity_id == 'f815a4'
        assert r.attributes.call_semantics is False
        check(r.relation_id, 'direct_call', 'incompatible')
        check(r.relation_id, 'direct_branch', 'supported')
    for pc in (0x80eba, 0x80eca, 0x80ed2, 0x80eda, 0x80ee6, 0x80ef2, 0x80efe, 0x80f0a):
        direction = facts[f'mmio-direction-{pc:x}']
        assert (direction.attributes.direction, direction.attributes.mnemonic) == ('read', 'ldr')
        assert facts[f'mmio-containment-{pc:x}'].target.entity_id == 'f80eac'
        check(direction.relation_id, 'mmio_read', 'supported')
        check(direction.relation_id, 'mmio_write', 'incompatible')
    containments = [r for r in catalog.relations if r.kind == 'mmio_function_containment']
    assert Counter(r.status for r in containments) == {'confirmed_static': 20, 'missing': 3}
    assert {r.site_address for r in containments if r.status == 'missing' and r.target is None} == {0x80d4e, 0x80d50, 0x80d5a}
    dispatch = [r for r in catalog.relations if r.kind == 'vector_dispatch']
    assert len(dispatch) == 51 and all(r.status == 'confirmed_static' for r in dispatch)
    assert {r.attributes.vector_index for r in dispatch} == {b.vector_index for b in vectors.bindings if b.vector_index and b.raw_handler_value}
    assert facts['vector-1'].target.entity_id == 'f80f34'
    check('vector-1', 'vector_dispatch', 'supported')
    check('vector-1', 'direct_call', 'incompatible', function('f80f34'), function('f80eac'))
    check('vector-1', 'trigger_to_handler', 'unsupported')
    check('call-80afa', 'runtime_reachability', 'unsupported')
    check('vector-1', 'physical_input_path', 'unsupported')
    assert outcomes == {'supported': 14, 'incompatible': 14, 'unsupported': 3}
    for r in catalog.relations:
        assert not any((r.capabilities.supports_runtime_execution, r.capabilities.supports_runtime_reachability,
                        r.capabilities.supports_input_consumption, r.capabilities.supports_physical_interface))
    metrics = dict(counts=counts, total=len(catalog.relations), registry_count=len(registry),
        containment_statuses=Counter(r.status.value for r in containments),
        directions=Counter(r.attributes.direction for r in catalog.relations if r.kind == 'mmio_access_direction'),
        claim_regressions=outcomes, classification_table=table, characters=len(text),
        sha256=firmware_static_relations_sha256(catalog), source_identities=catalog.source_identities.model_dump(mode='json'))
    audit = tmp_path/'audit'
    audit.mkdir()
    (audit/'firmware_static_relations.json').write_text(text, encoding='utf-8')
    (audit/'metrics.json').write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding='utf-8')
    print(json.dumps({'audit_directory': str(audit), **metrics}, sort_keys=True))
