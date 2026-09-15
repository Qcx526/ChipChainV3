"""Synthetic hardware facts and adversarial typed support contracts (no LLM)."""

import json

import pytest
from pydantic import ValidationError

from chipchain.agents.contracts import HardwareAgentInput
from chipchain.domain.evidence import EvidenceTime
from chipchain.tools.architecture.riscv import RiscVInstructionDecoder
from chipchain.tools.contracts import HardwareObservationKind as ObservationKind
from chipchain.tools.hardware.encorpus import EnCorpusIbexDriverAnalyzer, EnCorpusIngestionResult
from chipchain.tools.hardware.encorpus.projection import PROJECTION_DESCRIPTOR
from chipchain.tools.hardware.relation_builder import build_hardware_relation_catalog
from chipchain.tools.hardware.relation_claims import (
    CAPABILITY_FOR_CLAIM, HardwareClaimKind, HardwareRelationFactClaim, HardwareSemanticClaim,
    check_hardware_claim,
)
from chipchain.tools.hardware.relations import (
    HardwareRelationCatalog, HardwareRelationKind as Kind, InstructionAttributes,
    hardware_relation_catalog_sha256, parse_hardware_relation_catalog, serialize_hardware_relation_catalog,
)
from tests.unit.test_encorpus_ingestion import sample


def enriched(result):
    projected = result.analysis_input()
    return HardwareAgentInput(case=projected.case, deterministic_observations=
                              RiscVInstructionDecoder().enrich(projected.deterministic_observations))


def build(inputs):
    return build_hardware_relation_catalog(inputs, projection_descriptor=PROJECTION_DESCRIPTOR)


@pytest.fixture
def inputs(sample):
    return enriched(EnCorpusIbexDriverAnalyzer().ingest(sample))


@pytest.fixture
def catalog(inputs):
    return build(inputs)


def fact(relation, **changes):
    data = dict(claim_id="fact", relation_id=relation.relation_id, expected_kind=relation.kind,
                expected_status=relation.status, expected_attributes=relation.attributes)
    data.update(changes)
    return HardwareRelationFactClaim(**data)


def semantic(kind, relations=(), **changes):
    data = dict(claim_id="semantic", kind=kind, relation_ids=[r.relation_id for r in relations])
    if len(relations) == 1:
        data.update(expected_attributes=relations[0].attributes, expected_status=relations[0].status)
    data.update(changes)
    return HardwareSemanticClaim(**data)


def test_mapping_exact_samples_and_evidence(inputs, catalog):
    before = inputs.model_dump_json()
    originals = {o.observation_id: o for o in inputs.deterministic_observations.observations}
    assert {r.kind for r in catalog.relations} == set(Kind)
    assert len(catalog.relations) == len(originals)
    for r in catalog.relations:
        o = originals[r.source_observation_id]
        a, d = r.attributes, o.details
        assert r.status == o.epistemic_status
        assert set(e.evidence_id for e in o.evidence) <= set(r.evidence_ids)
        if r.kind in (Kind.LOCAL, Kind.REGISTER):
            assert a.time == d.time
            for side in ("host", "reference"):
                for key in ("signal", "width", "bit_range", "value"):
                    assert getattr(a, side + "_" + key) == getattr(getattr(d, side), key)
            assert [e.side for e in r.endpoints] == ["host", "reference"]
            assert all(e.time == a.time for e in r.endpoints)
            if r.kind == Kind.REGISTER:
                assert a.register_name == d.register_name
                assert all(e.register_name == a.register_name for e in r.endpoints)
        elif r.kind == Kind.INSTRUCTION:
            assert a.time == d.time and a.signal_id == d.host.signal
            assert a.encoding_bits == d.host.value and a.encoding_width_bits == d.host.width
            assert a.decoded_instruction == o.behaviors[0].decoded_instruction
            assert a.decoded_instruction.epistemic_status == "derived"
        else:
            assert a.raw_result == d.raw_result
            assert a.interpretation_boundary == d.interpretation_boundary
            if r.kind == Kind.COVER:
                assert a.property_name == d.property_name and a.cycles == 8
            else:
                assert a.error_code == "EVS053"
    assert before == inputs.model_dump_json()


@pytest.mark.parametrize("kind", list(Kind))
def test_exact_fact_supported(catalog, kind):
    r = next(r for r in catalog.relations if r.kind == kind)
    assert check_hardware_claim(catalog, fact(r)).status == "supported"


@pytest.mark.parametrize("kind", list(CAPABILITY_FOR_CLAIM))
def test_positive_typed_semantics_require_exact_fact(catalog, kind):
    r = next(r for r in catalog.relations if r.kind == CAPABILITY_FOR_CLAIM[kind][0])
    assert check_hardware_claim(catalog, semantic(kind, [r])).status == "supported"
    assert check_hardware_claim(catalog, semantic(kind, [r], expected_attributes=None)).status == "unsupported"
    assert check_hardware_claim(catalog, semantic(kind)).status == "unsupported"


@pytest.mark.parametrize("field,value", [
    ("time", {"value": 999, "unit": "ps"}), ("host_signal", "other.signal"),
    ("reference_signal", "other.reference"), ("host_value", "1" * 32),
    ("register_name", "x29"),
])
def test_wrong_exact_register_fact_incompatible(catalog, field, value):
    r = next(r for r in catalog.relations if r.kind == Kind.REGISTER)
    attrs = r.attributes.model_dump(mode="json")
    attrs[field] = value
    claim = fact(r, expected_attributes=attrs)
    assert check_hardware_claim(catalog, claim).status == "incompatible"


def test_reversed_values_incompatible(catalog):
    r = next(r for r in catalog.relations if r.kind == Kind.REGISTER)
    attrs = r.attributes.model_dump()
    attrs["host_value"], attrs["reference_value"] = attrs["reference_value"], attrs["host_value"]
    assert check_hardware_claim(catalog, fact(r, expected_attributes=attrs)).status == "incompatible"


def test_wrong_mnemonic_and_status_incompatible(catalog):
    r = next(r for r in catalog.relations if r.kind == Kind.INSTRUCTION)
    attrs = r.attributes.model_dump(mode="json")
    attrs["decoded_instruction"]["mnemonic"] = "made_up"
    assert check_hardware_claim(catalog, fact(r, expected_attributes=attrs)).status == "incompatible"
    assert check_hardware_claim(catalog, fact(r, expected_status="observed")).status == "incompatible"
    assert check_hardware_claim(catalog, fact(r, expected_kind=Kind.LOCAL)).status == "incompatible"
    assert check_hardware_claim(catalog, fact(r, relation_id="not-supplied")).status == "incompatible"


@pytest.mark.parametrize("kind", [k for k in HardwareClaimKind if k not in CAPABILITY_FOR_CLAIM])
def test_semantic_promotions_always_unsupported(catalog, kind):
    extra = {"start": EvidenceTime(value=50, unit="ns"), "end": EvidenceTime(value=70, unit="ns")} if kind == HardwareClaimKind.INTERVAL else {}
    assert check_hardware_claim(catalog, semantic(kind, catalog.relations, **extra)).status == "unsupported"


def test_encoding_without_decode_does_not_support_decode(inputs):
    for o in inputs.deterministic_observations.observations:
        for b in o.behaviors:
            b.decoded_instruction = None
    c = build(inputs)
    r = next(r for r in c.relations if r.kind == Kind.INSTRUCTION)
    assert r.capabilities.supports_instruction_encoding_observed
    assert not r.capabilities.supports_instruction_decode
    assert check_hardware_claim(c, semantic(HardwareClaimKind.DECODED, [r])).status == "unsupported"
    assert c.source.decoder_descriptors == []


def test_failed_decode_has_no_positive_decode_power(inputs):
    for o in inputs.deterministic_observations.observations:
        for b in o.behaviors:
            if b.decoded_instruction:
                data = b.decoded_instruction.model_dump()
                data.update(status="unsupported", reason="synthetic backend limitation", mnemonic=None,
                            operand_text=None, operands=[])
                b.decoded_instruction = type(b.decoded_instruction).model_validate(data)
    c = build(inputs)
    r = next(r for r in c.relations if r.kind == Kind.INSTRUCTION)
    assert not r.capabilities.supports_instruction_decode
    assert check_hardware_claim(c, semantic(HardwareClaimKind.DECODED, [r])).status == "unsupported"


@pytest.mark.parametrize("capability", [
    "supports_instruction_execution", "supports_instruction_retirement", "supports_continuous_interval",
    "supports_register_read", "supports_register_write", "supports_causal_propagation",
    "supports_verified_trigger", "supports_root_cause", "supports_mutation_identity",
    "supports_physical_observability", "supports_same_configuration", "supports_vulnerability",
    "supports_instruction_decode", "supports_formal_result_observed",
])
def test_producer_cannot_forge_capability(catalog, capability):
    data = catalog.model_dump(mode="json")
    r = next(r for r in data["relations"] if r["kind"] == Kind.LOCAL)
    r["capabilities"][capability] = True
    with pytest.raises(ValidationError):
        HardwareRelationCatalog.model_validate(data)


@pytest.mark.parametrize("tamper", ["oracle_role", "mutation", "generic", "unknown_status", "decode_identity", "decode_artifact", "decode_width"])
def test_fail_closed_input(inputs, sample, tamper):
    o = inputs.deterministic_observations.observations[0]
    if tamper == "oracle_role":
        o.role = "benchmark_oracle"
    elif tamper == "mutation":
        oracle = EnCorpusIbexDriverAnalyzer().ingest(sample).oracle.observations[0]
        # Bypass model validation deliberately: builder must revalidate at boundary.
        oracle = oracle.model_copy(update={"role": "analysis_input"})
        inputs.deterministic_observations.observations.append(oracle)
    elif tamper == "generic":
        from chipchain.tools.contracts import DeterministicObservation
        inputs.deterministic_observations.observations[0] = DeterministicObservation(
            observation_id=o.observation_id, summary="unknown producer", evidence=o.evidence)
    elif tamper == "unknown_status":
        o.epistemic_status = "unknown"
    elif tamper == "decode_identity":
        o.behaviors[0].decoded_instruction.observation_id = "other-observation"
    elif tamper == "decode_width":
        o.behaviors[0].decoded_instruction.instruction_width_bits = 16
    else:
        o.behaviors[0].decoded_instruction.evidence[0].artifact_id = "not-available"
    with pytest.raises(ValueError):
        build(inputs)


def change_hidden_oracle(result):
    """Different validated ingestion container, not a dead field on Agent input."""
    changed = result.model_copy(deep=True)
    marker = "HIDDEN_ORACLE_CHANGED"
    mutation = next(o for o in changed.oracle.observations if o.kind == ObservationKind.MUTATION_PRESENT)
    mutation.details.signal = marker
    mutation.details.module = marker
    mutation.details.source_location = marker
    mutation.details.host_connection = marker
    mutation.details.reference_connection = "HIDDEN_REFERENCE_CHANGED"
    mutation.summary = marker
    changed.oracle.limitations.append(marker)
    for artifact in changed.artifacts:
        artifact.metadata["benchmark_family"] = marker
        if artifact.format == "rtlil":
            artifact.path = marker
    return EnCorpusIngestionResult.model_validate_json(changed.model_dump_json())


def test_oracle_independence_from_two_ingestion_containers(sample):
    result = EnCorpusIbexDriverAnalyzer().ingest(sample)
    changed = change_hidden_oracle(result)
    assert result.oracle.model_dump_json() != changed.oracle.model_dump_json()
    a, b = build(enriched(result)), build(enriched(changed))
    assert serialize_hardware_relation_catalog(a) == serialize_hardware_relation_catalog(b)
    assert hardware_relation_catalog_sha256(a) == hardware_relation_catalog_sha256(b)
    assert "HIDDEN_ORACLE" not in serialize_hardware_relation_catalog(b)


def test_canonical_order_roundtrip_fresh_build_and_metadata_exclusion(inputs, catalog):
    before = serialize_hardware_relation_catalog(catalog)
    assert before == serialize_hardware_relation_catalog(parse_hardware_relation_catalog(before))
    inputs.deterministic_observations.observations.reverse()
    inputs.case.metadata["benchmark_root_cause"] = "HIDDEN"
    for a in inputs.case.hardware_artifacts:
        a.metadata["family"] = "HIDDEN"
    shuffled = build(inputs)
    assert before == serialize_hardware_relation_catalog(shuffled)
    assert hardware_relation_catalog_sha256(catalog) == hardware_relation_catalog_sha256(shuffled)
    assert "HIDDEN" not in before
    for r in json.loads(before)["relations"]:
        assert r["evidence_ids"] == sorted(r["evidence_ids"])


def test_corrupt_catalog_rejected_on_codec_and_check(catalog):
    catalog.relations[0].endpoints[0].side = "reference"
    with pytest.raises(ValueError):
        serialize_hardware_relation_catalog(catalog)
    with pytest.raises(ValueError):
        check_hardware_claim(catalog, fact(catalog.relations[0]))


def test_explicit_persistence_only(catalog, tmp_path):
    from chipchain.integrations.hardware_typed_relations import persist_hardware_relation_catalog
    root = tmp_path / "results"
    assert not root.exists()
    one = persist_hardware_relation_catalog(catalog, root)
    two = persist_hardware_relation_catalog(catalog, root)
    assert one != two
    assert one.read_text() == two.read_text() == serialize_hardware_relation_catalog(catalog)
    assert {p.name for p in root.rglob('*') if p.is_file()} == {"hardware_typed_relations.json"}


def test_builder_rejects_ingestion_container(sample):
    with pytest.raises(TypeError, match="HardwareAgentInput"):
        build(EnCorpusIbexDriverAnalyzer().ingest(sample))


def test_operational_change_changes_catalog_identity(inputs):
    before = build(inputs)
    local = next(o for o in inputs.deterministic_observations.observations if o.kind == ObservationKind.LOCAL_EFFECT_OBSERVED)
    local.details.host.signal = "synthetic.other.operational.signal"
    after = build(inputs)
    assert before.source.operational_projection_sha256 != after.source.operational_projection_sha256
    assert hardware_relation_catalog_sha256(before) != hardware_relation_catalog_sha256(after)
    assert before.source.evidence_registry_sha256 == after.source.evidence_registry_sha256


def test_conflicting_evidence_id_rejected(inputs):
    o = inputs.deterministic_observations.observations[0]
    other = o.evidence[0].model_copy(deep=True)
    other.summary = "different provenance under the same identity"
    o.evidence.append(other)
    with pytest.raises(ValueError, match="Conflicting evidence"):
        build(inputs)


def test_builder_performs_no_io(inputs, monkeypatch):
    from pathlib import Path
    import builtins

    def forbidden(*args, **kwargs):
        raise AssertionError("Pure relation builder must not access files")

    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(builtins, "open", forbidden)
    assert build(inputs).relations


def test_architecture_neutral_non_instruction_facts(inputs):
    inputs.deterministic_observations.observations[:] = [
        o for o in inputs.deterministic_observations.observations if o.kind != ObservationKind.INSTRUCTION_ENCODING_OBSERVED]
    inputs.case.target.architecture = "arm"
    for o in inputs.deterministic_observations.observations:
        for b in o.behaviors:
            b.architecture = "arm"
    c = build(inputs)
    assert c.source.architecture == "arm"
    assert c.source.decoder_descriptors == []


@pytest.mark.parametrize("tamper", ["duplicate", "evidence_count", "evidence_id", "descriptor", "unsupported_status", "wrong_kind"])
def test_catalog_contract_rejects_inconsistent_wire_data(catalog, tamper):
    data = catalog.model_dump(mode="json")
    if tamper == "duplicate":
        data["relations"].append(data["relations"][0])
        data["source"]["observation_count"] += 1
    elif tamper == "evidence_count":
        data["source"]["evidence_registry_count"] += 1
    elif tamper == "evidence_id":
        data["relations"][0]["evidence_ids"].append("not-registered")
    elif tamper == "descriptor":
        data["source"]["decoder_descriptors"] = []
    elif tamper == "unsupported_status":
        data["relations"][0]["status"] = "unsupported"
    else:
        data["relations"][0]["kind"] = "formal_cover_hit"
    with pytest.raises(ValidationError):
        parse_hardware_relation_catalog(json.dumps(data))


def test_time_order_uses_exact_units(inputs):
    local = [o for o in inputs.deterministic_observations.observations if o.kind == ObservationKind.LOCAL_EFFECT_OBSERVED]
    second = local[0].model_copy(deep=True)
    second.observation_id += ":second-synthetic-point"
    inputs.deterministic_observations.observations.append(second)
    local.append(second)
    local[0].details.time = EvidenceTime(value=1, unit="ns")
    local[1].details.time = EvidenceTime(value=999, unit="ps")
    c = build(inputs)
    ids = [r.source_observation_id for r in c.relations]
    assert ids.index(local[1].observation_id) < ids.index(local[0].observation_id)
    reversed_catalog = c.model_copy(deep=True)
    reversed_catalog.relations.reverse()
    reversed_catalog.source.evidence_ids.reverse()
    for r in reversed_catalog.relations:
        r.evidence_ids.reverse()
    assert serialize_hardware_relation_catalog(c) == serialize_hardware_relation_catalog(reversed_catalog)
