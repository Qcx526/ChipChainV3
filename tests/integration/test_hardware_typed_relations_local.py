"""Opt-in local corpus tests: frozen B.1 + A2, no external tools or model calls."""

from collections import Counter
import os
from pathlib import Path

import pytest

from chipchain.agents.context import hardware_context
from chipchain.domain.evidence import EvidenceTime
from chipchain.integrations.hardware_typed_relations import FROZEN_CONTEXT_SHA256, prepare_local_catalog
from chipchain.tools.hardware.encorpus import EnCorpusIbexDriverAnalyzer
from chipchain.tools.hardware.relation_claims import HardwareClaimKind as Claim, check_hardware_claim
from chipchain.tools.hardware.relations import (
    HardwareRelationKind as Kind, hardware_relation_catalog_sha256, parse_hardware_relation_catalog,
    serialize_hardware_relation_catalog, sha256_text,
)
from tests.unit.test_hardware_typed_relations import build, change_hidden_oracle, enriched, fact, semantic


@pytest.fixture(params=["743", "820"])
def real(request):
    root = os.environ.get("CHIPCHAIN_ENCORPUS_IBEX_ROOT")
    if not root:
        pytest.skip("Set CHIPCHAIN_ENCORPUS_IBEX_ROOT to the local ibex/ibex directory")
    path = Path(root) / "driver" / request.param
    inputs, catalog = prepare_local_catalog(path)
    return request.param, path, inputs, catalog


def test_real_exact_facts_and_frozen_context(real):
    sample, _, inputs, c = real
    assert sha256_text(hardware_context(inputs)) == FROZEN_CONTEXT_SHA256[c.source.case_id]
    assert c.source.architecture == "riscv"
    expected = {Kind.INSTRUCTION: 3, Kind.LOCAL: 3, Kind.REGISTER: 2, Kind.COVER: 1, Kind.ERROR: 1} if sample == "743" else {
        Kind.LOCAL: 6, Kind.REGISTER: 1, Kind.COVER: 1, Kind.ERROR: 1}
    assert Counter(r.kind for r in c.relations) == Counter(expected)
    assert c.source.observation_count == (10 if sample == "743" else 9)
    assert c.source.behavior_count == (5 if sample == "743" else 1)
    assert c.source.evidence_registry_count == (24 if sample == "743" else 16)
    instructions = [r.attributes for r in c.relations if r.kind == Kind.INSTRUCTION]
    assert [(a.decoded_instruction.raw_encoding, a.decoded_instruction.mnemonic,
             a.decoded_instruction.operand_text, a.time.value, a.time.unit) for a in instructions] == (
        [("0x00130e13", "addi", "x28, x6, 1", 30, "ns"), ("0x00001537", "lui", "x10, 1", 40, "ns"),
         ("0x007e2503", "lw", "x10, 7(x28)", 50, "ns")] if sample == "743" else [])
    for a in instructions:
        assert a.stage == "id" and a.encoding_width_bits == 32
        assert a.encoding_representation == "decompressed_word"
        assert a.decoded_instruction.decoder.tool_version == "5.0.9"
        assert a.decoded_instruction.instruction_width_bits == 32
        assert int(a.encoding_bits, 2) == int(a.decoded_instruction.raw_encoding, 16)
    local = [r.attributes for r in c.relations if r.kind == Kind.LOCAL]
    assert [(a.host_signal.rsplit('.', 1)[1], a.time.value, int(a.host_value, 2), int(a.reference_value, 2)) for a in local] == (
        [("ls_fsm_ns", 50, 2, 0), ("ls_fsm_cs", 60, 2, 0), ("ls_fsm_ns", 70, 2, 0)] if sample == "743" else
        [("debug_mode_q", t, 0, 1) for t in [100, 230, 330, 410, 490, 540]])
    registers = [r.attributes for r in c.relations if r.kind == Kind.REGISTER]
    assert [(a.register_name, a.time.value, int(a.host_value, 2), int(a.reference_value, 2)) for a in registers] == (
        [("x28", 50, 0, 1), ("x10", 70, 4096, 0)] if sample == "743" else [("x10", 580, 0, 888)])
    for a in [*local, *registers]:
        assert a.time.unit == "ns"
        assert len(a.host_value) == a.host_width == a.reference_width == len(a.reference_value)
        assert a.host_signal.startswith("miter.\\host.")
        assert a.reference_signal.startswith("miter.\\reference.")
    for a in registers:
        assert a.host_width == 32
        assert (a.host_bit_range.msb, a.host_bit_range.lsb) == (a.reference_bit_range.msb, a.reference_bit_range.lsb)
        assert a.host_bit_range.msb == (927 if a.register_name == "x28" else 351)
    cover = next(r.attributes for r in c.relations if r.kind == Kind.COVER)
    assert cover.property_name == "miter.i_miter.c_propagated"
    assert cover.cycles == (8 if sample == "743" else 59)
    assert next(r.attributes.error_code for r in c.relations if r.kind == Kind.ERROR) == "EVS053"
    # All canonical facts are directly machine-checkable.
    assert all(check_hardware_claim(c, fact(r)).status == "supported" for r in c.relations)


def test_real_claim_regression_matrix(real):
    sample, _, _, c = real
    by = lambda kind: [r for r in c.relations if r.kind == kind]
    local, registers, formal = by(Kind.LOCAL), by(Kind.REGISTER), by(Kind.COVER) + by(Kind.ERROR)
    x10 = next(r for r in registers if r.attributes.register_name == "x10")
    matrix = [
        (semantic(Claim.LOCAL, [local[0]]), "supported"),
        (semantic(Claim.REGISTER, [x10]), "supported"),
        (semantic(Claim.READ, [x10]), "unsupported"),
        (semantic(Claim.WRITE, [x10]), "unsupported"),
        (semantic(Claim.COVER, [formal[0]]), "supported"),
        (semantic(Claim.ERROR, [formal[1]]), "supported"),
        (semantic(Claim.SAME_CONFIGURATION, formal), "unsupported"),
        (semantic(Claim.FORMAL_CAUSAL, formal), "unsupported"),
        (semantic(Claim.CAUSAL, [local[0], x10]), "unsupported"),
    ]
    if sample == "743":
        addi = by(Kind.INSTRUCTION)[0]
        matrix += [
            (semantic(Claim.DECODED, [addi]), "supported"),
            (semantic(Claim.ENCODING, [addi]), "supported"),
            (semantic(Claim.EXECUTED, [addi]), "unsupported"),
            (semantic(Claim.RETIRED, [addi]), "unsupported"),
            (semantic(Claim.INTERVAL, local, start=EvidenceTime(value=50, unit="ns"),
                      end=EvidenceTime(value=70, unit="ns")), "unsupported"),
            (semantic(Claim.TRIGGER, [by(Kind.INSTRUCTION)[2], local[0], x10]), "unsupported"),
        ]
        assert local[0].attributes.host_signal != local[1].attributes.host_signal
    else:
        matrix += [(semantic(Claim.ENCODING), "unsupported"), (semantic(Claim.DECODED), "unsupported"),
                   (semantic(Claim.ENCODING, [local[0]]), "unsupported")]
    for claim, expected in matrix:
        result = check_hardware_claim(c, claim)
        assert result.status == expected, (sample, claim.kind, result)
    # Exact value inversion is disagreement, not missing semantic power.
    attrs = x10.attributes.model_dump()
    attrs["host_value"], attrs["reference_value"] = attrs["reference_value"], attrs["host_value"]
    assert check_hardware_claim(c, fact(x10, expected_attributes=attrs)).status == "incompatible"


def test_real_two_fresh_builds_and_roundtrip(real):
    sample, path, _, first = real
    _, second = prepare_local_catalog(path)
    a, b = serialize_hardware_relation_catalog(first), serialize_hardware_relation_catalog(second)
    assert a == b == serialize_hardware_relation_catalog(parse_hardware_relation_catalog(a))
    assert hardware_relation_catalog_sha256(first) == hardware_relation_catalog_sha256(second)
    print(f"{sample}: chars={len(a)}, sha256={hardware_relation_catalog_sha256(first)}, "
          f"projection_sha256={first.source.operational_projection_sha256}, "
          f"evidence_sha256={first.source.evidence_registry_sha256}")


def test_real_hidden_oracle_independence(real):
    _, path, _, first = real
    original = EnCorpusIbexDriverAnalyzer().ingest(path)
    changed = change_hidden_oracle(original)
    assert original.oracle.model_dump_json() != changed.oracle.model_dump_json()
    second = build(enriched(changed))
    assert serialize_hardware_relation_catalog(first) == serialize_hardware_relation_catalog(second)
    assert hardware_relation_catalog_sha256(first) == hardware_relation_catalog_sha256(second)
