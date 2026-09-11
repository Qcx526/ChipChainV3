"""Independent known-answer RV32 words, with synthetic evidence (no corpus needed)."""

from importlib.metadata import version

import pytest
from capstone import riscv_const
from pydantic import ValidationError

from chipchain.domain.behavior import BehaviorKind, ProcessorBehavior, ProcessorBehaviorIR
from chipchain.domain.common import Architecture
from chipchain.domain.evidence import BitRange, EvidenceLocation, EvidenceRef, EvidenceTime
from chipchain.domain.instruction import DecodedInstruction, DecodeStatus, EncodingRepresentation as Representation, InstructionEncoding
from chipchain.tools.architecture import RiscVInstructionDecoder
from chipchain.tools.architecture.riscv import instruction_bytes
from chipchain.tools.contracts import HardwareObservation, HardwareObservations, SignalValue, WaveformObservationDetails


def encoding(word, *, width=32, representation=Representation.INSTRUCTION_WORD):
    bits = f"{word:0{width}b}" if isinstance(word, int) else word
    return InstructionEncoding(
        observation_id="synthetic:instruction", architecture="riscv", bits=bits, width_bits=width,
        representation=representation, source_stage="synthetic_known_answer",
        evidence=[EvidenceRef(evidence_id="synthetic:word", artifact_id="synthetic:trace",
            source_type="synthetic", summary="Synthetic instruction word fixture", epistemic_status="observed",
            location=EvidenceLocation(line=7, signal="synthetic.host.id_word", time=EvidenceTime(value=30, unit="ns"),
                                      bit_range=BitRange(msb=width-1, lsb=0)))],
    )


def observation(word=0x00130e13, *, representation=Representation.DECOMPRESSED_WORD):
    source = encoding(word, representation=representation)
    raw = (f"0x{int(source.bits, 2):08x}" if not any(c in source.bits for c in "xz") else "0b" + source.bits)
    behavior = ProcessorBehavior(behavior_id="existing:instruction", kind="instruction", architecture="riscv",
        origin="hardware", summary="ID-stage word observed; retirement unknown", evidence=source.evidence,
        epistemic_status="derived", attributes={"encoding": raw, "observation_stage": "id", "pc": 0})
    return HardwareObservation(observation_id=source.observation_id, kind="instruction_encoding_observed",
        role="analysis_input", summary=behavior.summary, evidence=source.evidence, behaviors=[behavior],
        epistemic_status="derived", details=WaveformObservationDetails(
            time=EvidenceTime(value=30, unit="ns"), observation_stage="id", encoding_representation=representation,
            host=SignalValue(signal="synthetic.host.id_word", role="host", width=32, value=source.bits,
                             bit_range=BitRange(msb=31, lsb=0), declaration_line=1)))


@pytest.mark.parametrize("word,mnemonic,operands", [
    (0x00130e13, "addi", "x28, x6, 1"),
    (0xfff30513, "addi", "x10, x6, -1"),
    (0x003100b3, "add", "x1, x2, x3"),
    (0x403100b3, "sub", "x1, x2, x3"),
    (0x00001537, "lui", "x10, 1"),
    (0x007e2503, "lw", "x10, 7(x28)"),
    (0xffc12083, "lw", "x1, -4(x2)"),
    (0x00312223, "sw", "x3, 4(x2)"),
    (0x00208463, "beq", "x1, x2, 8"),
    (0x008000ef, "jal", "8"),  # backend alias omits implicit x1; no invented operand
    (0x00000013, "nop", ""),   # backend alias, not a newly implemented decoder
])
def test_known_answers(word, mnemonic, operands):
    result = RiscVInstructionDecoder().decode(encoding(word))
    assert result.status == DecodeStatus.DECODED
    assert result.mnemonic == mnemonic and result.operand_text == operands
    assert result.instruction_width_bits == 32
    assert result.evidence == encoding(word).evidence


def test_byte_order_is_instruction_parcel_order():
    assert instruction_bytes(encoding(0x00130e13)) == bytes.fromhex("13 0e 13 00")
    assert instruction_bytes(encoding(0x00001537)) == bytes.fromhex("37 15 00 00")
    assert instruction_bytes(encoding(0x007e2503)) == bytes.fromhex("03 25 7e 00")
    assert instruction_bytes(encoding(0x00130e13)) != bytes.fromhex("00 13 0e 13")


def test_canonical_gpr_identity_and_backend_display_aliases():
    decoder = RiscVInstructionDecoder()
    assert decoder.canonical_register(riscv_const.RISCV_REG_A0) == "x10"
    assert decoder.canonical_register(riscv_const.RISCV_REG_X10) == "x10"
    assert decoder.canonical_register(riscv_const.RISCV_REG_T3) == "x28"
    result = decoder.decode(encoding(0x007e2503))
    assert result.backend_operand_text == "a0, 7(t3)"
    assert result.operands[0].register_name == "x10"
    assert result.operands[1].base == "x28" and result.operands[1].displacement == 7
    assert result.operands[1].kind == "memory"


@pytest.mark.parametrize("source,status", [
    (encoding(0), DecodeStatus.INVALID),
    (encoding(0xffffffff), DecodeStatus.UNSUPPORTED),
    (encoding(0x0000000b), DecodeStatus.UNSUPPORTED),  # unrecognized custom opcode != universally illegal
    (encoding("x" * 32), DecodeStatus.UNKNOWN),
    (encoding("z" * 32), DecodeStatus.UNKNOWN),
    (encoding(0x00130e13, representation=Representation.UNKNOWN), DecodeStatus.UNKNOWN),
    (encoding(0x0085, width=16), DecodeStatus.UNSUPPORTED),  # c.addi, deliberately not enabled
    (encoding(0x0085, representation=Representation.DECOMPRESSED_WORD), DecodeStatus.INVALID),
    (encoding(0x0085), DecodeStatus.UNSUPPORTED),  # no implicit C-mode scan of a 32-bit word
])
def test_failure_status_keeps_encoding_evidence_and_reason(source, status):
    result = RiscVInstructionDecoder().decode(source)
    assert result.status == status
    assert result.reason and result.mnemonic is None and result.operand_text is None
    assert result.evidence == source.evidence and result.observation_id == source.observation_id
    assert result.instruction_width_bits == source.width_bits
    assert result.operands == []


def test_non_riscv_input_is_explicitly_unsupported():
    source = encoding(0x00130e13)
    source.architecture = Architecture.ARM
    assert RiscVInstructionDecoder().decode(source).status == DecodeStatus.UNSUPPORTED


def test_decoder_provenance_uses_distribution_not_stale_module_version():
    result = RiscVInstructionDecoder().decode(encoding(0x00130e13))
    assert result.decoder.tool_name == "capstone"
    assert result.decoder.tool_version == version("capstone")
    assert result.decoder.tool_role == "instruction_decoder"
    assert len(result.decoder.configuration_sha256) == 64
    assert "RV32" in result.decoder_mode and "C disabled" in result.decoder_mode
    assert len(result.evidence) == 1 and result.evidence[0].source_type == "synthetic"
    assert DecodedInstruction.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize("resolved", ["5.0.7", "6.0.0", "6.0.0a1", "5.0.10rc1"])
def test_backend_version_guard(monkeypatch, resolved):
    from chipchain.tools.architecture import riscv
    monkeypatch.setattr(riscv, "version", lambda _: resolved)
    with pytest.raises(ValueError, match="stable Capstone 5"):
        RiscVInstructionDecoder()


@pytest.mark.parametrize("word", [0x00130e13, 0, 0x0000000b, "x" * 32])
def test_enrichment_is_nonmutating_preserves_identity_and_does_not_lift(word):
    source = observation(word)
    batch = HardwareObservations(case_id="case", observations=[source])
    original = batch.model_dump_json()
    decoder = RiscVInstructionDecoder()
    enriched = decoder.enrich(batch)
    assert batch.model_dump_json() == original
    assert len(enriched.observations) == 1
    obs = enriched.observations[0]
    assert obs.observation_id == source.observation_id and obs.role == source.role
    assert obs.evidence == source.evidence and obs.details == source.details
    behavior = obs.behaviors[0]
    assert behavior.behavior_id == source.behaviors[0].behavior_id
    assert behavior.attributes == source.behaviors[0].attributes
    assert behavior.summary == source.behaviors[0].summary
    assert behavior.epistemic_status == source.behaviors[0].epistemic_status
    assert behavior.evidence == source.behaviors[0].evidence
    assert behavior.decoded_instruction.evidence == source.evidence
    ir = ProcessorBehaviorIR(case_id="case", behaviors=[b for o in enriched.observations for b in o.behaviors])
    assert len(ir.behaviors) == 1 and ir.behaviors[0].kind == BehaviorKind.INSTRUCTION
    assert not {"executed", "committed", "retired", "triggered", "caused_divergence"} & behavior.model_dump().keys()
    assert decoder.enrich(enriched) == enriched
    assert HardwareObservations.model_validate_json(enriched.model_dump_json()) == enriched


def test_old_observation_without_representation_stays_unknown():
    source = observation(representation=Representation.UNKNOWN)
    batch = HardwareObservations(case_id="case", observations=[source])
    result = RiscVInstructionDecoder().enrich(batch)
    assert result.observations[0].behaviors[0].decoded_instruction.status == DecodeStatus.UNKNOWN


def test_empty_input_stays_empty():
    batch = HardwareObservations(case_id="empty")
    assert RiscVInstructionDecoder().enrich(batch) == batch


def test_identity_conflict_or_duplicate_instruction_behavior_is_rejected():
    source = observation()
    source.behaviors[0].attributes["encoding"] = "0x00000013"
    with pytest.raises(ValueError, match="disagrees"):
        RiscVInstructionDecoder().enrich(HardwareObservations(case_id="case", observations=[source]))
    source = observation()
    source.behaviors.append(source.behaviors[0].model_copy(deep=True))
    with pytest.raises(ValueError, match="exactly one"):
        RiscVInstructionDecoder().enrich(HardwareObservations(case_id="case", observations=[source]))


def test_architecture_neutral_contract_has_no_backend_objects():
    data = RiscVInstructionDecoder().decode(encoding(0x00130e13)).model_dump(mode="json")
    assert data["operands"][0]["register_name"] == "x28"
    with pytest.raises(ValidationError):
        InstructionEncoding(**{**encoding(1).model_dump(), "width_bits": 16})


@pytest.mark.parametrize("word,mask,match,rd,rs1,immediate", [
    (0x00130e13, 0x707f, 0x13, 28, 6, 1),
    (0x00001537, 0x007f, 0x37, 10, None, 1),
    (0x007e2503, 0x707f, 0x03 | (2 << 12), 10, 28, 7),
])
def test_743_independent_riscv_opcode_definition_cross_check(word, mask, match, rd, rs1, immediate):
    # Independently specified masks/field positions from official extensions/rv_i.
    # No Capstone call: this cross-check cannot validate itself via the backend.
    assert word & mask == match
    assert (word >> 7) & 31 == rd
    if rs1 is not None:
        assert (word >> 15) & 31 == rs1
        assert word >> 20 == immediate
    else:
        assert word >> 12 == immediate
