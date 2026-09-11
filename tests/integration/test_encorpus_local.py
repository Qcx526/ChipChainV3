"""Optional read-only real-corpus checks, never required by default pytest/CI."""

import os
from pathlib import Path

import pytest

from chipchain.tools.contracts import HardwareObservationKind as Kind
from chipchain.tools.hardware.encorpus import EnCorpusIbexDriverAnalyzer
from chipchain.tools.architecture import RiscVInstructionDecoder
from chipchain.domain.behavior import ProcessorBehaviorIR


@pytest.mark.parametrize("sample_id", ["743", "820"])
def test_local_ibex_driver(sample_id):
    root = os.environ.get("CHIPCHAIN_ENCORPUS_IBEX_ROOT")
    if not root:
        pytest.skip("Set CHIPCHAIN_ENCORPUS_IBEX_ROOT explicitly to enable local corpus checks")
    directory = Path(root) / "driver" / sample_id
    result = EnCorpusIbexDriverAnalyzer().ingest(directory)
    kinds = [o.kind for o in result.oracle.observations]
    assert kinds.count(Kind.MUTATION_PRESENT) == 1
    assert kinds.count(Kind.FORMAL_RESULT) == 2
    assert Kind.LOCAL_EFFECT_OBSERVED in kinds
    assert Kind.ARCHITECTURAL_PROPAGATION_OBSERVED in kinds
    if sample_id == "743":
        assert [b.attributes["encoding"] for b in result.processor_behavior_ir.behaviors] == [
            "0x00130e13", "0x00001537", "0x007e2503",
        ]
        differences = [o for o in result.oracle.observations if o.kind == Kind.ARCHITECTURAL_PROPAGATION_OBSERVED]
        assert {(o.details.register_name, o.details.time.value, int(o.details.host.value, 2),
                 int(o.details.reference.value, 2)) for o in differences} == {
            ("x28", 50, 0, 1), ("x10", 70, 0x1000, 0),
        }
    else:
        assert result.sample_identity.endswith(":820")
        assert result.oracle.observations[0].details.host_connection == "\\ebrk_insn"


@pytest.mark.parametrize("sample_id", ["743", "820"])
def test_local_ibex_decoding(sample_id):
    root = os.environ.get("CHIPCHAIN_ENCORPUS_IBEX_ROOT")
    if not root:
        pytest.skip("Set CHIPCHAIN_ENCORPUS_IBEX_ROOT explicitly to enable local corpus checks")
    original = EnCorpusIbexDriverAnalyzer().ingest(Path(root) / "driver" / sample_id)
    enriched = RiscVInstructionDecoder().enrich(original.observations)
    ir = ProcessorBehaviorIR(case_id=enriched.case_id, behaviors=[b for o in enriched.observations for b in o.behaviors])
    assert [b.behavior_id for b in ir.behaviors] == [b.behavior_id for b in original.processor_behavior_ir.behaviors]
    if sample_id == "743":
        decoded = [b.decoded_instruction for b in ir.behaviors]
        assert [(d.raw_encoding, d.mnemonic, d.operand_text, d.instruction_width_bits) for d in decoded] == [
            ("0x00130e13", "addi", "x28, x6, 1", 32),
            ("0x00001537", "lui", "x10, 1", 32),
            ("0x007e2503", "lw", "x10, 7(x28)", 32),
        ]
        assert all(d.status == "decoded" and d.representation == "decompressed_word" for d in decoded)
        assert [d.evidence[0].location.time.value for d in decoded] == [30, 40, 50]
        assert all(d.evidence[0].location.signal.endswith("instr_rdata_alu_id_o") for d in decoded)
    else:
        assert enriched.observations == [] and ir.behaviors == []
