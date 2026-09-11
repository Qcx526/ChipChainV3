"""Optional read-only real-corpus checks, never required by default pytest/CI."""

import os
from pathlib import Path

import pytest

from chipchain.tools.contracts import HardwareObservationKind as Kind
from chipchain.tools.hardware.encorpus import EnCorpusIbexDriverAnalyzer


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
