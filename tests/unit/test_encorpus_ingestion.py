"""Handwritten synthetic/minimized inputs following the A0 layout, not corpus copies."""

import json
import pytest
from pydantic import ValidationError

from chipchain.agents.context import hardware_context
from chipchain.agents.contracts import HardwareAgentInput
from chipchain.domain.common import Architecture, EpistemicStatus
from chipchain.domain.evidence import BitRange, EvidenceLocation, EvidenceTime
from chipchain.tools.contracts import HardwareObservation, HardwareObservationKind as Kind, HardwareObservations
from chipchain.tools.hardware.encorpus import EnCorpusIbexDriverAnalyzer, EnCorpusIngestionResult, IngestionError
from chipchain.tools.hardware.encorpus.ibex_driver import EXECUTING, GPR, HOST, ID_BASE, LOCAL, PC, REFERENCE, VALID
from chipchain.tools.hardware.encorpus.readers import parse_driver_mutation, parse_formal_log, parse_vcd

GOLDEN = r'''# synthetic RTLIL subset
autoidx 1
module \cellift_ibex_register_file_ff
  wire width 5 $driver
  wire width 5 \address
  attribute \src "synthetic.v:12.1-12.20"
  cell $eq $compare
    parameter \A_WIDTH 5
    connect \A $driver
    connect \B 5'11100
    connect \Y $out
  end
  connect $driver \address
end
'''
HOST_RTL = GOLDEN.replace('  wire width 5 $driver', '  attribute \\buggy "buggy"\n  wire width 5 $driver').replace(
    'connect $driver \\address', "connect $driver 5'00100")
LOG = '''INFO: The cover property "miter.i_miter.c_propagated" was covered in 8 cycles in 0.10 s.
ERROR (EVS053): No trace satisfying these configurations exists for any max_length.
INFO: Exiting the analysis session with status 0.
'''


def synthetic_vcd():
    """Small signal set, original synthetic values and timestamps; no real VCD excerpt."""
    specs = [(HOST + ID_BASE + "instr_rdata_id_o", 32, "[31:0]"),
             (HOST + VALID, 1, ""), (HOST + EXECUTING, 1, ""), (HOST + PC, 32, "[31:0]"),
             (HOST + GPR, 992, "[1023:32]"), (REFERENCE + GPR, 992, "[1023:32]"),
             (HOST + LOCAL[2], 3, "[2:0]"), (REFERENCE + LOCAL[2], 3, "[2:0]")]
    header = ["$date synthetic\n$end", "$timescale 10 ps $end", "$scope module miter $end"]
    for i, (name, width, bits) in enumerate(specs):
        header.append(f"$var wire {width} c{i} {name.removeprefix('miter.')} {bits} $end")
    header.extend(["$upscope $end", "$enddefinitions $end", "#0"])
    initial = [f"b0 c{i}" if width != 1 else f"0c{i}" for i, (_, width, _) in enumerate(specs)]
    # Changes use abbreviated vectors, scalar transitions and carry-forward values.
    return "\n".join([*header, *initial,
        "#1", "b00000000000100000000000010010011 c0", "1c1", "1c2",
        f"b{1 << (32 * 27):b} c5", "b1 c7",
        "#2", "b00000000000000000001000100110111 c0", "b100 c3",
        f"b{4096 << (32 * 9):b} c4", "#3", "#4", ""])


@pytest.fixture
def sample(tmp_path):
    directory = tmp_path / "driver" / "901"
    directory.mkdir(parents=True)
    for name, content in {"host_driver.rtlil": HOST_RTL, "reference_driver.rtlil": GOLDEN,
                          "proof.vcd": synthetic_vcd(), "verify.log": LOG}.items():
        (directory / name).write_text(content)
    return directory


def test_driver_connection_source_and_no_difference():
    change = parse_driver_mutation(HOST_RTL, GOLDEN)
    assert change.signal == "$driver"
    assert change.reference == "\\address" and change.host == "5'00100"
    assert change.module == "\\cellift_ibex_register_file_ff"
    assert change.source == "synthetic.v:12.1-12.20"
    assert HOST_RTL.splitlines()[change.host_line - 1].strip() == "connect $driver 5'00100"
    assert parse_driver_mutation(GOLDEN, GOLDEN) is None


def test_source_annotation_is_not_borrowed_from_unrelated_wire():
    source = '  attribute \\src "synthetic.v:12.1-12.20"\n'
    host = HOST_RTL.replace(source, "").replace("  wire width 5 \\address", source + "  wire width 5 \\address")
    reference = GOLDEN.replace(source, "").replace("  wire width 5 \\address", source + "  wire width 5 \\address")
    assert parse_driver_mutation(host, reference).source is None


@pytest.mark.parametrize("host,reference", [
    (HOST_RTL.removesuffix("end\n"), GOLDEN),
    (HOST_RTL.replace("$driver 5'00100", "$driver { \\address 1'0 }"), GOLDEN),
    (HOST_RTL.replace("wire width 5 $driver", "wire width 5 $different"), GOLDEN),
    (HOST_RTL.replace("parameter \\A_WIDTH 5", "parameter \\A_WIDTH 6"), GOLDEN),
    (HOST_RTL.replace("cell $eq $compare", "process $compare"), GOLDEN),
    (HOST_RTL.replace("$driver 5'00100", "$driver \\address"), GOLDEN),
    (HOST_RTL, HOST_RTL),
    ("", ""),
    ("autoidx 1", "autoidx 1"),
])
def test_driver_rejects_unsupported_or_malformed_mutations(host, reference):
    with pytest.raises(IngestionError):
        parse_driver_mutation(host, reference)


def test_formal_success_and_later_error_are_separate():
    results = parse_formal_log(LOG)
    assert [r["category"] for r in results] == ["cover_hit", "trace_error"]
    assert results[0]["cycles"] == 8 and results[1]["error_code"] == "EVS053"
    assert results[0]["line"] == 1 and results[1]["line"] == 2
    assert "Exiting" not in str(results)
    assert len(parse_formal_log(LOG.splitlines()[1])) == 1  # Error does not imply cover.


@pytest.mark.parametrize("text", [
    "", "INFO: exiting with status 0", LOG.replace("8 cycles", "eight cycles"),
    "ERROR (EVS053)", "ERROR (OTHER): unsupported result", LOG.replace("0.10 s.", "unknown s."),
    LOG.replace("0.10 s.", "1..0 s."),
])
def test_formal_missing_and_malformed_results_fail(text):
    with pytest.raises(IngestionError):
        parse_formal_log(text)


def small_vcd(body="", *, declarations=""):
    return ("$timescale 1 ns $end\n$scope module top $end\n"
            "$var wire 1 ! flag $end\n$var reg 4 v word [7:4] $end\n"
            "$scope module nested $end\n$var wire 1 n flag $end\n$upscope $end\n"
            + declarations + "$upscope $end\n$enddefinitions $end\n" + body)


def test_vcd_scalar_vector_hierarchy_time_and_carry_forward():
    wave = parse_vcd(small_vcd("#0\n0!\n0n\nb1 v\n#5\n1!\nb1010 v\n#10\n1n\n#15\n"))
    assert wave.signals["top.word"].bit_range == BitRange(msb=7, lsb=4)
    assert wave.signals["top.flag"].code != wave.signals["top.nested.flag"].code
    assert [t for t, _ in wave.frames] == [0, 5, 10, 15]
    assert wave.frames[0][1]["v"].bits == "0001"
    assert wave.frames[1][1]["!"].bits == "1"
    assert wave.frames[3][1]["v"].bits == "1010"
    assert wave.frames[3][1]["v"].line == wave.frames[1][1]["v"].line


def test_vcd_four_state_extension_dumpvars_and_aliases():
    wave = parse_vcd(small_vcd("$dumpvars\n0!\nbx v\n$end\n#2\nbz v\n#3\nbx1 v\n",
                              declarations="$var reg 4 v alias [7:4] $end\n"))
    assert wave.frames[0][1]["v"].bits == "xxxx"
    assert wave.frames[1][1]["v"].bits == "zzzz"
    assert wave.frames[2][1]["v"].bits == "xxx1"
    assert wave.signals["top.alias"].code == wave.signals["top.word"].code


@pytest.mark.parametrize("body", [
    "", "#0\nr1.0 v\n", "#2\n#1\n", "#0\nb10101 v\n", "#0\nb102 v\n",
    "#0\n0v\n", "#0\n1absent\n", "#0\n$dumpoff\n", "$dumpvars\n0!\n",
    "0!\n", "#0\n$unsupported $end\n",
])
def test_vcd_rejects_unsupported_critical_body(body):
    with pytest.raises(IngestionError):
        parse_vcd(small_vcd(body))


@pytest.mark.parametrize("old,new", [
    ("$enddefinitions $end", ""), ("[7:4]", "[0:3]"), ("$var reg", "$var real"),
    ("$timescale 1 ns", "$timescale 3 ns"), ("$scope module nested", "$scope task nested"),
    ("$var wire 1 n", "$var wire 2 !"),
])
def test_vcd_rejects_unsupported_header(old, new):
    with pytest.raises(IngestionError):
        parse_vcd(small_vcd("#0\n").replace(old, new))


def test_vcd_selection_does_not_ignore_malformed_unselected_changes():
    with pytest.raises(IngestionError):
        parse_vcd(small_vcd("#0\nb111111 v\n"), select=lambda name: name == "top.flag")


def test_reader_resource_bounds(monkeypatch):
    from chipchain.tools.hardware.encorpus import readers
    monkeypatch.setattr(readers, "MAX_FRAMES", 2)
    with pytest.raises(IngestionError, match="limit"):
        parse_vcd(small_vcd("#0\n0!\n#1\n#2\n"))
    monkeypatch.setattr(readers, "MAX_BYTES", 4)
    with pytest.raises(IngestionError, match="limit"):
        parse_driver_mutation(HOST_RTL, GOLDEN)


def test_typed_semantics_ir_evidence_and_serialization(sample):
    result = EnCorpusIbexDriverAnalyzer().ingest(sample)
    observations = [*result.observations.observations, *result.oracle.observations]
    assert {o.kind for o in observations} == set(Kind)
    assert all(isinstance(o, HardwareObservation) for o in observations)
    assert len(result.processor_behavior_ir.behaviors) == 2
    assert len(result.oracle.processor_behavior_ir.behaviors) == 2
    for behavior in [*result.processor_behavior_ir.behaviors, *result.oracle.processor_behavior_ir.behaviors]:
        assert behavior.evidence
        assert behavior.epistemic_status in {EpistemicStatus.OBSERVED, EpistemicStatus.DERIVED}
        assert not {"mnemonic", "rd", "rs1", "retired", "write", "read"} & behavior.attributes.keys()
    arch = [o for o in result.oracle.observations if o.kind == Kind.ARCHITECTURAL_PROPAGATION_OBSERVED]
    assert {o.details.register_name for o in arch} == {"x10", "x28"}
    x28 = next(o for o in arch if o.details.register_name == "x28")
    assert x28.details.time == EvidenceTime(value=10, unit="ps")
    assert int(x28.details.host.value, 2) == 0 and int(x28.details.reference.value, 2) == 1
    assert x28.evidence[0].location.bit_range == BitRange(msb=927, lsb=896)
    assert x28.evidence[0].location.signal == HOST + GPR
    assert x28.evidence[0].location.time == x28.details.time
    assert EnCorpusIngestionResult.model_validate_json(result.model_dump_json()) == result
    restored = HardwareObservations.model_validate_json(result.observations.model_dump_json())
    assert restored.observations[0].details == result.observations.observations[0].details
    legacy = EvidenceLocation(line=1, register="x2")
    assert legacy.time is None and legacy.signal is None and legacy.bit_range is None
    assert EvidenceLocation.model_validate_json(legacy.model_dump_json()) == legacy


def test_oracle_does_not_enter_analysis_projection_or_agent_input(sample):
    analyzer = EnCorpusIbexDriverAnalyzer()
    before = analyzer.ingest(sample)
    before_context = hardware_context(before.analysis_input())
    # B.1 hides RTL mutation answers, but permits operational waveform/log facts.
    for name in ["host_driver.rtlil", "reference_driver.rtlil"]:
        p = sample / name
        p.write_text(p.read_text().replace("\\address", "\\oracle_changed"))
    after = analyzer.ingest(sample)
    assert before.oracle != after.oracle
    assert before.observations == after.observations
    assert before.processor_behavior_ir == after.processor_behavior_ir
    assert before_context == hardware_context(after.analysis_input())
    assert not any(name in before_context for name in ["reference_connection", "oracle_changed", "mutation_present"])
    assert "cover_hit" in before_context
    assert len(before.analysis_input().case.hardware_artifacts) == 2
    assert {a.format for a in before.analysis_input().case.hardware_artifacts} == {"vcd", "log"}
    unsafe = HardwareObservations(case_id=before.observations.case_id, observations=before.oracle.observations)
    with pytest.raises(ValidationError, match="oracle"):
        HardwareAgentInput(case=before.analysis_input().case, deterministic_observations=unsafe)
    # Serialization must not erase the typed role guard through the legacy union.
    with pytest.raises(ValidationError, match="oracle"):
        HardwareAgentInput.model_validate({"case": before.analysis_input().case.model_dump(),
                                           "deterministic_observations": unsafe.model_dump()})


def test_protocol_reads_only_host_projection_and_honors_fingerprint(sample):
    analyzer = EnCorpusIbexDriverAnalyzer()
    result = analyzer.ingest(sample)
    for filename in ["host_driver.rtlil", "reference_driver.rtlil", "verify.log"]:
        (sample / filename).unlink()
    observations = analyzer.analyze(case_id=result.observations.case_id, target=result.target, artifacts=result.artifacts)
    assert observations == result.observations
    bad = result.artifacts[-2].model_copy(update={"sha256": "a" * 64})
    with pytest.raises(IngestionError, match="fingerprint"):
        analyzer.analyze(case_id="case", target=result.target, artifacts=[bad])
    with pytest.raises(IngestionError, match="Ibex"):
        analyzer.analyze(case_id="case", target=result.target.model_copy(update={"architecture": Architecture.ARM}),
                         artifacts=result.artifacts)


def test_scope_missing_artifacts_and_read_only_no_implicit_output(sample):
    before = {p: p.read_bytes() for p in sample.iterdir()}
    result = EnCorpusIbexDriverAnalyzer().ingest(sample)
    assert result.sample_identity == "encorpus:ibex:driver:901"
    assert {p: p.read_bytes() for p in sample.iterdir()} == before
    assert len(result.artifact_roles) == 6
    assert len(result.artifacts) == 4
    with pytest.raises(IngestionError, match="driver"):
        EnCorpusIbexDriverAnalyzer().ingest(sample.parent.parent / "multiplexer" / "901")
    (sample / "verify.log").unlink()
    with pytest.raises(IngestionError, match="Cannot read"):
        EnCorpusIbexDriverAnalyzer().ingest(sample)


@pytest.mark.parametrize("old,new", [
    ("[1023:32]", "[991:0]"), ("instr_valid_id_q", "unsupported_valid"),
    ("instr_executing", "unsupported_executing"), ("wire 992", "wire 991"),
])
def test_ingestion_rejects_unsupported_signal_layout(sample, old, new):
    p = sample / "proof.vcd"
    p.write_text(p.read_text().replace(old, new))
    with pytest.raises(IngestionError):
        EnCorpusIbexDriverAnalyzer().ingest(sample)


def test_unknowns_are_not_false_architectural_differences(sample):
    p = sample / "proof.vcd"
    p.write_text(p.read_text().replace(f"b{1 << (32 * 27):b} c5", "bx c5"))
    result = EnCorpusIbexDriverAnalyzer().ingest(sample)
    assert not any(o.kind == Kind.ARCHITECTURAL_PROPAGATION_OBSERVED for o in result.oracle.observations)
    assert any("unknown" in s for s in result.oracle.limitations)


def test_context_preserves_typed_host_details(sample):
    result = EnCorpusIbexDriverAnalyzer().ingest(sample)
    data = json.loads(hardware_context(result.analysis_input()))
    observation = data["observations"][0]
    assert observation["kind"] == "instruction_encoding_observed"
    assert observation["details"]["host"]["signal"].startswith(HOST)
    assert observation["details"]["time"] == {"value": 10, "unit": "ps"}


def test_observation_kind_status_and_details_are_orthogonal(sample):
    result = EnCorpusIbexDriverAnalyzer().ingest(sample)
    arch = next(o for o in result.oracle.observations if o.kind == Kind.ARCHITECTURAL_PROPAGATION_OBSERVED)
    data = arch.model_dump()
    data["epistemic_status"] = "observed"
    assert HardwareObservation.model_validate(data).kind == Kind.ARCHITECTURAL_PROPAGATION_OBSERVED
    data["kind"] = "mutation_present"
    with pytest.raises(ValidationError, match="details"):
        HardwareObservation.model_validate(data)
    data = arch.model_dump()
    data["role"] = "analysis_input"
    assert HardwareObservation.model_validate(data).role == "analysis_input"
    mutation = next(o for o in result.oracle.observations if o.kind == Kind.MUTATION_PRESENT)
    data = mutation.model_dump()
    data["role"] = "analysis_input"
    with pytest.raises(ValidationError, match="oracle"):
        HardwareObservation.model_validate(data)
