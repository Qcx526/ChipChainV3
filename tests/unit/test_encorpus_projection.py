"""Operational availability is distinct from hidden benchmark answer provenance."""

import json

import pytest

from chipchain.agents.context import hardware_context
from chipchain.tools.contracts import HardwareObservationKind as Kind
from chipchain.tools.hardware.encorpus import EnCorpusIbexDriverAnalyzer
from chipchain.tools.hardware.encorpus.projection import build_hardware_analysis_projection
from tests.unit.test_encorpus_ingestion import sample  # reusable synthetic fixture


def test_projection_copies_existing_facts_and_preserves_instructions(sample):
    result = EnCorpusIbexDriverAnalyzer().ingest(sample)
    before = result.model_dump_json()
    inputs = build_hardware_analysis_projection(result)
    selected = inputs.deterministic_observations.observations
    assert {o.kind for o in selected} == {Kind.INSTRUCTION_ENCODING_OBSERVED, Kind.LOCAL_EFFECT_OBSERVED,
                                         Kind.ARCHITECTURAL_PROPAGATION_OBSERVED, Kind.FORMAL_RESULT}
    originals = {o.observation_id: o for o in [*result.observations.observations, *result.oracle.observations]}
    for observation in selected:
        assert observation.role == "analysis_input"
        assert observation.model_dump(exclude={"role"}) == originals[observation.observation_id].model_dump(exclude={"role"})
    instructions = [o for o in selected if o.kind == Kind.INSTRUCTION_ENCODING_OBSERVED]
    assert instructions == result.observations.observations
    for formal in [o for o in selected if o.kind == Kind.FORMAL_RESULT]:
        assert "harness" in formal.details.interpretation_boundary
        assert "verified trigger" in formal.details.interpretation_boundary
    assert result.model_dump_json() == before
    assert hardware_context(inputs) == hardware_context(build_hardware_analysis_projection(result))


def test_hidden_answer_and_raw_benchmark_metadata_do_not_change_context(sample):
    result = EnCorpusIbexDriverAnalyzer().ingest(sample)
    before = hardware_context(result.analysis_input())
    mutation = next(o for o in result.oracle.observations if o.kind == Kind.MUTATION_PRESENT)
    marker = "HIDDEN_BENCHMARK_ANSWER_MUST_NOT_ENTER"
    mutation.details.source_location = marker
    mutation.details.host_connection = marker
    mutation.details.signal = marker
    mutation.summary = marker
    mutation.evidence[0].summary = marker
    result.oracle.limitations.append(marker)
    for a in result.artifacts:
        a.metadata["known_root_cause"] = marker
        if a.format == "rtlil":
            a.path = marker
    for role in result.artifact_roles:
        role.explanation = marker
    assert hardware_context(result.analysis_input()) == before
    assert marker not in before and "source_location" not in before and "reference_connection" not in before


@pytest.mark.parametrize("kind", ["architectural", "local", "formal"])
def test_changed_operational_tool_output_changes_context(sample, kind):
    analyzer = EnCorpusIbexDriverAnalyzer()
    before = hardware_context(analyzer.ingest(sample).analysis_input())
    path = sample / ("verify.log" if kind == "formal" else "proof.vcd")
    old = path.read_text()
    if kind == "formal":
        new = old.replace("8 cycles", "9 cycles")
    elif kind == "local":
        new = old.replace("b1 c7", "b10 c7")
    else:
        new = old.replace(f"b{1 << (32 * 27):b} c5", f"b{2 << (32 * 27):b} c5")
    assert new != old
    path.write_text(new)
    assert hardware_context(analyzer.ingest(sample).analysis_input()) != before


@pytest.mark.parametrize("bad_source", ["producer", "artifact", "signal"])
def test_kind_alone_does_not_authorize_an_observation(sample, bad_source):
    result = EnCorpusIbexDriverAnalyzer().ingest(sample)
    local = next(o for o in result.oracle.observations if o.kind == Kind.LOCAL_EFFECT_OBSERVED)
    if bad_source == "producer":
        local.evidence[0].analyzer = "unapproved-answer-generator"
    elif bad_source == "artifact":
        local.evidence[0].artifact_id = result.artifacts[0].artifact_id
    else:
        local.details.host.signal = "hidden.mutation.root_cause"
    assert local.observation_id not in hardware_context(result.analysis_input())


def test_no_valid_instruction_still_projects_existing_operational_evidence(sample):
    path = sample / "proof.vcd"
    path.write_text(path.read_text().replace("1c1", "0c1"))
    result = EnCorpusIbexDriverAnalyzer().ingest(sample)
    context = json.loads(hardware_context(result.analysis_input()))
    assert result.observations.observations == []
    assert not any(o["kind"] == "instruction_encoding_observed" for o in context["observations"])
    assert any(o["kind"] == "architectural_propagation_observed" for o in context["observations"])
    assert any(o["kind"] == "formal_result" for o in context["observations"])
