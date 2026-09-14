"""Fake LangChain reports exercise evidence/finding gates without any provider."""

import pytest

from chipchain.agents.contracts import FirmwareAgentInput
from chipchain.agents.firmware import FirmwareSecurityAgent, validate_firmware_evidence
from chipchain.agents.model_outputs.firmware import ModelFirmwareAnalysisReport
from chipchain.agents.runtime import AgentStructuredOutputError
from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.firmware import (
    ExternalInputPath, FirmwareAnalysisReport, FirmwareFinding, FirmwareIssueAnchor, ReachableBehavior,
)
from chipchain.tools.contracts import DeterministicObservation, FirmwareObservations
from chipchain.tools.firmware.fuzzware import FuzzwareHeatPressScenarioAnalyzer
from tests.fakes import fake_model
from tests.firmware_fakes import make_case, model_report_fixture


@pytest.fixture
def inputs(tmp_path):
    case = make_case(tmp_path)
    batch = FuzzwareHeatPressScenarioAnalyzer().analyze(
        case_id=case.case_id, target=case.target, artifacts=case.firmware_artifacts,
    )
    return FirmwareAgentInput(case=case, deterministic_observations=batch)


def report_with_all_objects(inputs):
    o = inputs.deterministic_observations.observations[0]
    bid = o.behaviors[0].behavior_id
    ref = o.evidence[0]
    return FirmwareAnalysisReport(
        case_id=inputs.case.case_id, processor_behavior_ids=[bid],
        findings=[FirmwareFinding(finding_id='f', summary='Synthetic finding', evidence=[ref], processor_behavior_ids=[bid])],
        external_input_paths=[ExternalInputPath(path_id='p', entry_point='synthetic', summary='Synthetic path', evidence=[ref])],
        reachable_behaviors=[ReachableBehavior(reachability_id='r', processor_behavior_id=bid, evidence=[ref])],
        issue_anchors=[FirmwareIssueAnchor(anchor_id='a', firmware_finding_ids=['f'], summary='Synthetic anchor', evidence=[ref])],
    ).model_copy(deep=True)


def test_exact_fake_report_accepted_ir_is_still_deterministic(inputs):
    before = inputs.model_dump_json()
    report = report_with_all_objects(inputs)
    model = fake_model(ModelFirmwareAnalysisReport, model_report_fixture(report))
    output = FirmwareSecurityAgent(model=model).invoke(inputs)
    assert output.report == report
    assert output.processor_behavior_ir == ProcessorBehaviorIR(
        case_id=inputs.case.case_id,
        behaviors=[b for o in inputs.deterministic_observations.observations for b in o.behaviors],
    )
    assert inputs.model_dump_json() == before
    assert len(model.seen_messages) == 1
    assert 'firmware-analysis-projection/v1' in model.seen_messages[0][1].content


@pytest.mark.parametrize('collection', ['findings', 'external_input_paths', 'reachable_behaviors', 'issue_anchors'])
@pytest.mark.parametrize('alteration', ['invented_id', 'location', 'summary', 'artifact', 'epistemic_status'])
def test_canonical_gate_still_rejects_invented_or_rewritten_evidence(inputs, collection, alteration):
    report = report_with_all_objects(inputs)
    ref = getattr(report, collection)[0].evidence[0].model_copy(deep=True)
    if alteration == 'invented_id':
        ref.evidence_id = 'invented'
    elif alteration == 'location':
        ref.location.address += 2
    elif alteration == 'summary':
        ref.summary = 'Rewritten summary'
    elif alteration == 'artifact':
        ref.artifact_id = 'opaque'  # Even another valid supplied artifact is not the same evidence.
    else:
        ref.epistemic_status = 'verified'
    getattr(report, collection)[0].evidence = [ref]
    # Canonical exact validation is unchanged after hydration; do not reduce
    # tampered full references to IDs in this regression test.
    with pytest.raises(AgentStructuredOutputError, match='unknown or altered'):
        validate_firmware_evidence(report, inputs)


def test_unknown_finding_anchor_rejected(inputs):
    report = report_with_all_objects(inputs)
    report.issue_anchors[0].firmware_finding_ids = ['missing']
    with pytest.raises(AgentStructuredOutputError, match='finding references'):
        FirmwareSecurityAgent(model=fake_model(ModelFirmwareAnalysisReport, model_report_fixture(report))).invoke(inputs)


def test_existing_ir_gate_still_rejects_unknown_behavior(inputs):
    report = report_with_all_objects(inputs)
    report.processor_behavior_ids = ['invented-behavior']
    with pytest.raises(AgentStructuredOutputError, match='output contract'):
        FirmwareSecurityAgent(model=fake_model(ModelFirmwareAnalysisReport, model_report_fixture(report))).invoke(inputs)


@pytest.mark.parametrize('level', ['observation', 'behavior', 'decoded'])
def test_generic_observation_grounding_covers_each_evidence_level(inputs, level):
    original = inputs.deterministic_observations.observations[0]
    b = original.behaviors[0].model_copy(deep=True)
    observation_ref = original.evidence[0].model_copy(deep=True)
    b.evidence = [observation_ref.model_copy(update={'evidence_id': 'behavior-only'})]
    b.decoded_instruction.evidence = [observation_ref.model_copy(update={'evidence_id': 'decoded-only'})]
    generic = DeterministicObservation(observation_id='generic', summary='Synthetic generic fact',
                                       evidence=[observation_ref], behaviors=[b])
    inputs.deterministic_observations = FirmwareObservations(case_id=inputs.case.case_id, observations=[generic])
    ref = {'observation': observation_ref, 'behavior': b.evidence[0], 'decoded': b.decoded_instruction.evidence[0]}[level]
    report = FirmwareAnalysisReport(case_id=inputs.case.case_id,
        findings=[FirmwareFinding(finding_id='f', summary='Synthetic finding', evidence=[ref])])
    output = FirmwareSecurityAgent(model=fake_model(ModelFirmwareAnalysisReport, model_report_fixture(report))).invoke(inputs)
    assert output.report == report


@pytest.mark.parametrize('model_enabled', [False, True])
def test_conflicting_input_rejected_before_model_or_stub(inputs, model_enabled):
    o = inputs.deterministic_observations.observations[0]
    o.behaviors[0].decoded_instruction.evidence = [o.evidence[0].model_copy(update={'summary': 'Conflicting input'})]
    model = fake_model(ModelFirmwareAnalysisReport, ModelFirmwareAnalysisReport(case_id=inputs.case.case_id))
    with pytest.raises(AgentStructuredOutputError, match='Conflicting'):
        FirmwareSecurityAgent(model=model if model_enabled else None).invoke(inputs)
    assert not model.seen_messages


def test_exact_verified_finding_not_subject_to_future_provider_policy(inputs):
    report = report_with_all_objects(inputs)
    report.findings[0].epistemic_status = 'verified'
    validate_firmware_evidence(report, inputs)
    output = FirmwareSecurityAgent(model=fake_model(ModelFirmwareAnalysisReport, model_report_fixture(report))).invoke(inputs)
    assert output.report.findings[0].epistemic_status == 'verified'
