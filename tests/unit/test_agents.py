from collections.abc import Callable

import pytest
from pydantic import ValidationError

from chipchain.agents.contracts import (
    CrossLayerAgentInput, FirmwareAgentInput, HardwareAgentInput, HardwareAgentOutput,
)
from chipchain.agents.cross_layer import CrossLayerSecurityAgent
from chipchain.agents.firmware import FirmwareSecurityAgent
from chipchain.agents.hardware import HardwareSecurityAgent
from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.case import CaseBundle
from chipchain.domain.common import AnalysisLayer
from chipchain.domain.firmware import FirmwareAnalysisReport
from chipchain.domain.hardware import HardwareAnalysisReport
from chipchain.graphs.contracts import BehaviorGraphContext, RetrievedKnowledgeContext
from chipchain.tools.contracts import DeterministicObservation, FirmwareObservations, HardwareObservations

from .test_domain import assert_round_trip, behavior, evidence


def test_hardware_agent_independent(load_case: Callable[[str], CaseBundle]) -> None:
    case = load_case("hardware_only")
    hw = behavior(AnalysisLayer.HARDWARE)
    inputs = HardwareAgentInput(case=case, deterministic_observations=HardwareObservations(
        case_id=case.case_id, observations=[DeterministicObservation(
            observation_id="hw:observation", summary="Synthetic", evidence=hw.evidence, behaviors=[hw],
        )],
    ))
    result = HardwareSecurityAgent().invoke(inputs)
    assert result.processor_behavior_ir.behaviors == [hw]
    assert result.report.findings == []
    assert result.report.trigger_hypotheses == []
    assert result.report.unresolved_questions
    assert_round_trip(inputs)
    assert_round_trip(result)


def test_firmware_agent_independent(load_case: Callable[[str], CaseBundle]) -> None:
    case = load_case("firmware_only")
    fw = behavior(AnalysisLayer.FIRMWARE)
    inputs = FirmwareAgentInput(case=case, deterministic_observations=FirmwareObservations(
        case_id=case.case_id, observations=[DeterministicObservation(
            observation_id="fw:observation", summary="Synthetic", evidence=fw.evidence, behaviors=[fw],
        )],
    ))
    result = FirmwareSecurityAgent().invoke(inputs)
    assert result.processor_behavior_ir.behaviors == [fw]
    assert result.report.findings == []
    assert result.report.reachable_behaviors == []
    assert result.report.unresolved_questions
    assert_round_trip(inputs)
    assert_round_trip(result)


def test_agents_reject_wrong_side_and_case(load_case: Callable[[str], CaseBundle]) -> None:
    fw = load_case("firmware_only")
    hw = load_case("hardware_only")
    with pytest.raises(ValidationError, match="requires hardware"):
        HardwareAgentInput(case=fw, deterministic_observations=HardwareObservations(case_id=fw.case_id))
    with pytest.raises(ValidationError, match="requires firmware"):
        FirmwareAgentInput(case=hw, deterministic_observations=FirmwareObservations(case_id=hw.case_id))
    with pytest.raises(ValidationError, match="case_id"):
        HardwareAgentInput(case=hw, deterministic_observations=HardwareObservations(case_id="different"))


def test_observation_provenance_and_epistemic_boundary(load_case: Callable[[str], CaseBundle]) -> None:
    case = load_case("hardware_only")
    with pytest.raises(ValidationError):
        DeterministicObservation(observation_id="o", summary="LLM hypothesis", evidence=[evidence()], epistemic_status="hypothesized")
    with pytest.raises(ValidationError, match="artifact"):
        HardwareAgentInput(case=case, deterministic_observations=HardwareObservations(
            case_id=case.case_id, observations=[DeterministicObservation(
                observation_id="o", summary="Wrong artifact", evidence=[evidence("unrelated")],
            )],
        ))
    with pytest.raises(ValidationError, match="origin"):
        HardwareAgentInput(case=case, deterministic_observations=HardwareObservations(
            case_id=case.case_id, observations=[DeterministicObservation(
                observation_id="o", summary="Wrong layer", evidence=[evidence()],
                behaviors=[behavior(AnalysisLayer.FIRMWARE)],
            )],
        ))


def test_output_report_ir_reference_validation() -> None:
    with pytest.raises(ValidationError, match="unresolved"):
        HardwareAgentOutput(report=HardwareAnalysisReport(case_id="c", processor_behavior_ids=["missing"]),
                            processor_behavior_ir=ProcessorBehaviorIR(case_id="c"))
    with pytest.raises(ValidationError, match="case_id"):
        HardwareAgentOutput(report=HardwareAnalysisReport(case_id="a"),
                            processor_behavior_ir=ProcessorBehaviorIR(case_id="b"))


def test_cross_layer_independent_and_bounded_context(load_case: Callable[[str], CaseBundle]) -> None:
    case = load_case("paired")
    inputs = CrossLayerAgentInput(
        case=case, hardware_report=HardwareAnalysisReport(case_id=case.case_id),
        firmware_report=FirmwareAnalysisReport(case_id=case.case_id),
        processor_behavior_ir=ProcessorBehaviorIR(case_id=case.case_id),
        behavior_graph_context=BehaviorGraphContext(graph_id="graph", case_id=case.case_id),
        retrieved_knowledge_context=RetrievedKnowledgeContext(retrieval_id="retrieval", knowledge_graph_id="kg"),
    )
    output = CrossLayerSecurityAgent().invoke(inputs)
    assert not output.report.candidates
    assert not output.report.attack_chain_candidates
    assert output.report.missing_constraints
    assert_round_trip(inputs)
    assert_round_trip(output)
    with pytest.raises(ValidationError):
        RetrievedKnowledgeContext(retrieval_id="r", knowledge_graph_id="kg", node_ids=["n"] * 257)
    bad = inputs.model_dump()
    bad["hardware_report"]["case_id"] = "different"
    with pytest.raises(ValidationError, match="same case"):
        CrossLayerAgentInput.model_validate(bad)
    bad = inputs.model_dump()
    bad["behavior_graph_context"]["processor_behavior_ids"] = ["missing"]
    with pytest.raises(ValidationError, match="unresolved"):
        CrossLayerAgentInput.model_validate(bad)
