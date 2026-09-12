import json
from collections.abc import Callable

import pytest
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.runnables import RunnableLambda
from pydantic import ValidationError

from chipchain.agents.context import MAX_CONTEXT_CHARS, MAX_CONTEXT_ITEMS
from chipchain.agents.contracts import CrossLayerAgentInput, FirmwareAgentInput, HardwareAgentInput
from chipchain.agents.cross_layer import CrossLayerSecurityAgent
from chipchain.agents.firmware import FirmwareSecurityAgent
from chipchain.agents.hardware import HardwareSecurityAgent
from chipchain.agents.runtime import AgentExecutionError, AgentStructuredOutputError, StructuredReportRuntime
from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.case import CaseBundle
from chipchain.domain.common import AnalysisLayer, EpistemicStatus
from chipchain.domain.cross_layer import CrossLayerAnalysisReport
from chipchain.domain.firmware import FirmwareAnalysisReport
from chipchain.domain.hardware import HardwareAnalysisReport, HardwareTriggerHypothesis
from chipchain.graphs.contracts import BehaviorGraphContext, RetrievedKnowledgeContext
from chipchain.tools.contracts import DeterministicObservation, FirmwareObservations, HardwareObservations
from tests.fakes import fake_model
from tests.unit.test_domain import assert_round_trip, behavior


def cross_input(case: CaseBundle) -> CrossLayerAgentInput:
    return CrossLayerAgentInput(
        case=case, hardware_report=HardwareAnalysisReport(case_id=case.case_id),
        firmware_report=FirmwareAnalysisReport(case_id=case.case_id),
        processor_behavior_ir=ProcessorBehaviorIR(case_id=case.case_id),
    )


@pytest.mark.parametrize("layer", ["hardware", "firmware"])
def test_model_report_preserves_deterministic_ir(
    load_case: Callable[[str], CaseBundle], layer: str,
) -> None:
    case = load_case("paired")
    item = behavior(AnalysisLayer(layer))
    observation = DeterministicObservation(
        observation_id="synthetic:observation", summary="Synthetic observation",
        evidence=item.evidence, behaviors=[item],
    )
    schema = HardwareAnalysisReport if layer == "hardware" else FirmwareAnalysisReport
    report = schema(case_id=case.case_id, processor_behavior_ids=[item.behavior_id])
    model = fake_model(schema, report)
    if layer == "hardware":
        inputs = HardwareAgentInput(case=case, deterministic_observations=HardwareObservations(
            case_id=case.case_id, observations=[observation],
        ))
        output = HardwareSecurityAgent(model=model).invoke(inputs)
    else:
        inputs = FirmwareAgentInput(case=case, deterministic_observations=FirmwareObservations(
            case_id=case.case_id, observations=[observation],
        ))
        output = FirmwareSecurityAgent(model=model).invoke(inputs)
    assert output.report == report
    assert output.report.findings == []
    assert output.processor_behavior_ir.behaviors == [item]
    assert output.processor_behavior_ir.behaviors[0].epistemic_status == EpistemicStatus.OBSERVED
    assert_round_trip(output)
    assert model.bound_schema_names == [schema.__name__]
    assert len(model.seen_messages) == 1
    system, human = model.seen_messages[0]
    assert isinstance(system, SystemMessage) and isinstance(human, HumanMessage)
    context = json.loads(human.content)
    assert len(context["artifacts"]) == 1
    assert context["artifacts"][0]["artifact_id"] == f"synthetic:{layer}:artifact"
    if layer == "hardware":
        assert context["observations"][0]["behaviors"][0]["behavior_id"] == item.behavior_id
        assert context["observations"][0]["evidence"][0]["artifact_id"] == item.evidence[0].artifact_id
    else:
        assert context["observations"][0]["behavior_ids"] == [item.behavior_id]
        assert context["behaviors"][0]["behavior_id"] == item.behavior_id
        assert context["evidence_catalog"][0]["artifact_id"] == item.evidence[0].artifact_id



def test_cross_model_report_and_bounded_graph_context(load_case: Callable[[str], CaseBundle]) -> None:
    inputs = cross_input(load_case("paired"))
    inputs.behavior_graph_context = BehaviorGraphContext(graph_id="synthetic:graph", case_id=inputs.case.case_id)
    inputs.retrieved_knowledge_context = RetrievedKnowledgeContext(retrieval_id="synthetic:retrieval", knowledge_graph_id="synthetic:kg")
    report = CrossLayerAnalysisReport(case_id=inputs.case.case_id, unresolved_questions=["Synthetic: missing evidence"])
    model = fake_model(CrossLayerAnalysisReport, report)
    output = CrossLayerSecurityAgent(model=model).invoke(inputs)
    assert output.report == report
    assert output.report.candidates == output.report.attack_chain_candidates == []
    assert_round_trip(output)
    context = json.loads(model.seen_messages[0][1].content)
    assert set(context) == {"case", "hardware_report", "firmware_report", "processor_behavior_ir",
                            "behavior_graph_context", "retrieved_knowledge_context"}
    assert context["retrieved_knowledge_context"]["retrieval_id"] == "synthetic:retrieval"


def test_context_omits_labels_debug_metadata_and_other_side(load_case: Callable[[str], CaseBundle]) -> None:
    case = load_case("paired")
    case.metadata["debug_secret"] = "not-model-context"
    case.hardware_artifacts[0].metadata["debug_secret"] = "not-model-context"
    inputs = HardwareAgentInput(case=case, deterministic_observations=HardwareObservations(case_id=case.case_id))
    model = fake_model(HardwareAnalysisReport, HardwareAnalysisReport(case_id=case.case_id))
    agent = HardwareSecurityAgent(model=model)
    agent.invoke(inputs)
    text = model.seen_messages[0][1].content
    context = json.loads(text)
    assert context["case"]["synthetic"] is True
    assert "not-model-context" not in text
    assert "ground_truth_label" not in text
    assert "firmware_artifacts" not in text and "synthetic:firmware:artifact" not in text
    assert "firmware_id" not in context["case"]["target"]
    agent.invoke(inputs)
    assert model.seen_messages[1][1].content == text


@pytest.mark.parametrize("oversize", ["characters", "items", "nested_evidence"])
def test_oversized_context_fails_before_model_call(
    load_case: Callable[[str], CaseBundle], oversize: str,
) -> None:
    case = load_case("hardware_only")
    batch = HardwareObservations(case_id=case.case_id)
    if oversize == "characters":
        case.name = "x" * (MAX_CONTEXT_CHARS + 1)
    elif oversize == "items":
        batch.unresolved_questions = ["synthetic"] * (MAX_CONTEXT_ITEMS + 1)
    else:
        item = behavior(AnalysisLayer.HARDWARE)
        item.evidence[0].summary = "x" * (MAX_CONTEXT_CHARS + 1)
        batch.observations = [DeterministicObservation(
            observation_id="o", summary="Synthetic", evidence=item.evidence,
        )]
    model = fake_model(HardwareAnalysisReport, HardwareAnalysisReport(case_id=case.case_id))
    with pytest.raises(AgentExecutionError, match="context"):
        HardwareSecurityAgent(model=model).invoke(HardwareAgentInput(case=case, deterministic_observations=batch))
    assert model.seen_messages == []


def test_cross_context_total_size_limit(load_case: Callable[[str], CaseBundle]) -> None:
    inputs = cross_input(load_case("paired"))
    inputs.hardware_report.unresolved_questions = ["x" * (MAX_CONTEXT_CHARS + 1)]
    model = fake_model(CrossLayerAnalysisReport, CrossLayerAnalysisReport(case_id=inputs.case.case_id))
    with pytest.raises(AgentExecutionError, match="context"):
        CrossLayerSecurityAgent(model=model).invoke(inputs)
    assert not model.seen_messages


@pytest.mark.parametrize("payload", [
    {}, {"case_id": "synthetic:hardware_only", "findings": "invalid"},
    AIMessage(content="No structured response"),
    AIMessage(content="", additional_kwargs={"tool_calls": [{
        "id": "synthetic", "type": "function",
        "function": {"name": "HardwareAnalysisReport", "arguments": "{broken json"},
    }]}),
])
def test_invalid_structured_output_fails_without_repair(
    load_case: Callable[[str], CaseBundle], payload: dict[str, object] | AIMessage,
) -> None:
    case = load_case("hardware_only")
    model = fake_model(HardwareAnalysisReport, payload)
    with pytest.raises(AgentStructuredOutputError) as caught:
        HardwareSecurityAgent(model=model).invoke(HardwareAgentInput(
            case=case, deterministic_observations=HardwareObservations(case_id=case.case_id),
        ))
    assert caught.value.__cause__ is not None
    assert len(model.seen_messages) == 1


def test_hardware_hypothesis_stays_hypothesized(load_case: Callable[[str], CaseBundle]) -> None:
    case = load_case("hardware_only")
    report = HardwareAnalysisReport(case_id=case.case_id, trigger_hypotheses=[
        HardwareTriggerHypothesis(hypothesis_id="synthetic:hypothesis", summary="Synthetic proposed condition"),
    ])
    model = fake_model(HardwareAnalysisReport, report)
    output = HardwareSecurityAgent(model=model).invoke(HardwareAgentInput(
        case=case, deterministic_observations=HardwareObservations(case_id=case.case_id),
    ))
    assert output.report.trigger_hypotheses[0].epistemic_status == EpistemicStatus.HYPOTHESIZED


@pytest.mark.parametrize("layer", ["hardware", "cross_layer"])
def test_verified_hypothesis_or_candidate_is_rejected(load_case: Callable[[str], CaseBundle], layer: str) -> None:
    case = load_case("paired")
    if layer == "hardware":
        model = fake_model(HardwareAnalysisReport, {"case_id": case.case_id, "trigger_hypotheses": [
            {"hypothesis_id": "h", "summary": "Synthetic", "epistemic_status": "verified"},
        ]})
        agent = HardwareSecurityAgent(model=model)
        inputs = HardwareAgentInput(case=case, deterministic_observations=HardwareObservations(case_id=case.case_id))
    else:
        model = fake_model(CrossLayerAnalysisReport, {"case_id": case.case_id, "candidates": [
            {"candidate_id": "c", "candidate_type": "TYPE_II", "summary": "Synthetic", "epistemic_status": "verified"},
        ]})
        agent = CrossLayerSecurityAgent(model=model)
        inputs = cross_input(case)
    with pytest.raises(AgentStructuredOutputError) as caught:
        agent.invoke(inputs)
    assert isinstance(caught.value.__cause__, ValidationError)


@pytest.mark.parametrize("defect", ["case_id", "behavior_id"])
def test_model_report_cannot_replace_deterministic_ir(load_case: Callable[[str], CaseBundle], defect: str) -> None:
    case = load_case("hardware_only")
    report = HardwareAnalysisReport(
        case_id="different" if defect == "case_id" else case.case_id,
        processor_behavior_ids=["invented"] if defect == "behavior_id" else [],
    )
    model = fake_model(HardwareAnalysisReport, report)
    with pytest.raises(AgentStructuredOutputError):
        HardwareSecurityAgent(model=model).invoke(HardwareAgentInput(
            case=case, deterministic_observations=HardwareObservations(case_id=case.case_id),
        ))


def test_runtime_revalidates_even_constructed_model_instances() -> None:
    model = fake_model(HardwareAnalysisReport, {})
    runtime = StructuredReportRuntime(model, HardwareAnalysisReport, "Synthetic test")
    invalid = HardwareAnalysisReport.model_construct(case_id="c", findings="invalid")
    runtime.runnable = RunnableLambda(lambda _: {"parsed": invalid, "parsing_error": None})
    with pytest.raises(AgentStructuredOutputError):
        runtime.invoke("{}")


def test_model_error_chain_is_preserved_without_public_secret(load_case: Callable[[str], CaseBundle]) -> None:
    case = load_case("hardware_only")
    original = RuntimeError("synthetic-secret-must-not-leak")
    model = fake_model(HardwareAnalysisReport, {}, failure=original)
    with pytest.raises(AgentExecutionError) as caught:
        HardwareSecurityAgent(model=model).invoke(HardwareAgentInput(
            case=case, deterministic_observations=HardwareObservations(case_id=case.case_id),
        ))
    assert type(caught.value) is AgentExecutionError
    assert caught.value.__cause__ is original
    assert "synthetic-secret" not in str(caught.value)


def test_unsupported_official_fake_reports_setup_failure() -> None:
    with pytest.raises(AgentExecutionError) as caught:
        HardwareSecurityAgent(model=FakeListChatModel(responses=["synthetic"]))
    assert isinstance(caught.value.__cause__, NotImplementedError)


def test_domain_prompt_rules() -> None:
    from chipchain.agents.prompts.hardware import SYSTEM_PROMPT as hardware
    from chipchain.agents.prompts.firmware import SYSTEM_PROMPT as firmware
    from chipchain.agents.prompts.cross_layer import SYSTEM_PROMPT as cross

    assert "hypothesis != verified trigger" in hardware
    assert "original firmware behavior" in firmware
    assert "Static reachability != Runtime reachability" in firmware
    assert "Candidate != Verified Trigger" in cross
    assert "missing_constraints" in cross


def test_multiple_structured_tool_calls_are_not_silently_ignored(load_case: Callable[[str], CaseBundle]) -> None:
    case = load_case("hardware_only")
    message = AIMessage(content="", tool_calls=[
        {"name": "HardwareAnalysisReport", "args": {"case_id": case.case_id}, "id": "first"},
        {"name": "HardwareAnalysisReport", "args": {}, "id": "second"},
    ])
    model = fake_model(HardwareAnalysisReport, message)
    with pytest.raises(AgentStructuredOutputError):
        HardwareSecurityAgent(model=model).invoke(HardwareAgentInput(
            case=case, deterministic_observations=HardwareObservations(case_id=case.case_id),
        ))


def test_cross_report_case_mismatch_is_structured_error(load_case: Callable[[str], CaseBundle]) -> None:
    model = fake_model(CrossLayerAnalysisReport, CrossLayerAnalysisReport(case_id="different"))
    with pytest.raises(AgentStructuredOutputError) as caught:
        CrossLayerSecurityAgent(model=model).invoke(cross_input(load_case("paired")))
    assert caught.value.__cause__ is not None
