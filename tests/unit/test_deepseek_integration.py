"""Offline provider binding and real-entry boundary tests, with synthetic credentials."""

import importlib
import json
from pathlib import Path
from uuid import uuid4

import pytest
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_deepseek import ChatDeepSeek
from pydantic import SecretStr

from chipchain.agents.context import hardware_context
from chipchain.agents.contracts import HardwareAgentInput
from chipchain.agents.hardware import HardwareSecurityAgent
from chipchain.agents.prompts.hardware import PROMPT_DESCRIPTOR, SYSTEM_PROMPT
from chipchain.agents.runtime import AgentExecutionError, AgentStructuredOutputError
from chipchain.domain.common import AnalysisLayer
from chipchain.domain.hardware import HardwareAnalysisReport, HardwareFinding, HardwareTriggerHypothesis
from chipchain.domain.run import AnalysisRun
from chipchain.integrations import deepseek, deepseek_hardware as real
from chipchain.tools.contracts import DeterministicObservation, HardwareObservations
from tests.fakes import fake_model
from tests.unit.test_domain import behavior


@pytest.fixture
def config():
    return deepseek.DeepSeekConfig(api_key=SecretStr("synthetic-test-secret-not-a-real-key"))


@pytest.fixture
def inputs(load_case):
    case = load_case("hardware_only")
    item = behavior(AnalysisLayer.HARDWARE)
    return HardwareAgentInput(case=case, deterministic_observations=HardwareObservations(
        case_id=case.case_id, observations=[DeterministicObservation(
            observation_id="synthetic:observation", summary="Synthetic hardware evidence",
            evidence=item.evidence, behaviors=[item],
        )],
    ))


def grounded_report(inputs):
    item = inputs.deterministic_observations.observations[0].behaviors[0]
    return HardwareAnalysisReport(case_id=inputs.case.case_id, processor_behavior_ids=[item.behavior_id],
        findings=[HardwareFinding(finding_id="synthetic:finding", summary="Synthetic evidence summary",
            evidence=item.evidence, processor_behavior_ids=[item.behavior_id], epistemic_status="inferred")],
        trigger_hypotheses=[HardwareTriggerHypothesis(hypothesis_id="synthetic:hypothesis",
            summary="Synthetic unverified proposed condition", evidence=item.evidence,
            hardware_finding_ids=["synthetic:finding"], processor_behavior_ids=[item.behavior_id])],
        unresolved_questions=["Synthetic: missing replay constraints"])


def script_provider(monkeypatch, report):
    """Exercise actual ChatDeepSeek tool binding and Pydantic parser, without HTTP."""
    seen = []

    def generate(self, messages, **kwargs):
        seen.append((messages, kwargs))
        message = AIMessage(content="", tool_calls=[{
            "name": "HardwareAnalysisReport", "args": report.model_dump(mode="json"), "id": "synthetic-call",
        }], usage_metadata={"input_tokens": 10, "output_tokens": 20, "total_tokens": 30})
        return ChatResult(generations=[ChatGeneration(message=message)])

    monkeypatch.setattr(ChatDeepSeek, "_generate", generate)
    return seen


def test_factory_constructs_official_model_without_invocation(config):
    model = deepseek.build_deepseek_chat_model(config)
    assert isinstance(model, ChatDeepSeek)
    assert model.model_name == "deepseek-v4-pro" and model.temperature == 0
    assert model.max_retries == 0 and model.extra_body == {"thinking": {"type": "disabled"}}
    assert model.api_base == "https://api.deepseek.com"
    assert config.api_key.get_secret_value() not in repr(config)
    descriptor = config.descriptor().model_dump_json()
    assert "deepseek-v4-pro" in descriptor and "hardware" in descriptor
    assert config.api_key.get_secret_value() not in descriptor


def test_explicit_env_loading_does_not_mutate_environment(tmp_path, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    path = tmp_path / ".env"
    path.write_text("DEEPSEEK_API_KEY=synthetic-file-key\nCHIPCHAIN_HARDWARE_MODEL=deepseek-v4-pro\n")
    result = deepseek.load_deepseek_config({"CHIPCHAIN_HARDWARE_MODEL": "deepseek-v4-flash"}, env_file=path)
    assert result.model == "deepseek-v4-flash"
    assert result.api_key.get_secret_value() == "synthetic-file-key"
    import os
    assert "DEEPSEEK_API_KEY" not in os.environ
    override = deepseek.load_deepseek_config({"DEEPSEEK_API_KEY": "synthetic-shell-key"}, env_file=path)
    assert override.api_key.get_secret_value() == "synthetic-shell-key"


def test_module_reload_has_no_secret_loading_or_invocation(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Import must not load credentials or construct a model")
    import dotenv
    monkeypatch.setattr(dotenv, "dotenv_values", forbidden)
    monkeypatch.setattr(ChatDeepSeek, "__init__", forbidden)
    importlib.reload(real)
    import chipchain
    importlib.reload(chipchain)


@pytest.mark.parametrize("values", [{}, {"DEEPSEEK_API_KEY": ""}, {"DEEPSEEK_API_KEY": "  "}])
def test_missing_key_has_clear_fixed_message(values):
    with pytest.raises(deepseek.DeepSeekConfigurationError, match="DEEPSEEK_API_KEY is required"):
        deepseek.load_deepseek_config(values)


@pytest.mark.parametrize("model", ["deepseek-chat", "deepseek-reasoner", "synthetic-secret-not-model"])
def test_model_identifier_validation_does_not_echo_bad_value(model):
    with pytest.raises(deepseek.DeepSeekConfigurationError) as error:
        deepseek.DeepSeekConfig(api_key=SecretStr("synthetic-key"), model=model)
    assert model not in str(error.value)


def test_real_opt_in_is_required_before_reading_input_or_creating_output(config, tmp_path, monkeypatch):
    def forbidden(*args):
        raise AssertionError("No ingestion without opt-in")
    monkeypatch.setattr(real, "prepare_hardware_input", forbidden)
    with pytest.raises(deepseek.DeepSeekConfigurationError, match="CHIPCHAIN_ENABLE_REAL_LLM"):
        real.run_real_hardware(Path("absent"), config=config, enabled=False, output_root=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_cli_without_opt_in_does_not_load_even_present_env(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text("DEEPSEEK_API_KEY=synthetic-key\nCHIPCHAIN_ENABLE_REAL_LLM=1\n")
    monkeypatch.setattr("sys.argv", ["real", "--sample", "absent", "--env-file", str(path)])
    monkeypatch.setattr(real, "load_deepseek_config", lambda *a, **kw: pytest.fail("Must check opt-in first"))
    assert real.main() == 2


def test_prompt_v2_has_generic_boundaries():
    assert PROMPT_DESCRIPTOR.prompt_version == "v2"
    for token in ("retirement", "Mutation presence", "Architectural divergence", "unresolved_questions", "EvidenceRef"):
        assert token in SYSTEM_PROMPT
    for answer in ("743", "820", "x28", "x10", "addi", "lui", "lw", "EVS053"):
        assert answer not in SYSTEM_PROMPT


@pytest.mark.parametrize("defect", ["unknown_evidence", "changed_location", "changed_summary", "unknown_finding"])
def test_postcheck_rejects_invented_or_rewritten_references(inputs, defect):
    report = grounded_report(inputs).model_copy(deep=True)
    evidence = report.findings[0].evidence[0]
    if defect == "unknown_evidence":
        evidence.evidence_id = "invented"
    elif defect == "changed_location":
        evidence.location.line = 999
    elif defect == "changed_summary":
        evidence.summary = "Invented interpretation of source"
    else:
        report.trigger_hypotheses[0].hardware_finding_ids = ["invented"]
    with pytest.raises(AgentStructuredOutputError):
        HardwareSecurityAgent(model=fake_model(HardwareAnalysisReport, report)).invoke(inputs)


def test_official_deepseek_binding_and_validation_preserve_ir(inputs, config, monkeypatch):
    seen = script_provider(monkeypatch, grounded_report(inputs))
    before = inputs.model_dump_json()
    agent = HardwareSecurityAgent(model=deepseek.build_deepseek_chat_model(config), structured_output_method="function_calling")
    result = agent.invoke(inputs)
    assert result.processor_behavior_ir == HardwareSecurityAgent().invoke(inputs).processor_behavior_ir
    assert inputs.model_dump_json() == before
    assert agent.last_usage == {"input_tokens": 10, "output_tokens": 20, "total_tokens": 30}
    assert len(seen) == 1
    messages, kwargs = seen[0]
    assert messages[1].content == hardware_context(inputs)
    assert kwargs["tools"][0]["function"]["name"] == "HardwareAnalysisReport"
    assert kwargs["tools"][0]["function"].get("strict") is not True
    assert "ground_truth_label" not in messages[1].content


def test_explicit_run_persists_validated_report_provenance_and_no_raw(inputs, config, tmp_path, monkeypatch):
    monkeypatch.setattr(real, "prepare_hardware_input", lambda _: inputs)
    seen = script_provider(monkeypatch, grounded_report(inputs))
    identity = uuid4()
    directory = real.run_real_hardware(Path("synthetic"), config=config, enabled=True,
                                      output_root=tmp_path, run_id=identity)
    run = AnalysisRun.model_validate_json((directory / "analysis_run.json").read_text())
    report = HardwareAnalysisReport.model_validate_json((directory / "hardware_analysis_report.json").read_text())
    assert run.hardware_report == report and run.run_id == identity and run.case_id == directory.parent.name
    assert run.provenance.models[0] == config.descriptor()
    assert run.provenance.prompts == [PROMPT_DESCRIPTOR]
    assert run.provenance.runtime_packages["langchain-deepseek"]
    assert json.loads((directory / "invocation.json").read_text())["stub_ir_equal"] is True
    for file in directory.iterdir():
        assert config.api_key.get_secret_value() not in file.read_text()
        assert '"raw"' not in file.read_text() and '"tool_calls"' not in file.read_text()
    with pytest.raises(FileExistsError):
        real.run_real_hardware(Path("synthetic"), config=config, enabled=True, output_root=tmp_path, run_id=identity)
    assert len(seen) == 1  # collision fails before spending tokens


def test_bad_real_result_cannot_become_official_output(inputs, config, tmp_path, monkeypatch):
    monkeypatch.setattr(real, "prepare_hardware_input", lambda _: inputs)
    report = grounded_report(inputs)
    report.findings[0].evidence = []
    script_provider(monkeypatch, report)
    with pytest.raises(AgentExecutionError):
        real.run_real_hardware(Path("synthetic"), config=config, enabled=True, output_root=tmp_path)
    assert list(tmp_path.rglob("failure.json"))
    assert not list(tmp_path.rglob("hardware_analysis_report.json"))


def test_secret_in_context_fails_before_call_or_output(inputs, config, tmp_path, monkeypatch):
    inputs.case.name = config.api_key.get_secret_value()
    monkeypatch.setattr(real, "prepare_hardware_input", lambda _: inputs)
    monkeypatch.setattr(real, "build_deepseek_chat_model", lambda _: pytest.fail("Secret must never enter a request"))
    with pytest.raises(AgentExecutionError, match="Secret detected"):
        real.run_real_hardware(Path("synthetic"), config=config, enabled=True, output_root=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_secret_in_response_is_not_written(inputs, config, tmp_path, monkeypatch):
    monkeypatch.setattr(real, "prepare_hardware_input", lambda _: inputs)
    report = grounded_report(inputs)
    report.unresolved_questions.append(config.api_key.get_secret_value())
    script_provider(monkeypatch, report)
    with pytest.raises(AgentExecutionError) as error:
        real.run_real_hardware(Path("synthetic"), config=config, enabled=True, output_root=tmp_path)
    assert config.api_key.get_secret_value() not in str(error.value)
    assert not list(tmp_path.rglob("hardware_analysis_report.json"))
    for file in tmp_path.rglob("*.json"):
        assert config.api_key.get_secret_value() not in file.read_text()


def test_provider_exception_is_sanitized(inputs, config, tmp_path, monkeypatch):
    monkeypatch.setattr(real, "prepare_hardware_input", lambda _: inputs)

    def fail(*args, **kwargs):
        raise RuntimeError(config.api_key.get_secret_value())

    monkeypatch.setattr(ChatDeepSeek, "_generate", fail)
    with pytest.raises(AgentExecutionError) as error:
        real.run_real_hardware(Path("synthetic"), config=config, enabled=True, output_root=tmp_path)
    assert config.api_key.get_secret_value() not in str(error.value)
    failure = next(tmp_path.rglob("failure.json"))
    assert config.api_key.get_secret_value() not in failure.read_text()
    assert json.loads(failure.read_text())["reason_code"] == "provider_invocation"


@pytest.mark.parametrize("defect", ["verified_finding", "unknown_hypothesis"])
def test_real_gate_rejects_unsupported_epistemic_status(inputs, config, monkeypatch, defect):
    report = grounded_report(inputs)
    if defect == "verified_finding":
        report.findings[0].epistemic_status = "verified"
    else:
        report.trigger_hypotheses[0].epistemic_status = "unknown"
    script_provider(monkeypatch, report)
    output = HardwareSecurityAgent(model=deepseek.build_deepseek_chat_model(config),
                                   structured_output_method="function_calling").invoke(inputs)
    with pytest.raises(AgentStructuredOutputError):
        real.validate_real_report(output)


def test_env_example_has_no_key_and_ignore_rules_cover_private_files():
    root = Path(__file__).parents[2]
    rules = (root / ".gitignore").read_text().splitlines()
    assert all(rule in rules for rule in (".env", ".env.*", "!.env.example"))
    example = (root / ".env.example").read_text()
    assert "DEEPSEEK_API_KEY=\n" in example
    assert "CHIPCHAIN_ENABLE_REAL_LLM=0" in example


@pytest.mark.parametrize("name", ["deepseek-flash", "deepseek-v4-pro", "deepseek-v4-flash"])
def test_normal_env_model_is_used_without_override(name, tmp_path):
    path = tmp_path / ".env"
    path.write_text(f"DEEPSEEK_API_KEY=synthetic-key\nCHIPCHAIN_HARDWARE_MODEL={name}\n")
    loaded = deepseek.load_deepseek_config({}, env_file=path)
    assert loaded.model == name
    assert deepseek.build_deepseek_chat_model(loaded).model_name == name


@pytest.mark.parametrize("stage", ["provider_execution", "structured_output_parsing", "agent_post_validation"])
def test_attempt_records_distinguish_failure_stage_without_secrets(stage, inputs, config, tmp_path, monkeypatch):
    monkeypatch.setattr(real, "prepare_hardware_input", lambda _: inputs)

    def generate(self, messages, **kwargs):
        if stage == "provider_execution":
            raise RuntimeError(config.api_key.get_secret_value())
        payload = {} if stage == "structured_output_parsing" else grounded_report(inputs).model_dump(mode="json")
        if stage == "agent_post_validation":
            payload["findings"][0]["evidence"][0]["evidence_id"] = "invented"
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="", tool_calls=[{
            "name": "HardwareAnalysisReport", "args": payload, "id": "synthetic-call",
        }], usage_metadata={"input_tokens": 10, "output_tokens": 20, "total_tokens": 30},
            response_metadata={"request_id": "synthetic-request-id", "raw_secret_config": config.api_key.get_secret_value()}))])

    monkeypatch.setattr(ChatDeepSeek, "_generate", generate)
    with pytest.raises(AgentExecutionError):
        real.run_real_hardware(Path("synthetic"), config=config, enabled=True, output_root=tmp_path, attempt_index=2)
    path = next(tmp_path.rglob("invocation_attempts.jsonl"))
    assert config.api_key.get_secret_value() not in path.read_text()
    first, last = [json.loads(line) for line in path.read_text().splitlines()]
    assert first["status"] == "started" and last["status"] == "failed"
    assert last["failure_category"] == stage and last["attempt_index"] == 2
    assert last["model"] == config.model and last["provider"] == "deepseek"
    assert last["prompt_version"] == "v2" and last["prompt_id"] == "hardware-security-agent"
    assert len(last["context_sha256"]) == 64 and last["timestamp"] >= first["timestamp"]
    if stage != "provider_execution":
        assert last["usage"]["total_tokens"] == 30
        assert last["response_metadata"]["request_id"] == "synthetic-request-id"


def test_formal_claim_does_not_require_an_unrelated_behavior(inputs):
    item = inputs.deterministic_observations.observations[0].behaviors[0]
    evidence = item.evidence[0].model_copy(deep=True)
    evidence.evidence_id = "synthetic:formal-result"
    report = HardwareAnalysisReport(case_id=inputs.case.case_id, findings=[HardwareFinding(
        finding_id="formal", summary="Synthetic formal observation", evidence=[evidence], epistemic_status="derived",
    )])
    from chipchain.agents.contracts import HardwareAgentOutput
    from chipchain.domain.behavior import ProcessorBehaviorIR
    output = HardwareAgentOutput(report=report, processor_behavior_ir=ProcessorBehaviorIR(
        case_id=inputs.case.case_id, behaviors=[item]))
    real.validate_real_report(output)  # formal/local observations have no automatic behavior
