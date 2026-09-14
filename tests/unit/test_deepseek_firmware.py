"""Offline real-entry tests; actual ChatDeepSeek tool binding uses a synthetic response."""

import hashlib
import json
import runpy
from pathlib import Path
from uuid import uuid4

import pytest
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_deepseek import ChatDeepSeek
from pydantic import SecretStr

from chipchain.agents.context import firmware_context
from chipchain.agents.contracts import FirmwareAgentInput
from chipchain.agents.firmware import FirmwareSecurityAgent
from chipchain.agents.runtime import AgentExecutionError, AgentStructuredOutputError
from chipchain.domain.firmware import FirmwareAnalysisReport
from chipchain.domain.provenance import AgentRole
from chipchain.domain.run import AnalysisRun
from chipchain.execution.reviewed_output import ReviewedExportError, export_reviewed_output
from chipchain.integrations import deepseek, deepseek_firmware as real
from chipchain.tools.contracts import DeterministicObservation, FirmwareObservations, ObservationScope
from chipchain.tools.firmware.fuzzware import FuzzwareHeatPressScenarioAnalyzer
from tests.firmware_fakes import make_case, model_report_fixture
from tests.unit.test_firmware_grounding import report_with_all_objects


@pytest.fixture
def inputs(tmp_path):
    case = make_case(tmp_path / "inputs")
    batch = FuzzwareHeatPressScenarioAnalyzer().analyze(case_id=case.case_id, target=case.target,
                                                       artifacts=case.firmware_artifacts)
    return FirmwareAgentInput(case=case, deterministic_observations=batch)


@pytest.fixture
def config():
    return deepseek.DeepSeekConfig(api_key=SecretStr("synthetic-sensitive-credential"), model="deepseek-flash")


def script_provider(monkeypatch, report, *, reserved_root=None, config=None, defect=None):
    seen = []

    def generate(self, messages, **kwargs):
        if reserved_root is not None:
            assert list(reserved_root.rglob("invocation_attempts.jsonl"))
        seen.append((messages, kwargs))
        if defect == "transport":
            raise RuntimeError("RAW PROVIDER BODY " + config.api_key.get_secret_value())
        payload = {} if defect == "schema" else model_report_fixture(report).model_dump(mode="json")
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="RAW PROVIDER CONTENT",
            tool_calls=[{"name": "ModelFirmwareAnalysisReport", "args": payload, "id": "synthetic-call"}],
            usage_metadata={"input_tokens": 10, "output_tokens": 20, "total_tokens": 30},
            response_metadata={"model_name": "synthetic-returned-model", "request_id": "synthetic-request",
                               "headers": {"Authorization": "NEVER PERSIST"}}))])

    monkeypatch.setattr(ChatDeepSeek, "_generate", generate)
    return seen


def patch_inputs(monkeypatch, inputs):
    monkeypatch.setattr(real, "prepare_firmware_input", lambda _: inputs)
    # Synthetic mini corpus cannot match real 57/55/57 acceptance counts.
    # The production baseline gate itself has separate rejection coverage.
    monkeypatch.setattr(real, "validate_firmware_baseline", lambda *args: None)


@pytest.mark.parametrize("role,variable", [(AgentRole.HARDWARE, "CHIPCHAIN_HARDWARE_MODEL"),
                                          (AgentRole.FIRMWARE, "CHIPCHAIN_FIRMWARE_MODEL")])
def test_role_configuration_and_explicit_descriptor(role, variable, tmp_path):
    env = tmp_path / "selected.env"
    env.write_text("DEEPSEEK_API_KEY=synthetic-key\n" + variable + "=deepseek-flash\n")
    c = deepseek.load_deepseek_config({}, agent_role=role, env_file=env)
    assert c.model == "deepseek-flash" and c.descriptor(role).agent_role == role
    assert deepseek.load_deepseek_config({variable: "deepseek-v4-pro"}, agent_role=role, env_file=env).model == "deepseek-v4-pro"


def test_firmware_never_falls_back_to_hardware_model(tmp_path):
    env = tmp_path / "selected.env"
    env.write_text("DEEPSEEK_API_KEY=synthetic-key\nCHIPCHAIN_HARDWARE_MODEL=deepseek-flash\n")
    c = deepseek.load_deepseek_config({"CHIPCHAIN_HARDWARE_MODEL": "deepseek-v4-flash"},
                                    agent_role=AgentRole.FIRMWARE, env_file=env)
    assert c.model == "deepseek-flash"


def test_import_does_not_read_env(monkeypatch):
    import dotenv
    monkeypatch.setattr(dotenv, "dotenv_values", lambda *a, **kw: pytest.fail("Import read env"))
    for module in (deepseek, real):
        runpy.run_path(module.__file__, run_name="offline_import_probe")


def test_opt_in_and_baseline_fail_before_provider(inputs, config, tmp_path, monkeypatch):
    monkeypatch.setattr(real, "prepare_firmware_input", lambda _: inputs)
    monkeypatch.setattr(real, "build_deepseek_chat_model", lambda _: pytest.fail("Must not call provider"))
    with pytest.raises(deepseek.DeepSeekConfigurationError):
        real.run_real_firmware(tmp_path, config=config, enabled=False, output_root=tmp_path / "out")
    with pytest.raises(AgentExecutionError, match="baseline"):
        real.run_real_firmware(tmp_path, config=config, enabled=True, output_root=tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_cli_opt_in_before_env_read(monkeypatch):
    monkeypatch.delenv("CHIPCHAIN_ENABLE_REAL_LLM", raising=False)
    monkeypatch.setattr("sys.argv", ["firmware", "--corpus-root", "synthetic"])
    monkeypatch.setattr(real, "load_deepseek_config", lambda *a, **kw: pytest.fail("Should not read key"))
    assert real.main() == 2


def test_runtime_parity_usage_metadata_and_immutability(inputs, config, monkeypatch):
    before = inputs.model_dump_json()
    report = report_with_all_objects(inputs)
    seen = script_provider(monkeypatch, report)
    stub = FirmwareSecurityAgent().invoke(inputs)
    model = deepseek.build_deepseek_chat_model(config)
    assert model.max_retries == 0 and not model.streaming
    assert model.extra_body == {"thinking": {"type": "disabled"}}
    agent = FirmwareSecurityAgent(model=model, structured_output_method="function_calling")
    output = agent.invoke(inputs)
    real.validate_real_firmware_report(output, inputs)
    assert output.report == report and output.processor_behavior_ir == stub.processor_behavior_ir
    assert inputs.model_dump_json() == before
    assert agent.last_usage == {"input_tokens": 10, "output_tokens": 20, "total_tokens": 30}
    assert agent.last_response_metadata == {"model_name": "synthetic-returned-model", "request_id": "synthetic-request"}
    assert seen[0][0][1].content == firmware_context(inputs)
    assert seen[0][1]["tools"][0]["function"]["name"] == "ModelFirmwareAnalysisReport"
    assert seen[0][1]["tools"][0]["function"].get("strict", False) is False


@pytest.mark.parametrize("collection", ["findings", "external_input_paths", "reachable_behaviors", "issue_anchors"])
@pytest.mark.parametrize("defect", ["empty", "verified"])
def test_real_policy_for_all_structured_objects(inputs, config, monkeypatch, collection, defect):
    report = report_with_all_objects(inputs)
    item = getattr(report, collection)[0]
    if defect == "empty":
        item.evidence = []
    else:
        item.epistemic_status = "verified"
    script_provider(monkeypatch, report)
    output = FirmwareSecurityAgent(model=deepseek.build_deepseek_chat_model(config),
                                   structured_output_method="function_calling").invoke(inputs)
    with pytest.raises(AgentStructuredOutputError):
        real.validate_real_firmware_report(output, inputs)


@pytest.mark.parametrize("scope", ["static", "runtime"])
@pytest.mark.parametrize("nested", [False, True])
def test_runtime_scope_requires_actual_supplied_runtime_observation(inputs, config, monkeypatch, scope, nested):
    observation = inputs.deterministic_observations.observations[0]
    # Current typed A1 details deliberately have no runtime producer. A synthetic
    # generic extension supplies a scope to exercise the future runtime policy.
    class ScopedSyntheticObservation(DeterministicObservation):
        scope: ObservationScope

    observation = ScopedSyntheticObservation(
        observation_id=observation.observation_id, summary=observation.summary,
        evidence=observation.evidence, behaviors=observation.behaviors, scope=scope)
    inputs.deterministic_observations.observations[0] = observation
    report = report_with_all_objects(inputs)
    report.reachable_behaviors[0].reachability_kind = "runtime"
    if nested:
        ref = observation.evidence[0].model_copy(update={"evidence_id": "nested-only"})
        observation.behaviors[0].decoded_instruction.evidence = [ref]
        report.reachable_behaviors[0].evidence = [ref]
    script_provider(monkeypatch, report)
    output = FirmwareSecurityAgent(model=deepseek.build_deepseek_chat_model(config),
                                   structured_output_method="function_calling").invoke(inputs)
    if scope == "runtime":
        real.validate_real_firmware_report(output, inputs)
    else:
        with pytest.raises(AgentStructuredOutputError, match="runtime evidence"):
            real.validate_real_firmware_report(output, inputs)


def test_generic_scope_is_unknown(inputs):
    o = inputs.deterministic_observations.observations[0]
    generic = DeterministicObservation(observation_id=o.observation_id, summary=o.summary,
                                      evidence=o.evidence, behaviors=o.behaviors)
    inputs.deterministic_observations = FirmwareObservations(case_id=inputs.case.case_id, observations=[generic])
    assert all(scopes == {"unknown"} for scopes in real.firmware_evidence_scopes(inputs).values())


def test_empty_report_and_static_inference_allowed(inputs, config, monkeypatch):
    for report in (FirmwareAnalysisReport(case_id=inputs.case.case_id), report_with_all_objects(inputs)):
        if report.reachable_behaviors:
            report.reachable_behaviors[0].reachability_kind = "static"
        script_provider(monkeypatch, report)
        output = FirmwareSecurityAgent(model=deepseek.build_deepseek_chat_model(config),
                                       structured_output_method="function_calling").invoke(inputs)
        real.validate_real_firmware_report(output, inputs)


@pytest.fixture
def source(inputs, config, tmp_path, monkeypatch):
    patch_inputs(monkeypatch, inputs)
    script_provider(monkeypatch, report_with_all_objects(inputs), reserved_root=tmp_path / "runtime")
    return real.run_real_firmware(tmp_path, config=config, enabled=True, output_root=tmp_path / "runtime")


def test_successful_persistence_and_no_overwrite(source, inputs, config, monkeypatch, tmp_path):
    assert {p.name for p in source.iterdir()} == {"analysis_run.json", "firmware_analysis_report.json",
                                               "analysis_input.json", "invocation.json", "invocation_attempts.jsonl"}
    run = AnalysisRun.model_validate_json((source / "analysis_run.json").read_bytes())
    assert run.status == "completed" and run.hardware_report is None and run.cross_layer_report is None
    assert run.firmware_report == FirmwareAnalysisReport.model_validate_json((source / "firmware_analysis_report.json").read_bytes())
    assert run.provenance.models[0] == config.descriptor(AgentRole.FIRMWARE)
    assert len(run.provenance.tools) == 3
    text = (source / "analysis_input.json").read_text()[:-1]
    assert text == firmware_context(inputs)
    invocation = json.loads((source / "invocation.json").read_text())
    assert invocation["context_sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert invocation["context_characters"] == len(text) and invocation["stub_ir_equal"]
    assert invocation["claim_counts"] == {name: 1 for name in
        ("findings", "external_input_paths", "reachable_behaviors", "issue_anchors")}
    assert invocation["model_output_schema"] == "ModelFirmwareAnalysisReport"
    assert run.firmware_report.findings[0].evidence  # persisted canonical, not ID-only transport
    assert [json.loads(line)["status"] for line in (source / "invocation_attempts.jsonl").read_text().splitlines()] == ["started", "succeeded"]
    for p in source.iterdir():
        assert all(marker not in p.read_text() for marker in (config.api_key.get_secret_value(), "RAW PROVIDER", "tool_calls", "Authorization"))
    monkeypatch.setattr(real, "build_deepseek_chat_model", lambda _: pytest.fail("Collision before cost"))
    with pytest.raises(FileExistsError):
        real.run_real_firmware(tmp_path, config=config, enabled=True, output_root=source.parent.parent, run_id=run.run_id)


@pytest.mark.parametrize("defect", ["transport", "schema", "evidence", "finding", "behavior", "epistemic", "runtime", "secret", "raw"])
def test_all_gates_before_result_persistence_and_sanitized_failure(inputs, config, tmp_path, monkeypatch, defect):
    patch_inputs(monkeypatch, inputs)
    report = report_with_all_objects(inputs)
    if defect == "evidence": report.findings[0].evidence[0].evidence_id = "invented"
    if defect == "finding": report.issue_anchors[0].firmware_finding_ids = ["unknown"]
    if defect == "behavior": report.processor_behavior_ids = ["unknown"]
    if defect == "epistemic": report.findings[0].epistemic_status = "verified"
    if defect == "runtime": report.reachable_behaviors[0].reachability_kind = "runtime"
    if defect == "secret": report.unresolved_questions = [config.api_key.get_secret_value()]
    if defect == "raw": report.unresolved_questions = ['{"tool_calls": []}']
    seen = script_provider(monkeypatch, report, config=config, defect=defect)
    with pytest.raises(AgentExecutionError):
        real.run_real_firmware(tmp_path, config=config, enabled=True, output_root=tmp_path / "out")
    assert len(seen) == 1
    files = list((tmp_path / "out").rglob("*.*"))
    assert {p.name for p in files} == {"failure.json", "invocation_attempts.jsonl"}
    for p in files:
        assert config.api_key.get_secret_value() not in p.read_text() and "RAW PROVIDER" not in p.read_text()
    failure = json.loads(next((tmp_path / "out").rglob("failure.json")).read_text())
    if defect == "transport": assert failure["reason_code"] == "provider_invocation"
    if defect == "schema": assert failure["failure_category"] == "structured_output_parsing"


def test_secret_in_context_refused_before_cost(inputs, config, tmp_path, monkeypatch):
    patch_inputs(monkeypatch, inputs)
    inputs.deterministic_observations.unresolved_questions.append(config.api_key.get_secret_value())
    monkeypatch.setattr(real, "build_deepseek_chat_model", lambda _: pytest.fail("Secret before API"))
    with pytest.raises(AgentExecutionError, match="Secret"):
        real.run_real_firmware(tmp_path, config=config, enabled=True, output_root=tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_firmware_export_accepted_synthetic_only(source, tmp_path):
    with pytest.raises(ReviewedExportError, match="acceptance"):
        export_reviewed_output(source, phase="synthetic", reviewed_root=tmp_path / "reviewed")
    result = export_reviewed_output(source, phase="synthetic", accepted=True, reviewed_root=tmp_path / "reviewed")
    assert json.loads((result / "manifest.json").read_text())["agent_role"] == "firmware"
    for p in source.iterdir(): assert (result / p.name).read_bytes() == p.read_bytes()


@pytest.mark.parametrize("defect", ["report", "hash", "chars", "evidence", "behavior", "finding", "provenance",
                                    "projection_version", "raw", "secret", "counts", "stages", "path_reference", "duplicate_claim", "claim_counts"])
def test_firmware_reviewed_mismatches_rejected(source, tmp_path, defect, config):
    def edit(name, fn):
        p = source / name
        data = json.loads(p.read_text()); fn(data); p.write_text(json.dumps(data) + "\n")
    if defect in ("evidence", "finding", "behavior", "path_reference", "duplicate_claim"):
        def mutate(report):
            if defect == "evidence": report["findings"][0]["evidence"][0]["summary"] = "rewritten"
            if defect == "finding": report["issue_anchors"][0]["firmware_finding_ids"] = ["unknown"]
            if defect == "behavior": report["processor_behavior_ids"] = ["unknown"]
            if defect == "path_reference": report["reachable_behaviors"][0]["external_input_path_ids"] = ["unknown"]
            if defect == "duplicate_claim": report["external_input_paths"] *= 2
        edit("firmware_analysis_report.json", mutate)
        edit("analysis_run.json", lambda d: mutate(d["firmware_report"]))
    elif defect == "report": edit("firmware_analysis_report.json", lambda d: d.update(unresolved_questions=["different"]))
    elif defect == "hash": edit("invocation.json", lambda d: d.update(context_sha256="0"*64))
    elif defect == "chars": edit("invocation.json", lambda d: d.update(context_characters=0))
    elif defect == "claim_counts": edit("invocation.json", lambda d: d.update(claim_counts={"findings": 999}))
    elif defect == "counts": edit("invocation.json", lambda d: d.update(evidence_count=0))
    elif defect == "provenance": edit("analysis_run.json", lambda d: d["provenance"]["models"][0].update(agent_role="hardware"))
    elif defect == "projection_version": edit("analysis_input.json", lambda d: d.update(projection_version="unsupported/v2"))
    elif defect == "raw": edit("invocation.json", lambda d: d.update(raw_response={"text":"raw"}))
    elif defect == "secret": edit("firmware_analysis_report.json", lambda d: d.update(unresolved_questions=[config.api_key.get_secret_value()]))
    elif defect == "stages": edit("analysis_run.json", lambda d: d["stages"][0].update(status="completed"))
    env = tmp_path / "selected.env"; env.write_text("DEEPSEEK_API_KEY=" + config.api_key.get_secret_value() + "\n")
    with pytest.raises(ReviewedExportError):
        export_reviewed_output(source, phase="synthetic", accepted=True, reviewed_root=tmp_path / "reviewed", env_file=env)
    assert not (tmp_path / "reviewed").exists()
