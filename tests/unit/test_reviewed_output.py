"""Synthetic reviewed snapshots; no model, key, or external corpus required."""

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest

from chipchain.agents.context import hardware_context
from chipchain.agents.contracts import HardwareAgentInput
from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.case import ArtifactRef, CaseBundle, TargetDescriptor
from chipchain.domain.hardware import HardwareAnalysisReport
from chipchain.domain.provenance import ModelDescriptor, PromptDescriptor
from chipchain.execution.provenance import capture_provenance
from chipchain.execution.reviewed_output import FILES, ReviewedExportError, export_reviewed_output, safe_slug
from chipchain.execution.runner import analysis_run_from_state
from chipchain.tools.contracts import HardwareObservations
from chipchain.workflows.state import CaseWorkflowState

_LOCAL_POPEN = subprocess.Popen


@pytest.fixture
def source(tmp_path):
    case = CaseBundle(case_id="synthetic:hardware:743", name="Synthetic reviewed example",
        target=TargetDescriptor(architecture="riscv", processor_id="synthetic"),
        hardware_artifacts=[ArtifactRef(artifact_id="synthetic:trace", artifact_type="hardware_trace",
                                       format="vcd", path="/private/local/source.vcd")])
    inputs = HardwareAgentInput(case=case, deterministic_observations=HardwareObservations(case_id=case.case_id))
    context = hardware_context(inputs)
    report = HardwareAnalysisReport(case_id=case.case_id, unresolved_questions=["Synthetic: insufficient evidence"])
    rid = UUID("11111111-1111-4111-8111-111111111111")
    time = datetime(2026, 9, 12, tzinfo=timezone.utc)
    run = analysis_run_from_state(CaseWorkflowState(case=case, hardware_status="completed", hardware_report=report,
        processor_behavior_ir=ProcessorBehaviorIR(case_id=case.case_id)), run_id=rid, started_at=time, finished_at=time,
        provenance=capture_provenance(models=[ModelDescriptor(agent_role="hardware", provider_identifier="deepseek",
            model_identifier="deepseek-flash", mode="real")], prompts=[PromptDescriptor(agent_role="hardware",
            prompt_id="hardware-security-agent", prompt_version="v2")]))
    identity = dict(case_id=case.case_id, run_id=str(rid), provider="deepseek", model="deepseek-flash",
        prompt_id="hardware-security-agent", prompt_version="v2", context_sha256=hashlib.sha256(context.encode()).hexdigest(),
        attempt_index=1)
    invocation = dict(identity, temperature=0, max_tokens=8192, timeout_seconds=180, max_retries=0, thinking="disabled",
        structured_output_method="function_calling", strict=False, usage={}, context_characters=len(context),
        observation_count=0, behavior_count=0, stub_ir_equal=True, projection="synthetic")
    path = tmp_path / "runtime" / case.case_id / str(rid)
    path.mkdir(parents=True)
    texts = {"analysis_run.json": run.model_dump_json(indent=2), "hardware_analysis_report.json": report.model_dump_json(indent=2),
        "analysis_input.json": context, "invocation.json": json.dumps(invocation),
        "invocation_attempts.jsonl": json.dumps(dict(identity, timestamp=time.isoformat(), status="succeeded"))}
    for name, text in texts.items():
        (path / name).write_text(text + "\n")
    return path


def export(source, tmp_path, **kwargs):
    return export_reviewed_output(source, phase="v3-1b1", accepted=True, reviewed_root=tmp_path / "reviewed", **kwargs)


def edit(source, name, change):
    path = source / name
    data = json.loads(path.read_text())
    change(data)
    path.write_text(json.dumps(data) + "\n")


def test_exact_export_manifest_and_no_absolute_manifest_path(source, tmp_path):
    before = {name: (source / name).read_bytes() for name in FILES}
    # Ignored extras must never be copied, regardless of their contents.
    for name in ("failure.json", "raw_response.json", "debug.log", ".env", "input.elf", "proof.vcd"):
        (source / name).write_text("local-only")
    result = export(source, tmp_path)
    assert result.parts[-3:] == ("v3-1b1", "synthetic-hardware-743", source.name)
    assert {p.name for p in result.iterdir()} == {*FILES, "manifest.json"}
    manifest = json.loads((result / "manifest.json").read_text())
    assert manifest["source_run_status"] == "completed" and manifest["agent_role"] == "hardware"
    assert manifest["case_id"] == source.parent.name and manifest["run_id"] == source.name
    assert manifest["context_hash_basis"] == "single_terminal_lf_excluded"
    assert str(tmp_path) not in (result / "manifest.json").read_text()
    assert "/private/" not in (result / "manifest.json").read_text()
    assert {f["filename"] for f in manifest["files"]} == set(FILES)
    for record in manifest["files"]:
        data = (result / record["filename"]).read_bytes()
        assert data == before[record["filename"]] == (source / record["filename"]).read_bytes()
        assert record["sha256"] == hashlib.sha256(data).hexdigest() and record["size_bytes"] == len(data)


@pytest.mark.parametrize("defect", ["report", "hash", "case", "run", "model", "provider", "prompt", "input_case", "attempt_model"])
def test_consistency_mismatch_fails_before_writing(source, tmp_path, defect):
    if defect == "report":
        edit(source, "hardware_analysis_report.json", lambda d: d.update(unresolved_questions=["Changed"]))
    elif defect == "input_case":
        edit(source, "analysis_input.json", lambda d: d["case"].update(case_id="different"))
    else:
        name = "invocation_attempts.jsonl" if defect == "attempt_model" else "invocation.json"
        field = {"hash": "context_sha256", "case": "case_id", "run": "run_id", "prompt": "prompt_version",
                 "attempt_model": "model"}.get(defect, defect)
        value = "0" * 64 if defect == "hash" else "22222222-2222-4222-8222-222222222222" if defect == "run" else "different"
        edit(source, name, lambda d: d.update({field: value}))
    with pytest.raises(ReviewedExportError):
        export(source, tmp_path)
    assert not (tmp_path / "reviewed").exists()


@pytest.mark.parametrize("name", FILES)
def test_explicit_secret_rejected_in_every_exported_file(source, tmp_path, name):
    secret = "synthetic-sensitive-value"
    env = tmp_path / "credentials.env"
    env.write_text("DEEPSEEK_API_KEY=" + secret + "\n")
    # A JSON string escape must not evade the decoded-string check.
    edit(source, name, lambda d: d.update(unresolved_questions=[secret]))
    path = source / name
    path.write_text(path.read_text().replace("synthetic-", "\\u0073ynthetic-"))
    with pytest.raises(ReviewedExportError) as caught:
        export(source, tmp_path, env_file=env)
    assert secret not in str(caught.value)
    assert not (tmp_path / "reviewed").exists()


@pytest.mark.parametrize("field", ["authorization", "api_key", "secret", "raw_response", "response_body", "headers", "tool_calls"])
def test_forbidden_provider_fields_fail_closed(source, tmp_path, field):
    edit(source, "invocation_attempts.jsonl", lambda d: d.update(response_metadata={field: "forbidden"}))
    with pytest.raises(ReviewedExportError):
        export(source, tmp_path)


@pytest.mark.parametrize("text", ['{"tool_calls": []}', 'Authorization: Bearer synthetic-token', 'sk-1234567890123456'])
def test_raw_or_credentials_in_free_text_fail_closed(source, tmp_path, text):
    edit(source, "hardware_analysis_report.json", lambda d: d.update(unresolved_questions=[text]))
    with pytest.raises(ReviewedExportError):
        export(source, tmp_path)


@pytest.mark.parametrize("defect", ["malformed", "blank_line", "duplicate_key", "unknown_field", "missing_file", "invalid_report"])
def test_malformed_or_unallowlisted_data_rejected(source, tmp_path, defect):
    p = source / "invocation_attempts.jsonl"
    if defect == "malformed":
        p.write_text(p.read_text() + "{broken\n")
    elif defect == "blank_line":
        p.write_text(p.read_text() + "\n")
    elif defect == "duplicate_key":
        p.write_text(p.read_text().replace('"status": "succeeded"', '"status":"failed","status":"succeeded"'))
    elif defect == "unknown_field":
        edit(source, p.name, lambda d: d.update(arbitrary_payload={"content": "unknown"}))
    elif defect == "missing_file":
        p.unlink()
    else:
        (source / "hardware_analysis_report.json").write_text('{"case_id":null}')
    with pytest.raises(ReviewedExportError):
        export(source, tmp_path)


def test_failed_attempt_is_allowed_when_safe(source, tmp_path):
    p = source / "invocation_attempts.jsonl"
    failed = json.loads(p.read_text())
    failed.update(status="failed", failure_category="provider_execution", exception_type="AgentExecutionError",
                  diagnostics=[{"http_status": 503}])
    p.write_text(json.dumps(failed) + "\n" + p.read_text())
    assert export(source, tmp_path).is_dir()


def test_existing_snapshot_and_unaccepted_export_rejected(source, tmp_path):
    with pytest.raises(ReviewedExportError, match="acceptance"):
        export_reviewed_output(source, phase="v3-1b1", reviewed_root=tmp_path / "reviewed")
    result = export(source, tmp_path)
    before = {p.name: p.read_bytes() for p in result.iterdir()}
    with pytest.raises(ReviewedExportError, match="overwrite"):
        export(source, tmp_path)
    assert before == {p.name: p.read_bytes() for p in result.iterdir()}


@pytest.mark.parametrize("value,expected", [("encorpus:ibex:driver:743", "encorpus-ibex-driver-743"),
    ("CON", "case-con"), ("LPT9", "case-lpt9"), ("a/b\\c: d.", "a-b-c-d")])
def test_safe_portable_slug(value, expected):
    assert safe_slug(value) == expected


def test_unsafe_phase_and_symlink_rejected(source, tmp_path):
    with pytest.raises(ReviewedExportError):
        export_reviewed_output(source, phase="../escape", accepted=True, reviewed_root=tmp_path / "reviewed")
    p = source / "invocation.json"
    other = tmp_path / "other.json"
    p.rename(other)
    p.symlink_to(other)
    with pytest.raises(ReviewedExportError):
        export(source, tmp_path)


def test_context_hash_without_terminal_newline_supported(source, tmp_path):
    p = source / "analysis_input.json"
    p.write_bytes(p.read_bytes()[:-1])
    result = export(source, tmp_path)
    assert json.loads((result / "manifest.json").read_text())["context_hash_basis"] == "exact_file_bytes"


def test_git_ignore_boundaries(monkeypatch):
    # Narrow read-only Git exception to the suite subprocess guard; all socket
    # guards remain active. Inputs are synthetic paths, no files are created.
    root = Path(__file__).parents[2]
    paths = ["output/some-runtime-run/file.json", "output/reviewed/v3-1b1/synthetic/run/manifest.json", ".env", ".env.example"]
    with monkeypatch.context() as local:
        local.setattr(subprocess, "Popen", _LOCAL_POPEN)
        result = subprocess.run(["git", "check-ignore", "--no-index", "--stdin"], cwd=root,
                                input="\n".join(paths) + "\n", text=True, capture_output=True, check=False)
    assert result.returncode == 0
    assert set(result.stdout.splitlines()) == {paths[0], paths[2]}


def test_noncompleted_run_rejected(source, tmp_path):
    edit(source, "analysis_run.json", lambda d: d.update(status="blocked"))
    with pytest.raises(ReviewedExportError, match="Completed"):
        export(source, tmp_path)


def test_whitespace_is_not_arbitrarily_trimmed_for_context_hash(source, tmp_path):
    path = source / "analysis_input.json"
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ReviewedExportError, match="SHA256"):
        export(source, tmp_path)


def test_import_does_not_read_environment_file(monkeypatch):
    import runpy
    import dotenv
    import chipchain.execution.reviewed_output as module

    with monkeypatch.context() as scope:
        scope.setattr(dotenv, "dotenv_values", lambda *a, **kw: pytest.fail("Import read a secret file"))
        runpy.run_path(module.__file__, run_name="reviewed_import_probe")
