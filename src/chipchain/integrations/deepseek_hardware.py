"""Explicit, opt-in single-sample real run, with mandatory validated persistence.

Run from the repository root with python -m chipchain.integrations.deepseek_hardware.
This is deliberately a script/helper, not a new workflow, provider or persistence framework.
"""

import argparse
import hashlib
import json
import logging
import os
from collections import Counter
from importlib.metadata import version
from pathlib import Path
from uuid import UUID, uuid4

from langsmith import tracing_context
from pydantic import ValidationError

from chipchain.agents.context import hardware_context
from chipchain.agents.contracts import HardwareAgentInput, HardwareAgentOutput
from chipchain.agents.hardware import HardwareSecurityAgent
from chipchain.agents.prompts.hardware import PROMPT_DESCRIPTOR
from chipchain.agents.runtime import AgentExecutionError, AgentStructuredOutputError
from chipchain.domain.provenance import AgentRole
from chipchain.domain.run import AnalysisRun
from chipchain.execution.provenance import capture_provenance
from chipchain.execution.runner import analysis_run_from_state, utc_now
from chipchain.integrations.deepseek import (
    DeepSeekConfig, DeepSeekConfigurationError, build_deepseek_chat_model,
    load_deepseek_config, require_real_opt_in,
)
from chipchain.tools.architecture import RiscVInstructionDecoder
from chipchain.tools.hardware.encorpus import EnCorpusIbexDriverAnalyzer
from chipchain.tools.hardware.encorpus.projection import PROJECTION_DESCRIPTOR
from chipchain.workflows.state import CaseWorkflowState


def prepare_hardware_input(sample: Path) -> HardwareAgentInput:
    """Use the explicit operational policy, then A2. Never expose mutation answers."""
    result = EnCorpusIbexDriverAnalyzer().ingest(sample)
    inputs = result.analysis_input()
    return HardwareAgentInput(case=inputs.case, deterministic_observations=
                              RiscVInstructionDecoder().enrich(inputs.deterministic_observations))


def validate_real_report(output: HardwareAgentOutput) -> None:
    """Additional real-run grounding gate, without changing historical domain schema."""
    report = output.report
    for item in [*report.findings, *report.trigger_hypotheses, *report.abnormal_states]:
        if not item.evidence:
            raise AgentStructuredOutputError("Real findings, hypotheses and abnormal states require supplied evidence")
        related = {b.behavior_id for b in output.processor_behavior_ir.behaviors
                   if {e.evidence_id for e in b.evidence} & {e.evidence_id for e in item.evidence}}
        if related and not related.intersection(item.processor_behavior_ids):
            raise AgentStructuredOutputError("Real claims require relevant supplied behavior IDs")
        if item.epistemic_status == "verified":
            raise AgentStructuredOutputError("A model cannot independently verify a hardware claim")
    if any(h.epistemic_status not in ("hypothesized", "inferred") for h in report.trigger_hypotheses):
        raise AgentStructuredOutputError("Real trigger hypotheses must remain hypothesized or inferred")


def _check_secret(text: str, config: DeepSeekConfig) -> None:
    if config.api_key.get_secret_value() in text:
        raise AgentExecutionError("Secret detected in analysis data; invocation or persistence refused")


def persist_hardware_run(run: AnalysisRun, directory: Path, *, config: DeepSeekConfig,
                         invocation: dict, context: str) -> None:
    """Write allowlisted structured files exclusively into a reserved run directory."""
    validated = AnalysisRun.model_validate_json(run.model_dump_json())
    if validated.status != "completed" or validated.hardware_report is None:
        raise ValueError("Only a completed validated hardware run can be persisted here")
    if directory.name != str(validated.run_id) or directory.parent.name != validated.case_id:
        raise ValueError("Output directory must match case_id/run_id")
    documents = {
        "analysis_run.json": validated.model_dump_json(indent=2),
        "hardware_analysis_report.json": validated.hardware_report.model_dump_json(indent=2),
        "invocation.json": json.dumps(invocation, indent=2),
        "analysis_input.json": context,
    }
    for text in documents.values():
        _check_secret(text, config)
    # Preflight all names; exclusive create also catches races. Never overwrite.
    if any((directory / name).exists() for name in documents):
        raise FileExistsError("Run output already exists")
    for name, text in documents.items():
        with (directory / name).open("x", encoding="utf-8") as handle:
            handle.write(text + "\n")


def run_real_hardware(sample: Path, *, config: DeepSeekConfig, enabled: bool,
                      output_root: Path, run_id: UUID | None = None, attempt_index: int = 1) -> Path:
    """Exactly one model invocation, then validated files; no automatic retries."""
    require_real_opt_in(enabled)
    if type(attempt_index) is not int or attempt_index < 1:
        raise ValueError("Attempt index must be a positive integer")
    inputs = prepare_hardware_input(sample)
    context = hardware_context(inputs)
    _check_secret(context, config)
    before = inputs.model_dump_json()
    stub = HardwareSecurityAgent().invoke(inputs)
    case_id = inputs.case.case_id
    # Keep domain paths unrestricted; this script's directory components must be safe.
    if case_id in (".", "..") or any(c in case_id for c in "/\\\x00"):
        raise ValueError("Case ID cannot be used as an output directory component")
    identity = run_id or uuid4()
    directory = output_root / case_id / str(identity)
    directory.mkdir(parents=True, exist_ok=False)  # reserve before incurring API cost
    started = utc_now()
    agent = None
    attempt = {
        "case_id": case_id, "run_id": str(identity), "attempt_index": attempt_index,
        "timestamp": started.isoformat(), "provider": "deepseek", "model": config.model,
        "prompt_id": PROMPT_DESCRIPTOR.prompt_id, "prompt_version": PROMPT_DESCRIPTOR.prompt_version,
        "context_sha256": hashlib.sha256(context.encode()).hexdigest(), "status": "started",
    }

    def record_attempt(record):
        text = json.dumps(record, ensure_ascii=True)
        _check_secret(text, config)
        with (directory / "invocation_attempts.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(text + "\n")

    def response_metadata():
        return {key: value for key, value in (agent.last_response_metadata if agent else {}).items()
                if config.api_key.get_secret_value() not in value}

    record_attempt(attempt)
    phase = "provider_setup"
    previous_logging = logging.root.manager.disable
    try:
        # Explicit real entry only: suppress debug transports and tracing. No import effect.
        logging.disable(logging.CRITICAL)
        with tracing_context(enabled=False):
            model = build_deepseek_chat_model(config)
            agent = HardwareSecurityAgent(model=model, structured_output_method="function_calling")
            phase = "provider_execution"
            output = agent.invoke(inputs)
        phase = "agent_post_validation"
        validate_real_report(output)
        if inputs.model_dump_json() != before or output.processor_behavior_ir != stub.processor_behavior_ir:
            raise AgentStructuredOutputError("Model run changed deterministic input or IR")
        provenance = capture_provenance(prompts=[PROMPT_DESCRIPTOR], models=[config.descriptor(AgentRole.HARDWARE)],
                                        tools=[RiscVInstructionDecoder().descriptor, PROJECTION_DESCRIPTOR])
        # Existing extension point, only distribution versions, never model object/config dumps.
        for package in ("langchain-deepseek", "langchain-openai", "openai", "python-dotenv", "capstone"):
            provenance.runtime_packages[package] = version(package)
        state = CaseWorkflowState(case=inputs.case, hardware_status="completed",
                                  hardware_report=output.report, processor_behavior_ir=output.processor_behavior_ir)
        run = analysis_run_from_state(state, run_id=identity, started_at=started,
                                      finished_at=utc_now(), provenance=provenance)
        invocation = {
            "case_id": case_id, "run_id": str(identity), "model": config.model,
            "attempt_index": attempt_index, "prompt_id": PROMPT_DESCRIPTOR.prompt_id,
            "prompt_version": PROMPT_DESCRIPTOR.prompt_version,
            "provider": "deepseek", "temperature": config.temperature,
            "max_tokens": config.max_tokens, "timeout_seconds": config.timeout, "max_retries": 0,
            "thinking": "disabled", "structured_output_method": "function_calling", "strict": False,
            "usage": agent.last_usage, "context_sha256": hashlib.sha256(context.encode()).hexdigest(),
            "response_metadata": response_metadata(),
            "context_characters": len(context), "observation_count": len(inputs.deterministic_observations.observations),
            "observation_counts_by_kind": dict(Counter(o.kind.value for o in inputs.deterministic_observations.observations
                                                       if hasattr(o, "kind"))),
            "behavior_count": len(output.processor_behavior_ir.behaviors), "stub_ir_equal": True,
            "projection": "encorpus-operational-projection/v1 + A2; no mutation answers or raw artifact contents",
        }
        phase = "persistence"
        persist_hardware_run(run, directory, config=config, invocation=invocation, context=context)
        record_attempt({**attempt, "timestamp": utc_now().isoformat(), "status": "succeeded",
                        "usage": agent.last_usage, "response_metadata": response_metadata()})
    except Exception as exc:
        # Do not print provider bodies, raw responses, parser input, or chained tracebacks.
        # The reserved directory intentionally remains; reruns use a new UUID.
        category = (exc.failure_category if isinstance(exc, AgentStructuredOutputError) else phase)
        known_errors = {
            "Model invocation failed": "provider_invocation",
            "Model response contains unknown or altered evidence references": "evidence_mismatch",
            "Model response contains unknown finding references": "finding_reference_mismatch",
            "Model response failed the Agent output contract": "report_ir_mismatch",
            "Model response failed structured-output validation": "schema_or_tool_response",
            "Real findings, hypotheses and abnormal states require supplied evidence": "missing_evidence",
            "Real claims require relevant supplied behavior IDs": "missing_behavior_reference",
            "A model cannot independently verify a hardware claim": "unsupported_verification",
            "Real trigger hypotheses must remain hypothesized or inferred": "hypothesis_status",
        }
        # Only classify our own fixed messages. Never serialize arbitrary exception text.
        failure = {**attempt, "timestamp": utc_now().isoformat(), "status": "failed", "category": category,
                   "failure_category": category, "exception_type": type(exc).__name__,
                   "reason_code": known_errors.get(str(exc), "execution_or_persistence"),
                   "usage": agent.last_usage if agent is not None else {}}
        cause = exc
        diagnostics = []
        for _ in range(5):
            if cause is None:
                break
            diagnostics.append({"exception_type": type(cause).__name__})
            status = getattr(cause, "status_code", None)
            if type(status) is int and 100 <= status <= 599:
                diagnostics.append({"http_status": status})
            if isinstance(cause, ValidationError):
                # Error kinds only, no message/input/context that could contain response data.
                diagnostics.append({"validation_error_count": cause.error_count(),
                                    "validation_error_types": sorted({e["type"] for e in cause.errors(
                                        include_url=False, include_context=False, include_input=False)})})
            cause = cause.__cause__ or cause.__context__
        failure["diagnostics"] = diagnostics
        if agent is not None:
            failure["response_metadata"] = response_metadata()
        record_attempt(failure)
        with (directory / "failure.json").open("x", encoding="utf-8") as handle:
            json.dump(failure, handle, indent=2)
        raise AgentExecutionError("Real hardware run failed; inspect the sanitized failure record") from None
    finally:
        logging.disable(previous_logging)
    return directory


def main() -> int:
    parser = argparse.ArgumentParser(description="Explicit DeepSeek hardware run; writes validated results under output/")
    parser.add_argument("--sample", required=True, type=Path, help="Existing Ibex driver/<id> directory")
    parser.add_argument("--env-file", type=Path, help="Explicit .env file; shell values take precedence")
    parser.add_argument("--attempt-index", type=int, default=1, help="Explicit manual attempt index; does not enable retries")
    args = parser.parse_args()
    try:
        require_real_opt_in(os.environ.get("CHIPCHAIN_ENABLE_REAL_LLM") == "1")
        config = load_deepseek_config(os.environ, agent_role=AgentRole.HARDWARE, env_file=args.env_file)
        directory = run_real_hardware(args.sample, config=config, enabled=True, output_root=Path("output"),
                                     attempt_index=args.attempt_index)
    except DeepSeekConfigurationError as exc:
        print(str(exc))  # fixed public configuration messages only
        return 2
    except Exception:
        print("Real hardware run failed; no result is accepted without its validated report files.")
        return 1
    print(f"Validated real hardware run saved: {directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
