"""Explicit one-call Heat_Press integration; no retries or automatic reviewed export."""

import argparse
import hashlib
import json
import logging
import os
from dataclasses import replace
from collections import Counter, defaultdict
from importlib.metadata import version
from pathlib import Path
from uuid import UUID, uuid4

from langsmith import tracing_context
from pydantic import ValidationError

from chipchain.agents.context import firmware_context
from chipchain.agents.contracts import FirmwareAgentInput, FirmwareAgentOutput
from chipchain.agents.firmware import FirmwareSecurityAgent
from chipchain.agents.firmware_evidence import collect_firmware_evidence
from chipchain.agents.projections.firmware import (
    PROJECTION_VERSION, build_firmware_analysis_projection, firmware_projection_sha256,
)
from chipchain.agents.model_outputs.firmware import FirmwareBindingError
from chipchain.agents.relation_support import RelationSupportError
from chipchain.integrations.firmware_relations import prepare_relation_context
from chipchain.agents.prompts.firmware import PROMPT_DESCRIPTOR
from chipchain.agents.runtime import AgentExecutionError, AgentStructuredOutputError
from chipchain.domain.case import ArtifactRef, CaseBundle, TargetDescriptor
from chipchain.domain.firmware import FirmwareAnalysisReport
from chipchain.domain.provenance import AgentRole, ToolDescriptor
from chipchain.domain.run import AnalysisRun
from chipchain.execution.provenance import capture_provenance
from chipchain.execution.runner import analysis_run_from_state, utc_now
from chipchain.integrations.deepseek import (
    DeepSeekConfig, DeepSeekConfigurationError, build_deepseek_chat_model,
    load_deepseek_config, require_real_opt_in,
)
from chipchain.integrations.deepseek_hardware import _check_secret
from chipchain.tools.architecture.arm import ArmThumbInstructionDecoder
from chipchain.tools.contracts import ObservationScope
from chipchain.tools.firmware.fuzzware import FuzzwareHeatPressScenarioAnalyzer
from chipchain.workflows.state import CaseWorkflowState

# Descriptor only: A1.1 projection bytes and policy are unchanged.
PROJECTION_DESCRIPTOR = ToolDescriptor(tool_name="firmware-analysis-projection", tool_version="v1",
                                       tool_role="model_context_projection")
ARTIFACTS = (
    ("02-comparison-with-state-of-the-art/P2IM/Heat_Press/Heat_Press.elf", "firmware_binary", "elf",
     261365, "73f667524ed0ff8f24b460d4678b74f15eec13d954b93cdc92c839c2c3f1044e"),
    ("02-comparison-with-state-of-the-art/P2IM/Heat_Press/Heat_Press.bin", "firmware_binary", "bin",
     24896, "1f7654deeec0d26307f35ea683c891965aa671fd891ae24af1aa8949ede43620"),
    ("04-crash-analysis/13/config.yml", "firmware_config", "yaml",
     4253, "2d91c058a4326ddde28be2bc27afd6a073b9b8aabf1816f6bac22e76dcc33bc2"),
    ("04-crash-analysis/13/crashing_input", "firmware_input", "opaque",
     6009, "0eca471106cf883c5941a03376c4ee3aa4b6cebd26636fc401e50c168644ee22"),
)

B3_RELATION_MAX_TOKENS = 16384


def prepare_firmware_input(corpus_root: Path) -> FirmwareAgentInput:
    """Read only the four explicit inputs, verify frozen identity, then use A1."""
    artifacts = []
    for relative, kind, fmt, expected_size, expected_sha in ARTIFACTS:
        path = corpus_root / relative
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if (len(data), digest) != (expected_size, expected_sha):
            raise AgentExecutionError("Firmware artifact differs from the frozen baseline")
        artifacts.append(ArtifactRef(artifact_id=fmt, artifact_type=kind, format=fmt,
            path=str(path), sha256=digest, size_bytes=len(data)))
    case = CaseBundle(case_id="fuzzware:heat-press:scenario-13", name="Heat_Press scenario 13",
        firmware_artifacts=artifacts, target=TargetDescriptor(processor_id="sam3x", firmware_id="heat-press",
            architecture="arm", word_size_bits=32, endianness="little", isa_variant="ARMv7-M Thumb"))
    batch = FuzzwareHeatPressScenarioAnalyzer().analyze(case_id=case.case_id, target=case.target, artifacts=artifacts)
    return FirmwareAgentInput(case=case, deterministic_observations=batch)


def firmware_evidence_scopes(inputs: FirmwareAgentInput) -> dict[str, set[ObservationScope]]:
    """Scope is supplied by observations, including their nested evidence; generic is unknown."""
    collect_firmware_evidence(inputs)  # conflicts and undeclared artifacts must fail
    scopes = defaultdict(set)
    for observation in inputs.deterministic_observations.observations:
        refs = list(observation.evidence)
        for behavior in observation.behaviors:
            refs.extend(behavior.evidence)
            if behavior.decoded_instruction is not None:
                refs.extend(behavior.decoded_instruction.evidence)
        for ref in refs:
            scopes[ref.evidence_id].add(getattr(observation, "scope", ObservationScope.UNKNOWN))
    return dict(scopes)


def validate_real_firmware_claims(report: FirmwareAnalysisReport, scopes: dict[str, set]) -> None:
    """Real-run policy only; exact evidence and IR grounding run before this gate."""
    for item in [*report.findings, *report.external_input_paths, *report.reachable_behaviors, *report.issue_anchors]:
        if not item.evidence:
            raise AgentStructuredOutputError("Real firmware claims require supplied evidence")
        if item.epistemic_status == "verified":
            raise AgentStructuredOutputError("A model cannot independently verify a firmware claim")
    for item in report.reachable_behaviors:
        if item.reachability_kind == "runtime" and not any(
            ObservationScope.RUNTIME in scopes.get(ref.evidence_id, set()) for ref in item.evidence
        ):
            raise AgentStructuredOutputError("Runtime reachability requires supplied runtime evidence")


def validate_real_firmware_report(output: FirmwareAgentOutput, inputs: FirmwareAgentInput) -> None:
    validate_real_firmware_claims(output.report, firmware_evidence_scopes(inputs))


def firmware_input_counts(inputs: FirmwareAgentInput) -> dict:
    observations = inputs.deterministic_observations.observations
    scopes = dict(Counter(getattr(o, "scope", ObservationScope.UNKNOWN).value for o in observations))
    return {
        "observation_count": len(observations),
        "observation_counts_by_kind": dict(Counter(o.kind.value if hasattr(o, "kind") else "generic" for o in observations)),
        "observation_counts_by_scope": scopes,
        "behavior_count": sum(len(o.behaviors) for o in observations),
        "evidence_count": len(collect_firmware_evidence(inputs)),
        "runtime_observation_count": scopes.get("runtime", 0),
    }


def validate_firmware_baseline(inputs: FirmwareAgentInput, context: str) -> None:
    counts = firmware_input_counts(inputs)
    projection = build_firmware_analysis_projection(inputs)
    if (counts != {"observation_count": 57,
                   "observation_counts_by_kind": {"static_instruction_site": 23, "mmio_model": 32, "environment_input": 2},
                   "observation_counts_by_scope": {"static": 23, "configuration": 33, "artifact": 1},
                   "behavior_count": 55, "evidence_count": 57, "runtime_observation_count": 0}
            or projection.projection_version != "firmware-analysis-projection/v1"
            or len(context) != 39438 or len(context) > 40000):
        raise AgentExecutionError("Firmware pre-invocation baseline changed; API call refused")
    if (firmware_projection_sha256(projection) != hashlib.sha256(context.encode("utf-8")).hexdigest()
            or firmware_projection_sha256(projection) !=
            "48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803"):
        raise AgentExecutionError("Firmware projection and sent context disagree")


def prepare_enriched_context(inputs: FirmwareAgentInput, ghidra_home: Path):
    """Fresh local A2/A3, never reads a saved projection or historical report."""
    from chipchain.tools.firmware.ghidra.api import extract_heat_press_structure
    from chipchain.tools.firmware.structure_projection import build_relevant_static_structure
    from chipchain.agents.projections.firmware_envelope import build_firmware_envelope, serialize_firmware_envelope, envelope_metadata
    if ghidra_home is None:
        raise AgentExecutionError("Enriched mode requires explicit Ghidra home")
    validate_firmware_baseline(inputs, firmware_context(inputs))
    artifact=next(a for a in inputs.case.firmware_artifacts if a.artifact_id=='elf')
    source,vectors=extract_heat_press_structure(Path(artifact.path),ghidra_home=ghidra_home,
        script_path=Path(__file__).resolve().parents[3]/'scripts/ghidra/ExportFirmwareStructure.java')
    relevant=build_relevant_static_structure(inputs,source,vectors)
    envelope=build_firmware_envelope(inputs,relevant,source)
    context=serialize_firmware_envelope(envelope)
    metadata=envelope_metadata(envelope)
    validate_enriched_baseline(relevant,metadata)
    return relevant,source,context,metadata


def validate_enriched_baseline(relevant,metadata):
    expected=dict(base_projection_characters=39438,
        base_projection_sha256='48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803',
        relevant_structure_characters=16631,
        relevant_structure_sha256='4685e8fbc41fffd90a32bc550fc122955b329c24043dd860abecf55970056304',
        a1_evidence_count=57,a3_evidence_count=172,evidence_overlap_count=55,merged_evidence_count=174)
    if any(metadata.get(k)!=v for k,v in expected.items()) or (
        len(relevant.functions),len(relevant.mmio_sites),len(relevant.direct_call_edges),
        len(relevant.unresolved_call_sites),len(relevant.vector_handler_groups),
        sum(len(g.vector_indices) for g in relevant.vector_handler_groups),len(relevant.evidence_catalog)
    )!=(34,23,22,12,14,51,172):
        raise AgentExecutionError('Enriched baseline identity/count mismatch; API call refused')


def enriched_preflight_summary(context, metadata):
    return dict(**metadata, context_characters=len(context),
        context_sha256=hashlib.sha256(context.encode('utf-8')).hexdigest(),
        resolved_model='deepseek-flash',prompt_id=PROMPT_DESCRIPTOR.prompt_id,
        prompt_version=PROMPT_DESCRIPTOR.prompt_version,runtime_observation_count=0)


def persist_firmware_run(run: AnalysisRun, directory: Path, *, config: DeepSeekConfig,
                         invocation: dict, context: str, succeeded: dict, support=None) -> None:
    """Validate every allowlisted document before writing any accepted result."""
    from chipchain.execution.reviewed_output import _validate

    documents = {
        "analysis_run.json": run.model_dump_json(indent=2),
        "firmware_analysis_report.json": run.firmware_report.model_dump_json(indent=2),
        "analysis_input.json": context,
        "invocation.json": json.dumps(invocation, indent=2),
    }
    if support is not None:
        documents["firmware_relation_support.json"] = support.model_dump_json(indent=2)
    if directory.name != str(run.run_id) or directory.parent.name != run.case_id:
        raise ValueError("Output directory must match case_id/run_id")
    attempts = (directory / "invocation_attempts.jsonl").read_text(encoding="utf-8")
    success_text = json.dumps(succeeded)
    texts = {**documents, "invocation_attempts.jsonl": attempts + success_text + "\n"}
    for text in texts.values():
        _check_secret(text, config)
    # Same re-grounding and safe-field validation as export, without exporting or accepting.
    _validate({name: (text + "\n").encode() if not name.endswith("jsonl") else text.encode()
               for name, text in texts.items()}, config.api_key.get_secret_value())
    if any((directory / name).exists() for name in documents):
        raise FileExistsError("Run output already exists")
    created = []
    try:
        for name, text in documents.items():
            with (directory / name).open("x", encoding="utf-8") as handle:
                created.append(directory / name)
                handle.write(text + "\n")
        with (directory / "invocation_attempts.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(success_text + "\n")
    except Exception:
        for path in created:
            path.unlink()  # only result files created by this call
        raise


def run_real_firmware(corpus_root: Path, *, config: DeepSeekConfig, enabled: bool,
                      output_root: Path, run_id: UUID | None = None, attempt_index: int = 1,
                      context_mode: str = "v1", ghidra_home: Path | None = None) -> Path:
    require_real_opt_in(enabled)
    if config.model != "deepseek-flash":
        raise DeepSeekConfigurationError("Corrected Firmware baseline requires deepseek-flash")
    if type(attempt_index) is not int or attempt_index not in (1, 2):
        raise ValueError("Only an initial or explicitly recorded second attempt is supported")
    if context_mode not in ('v1','enriched_v2','relation_v3'):
        raise ValueError('Unknown firmware context mode')
    if context_mode == 'relation_v3':
        config = replace(config, max_tokens=B3_RELATION_MAX_TOKENS)
    expected_budget = B3_RELATION_MAX_TOKENS if context_mode == 'relation_v3' else 8192
    if context_mode in ('enriched_v2','relation_v3') and (config.temperature, config.max_tokens, config.timeout)!=(0,expected_budget,180):
        raise DeepSeekConfigurationError('Enriched firmware modes require unchanged baseline provider settings')
    inputs = prepare_firmware_input(corpus_root)
    context = firmware_context(inputs)
    validate_firmware_baseline(inputs, context)
    relevant = source = catalog = relation_projection = support = None
    prompt = PROMPT_DESCRIPTOR
    if context_mode=='relation_v3':
        from chipchain.agents.prompts.firmware_v2 import PROMPT_DESCRIPTOR as prompt
    enriched_metadata = {}
    if context_mode=='enriched_v2':
        relevant,source,context,enriched_metadata=prepare_enriched_context(inputs,ghidra_home)
        print(json.dumps({'preflight':enriched_preflight_summary(context,enriched_metadata)},sort_keys=True),flush=True)
    if context_mode=='relation_v3':
        relevant,source,catalog,relation_projection,context,enriched_metadata=prepare_relation_context(inputs,ghidra_home)
        print(json.dumps({'preflight':{**enriched_metadata,'context_characters':len(context),
            'context_sha256':hashlib.sha256(context.encode()).hexdigest(),'prompt_version':prompt.prompt_version}},sort_keys=True),flush=True)
    _check_secret(context, config)
    before = inputs.model_dump_json()
    stub = FirmwareSecurityAgent().invoke(inputs)
    case_id = inputs.case.case_id
    if case_id in (".", "..") or any(c in case_id for c in "/\\\x00"):
        raise ValueError("Case ID cannot be used as an output directory component")
    identity = run_id or uuid4()
    directory = output_root / case_id / str(identity)
    directory.mkdir(parents=True, exist_ok=False)
    started = utc_now()
    agent = None
    attempt = dict(case_id=case_id, run_id=str(identity), attempt_index=attempt_index,
        timestamp=started.isoformat(), provider="deepseek", model=config.model,
        prompt_id=prompt.prompt_id, prompt_version=prompt.prompt_version,
        context_sha256=hashlib.sha256(context.encode("utf-8")).hexdigest(), status="started")
    if context_mode == 'relation_v3':
        attempt['max_tokens'] = config.max_tokens

    def record_attempt(record):
        text = json.dumps(record)
        _check_secret(text, config)
        with (directory / "invocation_attempts.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(text + "\n")

    def metadata():
        return {k: v for k, v in (agent.last_response_metadata if agent else {}).items()
                if config.api_key.get_secret_value() not in v}

    record_attempt(attempt)
    phase = "provider_setup"
    previous_logging = logging.root.manager.disable
    try:
        logging.disable(logging.CRITICAL)
        with tracing_context(enabled=False):
            agent = FirmwareSecurityAgent(model=build_deepseek_chat_model(config),
                                          structured_output_method="function_calling")
            phase = "provider_execution"
            if context_mode=='relation_v3':
                output,support=agent.invoke_supported(inputs,static_relation_catalog=catalog,
                    relation_projection=relation_projection,relevant_static_structure=relevant)
            else:
                output = (agent.invoke(inputs,relevant_static_structure=relevant,static_source=source)
                          if relevant is not None else agent.invoke(inputs))
        phase = "agent_post_validation"
        validate_real_firmware_report(output, inputs)
        if inputs.model_dump_json() != before or output.processor_behavior_ir != stub.processor_behavior_ir:
            raise AgentStructuredOutputError("Model run changed deterministic input or IR")
        extra_tools=[]
        if relevant is not None:
            from chipchain.agents.projections.firmware_envelope import ENVELOPE_DESCRIPTOR, STRUCTURE_DESCRIPTOR
            extra_tools=[source.tool,STRUCTURE_DESCRIPTOR,ENVELOPE_DESCRIPTOR]
        if context_mode=='relation_v3':
            from chipchain.agents.projections.firmware_envelope_v3 import ENVELOPE_DESCRIPTOR, RELATION_DESCRIPTOR, CATALOG_DESCRIPTOR
            extra_tools=[source.tool,RELATION_DESCRIPTOR,CATALOG_DESCRIPTOR,ENVELOPE_DESCRIPTOR]
        provenance = capture_provenance(prompts=[prompt], models=[config.descriptor(AgentRole.FIRMWARE)],
            tools=[FuzzwareHeatPressScenarioAnalyzer().descriptor, ArmThumbInstructionDecoder().descriptor, PROJECTION_DESCRIPTOR, *extra_tools])
        for package in ("langchain-deepseek", "langchain-openai", "openai", "python-dotenv", "capstone", "pyelftools", "PyYAML"):
            provenance.runtime_packages[package] = version(package)
        state = CaseWorkflowState(case=inputs.case, firmware_status="completed", firmware_report=output.report,
                                  processor_behavior_ir=output.processor_behavior_ir)
        run = analysis_run_from_state(state, run_id=identity, started_at=started, finished_at=utc_now(), provenance=provenance)
        invocation = {
            **{k: v for k, v in attempt.items() if k not in ("timestamp", "status")},
            "agent_role": "firmware", "projection_version": PROJECTION_VERSION,
            "temperature": config.temperature, "max_tokens": config.max_tokens, "timeout_seconds": config.timeout,
            "max_retries": 0, "thinking": "disabled", "structured_output_method": "function_calling", "strict": False,
            "usage": agent.last_usage, "response_metadata": metadata(), "context_characters": len(context),
            **firmware_input_counts(inputs), "stub_ir_equal": True,
            "claim_counts": {name: len(getattr(output.report, name)) for name in
                             ("findings", "external_input_paths", "reachable_behaviors", "issue_anchors")},
            "model_output_schema": "ModelFirmwareAnalysisReportV2" if context_mode=="relation_v3" else "ModelFirmwareAnalysisReport",
            **enriched_metadata,
        }
        if support is not None:
            invocation.update(structured_support_claim_count=len(support.support_claims),
                supported_support_claim_count=sum(e.result=='supported' for e in support.support_claims))
        succeeded = {**attempt, "timestamp": utc_now().isoformat(), "status": "succeeded",
                     "usage": agent.last_usage, "response_metadata": metadata()}
        phase = "persistence"
        persist_firmware_run(run, directory, config=config, invocation=invocation, context=context, succeeded=succeeded, support=support)
    except Exception as exc:
        known = {
            "Model invocation failed": "provider_invocation",
            "Model response failed structured-output validation": "schema_or_tool_response",
            "Model response contains unknown or altered firmware evidence references": "evidence_mismatch",
            "Model response contains unknown firmware finding references": "finding_reference_mismatch",
            "Model response failed the Agent output contract": "report_ir_mismatch",
            "Real firmware claims require supplied evidence": "missing_claim_evidence",
            "A model cannot independently verify a firmware claim": "verified_model_claim",
            "Runtime reachability requires supplied runtime evidence": "runtime_without_runtime_evidence",
        }
        reason = exc.reason_code if isinstance(exc, (FirmwareBindingError,RelationSupportError)) else known.get(str(exc), "execution_or_persistence")
        # Classify the existing IR validator's fixed internal error, without
        # introducing a second behavior registry or persisting Pydantic inputs.
        if isinstance(exc.__cause__, ValidationError) and any(
            str(e.get("ctx", {}).get("error", "")) ==
            "Report contains unresolved or wrong-layer firmware behavior IDs"
            for e in exc.__cause__.errors(include_url=False, include_input=False)
        ):
            reason = "unknown_behavior_id"
        category = exc.failure_category if isinstance(exc, AgentStructuredOutputError) else phase
        failure = {**attempt, "timestamp": utc_now().isoformat(), "status": "failed", "category": category,
            "failure_category": category, "reason_code": reason,
            "exception_type": type(exc).__name__, "usage": agent.last_usage if agent else {}, "response_metadata": metadata()}
        if agent is not None and agent.last_parse_stage is not None:
            failure['structured_output_parse_stage'] = agent.last_parse_stage
        diagnostics = []
        cause = exc
        for _ in range(5):
            if cause is None:
                break
            diagnostics.append({"exception_type": type(cause).__name__})
            status = getattr(cause, "status_code", None)
            if type(status) is int and 100 <= status <= 599:
                diagnostics.append({"http_status": status})
            if isinstance(cause, ValidationError):
                diagnostics.append({"validation_error_count": cause.error_count(),
                    "validation_error_types": sorted({e["type"] for e in cause.errors(
                        include_url=False, include_context=False, include_input=False)})})
            cause = cause.__cause__ or cause.__context__
        failure["diagnostics"] = diagnostics
        text = json.dumps(failure, indent=2)
        _check_secret(text, config)
        record_attempt(failure)
        with (directory / "failure.json").open("x", encoding="utf-8") as handle:
            handle.write(text + "\n")
        raise AgentExecutionError("Real firmware run failed; inspect sanitized diagnostics; do not automatically retry") from None
    finally:
        logging.disable(previous_logging)
    return directory


def main() -> int:
    parser = argparse.ArgumentParser(description="One explicit DeepSeek Firmware run; no automatic retry or reviewed export")
    parser.add_argument("--corpus-root", required=True, type=Path)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--attempt-index", type=int, default=1)
    parser.add_argument('--context-mode',choices=('v1','enriched_v2','relation_v3'),default='v1')
    parser.add_argument('--ghidra-home',type=Path)
    parser.add_argument('--preflight-only',action='store_true')
    args = parser.parse_args()
    try:
        if args.preflight_only:
            if args.context_mode not in ('enriched_v2','relation_v3'):
                raise ValueError('Preflight-only requires enriched_v2 or relation_v3')
            inputs=prepare_firmware_input(args.corpus_root)
            if args.context_mode=='relation_v3':
                *_,context,metadata=prepare_relation_context(inputs,args.ghidra_home)
                summary={**metadata,'context_characters':len(context),'context_sha256':hashlib.sha256(context.encode()).hexdigest(),
                         'resolved_model':'deepseek-flash','prompt_id':'firmware-security-agent','prompt_version':'v2'}
            else:
                _,_,context,metadata=prepare_enriched_context(inputs,args.ghidra_home)
                summary=enriched_preflight_summary(context,metadata)
            print(json.dumps(summary,sort_keys=True))
            return 0
        require_real_opt_in(os.environ.get("CHIPCHAIN_ENABLE_REAL_LLM") == "1")
        config = load_deepseek_config(os.environ, agent_role=AgentRole.FIRMWARE, env_file=args.env_file)
        directory = run_real_firmware(args.corpus_root, config=config, enabled=True,
                                      output_root=Path("output"), attempt_index=args.attempt_index,
                                      context_mode=args.context_mode,ghidra_home=args.ghidra_home)
    except DeepSeekConfigurationError as exc:
        print(str(exc))
        return 2
    except Exception:
        print("Real firmware run failed; no result accepted without validated report files. No automatic retry.")
        return 1
    print(f"Validated real firmware run saved: {directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
