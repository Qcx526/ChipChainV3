"""Explicit reviewed snapshot export. No model calls, source edits or Git writes."""

import argparse
import hashlib
import json
import re
import shutil
from collections import Counter
from pathlib import Path
from typing import Literal
from uuid import UUID

from dotenv import dotenv_values
from pydantic import AwareDatetime, Field

from chipchain.agents.context import _SideContext
from chipchain.agents.contracts import FirmwareAgentOutput, HardwareAgentInput, HardwareAgentOutput
from chipchain.agents.projections.firmware import FirmwareAnalysisProjection, serialize_firmware_analysis_projection
from chipchain.domain.firmware import FirmwareAnalysisReport
from chipchain.integrations.deepseek_firmware import PROJECTION_DESCRIPTOR, validate_real_firmware_claims
from chipchain.agents.hardware import validate_hardware_evidence
from chipchain.agents.model_outputs.firmware import validate_firmware_report_references
from chipchain.domain.case import CaseBundle
from chipchain.domain.common import Contract, Sha256
from chipchain.domain.hardware import HardwareAnalysisReport
from chipchain.domain.run import AnalysisRun
from chipchain.tools.contracts import HardwareObservations

# Extend explicitly when another Agent has reviewed, tested output support.
REPORTS = {"hardware": ("hardware_analysis_report.json", HardwareAnalysisReport, "hardware_report"),
           "firmware": ("firmware_analysis_report.json", FirmwareAnalysisReport, "firmware_report")}
FILES = ("analysis_run.json", "hardware_analysis_report.json", "analysis_input.json",
         "invocation.json", "invocation_attempts.jsonl")
MAX_FILE_BYTES = 8 * 1024 * 1024
_FORBIDDEN = {
    "authorization", "apikey", "secret", "token", "accesstoken", "refreshtoken", "password",
    "raw", "rawresponse", "rawmessage", "rawprovidermessage", "providerbody", "responsebody",
    "headers", "requestheaders", "defaultheaders", "toolcalls", "invalidtoolcalls", "messages",
    "choices", "authentication", "credentials",
}


class ReviewedExportError(ValueError):
    """Fixed public errors never embed source contents, credentials or paths."""


class _Usage(Contract):
    input_tokens: int | None = Field(default=None, ge=0, strict=True)
    output_tokens: int | None = Field(default=None, ge=0, strict=True)
    total_tokens: int | None = Field(default=None, ge=0, strict=True)


class _ResponseMetadata(Contract):
    finish_reason: Literal['stop','length','tool_calls','content_filter','unknown'] | None = None
    request_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,128}$")
    id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,128}$")
    model: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,128}$")
    model_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,128}$")


class _Identity(Contract):
    case_id: str
    run_id: UUID
    provider: str
    model: str
    prompt_id: str
    prompt_version: str
    context_sha256: Sha256
    attempt_index: int = Field(ge=1, strict=True)


class _InvocationBase(_Identity):
    temperature: float
    max_tokens: int = Field(gt=0, strict=True)
    timeout_seconds: float
    max_retries: int = Field(ge=0, strict=True)
    thinking: Literal["disabled", "enabled"]
    structured_output_method: str
    strict: bool
    usage: _Usage
    response_metadata: _ResponseMetadata = Field(default_factory=_ResponseMetadata)
    context_characters: int = Field(ge=0, strict=True)
    observation_count: int = Field(ge=0, strict=True)
    observation_counts_by_kind: dict[str, int] = Field(default_factory=dict)
    behavior_count: int = Field(ge=0, strict=True)
    stub_ir_equal: bool


class _Invocation(_InvocationBase):
    projection: str  # Historical Hardware format is unchanged.


class _FirmwareInvocation(_InvocationBase):
    agent_role: Literal["firmware"]
    projection_version: Literal["firmware-analysis-projection/v1"]
    evidence_count: int = Field(ge=0, strict=True)
    runtime_observation_count: int = Field(ge=0, strict=True)
    observation_counts_by_scope: dict[str, int]
    claim_counts: dict[str, int] = Field(default_factory=dict)
    model_output_schema: Literal["ModelFirmwareAnalysisReport"] | None = None


class _EnrichedFirmwareInvocation(_FirmwareInvocation):
    context_mode: Literal['enriched_v2']
    envelope_version: Literal['firmware-analysis-envelope/v2']
    base_projection_version: Literal['firmware-analysis-projection/v1']
    base_projection_sha256: Sha256
    base_projection_characters: int
    relevant_structure_version: Literal['firmware-relevant-static-structure/v1']
    relevant_structure_sha256: Sha256
    relevant_structure_characters: int
    a1_evidence_count: int
    a3_evidence_count: int
    evidence_overlap_count: int
    merged_evidence_count: int


class _RelationFirmwareInvocation(_FirmwareInvocation):
    model_output_schema: Literal['ModelFirmwareAnalysisReportV2']
    prompt_version: Literal['v2']
    context_mode: Literal['relation_v3']
    envelope_version: Literal['firmware-analysis-envelope/v3']
    base_projection_version: Literal['firmware-analysis-projection/v1']
    base_projection_sha256: Sha256
    base_projection_characters: int
    relation_projection_version: Literal['firmware-relation-projection/v1']
    relation_projection_sha256: Sha256
    relation_projection_characters: int
    a4_catalog_version: Literal['firmware-static-relations/v1']
    a4_catalog_sha256: Sha256
    a4_relation_counts: dict[str,int]
    a4_relation_count: int
    merged_evidence_count: int
    relation_evidence_delta_count: int
    structured_support_claim_count: int
    supported_support_claim_count: int


class _Diagnostic(Contract):
    exception_type: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
    http_status: int | None = Field(default=None, ge=100, le=599, strict=True)
    validation_error_count: int | None = Field(default=None, ge=0, strict=True)
    validation_error_types: list[str] = Field(default_factory=list)


class _Attempt(_Identity):
    max_tokens: int | None = Field(default=None, gt=0, strict=True)
    structured_output_parse_stage: Literal['pydantic_validation','malformed_tool_arguments','missing_structured_result','unknown'] | None = None
    timestamp: AwareDatetime
    status: Literal["started", "succeeded", "failed"]
    usage: _Usage = Field(default_factory=_Usage)
    response_metadata: _ResponseMetadata = Field(default_factory=_ResponseMetadata)
    category: str | None = None
    failure_category: str | None = None
    exception_type: str | None = None
    reason_code: str | None = None
    diagnostics: list[_Diagnostic] = Field(default_factory=list)


def safe_slug(value: str) -> str:
    """Portable directory component; original case identity remains in JSON."""
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                *(f"lpt{i}" for i in range(1, 10))}
    if not slug or len(slug) > 100:
        raise ReviewedExportError("Identity cannot be represented as a safe snapshot slug")
    return "case-" + slug if slug in reserved else slug


def _json(text: str):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ReviewedExportError("Duplicate JSON keys are not accepted")
            result[key] = value
        return result

    def invalid_constant(_):
        raise ReviewedExportError("Non-finite JSON values are not accepted")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_constant)


def _safety(value, secret: str | None) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", key.lower())
            if normalized in _FORBIDDEN or any(x in normalized for x in ("apikey", "authorization", "rawresponse", "secret")):
                raise ReviewedExportError("Forbidden secret or raw-provider field detected")
            _safety(key, secret)
            _safety(child, secret)
    elif isinstance(value, list):
        for child in value:
            _safety(child, secret)
    elif isinstance(value, str):
        if secret and secret in value:
            raise ReviewedExportError("Secret detected; export refused")
        if re.search(r"(?i)(\bsk-[a-z0-9_-]{12,}|\bbearer\s+\S+|-----BEGIN .*PRIVATE KEY-----|"
                     r"(?:api[_-]?key|authorization|secret)\s*[=:]\s*\S+|"
                     r'["\x27](?:tool_calls|raw_response|response_body|headers|authorization)["\x27]\s*:)', value):
            raise ReviewedExportError("Credential or raw-provider content detected")


def _run_role(run: AnalysisRun) -> str:
    if run.cross_layer_report is not None or (run.hardware_report is not None) == (run.firmware_report is not None):
        raise ReviewedExportError("Only single-side hardware or firmware snapshots are supported")
    return "firmware" if run.firmware_report is not None else "hardware"


def _enriched_ir_matches(context, ir):
    """Recheck v1's deterministic projection of IR; no prose semantics gate."""
    from chipchain.agents.projections.firmware import _decoded
    evidence={e.evidence_id:e for e in context.evidence_catalog}
    for behavior in ir.behaviors:
        refs=[*behavior.evidence,*(behavior.decoded_instruction.evidence if behavior.decoded_instruction else [])]
        if any(evidence.get(ref.evidence_id)!=ref for ref in refs):
            raise ReviewedExportError('IR evidence differs from base projection')
    canonical={b.behavior_id:b for b in ir.behaviors}
    if len(canonical)!=len(ir.behaviors) or set(canonical)!={b.behavior_id for b in context.behaviors}:
        raise ReviewedExportError('Envelope/IR behavior catalog mismatch')
    for projected in context.behaviors:
        b=canonical[projected.behavior_id]
        attrs=dict(b.attributes)
        owners=[o for o in context.observations if b.behavior_id in o.behavior_ids]
        for key in tuple(attrs):
            if owners and all((key=='evidence_scope' and attrs[key]==o.scope.value) or
                (o.kind=='mmio_model' and key in ('pc','mmio_address','access_size_bytes') and attrs[key]==o.details.get(key)) for o in owners):
                del attrs[key]
        expected=dict(behavior_id=b.behavior_id,kind=b.kind.value,summary=b.summary,epistemic_status=b.epistemic_status,
            attributes=attrs,architecture=b.architecture.value if b.architecture!=context.case.target.architecture else None,
            evidence_ids=sorted({e.evidence_id for e in b.evidence}),
            decoded_instruction=_decoded(b.decoded_instruction) if b.decoded_instruction else None)
        if projected.model_dump()!=expected:
            raise ReviewedExportError('Envelope and deterministic IR values disagree')


def _firmware_context(run, report, context_data):
    envelope = relevant = None
    if context_data.get('envelope_version')=='firmware-analysis-envelope/v3':
        from chipchain.agents.projections.firmware_envelope_v3 import (
            parse_firmware_envelope_v3, envelope_v3_components, ENVELOPE_DESCRIPTOR, RELATION_DESCRIPTOR, CATALOG_DESCRIPTOR,
        )
        from chipchain.agents.projections.firmware_envelope import compact
        envelope=parse_firmware_envelope_v3(compact(context_data))
        context,projection,union=envelope_v3_components(envelope)
        binding=projection.catalog.source_identities
        artifact=next((a for a in run.artifacts if a.artifact_id==binding.elf_artifact_id),None)
        if artifact is None or (artifact.sha256,artifact.size_bytes)!=(binding.elf_sha256,binding.elf_size_bytes):
            raise ReviewedExportError('Envelope v3 ELF binding differs from run')
        if any(tool not in run.provenance.tools for tool in (ENVELOPE_DESCRIPTOR,RELATION_DESCRIPTOR,CATALOG_DESCRIPTOR)):
            raise ReviewedExportError('Relation v3 provenance missing')
        _enriched_ir_matches(context,run.processor_behavior_ir)
    elif 'envelope_version' in context_data:
        from chipchain.agents.projections.firmware_envelope import (
            parse_firmware_envelope, compact, envelope_components, ENVELOPE_DESCRIPTOR, STRUCTURE_DESCRIPTOR,
        )
        envelope=parse_firmware_envelope(compact(context_data))
        context,relevant,union=envelope_components(envelope)
        binding=envelope.static_source_binding
        artifact=next((a for a in run.artifacts if a.artifact_id==binding.artifact_id),None)
        if artifact is None or (artifact.sha256,artifact.size_bytes)!=(binding.sha256,binding.size_bytes):
            raise ReviewedExportError('Envelope ELF binding differs from run')
        if any(tool not in run.provenance.tools for tool in (ENVELOPE_DESCRIPTOR,STRUCTURE_DESCRIPTOR,relevant.source_structure.tool)):
            raise ReviewedExportError('Enriched context provenance missing')
        _enriched_ir_matches(context,run.processor_behavior_ir)
    else:
        context = FirmwareAnalysisProjection.model_validate(context_data)
    serialize_firmware_analysis_projection(context)  # references, neutrality, size, version
    validate_firmware_report_references(report)
    FirmwareAgentOutput(report=report, processor_behavior_ir=run.processor_behavior_ir)
    if context.case.case_id != run.case_id:
        raise ReviewedExportError("Context and run case identities disagree")
    if {b.behavior_id for b in context.behaviors} != {b.behavior_id for b in run.processor_behavior_ir.behaviors}:
        raise ReviewedExportError("Projection and IR behavior identities disagree")
    if {a.artifact_id for a in context.artifacts} != {a.artifact_id for a in run.artifacts}:
        raise ReviewedExportError("Projection and run artifact identities disagree")
    evidence = union if envelope is not None else {e.evidence_id: e for e in context.evidence_catalog}
    findings = {f.finding_id for f in report.findings}
    for item in [*report.findings, *report.external_input_paths, *report.reachable_behaviors, *report.issue_anchors]:
        if any(evidence.get(e.evidence_id) != e for e in item.evidence):
            raise ReviewedExportError("Firmware report evidence differs from the projection")
        if not set(getattr(item, "firmware_finding_ids", [])) <= findings:
            raise ReviewedExportError("Firmware report references unknown findings")
    scopes = {}
    behaviors = {b.behavior_id: b for b in context.behaviors}
    for observation in context.observations:
        ids = set(observation.evidence_ids)
        for bid in observation.behavior_ids:
            b = behaviors[bid]
            ids.update(b.evidence_ids)
            if b.decoded_instruction is not None:
                ids.update(b.decoded_instruction["evidence_ids"])
        for eid in ids:
            scopes.setdefault(eid, set()).add(observation.scope)
    validate_real_firmware_claims(report, scopes)
    expected_stages = {"hardware": "not_applicable", "firmware": "completed",
                       "ir_aggregation": "completed", "cross_layer": "not_applicable"}
    if {s.stage: s.status for s in run.stages} != expected_stages:
        raise ReviewedExportError("Firmware snapshot requires a completed firmware-only run")
    if PROJECTION_DESCRIPTOR not in run.provenance.tools:
        raise ReviewedExportError("Firmware projection provenance is required")
    return context


def _validate(blobs: dict[str, bytes], secret: str | None):
    objects = {}
    for name, data in blobs.items():
        text = data.decode("utf-8")
        if secret and secret in text:
            raise ReviewedExportError("Secret detected; export refused")
        if name.endswith(".jsonl"):
            objects[name] = [_json(line) for line in text.splitlines()]
            if not objects[name]:
                raise ReviewedExportError("Invocation attempts must not be empty")
        else:
            objects[name] = _json(text)
        _safety(objects[name], secret)
    run = AnalysisRun.model_validate_json(blobs["analysis_run.json"])
    role = _run_role(run)
    report_name, report_schema, report_field = REPORTS[role]
    report = report_schema.model_validate_json(blobs[report_name])
    if run.status != "completed" or getattr(run, report_field) != report or run.processor_behavior_ir is None:
        raise ReviewedExportError("Completed run and identical embedded report are required")
    if role == "firmware":
        context = _firmware_context(run, report, objects["analysis_input.json"])
        enriched = 'envelope_version' in objects['analysis_input.json']
        relation_v3=objects['analysis_input.json'].get('envelope_version')=='firmware-analysis-envelope/v3'
        invocation = (_RelationFirmwareInvocation if relation_v3 else _EnrichedFirmwareInvocation if enriched else _FirmwareInvocation).model_validate(objects["invocation.json"])
        if relation_v3:
            from chipchain.agents.projections.firmware_envelope_v3 import FirmwareAnalysisEnvelopeV3, envelope_v3_metadata, envelope_v3_components
            from chipchain.agents.relation_support import FirmwareRelationSupportReport, validate_support_artifact
            envelope=FirmwareAnalysisEnvelopeV3.model_validate(objects['analysis_input.json'])
            expected_metadata=envelope_v3_metadata(envelope)
            if any(getattr(invocation,k)!=v for k,v in expected_metadata.items()):
                raise ReviewedExportError('Relation projection metadata mismatch')
            audit=FirmwareRelationSupportReport.model_validate(objects['firmware_relation_support.json'])
            catalog=envelope_v3_components(envelope)[1].catalog
            if run.case_id=='fuzzware:heat-press:scenario-13':
                from chipchain.integrations.firmware_relations import validate_relation_baseline
                validate_relation_baseline(catalog)
            validate_support_artifact(audit,report,catalog)
            if (invocation.structured_support_claim_count,invocation.supported_support_claim_count)!=(len(audit.support_claims),len(audit.support_claims)):
                raise ReviewedExportError('Support claim counts mismatch')
            if (invocation.model,invocation.temperature,invocation.max_tokens)!=('deepseek-flash',0,16384):
                raise ReviewedExportError('Unsupported B3 model settings')
        elif enriched:
            from chipchain.agents.projections.firmware_envelope import FirmwareAnalysisEnvelopeV2, envelope_metadata
            expected_metadata=envelope_metadata(FirmwareAnalysisEnvelopeV2.model_validate(objects['analysis_input.json']))
            if any(getattr(invocation,k)!=v for k,v in expected_metadata.items()):
                raise ReviewedExportError('Envelope component hashes or counts disagree')
    else:
        HardwareAgentOutput(report=report, processor_behavior_ir=run.processor_behavior_ir)
        context_data = objects["analysis_input.json"]
        if set(context_data) != {"case", "artifacts", "observations", "unresolved_questions"}:
            raise ReviewedExportError("Unexpected analysis input fields")
        if set(context_data["case"]) - {"case_id", "name", "target", "synthetic"}:
            raise ReviewedExportError("Unexpected case projection fields")
        if any(set(a) != {"artifact_id", "artifact_type", "path", "format"} for a in context_data["artifacts"]):
            raise ReviewedExportError("Unexpected artifact projection fields")
        context = _SideContext.model_validate(context_data)
        inputs = HardwareAgentInput(case=CaseBundle(case_id=context.case.case_id, name=context.case.name,
            target=context.case.target, hardware_artifacts=[a.model_dump() for a in context.artifacts]),
            deterministic_observations=HardwareObservations(case_id=context.case.case_id,
                observations=context.observations, unresolved_questions=context.unresolved_questions))
        validate_hardware_evidence(report, inputs)
        if context.case.case_id != run.case_id or [b for o in context.observations for b in o.behaviors] != run.processor_behavior_ir.behaviors:
            raise ReviewedExportError("Context and run identities or deterministic behaviors disagree")
        invocation = _Invocation.model_validate(objects["invocation.json"])
    models = [m for m in run.provenance.models if m.agent_role == role]
    prompts = [p for p in run.provenance.prompts if p.agent_role == role]
    if len(models) != 1 or len(prompts) != 1:
        raise ReviewedExportError("Explicit agent model and prompt provenance are required")
    model, prompt = models[0], prompts[0]
    expected = dict(case_id=run.case_id, run_id=run.run_id, provider=model.provider_identifier,
                    model=model.model_identifier, prompt_id=prompt.prompt_id, prompt_version=prompt.prompt_version)
    if not model.provider_identifier or model.mode != "real":
        raise ReviewedExportError("Real model provenance is required")
    data = blobs["analysis_input.json"]
    # B/B.1 writers append exactly one LF after hashing the sent context text.
    basis = "exact_file_bytes"
    if hashlib.sha256(data).hexdigest() != invocation.context_sha256:
        if not data.endswith(b"\n") or hashlib.sha256(data[:-1]).hexdigest() != invocation.context_sha256:
            raise ReviewedExportError("Context SHA256 mismatch")
        data, basis = data[:-1], "single_terminal_lf_excluded"
    if invocation.context_characters != len(data.decode("utf-8")):
        raise ReviewedExportError("Context character count mismatch")
    if invocation.observation_count != len(context.observations) or invocation.behavior_count != len(run.processor_behavior_ir.behaviors):
        raise ReviewedExportError("Invocation input counts mismatch")
    if invocation.observation_counts_by_kind and invocation.observation_counts_by_kind != dict(Counter(
            (o.kind if role == "firmware" else o.kind.value) for o in context.observations if hasattr(o, "kind"))):
        raise ReviewedExportError("Invocation observation kind counts mismatch")
    if role == "firmware":
        if invocation.claim_counts and invocation.claim_counts != {
                name: len(getattr(report, name)) for name in
                ("findings", "external_input_paths", "reachable_behaviors", "issue_anchors")}:
            raise ReviewedExportError("Firmware invocation claim counts disagree")
        scopes = dict(Counter(o.scope.value for o in context.observations))
        if (invocation.evidence_count != len(context.evidence_catalog)
                or invocation.observation_counts_by_scope != scopes
                or invocation.runtime_observation_count != scopes.get("runtime", 0)
                or invocation.projection_version != context.projection_version
                or not invocation.stub_ir_equal):
            raise ReviewedExportError("Firmware invocation projection statistics disagree")
        if (len(run.provenance.prompts) != 1 or any(
                m.mode != "unknown" or m.model_identifier != "unknown" or m.provider_identifier is not None
                for m in run.provenance.models if m.agent_role != role)):
            raise ReviewedExportError("Firmware snapshot has unrelated agent provenance")
        if (invocation.max_retries != 0 or invocation.thinking != "disabled" or invocation.strict
                or invocation.structured_output_method != "function_calling"):
            raise ReviewedExportError("Unsupported firmware invocation settings")
    attempts = [_Attempt.model_validate(item) for item in objects["invocation_attempts.jsonl"]]
    for record in [invocation, *attempts]:
        if isinstance(record, _Attempt) and record.max_tokens is not None and record.max_tokens != invocation.max_tokens:
            raise ReviewedExportError('Attempt output budget differs from invocation')
        if any(getattr(record, key) != value for key, value in expected.items()):
            raise ReviewedExportError("Invocation model, prompt or run identity mismatch")
        if record.context_sha256 != invocation.context_sha256:
            raise ReviewedExportError("Attempt context SHA256 mismatch")
    # Failed historical attempts are permitted; the exported result still needs a success record.
    if not any(a.status == "succeeded" and a.attempt_index == invocation.attempt_index for a in attempts):
        raise ReviewedExportError("No successful invocation record for the exported result")
    return run, invocation, basis


def export_reviewed_output(source: Path, *, phase: str, accepted: bool = False,
                           reviewed_root: Path = Path("output/reviewed"), env_file: Path | None = None) -> Path:
    """Explicit human acceptance + fail-closed checks, then exact allowlisted bytes.

    Known credentials are checked only when a selected env file is supplied.
    Automated scans cannot replace human review of arbitrary prose or private data.
    """
    if accepted is not True:
        raise ReviewedExportError("Explicit human acceptance is required for a reviewed snapshot")
    if safe_slug(phase) != phase:
        raise ReviewedExportError("Phase must be a portable lowercase slug")
    try:
        secret = None
        if env_file is not None:
            if not env_file.is_file():
                raise ReviewedExportError("Explicit environment file is missing")
            secret = dotenv_values(env_file, interpolate=False).get("DEEPSEEK_API_KEY")
            if not secret:
                raise ReviewedExportError("Explicit environment file has no secret to check")
        blobs = {}
        run_path = source / "analysis_run.json"
        if run_path.is_symlink() or not run_path.is_file() or run_path.stat().st_size > MAX_FILE_BYTES:
            raise ReviewedExportError("Required run file missing, unsafe or oversized")
        with run_path.open("rb") as handle:
            run_bytes = handle.read(MAX_FILE_BYTES + 1)
        if len(run_bytes) > MAX_FILE_BYTES:
            raise ReviewedExportError("Run file exceeds size limit")
        role = _run_role(AnalysisRun.model_validate_json(run_bytes))
        files = tuple(REPORTS[role][0] if name == "hardware_analysis_report.json" else name for name in FILES)
        for name in files:
            path = source / name
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
                raise ReviewedExportError("Required snapshot file missing, unsafe or oversized")
            with path.open("rb") as handle:
                blobs[name] = handle.read(MAX_FILE_BYTES + 1)
            if len(blobs[name]) > MAX_FILE_BYTES:
                raise ReviewedExportError("Snapshot file exceeds size limit")
        if role=='firmware' and _json(blobs['analysis_input.json'].decode()).get('envelope_version')=='firmware-analysis-envelope/v3':
            path=source/'firmware_relation_support.json'
            if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_FILE_BYTES:
                raise ReviewedExportError('Required support artifact missing, unsafe or oversized')
            with path.open('rb') as handle:
                blobs[path.name]=handle.read(MAX_FILE_BYTES+1)
            if len(blobs[path.name])>MAX_FILE_BYTES:
                raise ReviewedExportError('Support artifact exceeds size limit')
        run, invocation, basis = _validate(blobs, secret)
        if source.name != str(run.run_id) or source.parent.name != run.case_id:
            raise ReviewedExportError("Source directory and run identities disagree")
        slug = safe_slug(run.case_id)
        manifest = {
            "snapshot_schema_version": "1.0", "phase": phase, "case_id": run.case_id,
            "safe_case_slug": slug, "run_id": str(run.run_id), "agent_role": role,
            "provider": invocation.provider, "model": invocation.model,
            "prompt_id": invocation.prompt_id, "prompt_version": invocation.prompt_version,
            "source_run_status": run.status, "human_accepted": True,
            "context_sha256": invocation.context_sha256, "context_hash_basis": basis,
            "files": [{"filename": name, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
                      for name, data in blobs.items()],
        }
        _safety(manifest, secret)
        if any(re.search(r"(?:^/|[A-Za-z]:[\\/]|/home/)", value)
               for value in manifest.values() if isinstance(value, str)):
            raise ReviewedExportError("Manifest must not contain absolute local paths")
        blobs["manifest.json"] = (json.dumps(manifest, indent=2, ensure_ascii=True) + "\n").encode()
    except ReviewedExportError:
        raise
    except Exception:
        raise ReviewedExportError("Snapshot validation or safety check failed; no export written") from None
    destination = reviewed_root / phase / slug / str(run.run_id)
    # Do not follow a symlink into another workspace during export.
    if any(p.is_symlink() for p in [destination, *destination.parents]):
        raise ReviewedExportError("Snapshot destination must not traverse symlinks")
    if destination.exists():
        raise ReviewedExportError("Reviewed snapshot already exists; overwrite refused")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(exist_ok=False)
    try:
        for name, data in blobs.items():
            with (destination / name).open("xb") as handle:
                handle.write(data)
    except Exception:
        shutil.rmtree(destination)  # only this call's newly created directory
        raise ReviewedExportError("Snapshot write failed; incomplete export removed") from None
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description="Export an accepted hardware or firmware run as an immutable reviewed snapshot")
    parser.add_argument("source", type=Path)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--accepted", action="store_true", help="Assert the run has been accepted for publication")
    parser.add_argument("--env-file", type=Path, help="Read key only for secret comparison; no network calls")
    args = parser.parse_args()
    try:
        result = export_reviewed_output(args.source, phase=args.phase, accepted=args.accepted, env_file=args.env_file)
    except (ReviewedExportError, OSError):
        print("Reviewed export refused; validation, safety or destination checks failed.")
        return 1
    print(f"Reviewed snapshot written: {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
