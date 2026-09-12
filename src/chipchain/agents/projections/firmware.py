"""Firmware analysis projection v1: neutral identities and exact evidence catalogs."""

import hashlib
import json
import re
from typing import Literal

from pydantic import Field, JsonValue

from chipchain.agents.context import MAX_CONTEXT_CHARS, MAX_CONTEXT_ITEMS
from chipchain.agents.contracts import FirmwareAgentInput
from chipchain.agents.firmware_evidence import collect_firmware_evidence
from chipchain.agents.runtime import AgentExecutionError
from chipchain.domain.behavior import ProcessorBehavior
from chipchain.domain.case import ArtifactType, TargetDescriptor
from chipchain.domain.common import Contract, EpistemicStatus, Metadata
from chipchain.domain.evidence import EvidenceRef
from chipchain.domain.instruction import DecodedInstruction
from chipchain.tools.contracts import (
    FirmwareObservation, InterruptTriggerDetails, MmioModelDetails, ObservationScope,
    OpaqueInputDetails, StaticInstructionSiteDetails,
)

PROJECTION_VERSION = "firmware-analysis-projection/v1"
# Closed neutral namespaces, not a claim that arbitrary caller names are safe.
# Exact EvidenceRefs prevent remapping artifact IDs here. Callers must assign
# neutral IDs when constructing canonical inputs, before evidence generation.
NEUTRAL_ARTIFACT_ID = re.compile(
    r"(?:(?:elf|bin|yaml|opaque)(?:[-_:][0-9]+)?|"
    r"(?:artifact|fw-artifact|firmware-artifact)[-_:][0-9]+|"
    r"synthetic:firmware:artifact(?:[-_:][0-9]+)?)\Z"
)
# A secondary content guard, not the projection's field allowlist. Exact evidence
# containing these cannot be sanitized without breaking grounding: reject it.
REFERENCE_MARKERS = ("cve-", "known root cause", "expected crash", "exploitability",
                     "crash-analysis", "crashing_input")


class ProjectedArtifact(Contract):
    artifact_id: str
    artifact_type: ArtifactType
    format: str


class ProjectedCase(Contract):
    case_id: str
    target: TargetDescriptor


class ProjectedObservation(Contract):
    observation_id: str
    kind: str
    scope: ObservationScope
    epistemic_status: EpistemicStatus
    summary: str | None = None
    details: dict[str, JsonValue] = Field(default_factory=dict)
    evidence_ids: list[str]
    behavior_ids: list[str]


class ProjectedBehavior(Contract):
    behavior_id: str
    kind: str
    summary: str
    epistemic_status: EpistemicStatus
    attributes: Metadata
    architecture: str | None = None
    evidence_ids: list[str]
    decoded_instruction: dict[str, JsonValue] | None = None


class FirmwareAnalysisProjection(Contract):
    projection_version: Literal["firmware-analysis-projection/v1"] = PROJECTION_VERSION
    case: ProjectedCase
    artifacts: list[ProjectedArtifact] = Field(max_length=MAX_CONTEXT_ITEMS)
    evidence_catalog: list[EvidenceRef] = Field(max_length=MAX_CONTEXT_ITEMS)
    observations: list[ProjectedObservation] = Field(max_length=MAX_CONTEXT_ITEMS)
    behaviors: list[ProjectedBehavior] = Field(max_length=MAX_CONTEXT_ITEMS)
    unresolved_questions: list[str] = Field(max_length=MAX_CONTEXT_ITEMS)


def _ids(refs: list[EvidenceRef]) -> list[str]:
    return sorted({ref.evidence_id for ref in refs})


def _decoded(decoded: DecodedInstruction) -> dict:
    # Keep the instruction interpretation once. Backend text, structured operands,
    # repeated observation identity and tool provenance stay in canonical state.
    fields = ("status", "reason", "raw_encoding", "instruction_width_bits", "representation",
              "mnemonic", "operand_text", "decoder_mode")
    data = decoded.model_dump(mode="json", include=set(fields), exclude_none=True)
    data["evidence_ids"] = _ids(decoded.evidence)
    return data


def _details(observation: FirmwareObservation) -> dict:
    d = observation.details
    if isinstance(d, StaticInstructionSiteDetails):
        data = {"address": d.address, "function": d.function}
        # Equivalent byte/width/mode facts live on the referenced instruction.
        # If a caller supplied different facts, retain both rather than erase the
        # disagreement or make sensitivity depend on which copy was selected.
        decodes = [b.decoded_instruction for b in observation.behaviors if b.decoded_instruction is not None]
        for field, value, decoded_field in (
            ("raw_bytes", d.raw_bytes, "raw_encoding"),
            ("width_bits", d.width_bits, "instruction_width_bits"),
            ("representation", d.representation.value, "representation"),
            ("isa_mode", d.isa_mode, "decoder_mode"),
        ):
            if not decodes or any(getattr(dec, decoded_field) != value for dec in decodes):
                data[field] = value
        return {k: v for k, v in data.items() if v is not None}
    if isinstance(d, MmioModelDetails):
        return {"pc": d.pc, "mmio_address": d.mmio_address, "access_size_bytes": d.access_size_bytes,
                "model_kind": d.model_kind.value, "parameters": d.model_dump(mode="json")["parameters"]}
    if isinstance(d, OpaqueInputDetails):
        # Hash retained once: distinguishes input identities of the same length.
        return {"input_kind": "opaque", "artifact_id": d.artifact_id,
                "size_bytes": d.size_bytes, "sha256": d.sha256}
    if isinstance(d, InterruptTriggerDetails):
        return {"input_kind": "interrupt_trigger", "every_nth_tick": d.every_nth_tick,
                "fuzz_mode": d.fuzz_mode, "tick_unit": d.tick_unit}
    raise AgentExecutionError("Unsupported firmware projection details")


def _check_neutral_strings(value) -> None:
    if isinstance(value, str):
        lowered = value.casefold()
        if "/" in value or "\\" in value or any(marker in lowered for marker in REFERENCE_MARKERS):
            raise AgentExecutionError("Firmware projection contains path-like or benchmark reference content")
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_neutral_strings(key)
            _check_neutral_strings(item)
    elif isinstance(value, list):
        for item in value:
            _check_neutral_strings(item)


def _validate_projection(projection: FirmwareAnalysisProjection) -> None:
    catalogs = (projection.artifacts, projection.evidence_catalog, projection.observations, projection.behaviors)
    keys = ("artifact_id", "evidence_id", "observation_id", "behavior_id")
    for catalog, key in zip(catalogs, keys):
        if len(catalog) > MAX_CONTEXT_ITEMS or len({getattr(item, key) for item in catalog}) != len(catalog):
            raise AgentExecutionError("Firmware projection catalog has duplicate IDs or exceeds item limit")
    if len(projection.unresolved_questions) > MAX_CONTEXT_ITEMS:
        raise AgentExecutionError("Firmware questions exceed item limit")
    for artifact in projection.artifacts:
        if not NEUTRAL_ARTIFACT_ID.fullmatch(artifact.artifact_id):
            raise AgentExecutionError("Firmware projection requires neutral artifact IDs")
    artifacts = {a.artifact_id for a in projection.artifacts}
    evidence = {e.evidence_id for e in projection.evidence_catalog}
    behaviors = {b.behavior_id for b in projection.behaviors}
    if any(e.artifact_id not in artifacts for e in projection.evidence_catalog):
        raise AgentExecutionError("Firmware projection has unresolved artifact references")
    for observation in projection.observations:
        if not set(observation.evidence_ids) <= evidence or not set(observation.behavior_ids) <= behaviors:
            raise AgentExecutionError("Firmware projection has unresolved observation references")
    for behavior in projection.behaviors:
        refs = list(behavior.evidence_ids)
        if behavior.decoded_instruction is not None:
            refs.extend(behavior.decoded_instruction["evidence_ids"])
        if not set(refs) <= evidence:
            raise AgentExecutionError("Firmware projection has unresolved behavior evidence")
    data = projection.model_dump(mode="json", exclude_none=True)
    data.pop("projection_version")  # Fixed descriptor contains '/', no input-derived content.
    _check_neutral_strings(data)


def build_firmware_analysis_projection(inputs: FirmwareAgentInput) -> FirmwareAnalysisProjection:
    """No IO or mutation. Every canonical observation/behavior/evidence ID remains."""
    batch = inputs.deterministic_observations
    if any(len(items) > MAX_CONTEXT_ITEMS for items in (
        inputs.case.firmware_artifacts, batch.observations, batch.unresolved_questions,
    )):
        raise AgentExecutionError("Firmware context exceeds item limit")
    evidence = collect_firmware_evidence(inputs)
    if len(evidence) > MAX_CONTEXT_ITEMS:
        raise AgentExecutionError("Firmware evidence catalog exceeds item limit")
    canonical_behaviors: dict[str, ProcessorBehavior] = {}
    for observation in batch.observations:
        for behavior in observation.behaviors:
            if behavior.behavior_id in canonical_behaviors:
                raise AgentExecutionError("Duplicate canonical firmware behavior ID")
            canonical_behaviors[behavior.behavior_id] = behavior
            if len(canonical_behaviors) > MAX_CONTEXT_ITEMS:
                raise AgentExecutionError("Firmware behavior catalog exceeds item limit")
    observations = []
    for observation in sorted(batch.observations, key=lambda o: o.observation_id):
        typed = isinstance(observation, FirmwareObservation)
        observations.append(ProjectedObservation(
            observation_id=observation.observation_id, kind=observation.kind.value if typed else "generic",
            scope=observation.scope if typed else ObservationScope.UNKNOWN,
            epistemic_status=observation.epistemic_status,
            # A1 typed summaries repeat the kind's meaning; generic summaries can
            # carry the only operational fact and are retained without rewriting.
            summary=None if typed and observation.summary in {
                "Confirmed Thumb site", "MMIO model configuration",
                "Opaque environment input artifact", "Configured environment trigger",
            } else observation.summary,
            details=_details(observation) if typed else {}, evidence_ids=_ids(observation.evidence),
            behavior_ids=sorted(b.behavior_id for b in observation.behaviors),
        ))
    behaviors = []
    for identifier, behavior in sorted(canonical_behaviors.items()):
        attributes = dict(behavior.attributes)
        # Remove only equal facts already held by every referencing observation.
        owners = [o for o in batch.observations if any(b.behavior_id == identifier for b in o.behaviors)]
        for key in tuple(attributes):
            duplicate = all(isinstance(o, FirmwareObservation) and (
                (key == "evidence_scope" and attributes[key] == o.scope.value) or
                (isinstance(o.details, MmioModelDetails) and key in ("pc", "mmio_address", "access_size_bytes")
                 and attributes[key] == getattr(o.details, key))
            ) for o in owners)
            if duplicate:
                del attributes[key]
        behaviors.append(ProjectedBehavior(
            behavior_id=identifier, kind=behavior.kind.value, summary=behavior.summary,
            epistemic_status=behavior.epistemic_status, attributes=attributes, evidence_ids=_ids(behavior.evidence),
            architecture=behavior.architecture.value if behavior.architecture != inputs.case.target.architecture else None,
            decoded_instruction=_decoded(behavior.decoded_instruction) if behavior.decoded_instruction is not None else None,
        ))
    projection = FirmwareAnalysisProjection(
        case=ProjectedCase(case_id=inputs.case.case_id, target=inputs.case.target.model_copy(deep=True)),
        artifacts=[ProjectedArtifact(artifact_id=a.artifact_id, artifact_type=a.artifact_type, format=a.format)
                   for a in sorted(inputs.case.firmware_artifacts, key=lambda a: a.artifact_id)],
        evidence_catalog=list(evidence.values()), observations=observations, behaviors=behaviors,
        unresolved_questions=list(batch.unresolved_questions),
    )
    _validate_projection(projection)
    return projection


def serialize_firmware_analysis_projection(projection: FirmwareAnalysisProjection) -> str:
    _validate_projection(projection)
    text = json.dumps(projection.model_dump(mode="json", exclude_none=True),
                      ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(text) > MAX_CONTEXT_CHARS:
        raise AgentExecutionError("Firmware context exceeds the 64000-character limit")
    return text


def firmware_projection_sha256(projection: FirmwareAnalysisProjection) -> str:
    """Hash exactly the UTF-8 JSON sent as firmware human-message content."""
    return hashlib.sha256(serialize_firmware_analysis_projection(projection).encode("utf-8")).hexdigest()
