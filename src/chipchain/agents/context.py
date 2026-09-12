"""Explicit model context projections; reject oversize inputs without truncation."""

import json

from pydantic import BaseModel, Field

from chipchain.agents.contracts import CrossLayerAgentInput, FirmwareAgentInput, HardwareAgentInput
from chipchain.agents.runtime import AgentExecutionError
from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.case import ArtifactRef, ArtifactType, CaseBundle, TargetDescriptor
from chipchain.domain.firmware import FirmwareAnalysisReport
from chipchain.domain.hardware import HardwareAnalysisReport
from chipchain.graphs.contracts import BehaviorGraphContext, RetrievedKnowledgeContext
from chipchain.tools.contracts import DeterministicObservation, FirmwareObservation, HardwareObservation

MAX_CONTEXT_ITEMS = 128
MAX_CONTEXT_CHARS = 64_000


class _CaseIdentity(BaseModel):
    case_id: str
    name: str
    target: TargetDescriptor
    synthetic: bool | None = None


class _ArtifactProvenance(BaseModel):
    artifact_id: str
    artifact_type: ArtifactType
    path: str
    format: str


class _SideContext(BaseModel):
    case: _CaseIdentity
    artifacts: list[_ArtifactProvenance] = Field(max_length=MAX_CONTEXT_ITEMS)
    observations: list[HardwareObservation | FirmwareObservation | DeterministicObservation] = Field(max_length=MAX_CONTEXT_ITEMS)
    unresolved_questions: list[str] = Field(max_length=MAX_CONTEXT_ITEMS)


class _CrossLayerContext(BaseModel):
    case: _CaseIdentity
    hardware_report: HardwareAnalysisReport
    firmware_report: FirmwareAnalysisReport
    processor_behavior_ir: ProcessorBehaviorIR
    behavior_graph_context: BehaviorGraphContext | None = None
    retrieved_knowledge_context: RetrievedKnowledgeContext | None = None


def _case_identity(case: CaseBundle) -> _CaseIdentity:
    synthetic = case.metadata.get("synthetic")
    return _CaseIdentity(
        case_id=case.case_id, name=case.name, target=case.target,
        synthetic=synthetic if isinstance(synthetic, bool) else None,
    )


def _serialize(context: BaseModel, *, compact_firmware_evidence: bool = False) -> str:
    if compact_firmware_evidence:
        data = context.model_dump(mode="json", exclude_none=True)
        # Full evidence stays on observations. Only identical nested copies are
        # replaced by IDs, resolvable across this same context's observations.
        refs = {}
        for observation in data["observations"]:
            for ref in observation["evidence"]:
                key = ref["evidence_id"]
                if key in refs and refs[key] != ref:
                    raise AgentExecutionError("Conflicting firmware evidence IDs")
                refs[key] = ref
        for observation in data["observations"]:
            if "scope" not in observation:
                continue  # Preserve existing generic firmware context structure.
            for behavior in observation["behaviors"]:
                for item in (behavior, behavior.get("decoded_instruction")):
                    if item is not None and item.get("evidence") and all(
                        refs.get(ref["evidence_id"]) == ref for ref in item["evidence"]
                    ):
                        item["evidence_ids"] = [ref["evidence_id"] for ref in item.pop("evidence")]
        serialized = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    else:
        serialized = context.model_dump_json(exclude_none=True)
    if len(serialized) > MAX_CONTEXT_CHARS:
        raise AgentExecutionError("Model context exceeds the 64000-character limit")
    return serialized


def _side_context(
    case: CaseBundle, artifacts: list[ArtifactRef], observations: list[DeterministicObservation],
    unresolved_questions: list[str], *, compact_firmware_evidence: bool = False,
) -> str:
    try:
        # Check top-level sizes before copying large input collections.
        if any(len(items) > MAX_CONTEXT_ITEMS for items in (artifacts, observations, unresolved_questions)):
            raise ValueError("Too many context items")
        return _serialize(_SideContext(
            case=_case_identity(case),
            artifacts=[_ArtifactProvenance(
                artifact_id=a.artifact_id, artifact_type=a.artifact_type, path=a.path, format=a.format,
            ) for a in artifacts],
            observations=observations, unresolved_questions=unresolved_questions,
        ), compact_firmware_evidence=compact_firmware_evidence)
    except ValueError as exc:
        raise AgentExecutionError("Model context failed construction or exceeds item limits") from exc


def hardware_context(inputs: HardwareAgentInput) -> str:
    batch = inputs.deterministic_observations
    return _side_context(inputs.case, inputs.case.hardware_artifacts, batch.observations, batch.unresolved_questions)


def firmware_context(inputs: FirmwareAgentInput) -> str:
    batch = inputs.deterministic_observations
    return _side_context(inputs.case, inputs.case.firmware_artifacts, batch.observations,
                         batch.unresolved_questions, compact_firmware_evidence=True)


def cross_layer_context(inputs: CrossLayerAgentInput) -> str:
    return _serialize(_CrossLayerContext(
        case=_case_identity(inputs.case), hardware_report=inputs.hardware_report,
        firmware_report=inputs.firmware_report, processor_behavior_ir=inputs.processor_behavior_ir,
        behavior_graph_context=inputs.behavior_graph_context,
        retrieved_knowledge_context=inputs.retrieved_knowledge_context,
    ))
