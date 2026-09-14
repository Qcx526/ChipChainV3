"""Versioned context container; frozen A1/A3 components retain exact wire identity."""
import hashlib
import json
from typing import Literal

from pydantic import JsonValue

from chipchain.agents.context import MAX_CONTEXT_CHARS
from chipchain.agents.contracts import FirmwareAgentInput
from chipchain.agents.firmware_evidence import merge_reasoning_evidence
from chipchain.agents.projections.firmware import (
    FirmwareAnalysisProjection, build_firmware_analysis_projection, serialize_firmware_analysis_projection,
)
from chipchain.domain.common import Contract, Sha256
from chipchain.domain.provenance import ToolDescriptor
from chipchain.tools.firmware.ghidra.models import GhidraStaticStructureResult
from chipchain.tools.firmware.structure_projection import (
    FirmwareRelevantStaticStructure, parse_relevant_static_structure, serialize_relevant_static_structure, _hash,
)

ENVELOPE_VERSION = 'firmware-analysis-envelope/v2'
MAX_ENRICHED_CONTEXT_CHARS = 58000
ENVELOPE_DESCRIPTOR = ToolDescriptor(tool_name='firmware-analysis-envelope', tool_version='v2', tool_role='model_context_projection')
STRUCTURE_DESCRIPTOR = ToolDescriptor(tool_name='firmware-relevant-static-structure', tool_version='v1', tool_role='model_context_projection')


class StaticSourceBinding(Contract):
    """Provenance link absent from frozen A3 wire; checked against full A2 before send."""
    artifact_id: str
    sha256: Sha256
    size_bytes: int
    source_structure_sha256: Sha256


class FirmwareAnalysisEnvelopeV2(Contract):
    envelope_version: Literal['firmware-analysis-envelope/v2'] = ENVELOPE_VERSION
    firmware_projection: dict[str, JsonValue]
    relevant_static_structure: dict[str, JsonValue]
    static_source_binding: StaticSourceBinding


def compact(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def neutral(value) -> None:
    # Version/tool IDs legitimately contain '/'; only path/oracle content is rejected.
    if isinstance(value, dict):
        for key, child in value.items(): neutral(key); neutral(child)
    elif isinstance(value, list):
        for child in value: neutral(child)
    elif isinstance(value, str):
        low=value.casefold()
        if (value.startswith(('/', '~', 'file:')) or '\\' in value or
            any(x in low for x in ('/home/', '04-crash-analysis', 'crashing_input', 'readme', 'cve',
                                  'known root cause', 'expected crash', 'exploitability'))):
            raise ValueError('Envelope contains path or oracle content')


def envelope_components(envelope: FirmwareAnalysisEnvelopeV2):
    base=FirmwareAnalysisProjection.model_validate(envelope.firmware_projection)
    base_text=serialize_firmware_analysis_projection(base)
    if compact(envelope.firmware_projection)!=base_text:
        raise ValueError('Noncanonical frozen base component')
    static_text=compact(envelope.relevant_static_structure)
    relevant=parse_relevant_static_structure(static_text)
    if base.case.case_id!=relevant.case_id:
        raise ValueError('Envelope component case mismatch')
    binding=envelope.static_source_binding
    if (binding.source_structure_sha256!=relevant.source_structure.structure_sha256 or
        binding.artifact_id not in {a.artifact_id for a in base.artifacts}):
        raise ValueError('Envelope source binding mismatch')
    registry=merge_reasoning_evidence({r.evidence_id:r for r in base.evidence_catalog}, relevant,
        case_id=base.case.case_id, artifact_ids={a.artifact_id for a in base.artifacts})
    # A3 site references must resolve into this A1 component, never a different run's sites.
    observations={o.observation_id:o for o in base.observations}
    behaviors={b.behavior_id:b for b in base.behaviors}
    for site in relevant.mmio_sites:
        observation=observations.get(site.static_instruction_observation_id)
        if observation is None or observation.details.get('address')!=site.pc:
            raise ValueError('A3 site does not match base observation')
        if any(bid not in behaviors for bid in site.mmio_behavior_ids):
            raise ValueError('A3 references unknown base behavior')
    neutral(envelope.model_dump(mode='json'))
    return base,relevant,registry


def serialize_firmware_envelope(envelope: FirmwareAnalysisEnvelopeV2) -> str:
    envelope_components(envelope)
    text=compact(envelope.model_dump(mode='json'))
    if len(text)>MAX_CONTEXT_CHARS or len(text)>MAX_ENRICHED_CONTEXT_CHARS:
        raise ValueError('Enriched context exceeds character budget')
    return text


def parse_firmware_envelope(text: str) -> FirmwareAnalysisEnvelopeV2:
    def pairs(items):
        result={}
        for k,v in items:
            if k in result: raise ValueError('Duplicate envelope JSON key')
            result[k]=v
        return result
    envelope=FirmwareAnalysisEnvelopeV2.model_validate(json.loads(text,object_pairs_hook=pairs))
    if serialize_firmware_envelope(envelope)!=text:
        raise ValueError('Noncanonical envelope JSON')
    return envelope


def build_firmware_envelope(inputs: FirmwareAgentInput, relevant: FirmwareRelevantStaticStructure,
                            source: GhidraStaticStructureResult) -> FirmwareAnalysisEnvelopeV2:
    if not isinstance(source,GhidraStaticStructureResult):
        raise ValueError('Enriched context requires the canonical A2 source')
    if source.case_id!=inputs.case.case_id or _hash(source.model_dump(mode='json'))!=relevant.source_structure.structure_sha256:
        raise ValueError('A3/full A2 source identity mismatch')
    artifact=next((a for a in inputs.case.firmware_artifacts if a.artifact_id==source.program.artifact_id),None)
    if artifact is None or (artifact.sha256,artifact.size_bytes)!=(source.program.sha256,source.program.size_bytes):
        raise ValueError('A1/A2 ELF identity mismatch')
    envelope=FirmwareAnalysisEnvelopeV2(
        firmware_projection=json.loads(serialize_firmware_analysis_projection(build_firmware_analysis_projection(inputs))),
        relevant_static_structure=json.loads(serialize_relevant_static_structure(relevant)),
        static_source_binding=StaticSourceBinding(artifact_id=artifact.artifact_id,sha256=artifact.sha256,
            size_bytes=artifact.size_bytes,source_structure_sha256=relevant.source_structure.structure_sha256))
    serialize_firmware_envelope(envelope)
    return envelope


def firmware_enriched_context(inputs, relevant_static_structure, *, static_source) -> str:
    return serialize_firmware_envelope(build_firmware_envelope(inputs,relevant_static_structure,static_source))


def firmware_envelope_sha256(envelope) -> str:
    return digest(serialize_firmware_envelope(envelope))


def envelope_metadata(envelope) -> dict:
    base,relevant,registry=envelope_components(envelope)
    base_text=serialize_firmware_analysis_projection(base)
    static_text=serialize_relevant_static_structure(relevant)
    return dict(context_mode='enriched_v2',envelope_version=ENVELOPE_VERSION,
        base_projection_version=base.projection_version,base_projection_sha256=digest(base_text),base_projection_characters=len(base_text),
        relevant_structure_version=relevant.projection_version,relevant_structure_sha256=digest(static_text),relevant_structure_characters=len(static_text),
        a1_evidence_count=len(base.evidence_catalog),a3_evidence_count=len(relevant.evidence_catalog),
        evidence_overlap_count=len(base.evidence_catalog)+len(relevant.evidence_catalog)-len(registry),merged_evidence_count=len(registry))
