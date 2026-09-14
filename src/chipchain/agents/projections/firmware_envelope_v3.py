"""Explicit B3 envelope. Frozen A1 bytes plus lossless compact typed A4 semantics."""
import json
from collections import Counter
from typing import Literal
from pydantic import JsonValue
from chipchain.domain.common import Contract, Sha256
from chipchain.domain.provenance import ToolDescriptor
from chipchain.agents.context import MAX_CONTEXT_CHARS
from chipchain.agents.projections.firmware import FirmwareAnalysisProjection, build_firmware_analysis_projection, serialize_firmware_analysis_projection
from chipchain.agents.projections.firmware_envelope import compact, digest, neutral
from chipchain.agents.projections.firmware_relations import (
    serialize_firmware_relation_projection, parse_firmware_relation_projection, projection_registry,
)

VERSION = 'firmware-analysis-envelope/v3'
MAX_V3_CHARS = 58000
ENVELOPE_DESCRIPTOR = ToolDescriptor(tool_name='firmware-analysis-envelope',tool_version='v3',tool_role='model_context_projection')
RELATION_DESCRIPTOR = ToolDescriptor(tool_name='firmware-relation-projection',tool_version='v1',tool_role='model_context_projection')
CATALOG_DESCRIPTOR = ToolDescriptor(tool_name='firmware-static-relations',tool_version='v1',tool_role='deterministic_relations')


class SourceBinding(Contract):
    catalog_version: Literal['firmware-static-relations/v1'] = 'firmware-static-relations/v1'
    catalog_sha256: Sha256


class FirmwareAnalysisEnvelopeV3(Contract):
    envelope_version: Literal['firmware-analysis-envelope/v3'] = VERSION
    base_firmware_projection: dict[str,JsonValue]
    typed_relation_projection: dict[str,JsonValue]
    source_binding: SourceBinding


def envelope_v3_components(envelope):
    base = FirmwareAnalysisProjection.model_validate(envelope.base_firmware_projection)
    if serialize_firmware_analysis_projection(base) != compact(envelope.base_firmware_projection):
        raise ValueError('Noncanonical A1 component')
    projection = parse_firmware_relation_projection(compact(envelope.typed_relation_projection),base=base)
    if projection.catalog_sha256 != envelope.source_binding.catalog_sha256:
        raise ValueError('Envelope A4 identity mismatch')
    identity = projection.catalog.source_identities
    elf = next((a for a in base.artifacts if a.artifact_id == identity.elf_artifact_id),None)
    if elf is None:
        raise ValueError('Envelope ELF identity mismatch')
    return base,projection,projection_registry(projection,base)


def serialize_firmware_envelope_v3(envelope):
    envelope_v3_components(envelope)
    value = envelope.model_dump(mode='json')
    neutral(value)
    text = compact(value)
    if len(text)>MAX_V3_CHARS or len(text)>MAX_CONTEXT_CHARS:
        raise ValueError('Envelope v3 exceeds character budget')
    return text


def parse_firmware_envelope_v3(text):
    envelope = FirmwareAnalysisEnvelopeV3.model_validate_json(text)
    if serialize_firmware_envelope_v3(envelope) != text:
        raise ValueError('Noncanonical envelope v3')
    return envelope


def build_firmware_envelope_v3(inputs, projection, *, static_relation_catalog):
    from chipchain.tools.firmware.relations import serialize_firmware_static_relations
    if serialize_firmware_static_relations(projection.catalog) != serialize_firmware_static_relations(static_relation_catalog):
        raise ValueError('Projection differs from canonical A4')
    identity = static_relation_catalog.source_identities
    artifact = next((a for a in inputs.case.firmware_artifacts if a.artifact_id == identity.elf_artifact_id),None)
    if artifact is None or (artifact.sha256,artifact.size_bytes) != (identity.elf_sha256,identity.elf_size_bytes):
        raise ValueError('A4 ELF fingerprint differs from canonical inputs')
    envelope = FirmwareAnalysisEnvelopeV3(
        base_firmware_projection=json.loads(serialize_firmware_analysis_projection(build_firmware_analysis_projection(inputs))),
        typed_relation_projection=json.loads(serialize_firmware_relation_projection(projection)),
        source_binding=SourceBinding(catalog_sha256=projection.catalog_sha256))
    serialize_firmware_envelope_v3(envelope)
    return envelope


def envelope_v3_metadata(envelope):
    base,p,registry = envelope_v3_components(envelope)
    base_text = serialize_firmware_analysis_projection(base)
    relation_text = serialize_firmware_relation_projection(p)
    return dict(context_mode='relation_v3',envelope_version=VERSION,
        base_projection_version=base.projection_version,base_projection_sha256=digest(base_text),base_projection_characters=len(base_text),
        relation_projection_version=p.projection_version,relation_projection_sha256=digest(relation_text),relation_projection_characters=len(relation_text),
        a4_catalog_version=p.catalog.schema_version,a4_catalog_sha256=p.catalog_sha256,
        a4_relation_counts=dict(sorted(Counter(r.kind.value for r in p.catalog.relations).items())),
        a4_relation_count=len(p.catalog.relations),merged_evidence_count=len(registry),
        relation_evidence_delta_count=len(p.evidence_delta))
