"""Explicit supported Hardware context, preserving the frozen B.1 JSON string."""
from typing import Literal

from chipchain.agents.context import hardware_context
from chipchain.agents.contracts import HardwareAgentInput
from chipchain.domain.common import Contract, Identifier, Sha256
from chipchain.tools.hardware.relation_builder import build_hardware_relation_catalog
from chipchain.tools.hardware.relations import canonical_json, sha256_text, hardware_relation_catalog_sha256
from chipchain.agents.projections.hardware_relations import (
    HardwareRelationProjection, validate_hardware_relation_projection, hardware_relation_projection_sha256,
)

MAX_HARDWARE_B2_CONTEXT_CHARS = 64000


class HardwareEnvelopeBindings(Contract):
    case_id: Identifier
    b1_context_sha256: Sha256
    a3_catalog_sha256: Sha256
    relation_projection_sha256: Sha256
    relation_projection_version: Literal['hardware-relation-projection/v1'] = 'hardware-relation-projection/v1'


class HardwareAnalysisEnvelopeV2(Contract):
    schema_version: Literal['hardware-analysis-envelope/v2'] = 'hardware-analysis-envelope/v2'
    bindings: HardwareEnvelopeBindings
    # JSON string preserves exact legacy bytes rather than silently reserializing.
    b1_context: str
    relation_projection: HardwareRelationProjection


def build_hardware_envelope(inputs: HardwareAgentInput, catalog, projection) -> HardwareAnalysisEnvelopeV2:
    rebuilt = build_hardware_relation_catalog(inputs, projection_descriptor=catalog.source.operational_projection)
    if hardware_relation_catalog_sha256(rebuilt) != hardware_relation_catalog_sha256(catalog):
        raise ValueError('Hardware input/catalog identity mismatch')
    validate_hardware_relation_projection(projection, catalog)
    context = hardware_context(inputs)
    envelope = HardwareAnalysisEnvelopeV2(
        bindings=HardwareEnvelopeBindings(case_id=inputs.case.case_id,
            b1_context_sha256=sha256_text(context), a3_catalog_sha256=hardware_relation_catalog_sha256(catalog),
            relation_projection_sha256=hardware_relation_projection_sha256(projection)),
        b1_context=context, relation_projection=projection,
    )
    serialize_hardware_envelope(envelope)
    return envelope


def serialize_hardware_envelope(envelope: HardwareAnalysisEnvelopeV2) -> str:
    e = HardwareAnalysisEnvelopeV2.model_validate_json(envelope.model_dump_json())
    if (e.bindings.b1_context_sha256 != sha256_text(e.b1_context)
        or e.bindings.case_id != e.relation_projection.case_id
        or e.bindings.a3_catalog_sha256 != e.relation_projection.catalog_sha256
        or e.bindings.relation_projection_sha256 != hardware_relation_projection_sha256(e.relation_projection)):
        raise ValueError('Hardware envelope binding mismatch')
    text = canonical_json(e.model_dump(mode='json'))
    if len(text) > MAX_HARDWARE_B2_CONTEXT_CHARS:
        raise ValueError('Hardware B2 envelope exceeds hard cap')
    return text
