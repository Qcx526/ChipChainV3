"""Bounded, lossless-for-support Hardware A3 projection; no artifact reads."""
from typing import Annotated, Literal

from pydantic import Field

from chipchain.domain.common import Contract, Identifier, Sha256
from chipchain.domain.evidence import EvidenceTime
from chipchain.domain.instruction import DecodeStatus, EncodingRepresentation
from chipchain.domain.provenance import ToolDescriptor
from chipchain.tools.hardware.relations import (
    HardwareRelationCatalog, HardwareRelationKind, HardwareRelationCapabilities,
    InstructionAttributes, LocalDifferenceAttributes, RegisterDifferenceAttributes,
    FormalCoverAttributes, FormalErrorAttributes, canonical_json, sha256_text,
    hardware_relation_catalog_sha256, parse_hardware_relation_catalog, serialize_hardware_relation_catalog,
)

VERSION = 'hardware-relation-projection/v1'
MAX_HARDWARE_RELATION_CHARS = 20000


class CompactDecode(Contract):
    status: DecodeStatus
    mnemonic: Identifier | None
    operand_text: str | None = Field(max_length=1024)
    instruction_width_bits: int = Field(gt=0, strict=True)
    decoder: ToolDescriptor


class CompactInstruction(Contract):
    kind: Literal[HardwareRelationKind.INSTRUCTION] = HardwareRelationKind.INSTRUCTION
    time: EvidenceTime
    stage: Literal['id'] = 'id'
    signal_id: Identifier
    encoding_bits: str = Field(pattern=r'^[01xz]+$')
    encoding_width_bits: int = Field(gt=0, strict=True)
    encoding_representation: EncodingRepresentation
    decoded_instruction: CompactDecode | None


class CompactCover(Contract):
    kind: Literal[HardwareRelationKind.COVER] = HardwareRelationKind.COVER
    property_name: Identifier
    cycles: int = Field(ge=0, strict=True)
    interpretation_boundary: str = Field(min_length=1, max_length=8192)


class CompactError(Contract):
    kind: Literal[HardwareRelationKind.ERROR] = HardwareRelationKind.ERROR
    error_code: Identifier
    interpretation_boundary: str = Field(min_length=1, max_length=8192)


CompactAttributes = Annotated[
    CompactInstruction | LocalDifferenceAttributes | RegisterDifferenceAttributes | CompactCover | CompactError,
    Field(discriminator='kind'),
]


class HardwareRelationRow(Contract):
    relation_id: Identifier
    kind: HardwareRelationKind
    status: Literal['observed', 'derived']
    source_observation_id: Identifier
    evidence_ids: list[Identifier]
    attributes: CompactAttributes
    # Every absent key inherits the explicit false default in the projection.
    capabilities: dict[str, Literal[True]]


class HardwareRelationProjection(Contract):
    schema_version: Literal[VERSION] = VERSION
    case_id: Identifier
    catalog_sha256: Sha256
    capability_defaults: HardwareRelationCapabilities
    relations: list[HardwareRelationRow]


def compact_attributes(attributes) -> CompactAttributes:
    data = attributes.model_dump(mode='json')
    if isinstance(attributes, InstructionAttributes):
        d = data['decoded_instruction']
        if d is not None:
            data['decoded_instruction'] = {k: d[k] for k in CompactDecode.model_fields}
        return CompactInstruction.model_validate(data)
    if isinstance(attributes, (FormalCoverAttributes, FormalErrorAttributes)):
        del data['raw_result']
        return (CompactCover if isinstance(attributes, FormalCoverAttributes) else CompactError).model_validate(data)
    return type(attributes).model_validate(data)


def build_hardware_relation_projection(catalog: HardwareRelationCatalog) -> HardwareRelationProjection:
    catalog = parse_hardware_relation_catalog(serialize_hardware_relation_catalog(catalog))
    projection = HardwareRelationProjection(
        case_id=catalog.source.case_id, catalog_sha256=hardware_relation_catalog_sha256(catalog),
        capability_defaults=HardwareRelationCapabilities(),
        relations=[HardwareRelationRow(
            relation_id=r.relation_id, kind=r.kind, status=r.status,
            source_observation_id=r.source_observation_id, evidence_ids=r.evidence_ids,
            attributes=compact_attributes(r.attributes),
            capabilities={k: v for k, v in r.capabilities.model_dump().items() if v},
        ) for r in catalog.relations],
    )
    serialize_hardware_relation_projection(projection)
    return projection


def serialize_hardware_relation_projection(projection: HardwareRelationProjection) -> str:
    projection = HardwareRelationProjection.model_validate_json(projection.model_dump_json())
    text = canonical_json(projection.model_dump(mode='json'))
    if len(text) > MAX_HARDWARE_RELATION_CHARS:
        raise ValueError('Hardware relation projection exceeds hard cap')
    return text


def hardware_relation_projection_sha256(projection: HardwareRelationProjection) -> str:
    return sha256_text(serialize_hardware_relation_projection(projection))


def validate_hardware_relation_projection(projection, catalog):
    if serialize_hardware_relation_projection(projection) != serialize_hardware_relation_projection(build_hardware_relation_projection(catalog)):
        raise ValueError('Hardware relation projection identity mismatch')
    return projection
