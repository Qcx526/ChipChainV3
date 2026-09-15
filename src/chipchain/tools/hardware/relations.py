"""Corpus-neutral point observations, without execution or causal semantics."""

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from chipchain.domain.common import Architecture, Contract, Identifier, Sha256
from chipchain.domain.evidence import BitRange, EvidenceTime
from chipchain.domain.instruction import DecodedInstruction, DecodeStatus, EncodingRepresentation
from chipchain.domain.provenance import ToolDescriptor

VERSION = "hardware-observation-relations/v1"
BoundedText = Annotated[str, Field(min_length=1, max_length=8192)]


class HardwareRelationKind(StrEnum):
    INSTRUCTION = "instruction_encoding_observed"
    LOCAL = "sampled_local_state_difference"
    REGISTER = "sampled_register_state_difference"
    COVER = "formal_cover_hit"
    ERROR = "formal_trace_error"


class InstructionAttributes(Contract):
    kind: Literal[HardwareRelationKind.INSTRUCTION] = HardwareRelationKind.INSTRUCTION
    time: EvidenceTime
    stage: Literal["id"] = "id"
    signal_id: Identifier
    encoding_bits: str = Field(pattern=r"^[01xz]+$")
    encoding_width_bits: int = Field(gt=0, strict=True)
    encoding_representation: EncodingRepresentation
    # Preserve the entire A2 result, including typed operands, evidence and descriptor.
    # Nested epistemic_status=derived does not promote the observed encoding.
    decoded_instruction: DecodedInstruction | None = None

    @model_validator(mode="after")
    def encoding_and_decode(self) -> Self:
        if len(self.encoding_bits) != self.encoding_width_bits:
            raise ValueError("Encoding width mismatch")
        d = self.decoded_instruction
        if d is not None:
            if d.instruction_width_bits != self.encoding_width_bits:
                raise ValueError("Decode width mismatch")
            if d.source_stage != self.stage or d.representation != self.encoding_representation:
                raise ValueError("Decode stage/representation mismatch")
            if d.status == DecodeStatus.DECODED:
                if any(c in self.encoding_bits for c in "xz") or int(d.raw_encoding, 16) != int(self.encoding_bits, 2):
                    raise ValueError("Decoded encoding mismatch")
            if not any(e.location.time == self.time and e.location.signal == self.signal_id for e in d.evidence):
                raise ValueError("Decode evidence does not identify this instruction sample")
        return self


class DifferenceAttributes(Contract):
    time: EvidenceTime
    host_signal: Identifier
    host_width: int = Field(gt=0, strict=True)
    host_bit_range: BitRange | None
    host_value: str = Field(pattern=r"^[01]+$")
    reference_signal: Identifier
    reference_width: int = Field(gt=0, strict=True)
    reference_bit_range: BitRange | None
    reference_value: str = Field(pattern=r"^[01]+$")

    @model_validator(mode="after")
    def paired_values(self) -> Self:
        for side in ("host", "reference"):
            width = getattr(self, side + "_width")
            bits = getattr(self, side + "_bit_range")
            if len(getattr(self, side + "_value")) != width or (bits and bits.msb - bits.lsb + 1 != width):
                raise ValueError("Difference width/bit range mismatch")
        if self.host_width != self.reference_width or self.host_value == self.reference_value:
            raise ValueError("Difference requires unequal paired values of equal width")
        return self


class LocalDifferenceAttributes(DifferenceAttributes):
    kind: Literal[HardwareRelationKind.LOCAL] = HardwareRelationKind.LOCAL
    observation_stage: Literal["local_state"] = "local_state"


class RegisterDifferenceAttributes(DifferenceAttributes):
    kind: Literal[HardwareRelationKind.REGISTER] = HardwareRelationKind.REGISTER
    observation_stage: Literal["register_state"] = "register_state"
    register_name: Identifier


class FormalCoverAttributes(Contract):
    kind: Literal[HardwareRelationKind.COVER] = HardwareRelationKind.COVER
    property_name: BoundedText
    cycles: int = Field(ge=0, strict=True)
    raw_result: BoundedText
    interpretation_boundary: BoundedText


class FormalErrorAttributes(Contract):
    kind: Literal[HardwareRelationKind.ERROR] = HardwareRelationKind.ERROR
    error_code: BoundedText
    raw_result: BoundedText
    interpretation_boundary: BoundedText


HardwareRelationAttributes = Annotated[
    InstructionAttributes | LocalDifferenceAttributes | RegisterDifferenceAttributes
    | FormalCoverAttributes | FormalErrorAttributes, Field(discriminator="kind"),
]


class HardwareRelationEndpoint(Contract):
    entity_type: Literal["instruction_sample", "signal_sample", "register_sample", "formal_property", "formal_tool_event"]
    identity: Identifier
    side: Literal["host", "reference"] | None = None
    time: EvidenceTime | None = None
    register_name: Identifier | None = None


class HardwareRelationCapabilities(Contract):
    supports_sampled_fact: bool = False
    supports_instruction_encoding_observed: bool = False
    supports_instruction_decode: bool = False
    supports_sampled_local_difference: bool = False
    supports_sampled_register_difference: bool = False
    supports_formal_result_observed: bool = False
    supports_instruction_execution: Literal[False] = False
    supports_instruction_commit: Literal[False] = False
    supports_instruction_retirement: Literal[False] = False
    supports_continuous_interval: Literal[False] = False
    supports_register_read: Literal[False] = False
    supports_register_write: Literal[False] = False
    supports_causal_propagation: Literal[False] = False
    supports_trigger_causality: Literal[False] = False
    supports_verified_trigger: Literal[False] = False
    supports_root_cause: Literal[False] = False
    supports_mutation_identity: Literal[False] = False
    supports_physical_observability: Literal[False] = False
    supports_same_configuration: Literal[False] = False
    supports_formal_causality: Literal[False] = False
    supports_vulnerability: Literal[False] = False


def derive_capabilities(attributes: HardwareRelationAttributes, status: str) -> HardwareRelationCapabilities:
    # Preserve producer extraction status; neither state implies execution.
    if status not in ("observed", "derived"):
        raise ValueError("Only observed/derived facts have v1 capabilities")
    kind = attributes.kind
    return HardwareRelationCapabilities(
        supports_sampled_fact=kind in (HardwareRelationKind.INSTRUCTION, HardwareRelationKind.LOCAL, HardwareRelationKind.REGISTER),
        supports_instruction_encoding_observed=kind == HardwareRelationKind.INSTRUCTION,
        supports_instruction_decode=isinstance(attributes, InstructionAttributes)
        and attributes.decoded_instruction is not None and attributes.decoded_instruction.status == DecodeStatus.DECODED,
        supports_sampled_local_difference=kind == HardwareRelationKind.LOCAL,
        supports_sampled_register_difference=kind == HardwareRelationKind.REGISTER,
        supports_formal_result_observed=kind in (HardwareRelationKind.COVER, HardwareRelationKind.ERROR),
    )


def derive_endpoints(attributes: HardwareRelationAttributes) -> list[HardwareRelationEndpoint]:
    a = attributes
    if isinstance(a, InstructionAttributes):
        return [HardwareRelationEndpoint(entity_type="instruction_sample", identity=a.signal_id, side="host", time=a.time)]
    if isinstance(a, DifferenceAttributes):
        register = isinstance(a, RegisterDifferenceAttributes)
        return [HardwareRelationEndpoint(
            entity_type="register_sample" if register else "signal_sample",
            identity=getattr(a, side + "_signal"), side=side, time=a.time,
            register_name=a.register_name if register else None,
        ) for side in ("host", "reference")]
    return [HardwareRelationEndpoint(
        entity_type="formal_property" if isinstance(a, FormalCoverAttributes) else "formal_tool_event",
        identity=a.property_name if isinstance(a, FormalCoverAttributes) else a.error_code,
    )]


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hardware_relation_id(observation_id: str, kind: HardwareRelationKind) -> str:
    return "hwrel:" + sha256_text(canonical_json([observation_id, kind]))


class HardwareRelation(Contract):
    relation_id: Identifier
    kind: HardwareRelationKind
    status: Literal["observed", "derived"] = "observed"
    source_observation_id: Identifier
    evidence_ids: list[Identifier] = Field(min_length=1)
    attributes: HardwareRelationAttributes
    endpoints: list[HardwareRelationEndpoint] = Field(min_length=1)
    capabilities: HardwareRelationCapabilities

    @model_validator(mode="after")
    def consistency(self) -> Self:
        if self.kind != self.attributes.kind or self.relation_id != hardware_relation_id(self.source_observation_id, self.kind):
            raise ValueError("Relation kind or identity mismatch")
        if self.capabilities != derive_capabilities(self.attributes, self.status):
            raise ValueError("Capabilities must be derived, not producer assertions")
        if self.endpoints != derive_endpoints(self.attributes):
            raise ValueError("Endpoints must exactly identify the attributes")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("Duplicate relation evidence IDs")
        a = self.attributes
        if isinstance(a, InstructionAttributes) and a.decoded_instruction:
            d = a.decoded_instruction
            if d.observation_id != self.source_observation_id or not {e.evidence_id for e in d.evidence} <= set(self.evidence_ids):
                raise ValueError("Decode belongs to another observation/evidence set")
        return self


class HardwareRelationSource(Contract):
    case_id: Identifier
    architecture: Architecture
    operational_projection: ToolDescriptor
    operational_projection_sha256: Sha256
    observation_count: int = Field(ge=0, strict=True)
    behavior_count: int = Field(ge=0, strict=True)
    evidence_registry_sha256: Sha256
    evidence_registry_count: int = Field(ge=0, strict=True)
    evidence_ids: list[Identifier]
    decoder_descriptors: list[ToolDescriptor]


class HardwareRelationCatalog(Contract):
    schema_version: Literal[VERSION] = VERSION
    source: HardwareRelationSource
    relations: list[HardwareRelation]

    @model_validator(mode="after")
    def catalog_consistency(self) -> Self:
        if len(self.relations) != self.source.observation_count:
            raise ValueError("v1 requires exactly one relation per operational observation")
        for field in ("relation_id", "source_observation_id"):
            ids = [getattr(r, field) for r in self.relations]
            if len(ids) != len(set(ids)):
                raise ValueError("Duplicate relation/observation identity")
        used = {e for r in self.relations for e in r.evidence_ids}
        if used != set(self.source.evidence_ids) or len(self.source.evidence_ids) != self.source.evidence_registry_count or len(used) != len(self.source.evidence_ids):
            raise ValueError("Evidence registry identity/count mismatch")
        descriptors = {}
        for r in self.relations:
            a = r.attributes
            if isinstance(a, InstructionAttributes) and a.decoded_instruction:
                d = a.decoded_instruction
                if d.architecture != self.source.architecture:
                    raise ValueError("Decode architecture mismatch")
                descriptors[canonical_json(d.decoder.model_dump(mode="json"))] = d.decoder
        if sorted(descriptors) != sorted(canonical_json(d.model_dump(mode="json")) for d in self.source.decoder_descriptors):
            raise ValueError("Decoder descriptor registry mismatch")
        return self


def _relation_order(relation: dict) -> tuple:
    time = relation["attributes"].get("time")
    # Compare units exactly as integer femtoseconds, without floating point.
    scales = {"s": 10**15, "ms": 10**12, "us": 10**9, "ns": 10**6, "ps": 1000, "fs": 1}
    return (time is None, time["value"] * scales[time["unit"]] if time else 0,
            relation["kind"], relation["relation_id"])


def serialize_hardware_relation_catalog(catalog: HardwareRelationCatalog) -> str:
    # Revalidation catches mutated nested models and model_copy(update=...) bypasses.
    data = HardwareRelationCatalog.model_validate_json(catalog.model_dump_json()).model_dump(mode="json")
    data["relations"].sort(key=_relation_order)
    data["source"]["evidence_ids"].sort()
    data["source"]["decoder_descriptors"].sort(key=canonical_json)
    for r in data["relations"]:
        r["evidence_ids"].sort()
    return canonical_json(data)


def parse_hardware_relation_catalog(text: str) -> HardwareRelationCatalog:
    return HardwareRelationCatalog.model_validate_json(text)


def hardware_relation_catalog_sha256(catalog: HardwareRelationCatalog) -> str:
    return sha256_text(serialize_hardware_relation_catalog(catalog))
