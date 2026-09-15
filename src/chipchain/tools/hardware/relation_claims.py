"""Explicit typed claims; no prose interpretation, model judge or causal inference."""

from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, model_validator

from chipchain.domain.common import Contract, Identifier
from chipchain.domain.evidence import EvidenceTime
from chipchain.tools.hardware.relations import (
    HardwareRelationAttributes, HardwareRelationCatalog, HardwareRelationKind,
    parse_hardware_relation_catalog, serialize_hardware_relation_catalog,
)


class HardwareClaimKind(StrEnum):
    ENCODING = "instruction_encoding_observed"
    DECODED = "instruction_decoded"
    LOCAL = "sampled_local_difference"
    REGISTER = "sampled_register_difference"
    COVER = "formal_cover_hit"
    ERROR = "formal_trace_error"
    EXECUTED = "instruction_executed"
    COMMITTED = "instruction_committed"
    RETIRED = "instruction_retired"
    INTERVAL = "continuous_interval_difference"
    READ = "register_read"
    WRITE = "register_write"
    CAUSAL = "causal_link"
    TRIGGER = "trigger_condition_verified"
    ROOT_CAUSE = "root_cause"
    PHYSICAL = "physical_observability"
    SAME_CONFIGURATION = "same_formal_configuration"
    FORMAL_CAUSAL = "formal_event_causality"
    MUTATION_LOCATION = "mutation_location"
    MUTATION_CONNECTION = "mutation_connection"
    MUTATION_FAMILY = "mutation_family"
    VULNERABILITY = "vulnerability_verified"


CAPABILITY_FOR_CLAIM = {
    HardwareClaimKind.ENCODING: (HardwareRelationKind.INSTRUCTION, "supports_instruction_encoding_observed"),
    HardwareClaimKind.DECODED: (HardwareRelationKind.INSTRUCTION, "supports_instruction_decode"),
    HardwareClaimKind.LOCAL: (HardwareRelationKind.LOCAL, "supports_sampled_local_difference"),
    HardwareClaimKind.REGISTER: (HardwareRelationKind.REGISTER, "supports_sampled_register_difference"),
    HardwareClaimKind.COVER: (HardwareRelationKind.COVER, "supports_formal_result_observed"),
    HardwareClaimKind.ERROR: (HardwareRelationKind.ERROR, "supports_formal_result_observed"),
}


class HardwareRelationFactClaim(Contract):
    claim_id: Identifier
    relation_id: Identifier
    expected_kind: HardwareRelationKind
    expected_status: Literal["observed", "derived"]
    expected_attributes: HardwareRelationAttributes


class HardwareSemanticClaim(Contract):
    claim_id: Identifier
    kind: HardwareClaimKind
    relation_ids: list[Identifier] = Field(default_factory=list)
    # Positive claims require exact typed attributes; absence never means match-any.
    expected_attributes: HardwareRelationAttributes | None = None
    expected_status: Literal["observed", "derived"] = "observed"
    start: EvidenceTime | None = None
    end: EvidenceTime | None = None

    @model_validator(mode="after")
    def shape(self) -> Self:
        if len(self.relation_ids) != len(set(self.relation_ids)):
            raise ValueError("Duplicate support relation ID")
        if self.kind == HardwareClaimKind.INTERVAL:
            if self.start is None or self.end is None:
                raise ValueError("Interval claims require explicit start and end")
            scales = {"s": 10**15, "ms": 10**12, "us": 10**9, "ns": 10**6, "ps": 1000, "fs": 1}
            if self.start.value * scales[self.start.unit] > self.end.value * scales[self.end.unit]:
                raise ValueError("Interval start exceeds end")
        elif self.start is not None or self.end is not None:
            raise ValueError("Only interval claims take interval endpoints")
        return self


class HardwareClaimSupport(Contract):
    claim_id: Identifier
    status: Literal["supported", "unsupported", "incompatible"]
    reason: Literal[
        "exact_fact_match", "exact_fact_mismatch", "unknown_relation", "semantic_power_unavailable",
        "missing_relation", "missing_exact_attributes", "ambiguous_support",
    ]
    relation_ids: list[Identifier]


def check_hardware_claim(
    catalog: HardwareRelationCatalog, claim: HardwareRelationFactClaim | HardwareSemanticClaim,
) -> HardwareClaimSupport:
    # Never trust capabilities on an unvalidated/mutated Python instance.
    catalog = parse_hardware_relation_catalog(serialize_hardware_relation_catalog(catalog))
    claim = type(claim).model_validate_json(claim.model_dump_json())
    relations = {r.relation_id: r for r in catalog.relations}
    ids = [claim.relation_id] if isinstance(claim, HardwareRelationFactClaim) else claim.relation_ids

    def result(status, reason):
        return HardwareClaimSupport(claim_id=claim.claim_id, status=status, reason=reason, relation_ids=ids)

    if isinstance(claim, HardwareSemanticClaim):
        if claim.kind not in CAPABILITY_FOR_CLAIM:
            return result("unsupported", "semantic_power_unavailable")
        kind, capability = CAPABILITY_FOR_CLAIM[claim.kind]
        # A catalog without any such fact (notably 820 instructions) cannot support it.
        if not ids or not any(r.kind == kind for r in relations.values()):
            return result("unsupported", "missing_relation")
        if any(i not in relations for i in ids):
            return result("incompatible", "unknown_relation")
        if len(ids) != 1:
            return result("unsupported", "ambiguous_support")
        r = relations[ids[0]]
        if r.kind != kind:
            return result("incompatible", "exact_fact_mismatch")
        if not getattr(r.capabilities, capability):
            return result("unsupported", "semantic_power_unavailable")
        if claim.expected_attributes is None:
            return result("unsupported", "missing_exact_attributes")
    else:
        if claim.relation_id not in relations:
            return result("incompatible", "unknown_relation")
        r = relations[claim.relation_id]
        if r.kind != claim.expected_kind:
            return result("incompatible", "exact_fact_mismatch")
    if r.status != claim.expected_status or r.attributes != claim.expected_attributes:
        return result("incompatible", "exact_fact_mismatch")
    return result("supported", "exact_fact_match")
