"""Minimal shared processor behavior IR; not a CFG or execution model."""

from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from chipchain.domain.common import (
    AnalysisLayer, Architecture, Contract, EpistemicStatus, Identifier, Metadata,
)
from chipchain.domain.evidence import EvidenceRef


class BehaviorKind(StrEnum):
    INSTRUCTION = "instruction"
    REGISTER_ACCESS = "register_access"
    CSR_ACCESS = "csr_access"
    MEMORY_ACCESS = "memory_access"
    MMIO_ACCESS = "mmio_access"
    PRIVILEGE = "privilege"
    CONTROL_TRANSFER = "control_transfer"
    EXCEPTION = "exception"
    INTERRUPT = "interrupt"
    DATA_DEPENDENCY = "data_dependency"
    CONTROL_DEPENDENCY = "control_dependency"


class ProcessorBehavior(Contract):
    behavior_id: Identifier
    kind: BehaviorKind
    architecture: Architecture
    origin: AnalysisLayer
    summary: Identifier
    evidence: list[EvidenceRef] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.UNKNOWN
    attributes: Metadata = Field(default_factory=dict)


class ProcessorBehaviorIR(Contract):
    case_id: Identifier
    behaviors: list[ProcessorBehavior] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_behavior_ids(self) -> Self:
        ids = [behavior.behavior_id for behavior in self.behaviors]
        if len(ids) != len(set(ids)):
            raise ValueError("behavior_id must be unique within an IR")
        return self
