"""Artifact -> deterministic observation boundary, without analyzer implementations."""

from typing import Literal, Protocol

from pydantic import Field

from chipchain.domain.behavior import ProcessorBehavior
from chipchain.domain.case import ArtifactRef, TargetDescriptor
from chipchain.domain.common import Contract, EpistemicStatus, Identifier
from chipchain.domain.evidence import EvidenceRef


class DeterministicObservation(Contract):
    observation_id: Identifier
    summary: Identifier
    evidence: list[EvidenceRef] = Field(min_length=1)
    behaviors: list[ProcessorBehavior] = Field(default_factory=list)
    epistemic_status: Literal[
        EpistemicStatus.OBSERVED, EpistemicStatus.DERIVED, EpistemicStatus.UNKNOWN
    ] = EpistemicStatus.OBSERVED


class HardwareObservations(Contract):
    case_id: Identifier
    observations: list[DeterministicObservation] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)


class FirmwareObservations(Contract):
    case_id: Identifier
    observations: list[DeterministicObservation] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)


class HardwareAnalyzer(Protocol):
    def analyze(
        self, *, case_id: str, target: TargetDescriptor, artifacts: list[ArtifactRef]
    ) -> HardwareObservations: ...


class FirmwareAnalyzer(Protocol):
    def analyze(
        self, *, case_id: str, target: TargetDescriptor, artifacts: list[ArtifactRef]
    ) -> FirmwareObservations: ...
