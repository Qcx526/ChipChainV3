"""Artifact -> deterministic observation contracts; implementations live in tools/hardware."""

from enum import StrEnum
from typing import Annotated, Literal, Protocol, Self

from pydantic import Field, model_validator

from chipchain.domain.behavior import ProcessorBehavior
from chipchain.domain.case import ArtifactRef, TargetDescriptor
from chipchain.domain.common import Contract, EpistemicStatus, Identifier
from chipchain.domain.evidence import BitRange, EvidenceRef, EvidenceTime
from chipchain.domain.provenance import ToolDescriptor

__all__ = [
    "DeterministicObservation", "HardwareObservations", "FirmwareObservations",
    "HardwareAnalyzer", "FirmwareAnalyzer", "ToolDescriptor",
    "HardwareObservation", "HardwareObservationKind", "ObservationRole",
    "MutationAnchorDetails", "WaveformObservationDetails", "FormalResultDetails", "SignalValue",
]


class DeterministicObservation(Contract):
    observation_id: Identifier
    summary: Identifier
    evidence: list[EvidenceRef] = Field(min_length=1)
    behaviors: list[ProcessorBehavior] = Field(default_factory=list)
    epistemic_status: Literal[
        EpistemicStatus.OBSERVED, EpistemicStatus.DERIVED, EpistemicStatus.UNKNOWN
    ] = EpistemicStatus.OBSERVED


class HardwareObservationKind(StrEnum):
    MUTATION_PRESENT = "mutation_present"
    LOCAL_EFFECT_OBSERVED = "local_effect_observed"
    ARCHITECTURAL_PROPAGATION_OBSERVED = "architectural_propagation_observed"
    FORMAL_RESULT = "formal_result"
    INSTRUCTION_ENCODING_OBSERVED = "instruction_encoding_observed"


class ObservationRole(StrEnum):
    ANALYSIS_INPUT = "analysis_input"
    BENCHMARK_ORACLE = "benchmark_oracle"


class MutationAnchorDetails(Contract):
    kind: Literal["mutation_anchor"] = "mutation_anchor"
    module: Identifier
    signal: Identifier
    reference_connection: Identifier
    host_connection: Identifier
    source_location: str | None = None

    @model_validator(mode="after")
    def different_connections(self) -> Self:
        if self.reference_connection == self.host_connection:
            raise ValueError("Mutation anchor requires a connection difference")
        return self


class SignalValue(Contract):
    signal: Identifier
    role: Literal["host", "reference"]
    width: int = Field(gt=0, strict=True)
    bit_range: BitRange | None = None
    value: str = Field(pattern=r"^[01xz]+$")
    declaration_line: int = Field(ge=1, strict=True)

    @model_validator(mode="after")
    def width_matches_value(self) -> Self:
        if len(self.value) != self.width:
            raise ValueError("Signal value must preserve its declared width")
        if self.bit_range and self.bit_range.msb - self.bit_range.lsb + 1 != self.width:
            raise ValueError("Signal bit range must match width")
        return self


class WaveformObservationDetails(Contract):
    kind: Literal["waveform_observation"] = "waveform_observation"
    time: EvidenceTime
    host: SignalValue
    reference: SignalValue | None = None
    register_name: str | None = None
    observation_stage: Literal["id", "local_state", "register_state"]

    @model_validator(mode="after")
    def signal_roles(self) -> Self:
        if self.host.role != "host" or (self.reference is not None and self.reference.role != "reference"):
            raise ValueError("Waveform values have incorrect host/reference roles")
        return self


class FormalResultDetails(Contract):
    kind: Literal["formal_result"] = "formal_result"
    category: Literal["cover_hit", "trace_error"]
    raw_result: Identifier
    property_name: str | None = None
    cycles: int | None = Field(default=None, ge=0, strict=True)
    error_code: str | None = None
    interpretation_boundary: Identifier

    @model_validator(mode="after")
    def result_fields(self) -> Self:
        if self.category == "cover_hit":
            if not self.property_name or self.cycles is None or self.error_code is not None:
                raise ValueError("Cover result requires property/cycles and no error code")
        elif not self.error_code or self.cycles is not None or self.property_name is not None:
            raise ValueError("Trace error requires its code without cover property/cycles")
        return self


class HardwareObservation(DeterministicObservation):
    kind: HardwareObservationKind
    role: ObservationRole = ObservationRole.BENCHMARK_ORACLE
    details: Annotated[
        MutationAnchorDetails | WaveformObservationDetails | FormalResultDetails,
        Field(discriminator="kind"),
    ]

    @model_validator(mode="after")
    def semantics_match_details(self) -> Self:
        expected = {
            HardwareObservationKind.MUTATION_PRESENT: MutationAnchorDetails,
            HardwareObservationKind.FORMAL_RESULT: FormalResultDetails,
        }.get(self.kind, WaveformObservationDetails)
        if not isinstance(self.details, expected):
            raise ValueError("Hardware observation kind does not match details")
        if isinstance(self.details, WaveformObservationDetails):
            instruction = self.kind == HardwareObservationKind.INSTRUCTION_ENCODING_OBSERVED
            if instruction:
                if self.details.reference is not None or self.details.observation_stage != "id":
                    raise ValueError("Instruction observation must describe the host ID stage")
            else:
                peer = self.details.reference
                host = self.details.host
                if peer is None or peer.width != host.width or peer.value == host.value:
                    raise ValueError("Difference observation requires unequal paired values")
                if any(c in host.value + peer.value for c in "xz"):
                    raise ValueError("Unknown values do not establish a difference")
                stage = ("register_state" if self.kind == HardwareObservationKind.ARCHITECTURAL_PROPAGATION_OBSERVED
                         else "local_state")
                if self.details.observation_stage != stage:
                    raise ValueError("Difference observation has the wrong stage")
                if stage == "register_state" and not self.details.register_name:
                    raise ValueError("Register state observation requires a register identity")
        # A1 analysis observations contain only host facts. Comparative results and
        # golden-derived anchors remain benchmark data, even with observed status.
        if self.role == ObservationRole.ANALYSIS_INPUT and self.kind != HardwareObservationKind.INSTRUCTION_ENCODING_OBSERVED:
            raise ValueError("Comparative and formal observations belong to the benchmark oracle")
        return self


class HardwareObservations(Contract):
    case_id: Identifier
    observations: list[HardwareObservation | DeterministicObservation] = Field(default_factory=list)
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
