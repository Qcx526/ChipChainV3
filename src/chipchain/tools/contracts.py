"""Artifact -> deterministic observation contracts; implementations live in tools/hardware."""

from enum import StrEnum
from typing import Annotated, Literal, Protocol, Self

from pydantic import Field, field_validator, model_validator

from chipchain.domain.behavior import ProcessorBehavior
from chipchain.domain.case import ArtifactRef, TargetDescriptor
from chipchain.domain.common import Contract, EpistemicStatus, Identifier, Sha256
from chipchain.domain.evidence import BitRange, EvidenceRef, EvidenceTime
from chipchain.domain.instruction import EncodingRepresentation
from chipchain.domain.provenance import ToolDescriptor

__all__ = [
    "FirmwareObservation", "FirmwareObservationKind", "ObservationScope",
    "StaticInstructionSiteDetails", "MmioModelDetails", "MmioModelKind",
    "OpaqueInputDetails", "InterruptTriggerDetails",
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
    encoding_representation: EncodingRepresentation = EncodingRepresentation.UNKNOWN

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
        # B.1: approved differential/tool results may be operational inputs.
        # The producer's projection policy decides availability; injected RTL
        # anchors remain hidden regardless of their deterministic status.
        if self.role == ObservationRole.ANALYSIS_INPUT and self.kind == HardwareObservationKind.MUTATION_PRESENT:
            raise ValueError("Injected mutation anchors belong to the benchmark oracle")
        return self


class HardwareObservations(Contract):
    case_id: Identifier
    observations: list[HardwareObservation | DeterministicObservation] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)


class ObservationScope(StrEnum):
    ARTIFACT = "artifact"
    STATIC = "static"
    CONFIGURATION = "configuration"
    RUNTIME = "runtime"
    UNKNOWN = "unknown"


class FirmwareObservationKind(StrEnum):
    STATIC_INSTRUCTION_SITE = "static_instruction_site"
    MMIO_MODEL = "mmio_model"
    ENVIRONMENT_INPUT = "environment_input"


UInt32 = Annotated[int, Field(strict=True, ge=0, le=0xffffffff)]


class StaticInstructionSiteDetails(Contract):
    kind: Literal["static_instruction_site"] = "static_instruction_site"
    address: UInt32
    elf_offset: int = Field(ge=0, strict=True)
    image_offset: int = Field(ge=0, strict=True)
    raw_bytes: str = Field(pattern=r"^(?:[0-9a-f]{4}|[0-9a-f]{8})$")
    width_bits: Literal[16, 32]
    function: Identifier | None = None
    raw_symbol_value: UInt32
    canonical_function_address: UInt32
    representation: Literal[EncodingRepresentation.MEMORY_BYTES] = EncodingRepresentation.MEMORY_BYTES
    isa_mode: Literal["thumb-m-little"] = "thumb-m-little"

    @model_validator(mode="after")
    def address_and_bytes(self) -> Self:
        if self.address % 2 or self.canonical_function_address != self.raw_symbol_value & ~1:
            raise ValueError("Invalid Thumb address normalization")
        if self.address < self.canonical_function_address or len(self.raw_bytes) * 4 != self.width_bits:
            raise ValueError("Instruction site bytes/address disagree")
        return self


class MmioModelKind(StrEnum):
    BITEXTRACT = "bitextract"
    CONSTANT = "constant"
    PASSTHROUGH = "passthrough"
    SET = "set"
    UNMODELED = "unmodeled"


class MmioModelDetails(Contract):
    kind: Literal["mmio_model"] = "mmio_model"
    pc: UInt32
    mmio_address: UInt32
    access_size_bytes: Literal[1, 2, 4]
    model_kind: MmioModelKind
    parameters: dict[str, UInt32 | Annotated[list[UInt32], Field(max_length=32)]] = Field(default_factory=dict, max_length=4)
    config_key: str = Field(min_length=1, max_length=128)

    @field_validator("access_size_bytes", mode="before")
    @classmethod
    def integer_access_size(cls, value):
        if type(value) is not int:
            raise ValueError("Access size must be an integer")
        return value

    @model_validator(mode="after")
    def parameters_match_model(self) -> Self:
        required = {
            MmioModelKind.BITEXTRACT: {"left_shift", "mask", "size"},
            MmioModelKind.CONSTANT: {"val"}, MmioModelKind.PASSTHROUGH: {"init_val"},
            MmioModelKind.SET: {"vals"}, MmioModelKind.UNMODELED: set(),
        }[self.model_kind]
        if set(self.parameters) != required or self.pc % 2:
            raise ValueError("Unsupported MMIO model parameters/PC")
        for name, value in self.parameters.items():
            if (name == "vals") != isinstance(value, list):
                raise ValueError("Only vals is a list parameter")
        if self.model_kind == MmioModelKind.SET and not self.parameters["vals"]:
            raise ValueError("Model value set must be nonempty")
        if self.model_kind == MmioModelKind.BITEXTRACT:
            if self.parameters["size"] not in (1, 2, 4) or self.parameters["left_shift"] > 31:
                raise ValueError("Unsupported bitextract size/shift")
        return self


class OpaqueInputDetails(Contract):
    kind: Literal["opaque_input"] = "opaque_input"
    artifact_id: Identifier
    size_bytes: int = Field(ge=0, strict=True)
    sha256: Sha256


class InterruptTriggerDetails(Contract):
    kind: Literal["interrupt_trigger"] = "interrupt_trigger"
    config_key: str = Field(min_length=1, max_length=128)
    every_nth_tick: int = Field(gt=0, le=0xffffffff, strict=True)
    fuzz_mode: Literal["round_robin"]
    tick_unit: Literal["emulator_tick"] = "emulator_tick"


class FirmwareObservation(DeterministicObservation):
    kind: FirmwareObservationKind
    scope: ObservationScope
    role: ObservationRole = ObservationRole.BENCHMARK_ORACLE
    details: Annotated[
        StaticInstructionSiteDetails | MmioModelDetails | OpaqueInputDetails | InterruptTriggerDetails,
        Field(discriminator="kind"),
    ]

    @model_validator(mode="after")
    def semantics_match_details(self) -> Self:
        expected = {
            StaticInstructionSiteDetails: (FirmwareObservationKind.STATIC_INSTRUCTION_SITE, ObservationScope.STATIC),
            MmioModelDetails: (FirmwareObservationKind.MMIO_MODEL, ObservationScope.CONFIGURATION),
            OpaqueInputDetails: (FirmwareObservationKind.ENVIRONMENT_INPUT, ObservationScope.ARTIFACT),
            InterruptTriggerDetails: (FirmwareObservationKind.ENVIRONMENT_INPUT, ObservationScope.CONFIGURATION),
        }[type(self.details)]
        if (self.kind, self.scope) != expected:
            raise ValueError("Firmware kind/scope must match supported details semantics")
        if isinstance(self.details, OpaqueInputDetails) and self.details.artifact_id not in {e.artifact_id for e in self.evidence}:
            raise ValueError("Opaque input identity must have matching evidence")
        return self


class FirmwareObservations(Contract):
    case_id: Identifier
    observations: list[FirmwareObservation | DeterministicObservation] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)


class HardwareAnalyzer(Protocol):
    def analyze(
        self, *, case_id: str, target: TargetDescriptor, artifacts: list[ArtifactRef]
    ) -> HardwareObservations: ...


class FirmwareAnalyzer(Protocol):
    def analyze(
        self, *, case_id: str, target: TargetDescriptor, artifacts: list[ArtifactRef]
    ) -> FirmwareObservations: ...
