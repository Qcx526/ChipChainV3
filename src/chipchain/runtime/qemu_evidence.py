"""Architecture-neutral, content-addressed QEMU firmware evidence contracts.

These objects describe emulator instruction callbacks, never hardware retirement.
Derived artifacts must be replayed from the raw stream and exact ELF before use;
content IDs are integrity checks, not signatures or independent source attestation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import ClassVar, Literal, TypeVar

from pydantic import ConfigDict, Field, model_validator

from chipchain.domain.common import Contract, Sha256
from chipchain.firmware.static_ir import FirmwareArtifactIdentity, StaticBehaviorKind, content_id
from chipchain.runtime.qemu_profile import QemuRunProfile
from chipchain.runtime.image_mapping import RuntimeImageMapping

SUPPORTED_DEFINITION = (
    "The exact static firmware fact has a compatible, source-bound QEMU instruction-execution "
    "callback observation under the declared run/profile and image mapping. This does not "
    "establish instruction completion, physical retirement, memory effects, hardware trigger, "
    "deviation, timing, silicon behavior or vulnerability verification."
)


class RuntimeProfile(Contract):
    architecture: Literal["arm", "riscv", "powerpc"]
    bit_width: Literal[32, 64]
    executable: str
    machine: str
    cpu: str | None
    boot_strategy: Literal["generic_loader", "kernel"]
    bios: str | None
    vcpus: int = Field(strict=True, ge=1)
    extra_args: tuple[str, ...] = ()

    @model_validator(mode="after")
    def profile_valid(self):
        QemuRunProfile(**self.model_dump())
        # V1 does not bind external disk/BIOS/device contents. No host paths or
        # unmodeled devices may enter the canonical launch configuration.
        if self.extra_args or self.bios != "none" or self.boot_strategy != "generic_loader":
            raise ValueError("Runtime evidence V1 requires a bare-metal generic-loader profile")
        if self.vcpus != 1:
            raise ValueError("Runtime evidence V1 requires one vCPU")
        return self

    @classmethod
    def from_profile(cls, profile: QemuRunProfile) -> RuntimeProfile:
        return cls.model_validate(asdict(profile))

    def to_profile(self) -> QemuRunProfile:
        return QemuRunProfile(**self.model_dump())


class AcquisitionPolicy(Contract):
    kind: Literal["event_prefix", "target_then_successors"]
    target_pc: int | None = Field(default=None, strict=True, ge=0)
    successor_events: int = Field(strict=True, ge=0, le=256)
    max_events: int = Field(strict=True, ge=1, le=100000)

    @model_validator(mode="after")
    def bounded(self):
        if self.kind == "event_prefix":
            if self.target_pc is not None or self.successor_events != 0:
                raise ValueError("Event prefix must not declare a target window")
        elif self.target_pc is None or self.successor_events < 1:
            raise ValueError("Target policy requires a PC and successor context")
        if self.successor_events >= self.max_events:
            raise ValueError("Successor context must fit within event bound")
        return self


class Identified(Contract):
    model_config = ConfigDict(frozen=True)
    prefix: ClassVar[str]
    id_field: ClassVar[str] = "artifact_id"

    @model_validator(mode="after")
    def check_content_id(self):
        payload = self.model_dump(mode="json", exclude={self.id_field})
        if getattr(self, self.id_field) != content_id(self.prefix, payload):
            raise ValueError(f"{self.prefix} content identity mismatch")
        return self


T = TypeVar("T", bound=Identified)


def identified(cls: type[T], **fields: object) -> T:
    """Include all schema defaults in the canonical identity recipe."""
    unknown = set(fields) - set(cls.model_fields)
    if unknown or cls.id_field in fields:
        raise ValueError("Unexpected fields in canonical identity input")
    payload = {}
    for name, field in cls.model_fields.items():
        if name == cls.id_field:
            continue
        if name in fields:
            payload[name] = fields[name]
        elif field.is_required():
            raise ValueError(f"Missing canonical field: {name}")
        else:
            payload[name] = field.get_default(call_default_factory=True)
    return cls.model_validate({**payload, cls.id_field: content_id(cls.prefix, payload)})


class QemuRuntimeRunDescriptor(Identified):
    prefix = "qemu-runtime-run"
    id_field = "run_id"
    schema_version: Literal["qemu-runtime-run/v1"] = "qemu-runtime-run/v1"
    run_id: str
    source_kind: Literal["qemu_tcg_plugin"] = "qemu_tcg_plugin"
    firmware: FirmwareArtifactIdentity
    image_mapping: RuntimeImageMapping
    profile: RuntimeProfile
    qemu_version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    qemu_executable_sha256: Sha256
    qemu_bundle_sha256: Sha256
    plugin_name: Literal["chipchain_trace/v1"] = "chipchain_trace/v1"
    plugin_sha256: Sha256
    plugin_source_sha256: Sha256
    plugin_api_header_sha256: Sha256
    plugin_header_provenance_sha256: Sha256
    plugin_api_version: Literal[7] = 7
    acquisition_args: tuple[str, ...]
    policy: AcquisitionPolicy
    observation_scope: Literal["emulator_instruction_dispatch_callback"] = "emulator_instruction_dispatch_callback"

    @model_validator(mode="after")
    def source_profile(self):
        self.image_mapping.validate_source(self.firmware)
        if (self.firmware.architecture, self.firmware.bit_width) != (
            self.profile.architecture, self.profile.bit_width
        ):
            raise ValueError("Firmware architecture/width and runtime profile disagree")
        if self.acquisition_args != ("-monitor", "none", "-serial", "none", "-nic", "none", "-no-reboot", "-no-user-config"):
            raise ValueError("Unrecognized runtime acquisition options")
        return self


class RuntimeEvent(Identified):
    prefix = "qemu-event"
    id_field = "event_id"
    event_id: str
    run_id: str
    sequence: int = Field(strict=True, ge=0)
    vcpu: int = Field(strict=True, ge=0)
    pc: int = Field(strict=True, ge=0)
    instruction_bytes: str = Field(pattern=r"^(?:[0-9a-f]{2})+$")
    instruction_size: int = Field(strict=True, ge=1, le=32)
    observation_kind: Literal["QEMU_INSTRUCTION_EXECUTION_OBSERVED"] = "QEMU_INSTRUCTION_EXECUTION_OBSERVED"

    @model_validator(mode="after")
    def byte_length(self):
        if len(self.instruction_bytes) != self.instruction_size * 2:
            raise ValueError("Runtime instruction byte length mismatch")
        return self


class RuntimeEvents(Identified):
    prefix = "qemu-runtime-events"
    schema_version: Literal["qemu-runtime-events/v1"] = "qemu-runtime-events/v1"
    artifact_id: str
    run_id: str
    firmware_sha256: Sha256
    raw_stream_sha256: Sha256
    events: tuple[RuntimeEvent, ...]
    stop_reason: Literal["event_bound", "target_window_complete"]
    target_sequence: int | None = Field(default=None, strict=True, ge=0)
    coverage: Literal["bounded_single_vcpu_callback_prefix"] = "bounded_single_vcpu_callback_prefix"

    @model_validator(mode="after")
    def sequence_valid(self):
        if not self.events:
            raise ValueError("Runtime callback prefix must be nonempty")
        for index, event in enumerate(self.events):
            if event.sequence != index or event.vcpu != 0 or event.run_id != self.run_id:
                raise ValueError("Runtime callback sequence or source mismatch")
        if self.target_sequence is not None and self.target_sequence >= len(self.events):
            raise ValueError("Target sequence is outside the prefix")
        return self


class RuntimeSemanticFact(Identified):
    prefix = "runtime-semantic"
    id_field = "fact_id"
    fact_id: str
    run_id: str
    source_event_id: str
    pc: int = Field(strict=True, ge=0)
    elf_virtual_address: int = Field(strict=True, ge=0)
    instruction_bytes: str
    decoder_id: str
    mnemonic: str
    operands: tuple[str, ...]
    kind: StaticBehaviorKind
    semantic_status: Literal["supported"] = Field(default="supported", description="Decoder classification is supported; no instruction-completion assertion")


class RuntimeSemantics(Identified):
    prefix = "runtime-semantics"
    schema_version: Literal["runtime-semantics/v1"] = "runtime-semantics/v1"
    artifact_id: str
    run_id: str
    events_id: str
    decoder_id: str | None
    facts: tuple[RuntimeSemanticFact, ...]
    unsupported_event_ids: tuple[str, ...]


class StaticRuntimeBinding(Identified):
    """SUPPORTED has only the source-bound callback meaning below."""
    prefix = "static-runtime-binding"
    id_field = "binding_id"
    binding_id: str
    analysis_id: str
    run_id: str
    static_behavior_id: str
    static_instruction_id: str
    pc: int = Field(strict=True, ge=0)
    kind: StaticBehaviorKind
    status: Literal["SUPPORTED", "UNKNOWN"] = Field(description=SUPPORTED_DEFINITION)
    reason: Literal["EXACT_SOURCE_INSTRUCTION_AND_SEMANTIC", "NOT_OBSERVED_IN_THIS_RUN",
                    "UNSUPPORTED_RUNTIME_SEMANTICS", "STATIC_SEMANTIC_NOT_SUPPORTED"]
    source_event_ids: tuple[str, ...]
    semantic_fact_ids: tuple[str, ...]

    @model_validator(mode="after")
    def support_requires_sources(self):
        if self.status == "SUPPORTED":
            if not self.source_event_ids or len(self.source_event_ids) != len(self.semantic_fact_ids):
                raise ValueError("Supported binding requires exact runtime semantic evidence")
            if self.reason != "EXACT_SOURCE_INSTRUCTION_AND_SEMANTIC":
                raise ValueError("Supported binding reason mismatch")
        elif self.semantic_fact_ids or self.reason == "EXACT_SOURCE_INSTRUCTION_AND_SEMANTIC":
            raise ValueError("Unknown binding cannot assert semantic support")
        return self


class StaticRuntimeBindings(Identified):
    prefix = "static-runtime-bindings"
    schema_version: Literal["static-runtime-bindings/v1"] = "static-runtime-bindings/v1"
    artifact_id: str
    analysis_id: str
    run_id: str
    events_id: str
    semantics_id: str
    bindings: tuple[StaticRuntimeBinding, ...]


class RuntimeSupportedCapability(Identified):
    """Additive support projection of a static behavior; does not mutate CAP0."""
    prefix = "runtime-supported-capability"
    id_field = "capability_id"
    capability_id: str
    static_behavior_id: str
    static_instruction_id: str
    binding_id: str
    run_id: str
    pc: int = Field(strict=True, ge=0)
    kind: StaticBehaviorKind
    status: Literal["SUPPORTED", "UNKNOWN"] = Field(description=SUPPORTED_DEFINITION)
    source_event_ids: tuple[str, ...]
    semantic_fact_ids: tuple[str, ...]
    control_authority: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    hardware_trigger: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    hardware_deviation: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    scope: Literal["supplied_firmware_in_declared_qemu_run"] = "supplied_firmware_in_declared_qemu_run"


class RuntimeCapabilities(Identified):
    prefix = "runtime-capabilities"
    schema_version: Literal["runtime-capabilities/v1"] = "runtime-capabilities/v1"
    artifact_id: str
    analysis_id: str
    run_id: str
    bindings_id: str
    capabilities: tuple[RuntimeSupportedCapability, ...]


@dataclass(frozen=True)
class RuntimeEvidence:
    run: QemuRuntimeRunDescriptor
    events: RuntimeEvents
    semantics: RuntimeSemantics
    bindings: StaticRuntimeBindings
    capabilities: RuntimeCapabilities
