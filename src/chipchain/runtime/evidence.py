"""Small, source-bound runtime observation vocabulary."""
from __future__ import annotations

from typing import Literal

from pydantic import Field

from chipchain.domain.common import Contract


class RuntimeSource(Contract):
    case_id: str = Field(min_length=1)
    elf_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    si_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trace_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rtl_trace_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    isa_trace_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    simulator_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    build_metadata_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    rtl_source_revision: str = "not_established"


class InstructionExecutionObservation(Contract):
    observation_id: str
    source: RuntimeSource
    stream: Literal["rtl", "isa_reference"]
    record_index: int = Field(ge=0)
    pc: int = Field(ge=0)
    encoding: str
    privilege_mode: str | None = None
    raw_record_sha256: str


class MemoryAccessObservation(Contract):
    observation_id: str
    source: RuntimeSource
    instruction_observation_id: str
    address: int | None = None
    access: Literal["read", "write", "unknown"] = "unknown"


class SystemRegisterObservation(Contract):
    observation_id: str
    source: RuntimeSource
    instruction_observation_id: str
    system_register: str
    value: int | None = None


class PrivilegeTransitionObservation(Contract):
    observation_id: str
    source: RuntimeSource
    from_mode: str | None = None
    to_mode: str | None = None
    instruction_observation_id: str


class ExceptionObservation(Contract):
    observation_id: str
    source: RuntimeSource
    instruction_observation_id: str
    cause: str | None = None


class ArchitecturalStateObservation(Contract):
    observation_id: str
    source: RuntimeSource
    instruction_observation_id: str
    fields: dict[str, str]
