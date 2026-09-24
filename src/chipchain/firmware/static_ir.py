"""Canonical, path-independent firmware static facts."""
from __future__ import annotations

from enum import StrEnum
from hashlib import sha256
import json
from typing import Literal

from pydantic import Field, model_validator
from pydantic import BaseModel

from chipchain.domain.common import Contract

SCHEMA = "firmware-static-analysis/v2"


def canonical(value: object) -> bytes:
    def plain(item):
        if isinstance(item, BaseModel): return item.model_dump(mode="json")
        if isinstance(item, dict): return {key: plain(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)): return [plain(child) for child in item]
        return item
    return json.dumps(plain(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def content_id(prefix: str, value: object) -> str:
    return prefix + ":" + sha256(canonical(value)).hexdigest()


class SegmentFact(Contract):
    virtual_address: int = Field(ge=0)
    file_offset: int = Field(ge=0)
    file_size: int = Field(ge=0)
    memory_size: int = Field(ge=0)
    flags: int = Field(ge=0)


class SectionFact(Contract):
    name: str
    address: int = Field(ge=0)
    size: int = Field(ge=0)
    flags: int = Field(ge=0)
    section_type: str


class FirmwareArtifactIdentity(Contract):
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    architecture: Literal["arm", "riscv", "powerpc"]
    bit_width: Literal[32, 64]
    endianness: Literal["little", "big"]
    entry: int = Field(ge=0)
    arm_profile: str | None = None
    arm_cpu_name: str | None = None
    segments: tuple[SegmentFact, ...]
    sections: tuple[SectionFact, ...]


class Range(Contract):
    start: int = Field(ge=0)
    end: int = Field(ge=0)


class FirmwareFunctionFact(Contract):
    fact_id: str
    entry: int = Field(ge=0)
    name: str
    ranges: tuple[Range, ...]
    thunk: bool
    external: bool


class BasicBlockFact(Contract):
    fact_id: str
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    ranges: tuple[Range, ...]
    function_ids: tuple[str, ...]


class InstructionFact(Contract):
    fact_id: str
    pc: int = Field(ge=0)
    raw_bytes: str = Field(pattern=r"^(?:[0-9a-f]{2})+$")
    mnemonic: str
    operands: tuple[str, ...]
    text: str
    function_ids: tuple[str, ...]
    block_id: str | None


class ControlFlowEdgeFact(Contract):
    fact_id: str
    source_block_id: str
    target_block_id: str | None
    target_address: int = Field(ge=0)
    edge_type: str


class CallSiteFact(Contract):
    fact_id: str
    pc: int = Field(ge=0)
    caller_function_ids: tuple[str, ...]
    direct: bool
    target: int | None = None
    target_function_id: str | None = None


class ReferenceFact(Contract):
    fact_id: str
    source_pc: int = Field(ge=0)
    target: int | None = None
    reference_type: str
    operand_index: int


class StaticBehaviorKind(StrEnum):
    INSTRUCTION = "INSTRUCTION"
    DIRECT_CALL = "DIRECT_CALL"
    INDIRECT_CALL = "INDIRECT_CALL"
    DIRECT_BRANCH = "DIRECT_BRANCH"
    CONDITIONAL_BRANCH = "CONDITIONAL_BRANCH"
    INDIRECT_BRANCH = "INDIRECT_BRANCH"
    RETURN = "RETURN"
    MEMORY_LOAD = "MEMORY_LOAD"
    MEMORY_STORE = "MEMORY_STORE"
    MMIO_READ = "MMIO_READ"
    MMIO_WRITE = "MMIO_WRITE"
    SYSTEM_REGISTER_READ = "SYSTEM_REGISTER_READ"
    SYSTEM_REGISTER_WRITE = "SYSTEM_REGISTER_WRITE"
    MEMORY_BARRIER = "MEMORY_BARRIER"
    INSTRUCTION_BARRIER = "INSTRUCTION_BARRIER"
    ATOMIC_LOAD = "ATOMIC_LOAD"
    ATOMIC_STORE = "ATOMIC_STORE"
    TLB_INVALIDATE = "TLB_INVALIDATE"
    EXCEPTION_RETURN = "EXCEPTION_RETURN"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class StaticBehaviorFact(Contract):
    fact_id: str
    instruction_id: str
    pc: int = Field(ge=0)
    kind: StaticBehaviorKind
    semantic_status: Literal["supported", "partial", "unsupported"]
    target: int | None = None
    address: int | None = None
    address_status: Literal["exact", "unknown", "not_applicable"] = "not_applicable"
    access_width_bits: int | None = Field(default=None, gt=0)
    system_register: str | None = None
    known_value: int | None = None
    detail: str | None = None

    @model_validator(mode="after")
    def identity(self):
        semantic = self.model_dump(mode="json", exclude={"fact_id", "instruction_id", "pc"},
                                   exclude_none=True, exclude_defaults=True)
        if self.fact_id != content_id("fwbehavior", {"instruction": self.instruction_id,
                                                      "semantic": semantic}):
            raise ValueError("Static behavior fact identity mismatch")
        return self


class FirmwareStaticAnalysis(Contract):
    schema_version: Literal["firmware-static-analysis/v2"] = SCHEMA
    analysis_id: str
    artifact: FirmwareArtifactIdentity
    ghidra_language: str
    ghidra_version: str
    producer: dict[str, str]
    functions: tuple[FirmwareFunctionFact, ...]
    blocks: tuple[BasicBlockFact, ...]
    instructions: tuple[InstructionFact, ...]
    edges: tuple[ControlFlowEdgeFact, ...]
    calls: tuple[CallSiteFact, ...]
    references: tuple[ReferenceFact, ...]
    behaviors: tuple[StaticBehaviorFact, ...]

    @model_validator(mode="after")
    def check_identity(self):
        data = self.model_dump(mode="json", exclude={"analysis_id"})
        if self.analysis_id != content_id("firmware-static", data):
            raise ValueError("Firmware analysis content identity mismatch")
        ids = [x.fact_id for collection in (self.functions, self.blocks, self.instructions,
                                             self.edges, self.calls, self.references, self.behaviors)
               for x in collection]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate firmware fact identity")
        sha = self.artifact.sha256
        for fact in self.functions:
            if fact.fact_id != content_id("fwfunction", {"elf": sha, **fact.model_dump(mode="json", exclude={"fact_id"})}):
                raise ValueError("Function fact identity mismatch")
        for fact in self.blocks:
            payload = fact.model_dump(mode="json", exclude={"fact_id", "function_ids"})
            if fact.fact_id != content_id("fwblock", {"elf": sha, **payload}):
                raise ValueError("Block fact identity mismatch")
        for fact in self.instructions:
            if fact.fact_id != content_id("fwinstruction", {"elf": sha, "pc": fact.pc, "bytes": fact.raw_bytes}):
                raise ValueError("Instruction fact identity mismatch")
        for fact in self.edges:
            if fact.fact_id != content_id("fwedge", fact.model_dump(mode="json", exclude={"fact_id"})):
                raise ValueError("CFG edge identity mismatch")
        for fact in self.calls:
            if fact.fact_id != content_id("fwcall", {"elf": sha, **fact.model_dump(mode="json", exclude={"fact_id"})}):
                raise ValueError("Call fact identity mismatch")
        for fact in self.references:
            if fact.fact_id != content_id("fwref", {"elf": sha, **fact.model_dump(mode="json", exclude={"fact_id"})}):
                raise ValueError("Reference fact identity mismatch")
        return self


def build_analysis(**fields: object) -> FirmwareStaticAnalysis:
    value = {"schema_version": SCHEMA, **fields}
    return FirmwareStaticAnalysis.model_validate({**value, "analysis_id": content_id("firmware-static", value)})


def serialize_analysis(value: FirmwareStaticAnalysis) -> str:
    return json.dumps(value.model_dump(mode="json"), sort_keys=True, ensure_ascii=False, indent=2) + "\n"
