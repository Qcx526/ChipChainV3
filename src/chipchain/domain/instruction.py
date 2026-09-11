"""Architecture-neutral instruction encoding/decoding, without execution claims."""

from enum import StrEnum
from typing import Literal, Self

from pydantic import ConfigDict, Field, model_validator

from chipchain.domain.common import Architecture, Contract, EpistemicStatus, Identifier
from chipchain.domain.evidence import EvidenceRef
from chipchain.domain.provenance import ToolDescriptor


class EncodingRepresentation(StrEnum):
    INSTRUCTION_WORD = "instruction_word"
    DECOMPRESSED_WORD = "decompressed_word"
    UNKNOWN = "unknown"


class InstructionEncoding(Contract):
    observation_id: Identifier
    architecture: Architecture
    # MSB-first bit-vector, not a memory byte stream; preserve unknown bits.
    bits: str = Field(pattern=r"^[01xz]+$")
    width_bits: int = Field(gt=0, strict=True)
    representation: EncodingRepresentation = EncodingRepresentation.UNKNOWN
    source_stage: Identifier
    evidence: list[EvidenceRef] = Field(min_length=1)

    @model_validator(mode="after")
    def consistent_width(self) -> Self:
        if len(self.bits) != self.width_bits:
            raise ValueError("Encoding width must match its bit-vector")
        return self


class DecodeStatus(StrEnum):
    DECODED = "decoded"
    UNSUPPORTED = "unsupported"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class DecodedOperand(Contract):
    """Ordered backend operands, not an ISA AST or a read/write access list."""

    model_config = ConfigDict(populate_by_name=True)

    kind: Literal["register", "immediate", "memory"]
    register_name: Identifier | None = Field(default=None, alias="register")
    immediate: int | None = Field(default=None, strict=True)
    base: Identifier | None = None
    displacement: int | None = Field(default=None, strict=True)

    @model_validator(mode="after")
    def fields_match_kind(self) -> Self:
        present = {k for k in ["register_name", "immediate", "base", "displacement"] if getattr(self, k) is not None}
        expected = {"register": {"register_name"}, "immediate": {"immediate"}, "memory": {"base", "displacement"}}
        if present != expected[self.kind]:
            raise ValueError("Operand fields do not match kind")
        return self


class DecodedInstruction(Contract):
    observation_id: Identifier
    architecture: Architecture
    raw_encoding: Identifier
    instruction_width_bits: int = Field(gt=0, strict=True)
    representation: EncodingRepresentation
    source_stage: Identifier
    status: DecodeStatus
    reason: Identifier | None = None
    mnemonic: Identifier | None = None
    operand_text: str | None = None
    backend_operand_text: str | None = None
    operands: list[DecodedOperand] = Field(default_factory=list)
    decoder: ToolDescriptor
    decoder_mode: Identifier
    evidence: list[EvidenceRef] = Field(min_length=1)
    epistemic_status: Literal[EpistemicStatus.DERIVED] = EpistemicStatus.DERIVED

    @model_validator(mode="after")
    def success_or_reason(self) -> Self:
        if self.status == DecodeStatus.DECODED:
            if self.mnemonic is None or self.operand_text is None or self.reason is not None:
                raise ValueError("Successful decode requires mnemonic/operands and no failure reason")
        elif self.reason is None or self.mnemonic is not None or self.operands or self.operand_text is not None:
            raise ValueError("Unsuccessful decode must preserve a reason without asserted decoded operands")
        return self
