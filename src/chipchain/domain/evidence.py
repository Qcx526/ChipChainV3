"""Evidence and lightweight provenance locations."""

from enum import StrEnum

from typing import Literal, Self

from pydantic import ConfigDict, Field, model_validator

from chipchain.domain.common import Contract, EpistemicStatus, Identifier


class EvidenceSourceType(StrEnum):
    ARTIFACT = "artifact"
    DETERMINISTIC_ANALYZER = "deterministic_analyzer"
    MANUAL = "manual"
    SYNTHETIC = "synthetic"


class EvidenceTime(Contract):
    value: int = Field(ge=0, strict=True)
    unit: Literal["s", "ms", "us", "ns", "ps", "fs"]


class BitRange(Contract):
    msb: int = Field(ge=0, strict=True)
    lsb: int = Field(ge=0, strict=True)

    @model_validator(mode="after")
    def descending_range(self) -> Self:
        if self.msb < self.lsb:
            raise ValueError("Only descending bit ranges are supported")
        return self


class EvidenceLocation(Contract):
    model_config = ConfigDict(populate_by_name=True)

    address: int | None = Field(default=None, ge=0)
    function: Identifier | None = None
    basic_block: Identifier | None = None
    line: int | None = Field(default=None, ge=1)
    instruction_index: int | None = Field(default=None, ge=0)
    # BaseModel inherits ABCMeta.register; accept the concise wire name as an alias.
    register_name: Identifier | None = Field(default=None, alias="register")
    signal: Identifier | None = None
    time: EvidenceTime | None = None
    bit_range: BitRange | None = None


class EvidenceRef(Contract):
    evidence_id: Identifier
    source_type: EvidenceSourceType
    artifact_id: Identifier
    analyzer: Identifier | None = None
    location: EvidenceLocation = Field(default_factory=EvidenceLocation)
    summary: Identifier
    epistemic_status: EpistemicStatus = EpistemicStatus.UNKNOWN
