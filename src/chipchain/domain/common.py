"""Small shared value types used across the public contracts."""

from enum import StrEnum
from typing import Annotated, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, StringConstraints

Identifier: TypeAlias = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Scalar: TypeAlias = str | int | float | bool | None
Metadata: TypeAlias = dict[str, Scalar]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True, allow_inf_nan=False)


class Architecture(StrEnum):
    ARM = "arm"
    RISCV = "riscv"
    POWERPC = "powerpc"
    X86 = "x86"
    UNKNOWN = "unknown"


class Endianness(StrEnum):
    """Known byte order of a concrete target, not its supported switching modes."""

    LITTLE = "little"
    BIG = "big"
    UNKNOWN = "unknown"


class EpistemicStatus(StrEnum):
    OBSERVED = "observed"
    DERIVED = "derived"
    INFERRED = "inferred"
    HYPOTHESIZED = "hypothesized"
    VERIFIED = "verified"
    REFUTED = "refuted"
    UNKNOWN = "unknown"


CandidateStatus: TypeAlias = Literal[
    EpistemicStatus.HYPOTHESIZED,
    EpistemicStatus.INFERRED,
    EpistemicStatus.REFUTED,
    EpistemicStatus.UNKNOWN,
]


class AnalysisLayer(StrEnum):
    HARDWARE = "hardware"
    FIRMWARE = "firmware"
