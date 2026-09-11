"""Small shared value types used across the public contracts."""

from enum import StrEnum
from typing import Annotated, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Identifier: TypeAlias = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Scalar: TypeAlias = str | int | float | bool | None
Metadata: TypeAlias = dict[str, Scalar]
Sha256: TypeAlias = Annotated[str, StringConstraints(
    strict=True, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$",
)]
FileSize: TypeAlias = Annotated[int, Field(strict=True, ge=0)]


class AnalysisStatus(StrEnum):
    PENDING = "pending"
    NOT_APPLICABLE = "not_applicable"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class WorkflowStage(StrEnum):
    HARDWARE = "hardware"
    FIRMWARE = "firmware"
    IR_AGGREGATION = "ir_aggregation"
    CROSS_LAYER = "cross_layer"


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
