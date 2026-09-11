"""Cases contain references, never binary contents."""

from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from chipchain.domain.common import Architecture, Contract, Endianness, Identifier, Metadata


class ArtifactType(StrEnum):
    HARDWARE_TESTCASE = "hardware_testcase"
    HARDWARE_TRACE = "hardware_trace"
    HARDWARE_DESCRIPTION = "hardware_description"
    FIRMWARE_BINARY = "firmware_binary"
    FIRMWARE_SOURCE = "firmware_source"
    OTHER = "other"


class ArtifactRef(Contract):
    artifact_id: Identifier
    artifact_type: ArtifactType
    path: Identifier
    format: Identifier
    metadata: Metadata = Field(default_factory=dict)


class TargetDescriptor(Contract):
    """Architecture-neutral target metadata; unknown details need not be invented."""

    architecture: Architecture = Architecture.UNKNOWN
    processor_id: Identifier
    firmware_id: Identifier | None = None
    isa_variant: str | None = None
    word_size_bits: int | None = Field(default=None, gt=0, strict=True)
    endianness: Endianness = Endianness.UNKNOWN


class CaseLabel(StrEnum):
    UNLABELED = "unlabeled"
    CONFIRMED_CROSS_LAYER = "confirmed_cross_layer"


class CaseBundle(Contract):
    case_id: Identifier
    name: Identifier
    target: TargetDescriptor
    hardware_artifacts: list[ArtifactRef] = Field(default_factory=list)
    firmware_artifacts: list[ArtifactRef] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)
    ground_truth_label: CaseLabel = CaseLabel.UNLABELED

    @property
    def has_hardware_inputs(self) -> bool:
        return bool(self.hardware_artifacts)

    @property
    def has_firmware_inputs(self) -> bool:
        return bool(self.firmware_artifacts)

    @property
    def is_paired(self) -> bool:
        return self.has_hardware_inputs and self.has_firmware_inputs

    @model_validator(mode="after")
    def validate_artifacts(self) -> Self:
        artifacts = self.hardware_artifacts + self.firmware_artifacts
        if not artifacts:
            raise ValueError("A case requires at least one hardware or firmware artifact")
        ids = [artifact.artifact_id for artifact in artifacts]
        if len(ids) != len(set(ids)):
            raise ValueError("artifact_id must be unique within a case")
        return self
