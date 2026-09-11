"""Adapter-local benchmark boundary; never attached to CaseBundle ground truth."""

from enum import StrEnum
from typing import TYPE_CHECKING, Self

from pydantic import Field, model_validator

from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.case import ArtifactRef, CaseBundle, TargetDescriptor
from chipchain.domain.common import Contract, Identifier
from chipchain.tools.contracts import HardwareObservation, HardwareObservations, ObservationRole

if TYPE_CHECKING:
    from chipchain.agents.contracts import HardwareAgentInput


class IngestionError(ValueError):
    """Missing, malformed, resource-limited, or unsupported corpus input."""


class ArtifactRole(StrEnum):
    ANALYSIS_INPUT = "analysis_input"
    VERIFICATION_EVIDENCE = "verification_evidence"
    BENCHMARK_ORACLE = "benchmark_oracle"
    SUPPORTING_CONTEXT = "supporting_context"


class ClassifiedArtifact(Contract):
    path: Identifier
    roles: list[ArtifactRole] = Field(min_length=1)
    explanation: Identifier


class EnCorpusOracle(Contract):
    observations: list[HardwareObservation] = Field(default_factory=list)
    processor_behavior_ir: ProcessorBehaviorIR
    limitations: list[str]

    @model_validator(mode="after")
    def oracle_roles(self) -> Self:
        if any(o.role != ObservationRole.BENCHMARK_ORACLE for o in self.observations):
            raise ValueError("Oracle must contain benchmark observations only")
        return self


class EnCorpusIngestionResult(Contract):
    sample_identity: Identifier
    target: TargetDescriptor
    observations: HardwareObservations
    processor_behavior_ir: ProcessorBehaviorIR
    oracle: EnCorpusOracle
    artifacts: list[ArtifactRef]
    artifact_roles: list[ClassifiedArtifact]

    @model_validator(mode="after")
    def isolated_analysis(self) -> Self:
        if any(not isinstance(o, HardwareObservation) or o.role != ObservationRole.ANALYSIS_INPUT
               for o in self.observations.observations):
            raise ValueError("Analysis projection cannot contain oracle observations")
        case_id = self.observations.case_id
        if any(ir.case_id != case_id for ir in [self.processor_behavior_ir, self.oracle.processor_behavior_ir]):
            raise ValueError("Ingestion case IDs must match")
        projected = [b for o in self.observations.observations for b in o.behaviors]
        if projected != self.processor_behavior_ir.behaviors:
            raise ValueError("Analysis IR must come only from analysis observations")
        oracle_behaviors = [b for o in self.oracle.observations for b in o.behaviors]
        if oracle_behaviors != self.oracle.processor_behavior_ir.behaviors:
            raise ValueError("Oracle IR must come only from oracle observations")
        observations = [*self.observations.observations, *self.oracle.observations]
        if len({o.observation_id for o in observations}) != len(observations):
            raise ValueError("Ingestion observation IDs must be unique")
        artifact_ids = {a.artifact_id for a in self.artifacts}
        for observation in observations:
            if any(not b.evidence for b in observation.behaviors):
                raise ValueError("Ingested behaviors require explicit evidence")
            refs = [*observation.evidence, *(e for b in observation.behaviors for e in b.evidence)]
            if any(e.artifact_id not in artifact_ids for e in refs):
                raise ValueError("Ingestion evidence must reference an input artifact")
        return self

    def analysis_input(self) -> "HardwareAgentInput":
        """Build the existing agent DTO without running an agent or exposing oracle.

        Only source provenance for host instruction observations is included.
        The referenced VCD itself is mixed-role; this DTO grants no raw-file tool.
        """
        from chipchain.agents.contracts import HardwareAgentInput

        evidence_ids = {
            e.artifact_id for o in self.observations.observations
            for e in [*o.evidence, *(e for b in o.behaviors for e in b.evidence)]
        }
        # A VCD with no valid ID observations still supplies an explicit input artifact.
        artifacts = [a.model_copy(deep=True) for a in self.artifacts
                     if a.artifact_id in evidence_ids or a.format == "vcd"]
        case = CaseBundle(case_id=self.observations.case_id, name=self.sample_identity,
                          target=self.target.model_copy(deep=True), hardware_artifacts=artifacts)
        return HardwareAgentInput(case=case, deterministic_observations=self.observations.model_copy(deep=True))
