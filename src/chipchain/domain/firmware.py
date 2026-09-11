"""Existing firmware behavior; static reachability is not runtime reachability."""

from enum import StrEnum

from pydantic import Field

from chipchain.domain.common import Contract, EpistemicStatus, Identifier
from chipchain.domain.evidence import EvidenceRef


class FirmwareFinding(Contract):
    finding_id: Identifier
    summary: Identifier
    evidence: list[EvidenceRef] = Field(default_factory=list)
    processor_behavior_ids: list[Identifier] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.UNKNOWN


class ExternalInputPath(Contract):
    path_id: Identifier
    entry_point: Identifier
    summary: Identifier
    processor_behavior_ids: list[Identifier] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.UNKNOWN


class ReachabilityKind(StrEnum):
    STATIC = "static"
    RUNTIME = "runtime"
    UNKNOWN = "unknown"


class ReachableBehavior(Contract):
    reachability_id: Identifier
    processor_behavior_id: Identifier
    external_input_path_ids: list[Identifier] = Field(default_factory=list)
    reachability_kind: ReachabilityKind = ReachabilityKind.UNKNOWN
    evidence: list[EvidenceRef] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.UNKNOWN


class FirmwareIssueAnchor(Contract):
    anchor_id: Identifier
    firmware_finding_ids: list[Identifier] = Field(default_factory=list)
    processor_behavior_ids: list[Identifier] = Field(default_factory=list)
    summary: Identifier
    evidence: list[EvidenceRef] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.UNKNOWN


class FirmwareAnalysisReport(Contract):
    case_id: Identifier
    findings: list[FirmwareFinding] = Field(default_factory=list)
    external_input_paths: list[ExternalInputPath] = Field(default_factory=list)
    reachable_behaviors: list[ReachableBehavior] = Field(default_factory=list)
    processor_behavior_ids: list[Identifier] = Field(default_factory=list)
    issue_anchors: list[FirmwareIssueAnchor] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
