"""ID-only Firmware model response and deterministic canonical evidence hydration."""

from pydantic import Field

from chipchain.agents.contracts import FirmwareAgentInput
from chipchain.agents.firmware_evidence import collect_firmware_reasoning_evidence
from chipchain.agents.runtime import AgentStructuredOutputError
from chipchain.domain.common import Contract, EpistemicStatus, Identifier
from chipchain.domain.firmware import FirmwareAnalysisReport, ReachabilityKind


class FirmwareBindingError(AgentStructuredOutputError):
    """Fixed categories only; never put model IDs, prose or rejected objects in diagnostics."""

    def __init__(self, reason_code: str) -> None:
        messages = {
            "unknown_evidence_id": "Model response contains unknown firmware evidence IDs",
            "duplicate_evidence_id": "Model response contains duplicate firmware evidence IDs",
            "unknown_finding_id": "Model response contains unknown firmware finding references",
            "unknown_external_input_path_id": "Model response contains unknown firmware external input path references",
            "duplicate_claim_id": "Model response contains duplicate firmware claim IDs",
        }
        super().__init__(messages[reason_code])
        self.reason_code = reason_code


class ModelFirmwareFinding(Contract):
    finding_id: Identifier
    summary: Identifier
    evidence_ids: list[Identifier] = Field(default_factory=list)
    processor_behavior_ids: list[Identifier] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.UNKNOWN


class ModelExternalInputPath(Contract):
    path_id: Identifier
    entry_point: Identifier
    summary: Identifier
    processor_behavior_ids: list[Identifier] = Field(default_factory=list)
    evidence_ids: list[Identifier] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.UNKNOWN


class ModelReachableBehavior(Contract):
    reachability_id: Identifier
    processor_behavior_id: Identifier
    external_input_path_ids: list[Identifier] = Field(default_factory=list)
    reachability_kind: ReachabilityKind = ReachabilityKind.UNKNOWN
    evidence_ids: list[Identifier] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.UNKNOWN


class ModelFirmwareIssueAnchor(Contract):
    anchor_id: Identifier
    firmware_finding_ids: list[Identifier] = Field(default_factory=list)
    processor_behavior_ids: list[Identifier] = Field(default_factory=list)
    summary: Identifier
    evidence_ids: list[Identifier] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.UNKNOWN


class ModelFirmwareAnalysisReport(Contract):
    """Model selects supplied evidence IDs; it must not regenerate EvidenceRef facts."""

    case_id: Identifier
    findings: list[ModelFirmwareFinding] = Field(default_factory=list)
    external_input_paths: list[ModelExternalInputPath] = Field(default_factory=list)
    reachable_behaviors: list[ModelReachableBehavior] = Field(default_factory=list)
    processor_behavior_ids: list[Identifier] = Field(default_factory=list)
    issue_anchors: list[ModelFirmwareIssueAnchor] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)


def validate_firmware_report_references(report: ModelFirmwareAnalysisReport | FirmwareAnalysisReport) -> None:
    """Claim identities/references only. Behavior truth stays in the existing IR gate."""
    for collection, key in ((report.findings, "finding_id"), (report.external_input_paths, "path_id"),
                            (report.reachable_behaviors, "reachability_id"), (report.issue_anchors, "anchor_id")):
        ids = [getattr(item, key) for item in collection]
        if len(ids) != len(set(ids)):
            raise FirmwareBindingError("duplicate_claim_id")
    findings = {item.finding_id for item in report.findings}
    paths = {item.path_id for item in report.external_input_paths}
    for item in report.issue_anchors:
        if not set(item.firmware_finding_ids) <= findings:
            raise FirmwareBindingError("unknown_finding_id")
    for item in report.reachable_behaviors:
        if not set(item.external_input_path_ids) <= paths:
            raise FirmwareBindingError("unknown_external_input_path_id")


def hydrate_firmware_report(model_report: ModelFirmwareAnalysisReport,
                            inputs: FirmwareAgentInput, *, relevant_static_structure=None) -> FirmwareAnalysisReport:
    """Resolve every ID exactly, in order, with isolated deep copies; never repair/drop."""
    registry = collect_firmware_reasoning_evidence(inputs, relevant_static_structure)
    # Also protects direct callers from mutated/unvalidated transport instances.
    model_report = ModelFirmwareAnalysisReport.model_validate(model_report.model_dump())
    validate_firmware_report_references(model_report)
    data = model_report.model_dump()
    for name in ("findings", "external_input_paths", "reachable_behaviors", "issue_anchors"):
        for claim in data[name]:
            ids = claim.pop("evidence_ids")
            if len(ids) != len(set(ids)):
                raise FirmwareBindingError("duplicate_evidence_id")
            if any(identifier not in registry for identifier in ids):
                raise FirmwareBindingError("unknown_evidence_id")
            claim["evidence"] = [registry[identifier].model_copy(deep=True) for identifier in ids]
    return FirmwareAnalysisReport.model_validate(data)
