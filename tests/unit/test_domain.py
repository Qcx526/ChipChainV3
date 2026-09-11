from collections.abc import Callable

import pytest
from pydantic import ValidationError

from chipchain.domain.behavior import BehaviorKind, ProcessorBehavior, ProcessorBehaviorIR
from chipchain.domain.case import CaseBundle
from chipchain.domain.common import AnalysisLayer, Architecture, Contract, EpistemicStatus
from chipchain.domain.cross_layer import (
    AttackChainCandidate, CrossLayerAnalysisReport, CrossLayerCandidate, CrossLayerType,
    MissingConstraint, RootLocationCandidate, TriggerFeature,
)
from chipchain.domain.evidence import EvidenceLocation, EvidenceRef, EvidenceSourceType
from chipchain.domain.firmware import (
    ExternalInputPath, FirmwareAnalysisReport, FirmwareFinding, FirmwareIssueAnchor,
    ReachabilityKind, ReachableBehavior,
)
from chipchain.domain.hardware import (
    AbnormalState, HardwareAnalysisReport, HardwareFinding, HardwareTriggerHypothesis,
    TriggerConstraint,
)


def assert_round_trip(model: Contract) -> None:
    assert type(model).model_validate(model.model_dump()) == model
    assert type(model).model_validate_json(model.model_dump_json()) == model


def evidence(artifact_id: str = "synthetic:hardware:artifact") -> EvidenceRef:
    return EvidenceRef(
        evidence_id=f"{artifact_id}:evidence",
        source_type=EvidenceSourceType.SYNTHETIC,
        artifact_id=artifact_id,
        analyzer="synthetic-test-fixture",
        location=EvidenceLocation(instruction_index=0),
        summary="Synthetic observation, not an actual analysis result",
        epistemic_status=EpistemicStatus.OBSERVED,
    )


def behavior(layer: AnalysisLayer) -> ProcessorBehavior:
    return ProcessorBehavior(
        behavior_id=f"synthetic:{layer.value}:behavior",
        kind=BehaviorKind.INSTRUCTION,
        architecture=Architecture.UNKNOWN,
        origin=layer,
        summary="Synthetic processor behavior",
        evidence=[evidence(f"synthetic:{layer.value}:artifact")],
        epistemic_status=EpistemicStatus.OBSERVED,
        attributes={"synthetic": True},
    )


@pytest.mark.parametrize("name,hardware,firmware", [
    ("hardware_only", True, False), ("firmware_only", False, True), ("paired", True, True),
])
def test_case_modes_and_round_trip(
    load_case: Callable[[str], CaseBundle], name: str, hardware: bool, firmware: bool,
) -> None:
    case = load_case(name)
    assert case.has_hardware_inputs is hardware
    assert case.has_firmware_inputs is firmware
    assert case.is_paired is (hardware and firmware)
    assert case.metadata["synthetic"] is True
    assert "is_paired" not in case.model_dump()
    assert_round_trip(case)


def test_empty_case_is_rejected(load_case: Callable[[str], CaseBundle]) -> None:
    data = load_case("paired").model_dump()
    data.update(hardware_artifacts=[], firmware_artifacts=[])
    with pytest.raises(ValidationError, match="at least one"):
        CaseBundle.model_validate(data)


def test_duplicate_artifacts_and_unexpected_fields_rejected(
    load_case: Callable[[str], CaseBundle],
) -> None:
    data = load_case("paired").model_dump()
    data["firmware_artifacts"] = data["hardware_artifacts"]
    with pytest.raises(ValidationError, match="unique"):
        CaseBundle.model_validate(data)
    data = load_case("paired").model_dump()
    data["is_paired"] = False
    with pytest.raises(ValidationError, match="Extra inputs"):
        CaseBundle.model_validate(data)


def test_metadata_is_a_bounded_extension(load_case: Callable[[str], CaseBundle]) -> None:
    data = load_case("paired").model_dump()
    data["metadata"] = {"hidden_schema": {"unconstrained": []}}
    with pytest.raises(ValidationError):
        CaseBundle.model_validate(data)


def test_unified_ir_and_evidence_reference_chain() -> None:
    hw, fw = behavior(AnalysisLayer.HARDWARE), behavior(AnalysisLayer.FIRMWARE)
    ir = ProcessorBehaviorIR(case_id="synthetic:paired", behaviors=[hw, fw])
    hardware = HardwareFinding(
        finding_id="hw:finding", summary="Synthetic hardware finding",
        processor_behavior_ids=[hw.behavior_id], evidence=hw.evidence,
        epistemic_status=EpistemicStatus.DERIVED,
    )
    firmware = FirmwareFinding(
        finding_id="fw:finding", summary="Synthetic firmware finding",
        processor_behavior_ids=[fw.behavior_id], evidence=fw.evidence,
    )
    candidate = CrossLayerCandidate(
        candidate_id="candidate", candidate_type=CrossLayerType.TYPE_II,
        summary="Synthetic candidate for contract testing only",
        hardware_finding_ids=[hardware.finding_id], firmware_finding_ids=[firmware.finding_id],
        processor_behavior_ids=[hw.behavior_id, fw.behavior_id],
        evidence=[*hw.evidence, *fw.evidence],
    )
    assert candidate.hardware_finding_ids == [hardware.finding_id]
    assert hardware.processor_behavior_ids[0] == ir.behaviors[0].behavior_id
    assert hardware.evidence[0].artifact_id == "synthetic:hardware:artifact"
    for model in (ir, hw, fw, hardware, firmware, candidate, *candidate.evidence):
        assert_round_trip(model)
    with pytest.raises(ValidationError, match="unique"):
        ProcessorBehaviorIR(case_id="synthetic:paired", behaviors=[hw, hw])


def test_all_report_structures_round_trip() -> None:
    hw, fw = behavior(AnalysisLayer.HARDWARE), behavior(AnalysisLayer.FIRMWARE)
    hardware = HardwareAnalysisReport(
        case_id="synthetic:paired",
        findings=[HardwareFinding(finding_id="hw:finding", summary="Synthetic")],
        trigger_hypotheses=[HardwareTriggerHypothesis(
            hypothesis_id="hypothesis", summary="Proposed condition only",
            hardware_finding_ids=["hw:finding"],
            constraints=[TriggerConstraint(subject="execution_mode", relation="equals", value="unknown")],
        )],
        abnormal_states=[AbnormalState(state_id="state", summary="Synthetic abnormal state")],
        processor_behavior_ids=[hw.behavior_id], unresolved_questions=["No real analysis"],
    )
    firmware = FirmwareAnalysisReport(
        case_id="synthetic:paired",
        findings=[FirmwareFinding(finding_id="fw:finding", summary="Synthetic")],
        external_input_paths=[ExternalInputPath(path_id="path", entry_point="synthetic-entry", summary="Synthetic")],
        reachable_behaviors=[ReachableBehavior(
            reachability_id="reachability", processor_behavior_id=fw.behavior_id,
            external_input_path_ids=["path"], reachability_kind=ReachabilityKind.STATIC,
        )],
        processor_behavior_ids=[fw.behavior_id],
        issue_anchors=[FirmwareIssueAnchor(anchor_id="anchor", summary="Synthetic")],
    )
    cross = CrossLayerAnalysisReport(
        case_id="synthetic:paired",
        candidates=[CrossLayerCandidate(candidate_id="candidate", candidate_type=CrossLayerType.TYPE_I, summary="Synthetic")],
        attack_chain_candidates=[AttackChainCandidate(candidate_id="chain", candidate_type=CrossLayerType.TYPE_I, summary="Synthetic")],
        trigger_features=[TriggerFeature(feature_id="feature", description="Proposed feature")],
        root_location_candidates=[RootLocationCandidate(candidate_id="root", summary="Synthetic")],
        missing_constraints=[MissingConstraint(constraint_id="constraint", description="Missing runtime evidence")],
    )
    for model in (hardware, firmware, cross):
        assert_round_trip(model)
    assert firmware.reachable_behaviors[0].reachability_kind == ReachabilityKind.STATIC
    assert firmware.reachable_behaviors[0].epistemic_status == EpistemicStatus.UNKNOWN


@pytest.mark.parametrize("model,data", [
    (HardwareTriggerHypothesis, {"hypothesis_id": "h", "summary": "Synthetic"}),
    (CrossLayerCandidate, {"candidate_id": "c", "summary": "Synthetic", "candidate_type": "TYPE_II"}),
    (AttackChainCandidate, {"candidate_id": "c", "summary": "Synthetic", "candidate_type": "TYPE_III"}),
    (TriggerFeature, {"feature_id": "t", "description": "Synthetic"}),
    (RootLocationCandidate, {"candidate_id": "r", "summary": "Synthetic"}),
])
def test_candidates_cannot_be_verified(model: type[Contract], data: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        model.model_validate({**data, "epistemic_status": "verified"})


@pytest.mark.parametrize("location", [{"address": -1}, {"line": 0}, {"instruction_index": -1}])
def test_location_ranges(location: dict[str, int]) -> None:
    with pytest.raises(ValidationError):
        EvidenceLocation.model_validate(location)


def test_register_location_alias_round_trip() -> None:
    location = EvidenceLocation.model_validate({"register": "synthetic-register"})
    assert location.register_name == "synthetic-register"
    assert location.model_dump(by_alias=True)["register"] == "synthetic-register"
    assert_round_trip(location)
