"""Pydantic input/output boundaries shared by agents and orchestration."""

from typing import Self

from pydantic import model_validator

from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.case import CaseBundle
from chipchain.domain.common import AnalysisLayer, Contract
from chipchain.domain.cross_layer import CrossLayerAnalysisReport
from chipchain.domain.firmware import FirmwareAnalysisReport
from chipchain.domain.hardware import HardwareAnalysisReport
from chipchain.graphs.contracts import BehaviorGraphContext, RetrievedKnowledgeContext
from chipchain.tools.contracts import (
    FirmwareObservation, FirmwareObservations, HardwareObservation, HardwareObservations, ObservationRole,
)


def _validate_observations(
    case: CaseBundle,
    observations: HardwareObservations | FirmwareObservations,
    layer: AnalysisLayer,
) -> None:
    artifacts = (
        case.hardware_artifacts if layer == AnalysisLayer.HARDWARE else case.firmware_artifacts
    )
    if not artifacts:
        raise ValueError(f"{layer.value} agent requires {layer.value} artifacts")
    if observations.case_id != case.case_id:
        raise ValueError("Observation case_id does not match case")
    artifact_ids = {artifact.artifact_id for artifact in artifacts}
    observation_ids = [item.observation_id for item in observations.observations]
    if len(observation_ids) != len(set(observation_ids)):
        raise ValueError("observation_id must be unique within an observation batch")
    for observation in observations.observations:
        if isinstance(observation, (HardwareObservation, FirmwareObservation)) and observation.role != ObservationRole.ANALYSIS_INPUT:
            raise ValueError("Benchmark oracle observations cannot enter agent input")
        evidence = list(observation.evidence)
        for behavior in observation.behaviors:
            if behavior.origin != layer:
                raise ValueError("Observation behavior origin does not match analysis layer")
            evidence.extend(behavior.evidence)
            if isinstance(observation, FirmwareObservation) and behavior.decoded_instruction is not None:
                evidence.extend(behavior.decoded_instruction.evidence)
        if any(ref.artifact_id not in artifact_ids for ref in evidence):
            raise ValueError("Observation evidence refers to an artifact outside its input layer")


def _validate_report_ir(
    report: HardwareAnalysisReport | FirmwareAnalysisReport,
    ir: ProcessorBehaviorIR,
    layer: AnalysisLayer,
) -> None:
    if report.case_id != ir.case_id:
        raise ValueError("Report and IR case_id must match")
    layer_ids = {item.behavior_id for item in ir.behaviors if item.origin == layer}
    refs = list(report.processor_behavior_ids)
    for finding in report.findings:
        refs.extend(finding.processor_behavior_ids)
    if isinstance(report, HardwareAnalysisReport):
        for item in [*report.trigger_hypotheses, *report.abnormal_states]:
            refs.extend(item.processor_behavior_ids)
    else:
        for item in [*report.external_input_paths, *report.issue_anchors]:
            refs.extend(item.processor_behavior_ids)
        refs.extend(item.processor_behavior_id for item in report.reachable_behaviors)
    if not set(refs).issubset(layer_ids):
        raise ValueError(f"Report contains unresolved or wrong-layer {layer.value} behavior IDs")
    finding_ids = [finding.finding_id for finding in report.findings]
    if len(finding_ids) != len(set(finding_ids)):
        raise ValueError("finding_id must be unique within a report")


class HardwareAgentInput(Contract):
    case: CaseBundle
    deterministic_observations: HardwareObservations

    @model_validator(mode="after")
    def validate_input(self) -> Self:
        _validate_observations(self.case, self.deterministic_observations, AnalysisLayer.HARDWARE)
        return self


class HardwareAgentOutput(Contract):
    report: HardwareAnalysisReport
    processor_behavior_ir: ProcessorBehaviorIR

    @model_validator(mode="after")
    def validate_output(self) -> Self:
        _validate_report_ir(self.report, self.processor_behavior_ir, AnalysisLayer.HARDWARE)
        if any(b.origin != AnalysisLayer.HARDWARE for b in self.processor_behavior_ir.behaviors):
            raise ValueError("Hardware output IR must contain only hardware behaviors")
        return self


class FirmwareAgentInput(Contract):
    case: CaseBundle
    deterministic_observations: FirmwareObservations

    @model_validator(mode="after")
    def validate_input(self) -> Self:
        _validate_observations(self.case, self.deterministic_observations, AnalysisLayer.FIRMWARE)
        return self


class FirmwareAgentOutput(Contract):
    report: FirmwareAnalysisReport
    processor_behavior_ir: ProcessorBehaviorIR

    @model_validator(mode="after")
    def validate_output(self) -> Self:
        _validate_report_ir(self.report, self.processor_behavior_ir, AnalysisLayer.FIRMWARE)
        if any(b.origin != AnalysisLayer.FIRMWARE for b in self.processor_behavior_ir.behaviors):
            raise ValueError("Firmware output IR must contain only firmware behaviors")
        return self


class CrossLayerAgentInput(Contract):
    case: CaseBundle
    hardware_report: HardwareAnalysisReport
    firmware_report: FirmwareAnalysisReport
    processor_behavior_ir: ProcessorBehaviorIR
    behavior_graph_context: BehaviorGraphContext | None = None
    retrieved_knowledge_context: RetrievedKnowledgeContext | None = None

    @model_validator(mode="after")
    def validate_eligibility(self) -> Self:
        if not self.case.is_paired:
            raise ValueError("Cross-layer analysis requires a paired case")
        if any(item.case_id != self.case.case_id for item in (
            self.hardware_report, self.firmware_report, self.processor_behavior_ir
        )):
            raise ValueError("Cross-layer reports and IR must belong to the same case")
        _validate_report_ir(self.hardware_report, self.processor_behavior_ir, AnalysisLayer.HARDWARE)
        _validate_report_ir(self.firmware_report, self.processor_behavior_ir, AnalysisLayer.FIRMWARE)
        context = self.behavior_graph_context
        if context is not None:
            if context.case_id != self.case.case_id:
                raise ValueError("Behavior graph context must belong to the same case")
            ids = {item.behavior_id for item in self.processor_behavior_ir.behaviors}
            if not set(context.processor_behavior_ids).issubset(ids):
                raise ValueError("Behavior graph context contains unresolved behavior IDs")
        return self


class CrossLayerAgentOutput(Contract):
    report: CrossLayerAnalysisReport
