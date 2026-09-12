"""Four explicitly fingerprinted files -> static/config/artifact facts only."""

import hashlib
from importlib.metadata import version
from pathlib import Path

from chipchain.domain.behavior import BehaviorKind, ProcessorBehavior
from chipchain.domain.case import ArtifactRef, ArtifactType, TargetDescriptor
from chipchain.domain.common import AnalysisLayer, Architecture, Endianness, EpistemicStatus
from chipchain.domain.evidence import EvidenceLocation, EvidenceRef, EvidenceSourceType
from chipchain.domain.provenance import ToolDescriptor
from chipchain.tools.architecture.arm import ArmThumbInstructionDecoder, memory_direction
from chipchain.tools.contracts import (
    FirmwareObservation, FirmwareObservationKind as Kind, FirmwareObservations,
    ObservationRole, ObservationScope as Scope, OpaqueInputDetails, StaticInstructionSiteDetails,
)
from chipchain.tools.firmware.fuzzware.readers import (
    CONFIG_CAP, FUNCTION_CAP, IMAGE_CAP, INPUT_CAP, MODEL_CAP, SYMBOL_CAP,
    FirmwareIngestionError, parse_configuration, parse_image, read_artifact,
)


class FuzzwareHeatPressScenarioAnalyzer:
    """Supports the researched YAML/ELF32-LE-ARM subset; never discovers companions."""

    def __init__(self) -> None:
        self.decoder = ArmThumbInstructionDecoder()
        self.dependency_versions = {name: version(name) for name in ("PyYAML", "pyelftools", "capstone")}
        config = f"{self.dependency_versions};v1;{IMAGE_CAP};{CONFIG_CAP};{INPUT_CAP};{MODEL_CAP};{SYMBOL_CAP};{FUNCTION_CAP}"
        self.descriptor = ToolDescriptor(tool_name="fuzzware-heat-press-scenario", tool_version="1",
            tool_role="firmware_ingestion", configuration_sha256=hashlib.sha256(config.encode()).hexdigest())

    def analyze(self, *, case_id: str, target: TargetDescriptor, artifacts: list[ArtifactRef]) -> FirmwareObservations:
        if target.architecture != Architecture.ARM or target.word_size_bits != 32 or target.endianness != Endianness.LITTLE:
            raise FirmwareIngestionError("Declare an ARM32 little-endian Thumb target")
        expected = {(ArtifactType.FIRMWARE_BINARY, "elf"), (ArtifactType.FIRMWARE_BINARY, "bin"),
                    (ArtifactType.FIRMWARE_CONFIG, "yaml"), (ArtifactType.FIRMWARE_INPUT, "opaque")}
        if len(artifacts) != 4 or {(a.artifact_type, a.format) for a in artifacts} != expected:
            raise FirmwareIngestionError("Exactly four explicit ELF/BIN/YAML/opaque artifact roles are required")
        if len({a.artifact_id for a in artifacts}) != 4 or len({Path(a.path).resolve() for a in artifacts}) != 4:
            raise FirmwareIngestionError("Artifact IDs and file paths must be distinct")
        refs = {a.format: a for a in artifacts}
        config_data = read_artifact(refs["yaml"], CONFIG_CAP)
        config = parse_configuration(config_data, refs["yaml"].path, refs["bin"].path)
        elf_data = read_artifact(refs["elf"], IMAGE_CAP)
        bin_data = read_artifact(refs["bin"], IMAGE_CAP)
        input_data = read_artifact(refs["opaque"], INPUT_CAP)
        image = parse_image(elf_data, bin_data, config.regions["text"])
        result = FirmwareObservations(case_id=case_id, unresolved_questions=[
            "Static sites and configuration associations do not establish execution or input reachability.",
            "Opaque input has no recorded MMIO consumption, runtime state or failure outcome.",
        ])

        def evidence(identifier, fmt, summary, pc=None):
            return EvidenceRef(evidence_id=identifier, source_type=EvidenceSourceType.ARTIFACT,
                artifact_id=refs[fmt].artifact_id, location=EvidenceLocation(address=pc),
                summary=summary, epistemic_status=EpistemicStatus.OBSERVED)

        decoded_sites = {}
        for pc in sorted({m.pc for m in config.models}):
            identifier = f"s{pc:x}"
            candidates = [f for f in image.functions if f.address <= pc < f.address + f.size]
            try:
                if not candidates:
                    raise ValueError("No containing sized function symbol")
                function = min(candidates, key=lambda f: (f.size, f.address, f.name))
                if function.size > FUNCTION_CAP:
                    raise ValueError("Containing function exceeds decode bound")
                segment = image.locate(function.address, function.size)
                offset = segment.offset + function.address - segment.vaddr
                ref = evidence(identifier, "elf", "ELF code bytes", pc)
                decoded = self.decoder.decode_site(function_bytes=elf_data[offset:offset+function.size],
                    function_address=function.address, pc=pc, observation_id=identifier, evidence=[ref])
                decoded_sites[pc] = decoded
                file_offset = segment.offset + pc - segment.vaddr
                image_offset = segment.paddr - config.regions["text"].base_addr + pc - segment.vaddr
                details = StaticInstructionSiteDetails(address=pc, elf_offset=file_offset, image_offset=image_offset,
                    raw_bytes=decoded.raw_encoding, width_bits=decoded.instruction_width_bits,
                    function=function.name or None, raw_symbol_value=function.raw_value,
                    canonical_function_address=function.address)
                behavior = ProcessorBehavior(behavior_id=identifier, kind=BehaviorKind.INSTRUCTION,
                    architecture=Architecture.ARM, origin=AnalysisLayer.FIRMWARE,
                    summary="Static instruction; execution unknown", evidence=[ref],
                    epistemic_status=EpistemicStatus.DERIVED, attributes={"evidence_scope": "static"}, decoded_instruction=decoded)
                result.observations.append(FirmwareObservation(observation_id=identifier,
                    summary="Confirmed Thumb site", kind=Kind.STATIC_INSTRUCTION_SITE, scope=Scope.STATIC,
                    role=ObservationRole.ANALYSIS_INPUT, details=details, evidence=[ref], behaviors=[behavior],
                    epistemic_status=EpistemicStatus.DERIVED))
            except ValueError as exc:
                result.unresolved_questions.append(f"PC 0x{pc:x}: {exc}; configuration retained.")

        for i, model in enumerate(config.models):
            identifier = f"m{i}"
            ref = evidence(identifier, "yaml", f"Model {model.config_key}", model.pc)
            direction = memory_direction(decoded_sites.get(model.pc), model.access_size_bytes)
            behavior = ProcessorBehavior(behavior_id=identifier, kind=BehaviorKind.MMIO_ACCESS,
                architecture=Architecture.ARM, origin=AnalysisLayer.FIRMWARE,
                summary="Configured access-site association", evidence=[ref], epistemic_status=EpistemicStatus.DERIVED,
                attributes={"evidence_scope": "configuration", "pc": model.pc, "mmio_address": model.mmio_address,
                            "access_size_bytes": model.access_size_bytes, "direction": direction})
            # Direction's code provenance must remain explicit, not just its config source.
            if direction != "unknown":
                behavior.evidence.extend(decoded_sites[model.pc].evidence)
            result.observations.append(FirmwareObservation(observation_id=identifier, summary="MMIO model configuration",
                kind=Kind.MMIO_MODEL, scope=Scope.CONFIGURATION, role=ObservationRole.ANALYSIS_INPUT,
                details=model, evidence=[ref], behaviors=[behavior]))
        result.observations.append(FirmwareObservation(observation_id="input", summary="Opaque environment input artifact",
            kind=Kind.ENVIRONMENT_INPUT, scope=Scope.ARTIFACT, role=ObservationRole.ANALYSIS_INPUT,
            details=OpaqueInputDetails(artifact_id=refs["opaque"].artifact_id, size_bytes=len(input_data),
                                       sha256=hashlib.sha256(input_data).hexdigest()),
            evidence=[evidence("input", "opaque", "Opaque input identity")]))
        result.observations.append(FirmwareObservation(observation_id="trigger", summary="Configured environment trigger",
            kind=Kind.ENVIRONMENT_INPUT, scope=Scope.CONFIGURATION, role=ObservationRole.ANALYSIS_INPUT,
            details=config.trigger, evidence=[evidence("trigger", "yaml", "Interrupt trigger configuration")]))
        return result
