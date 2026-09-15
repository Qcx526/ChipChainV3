"""Build typed facts only from an already approved HardwareAgentInput."""

from chipchain.agents.contracts import HardwareAgentInput
from chipchain.domain.instruction import DecodedInstruction
from chipchain.domain.provenance import ToolDescriptor
from chipchain.tools.contracts import HardwareObservation, HardwareObservationKind as Kind
from chipchain.tools.hardware.relations import (
    FormalCoverAttributes, FormalErrorAttributes, HardwareRelation, HardwareRelationCatalog,
    HardwareRelationSource, InstructionAttributes, LocalDifferenceAttributes,
    RegisterDifferenceAttributes, canonical_json, derive_capabilities, derive_endpoints,
    hardware_relation_id, sha256_text,
)


def build_hardware_relation_catalog(
    inputs: HardwareAgentInput, *, projection_descriptor: ToolDescriptor,
) -> HardwareRelationCatalog:
    """No adapter/oracle input, IO, metadata projection, inference or new decoding.

    Projection identity hashes a sorted allowlist of operational typed details,
    exact evidence references, behavior IDs and existing decodes. It is separate
    from the historical model-context hash (which also contains prose/paths).
    """
    if not isinstance(inputs, HardwareAgentInput):
        raise TypeError("Builder requires HardwareAgentInput")
    inputs = HardwareAgentInput.model_validate_json(inputs.model_dump_json())
    relations, identity, registry, decoders = [], [], {}, {}
    behavior_ids = set()
    for observation in inputs.deterministic_observations.observations:
        if not isinstance(observation, HardwareObservation) or observation.role != "analysis_input" or observation.kind == Kind.MUTATION_PRESENT:
            raise ValueError("Only typed operational hardware observations are eligible")
        if observation.epistemic_status not in ("observed", "derived"):
            raise ValueError("v1 raw observation must be observed/derived")
        details = observation.details
        evidence = list(observation.evidence)
        decoded: list[DecodedInstruction] = []
        local_behavior_ids = []
        for behavior in observation.behaviors:
            if behavior.architecture != inputs.case.target.architecture:
                raise ValueError("Behavior architecture mismatch")
            if behavior.behavior_id in behavior_ids:
                raise ValueError("Duplicate operational behavior identity")
            behavior_ids.add(behavior.behavior_id)
            local_behavior_ids.append(behavior.behavior_id)
            evidence.extend(behavior.evidence)
            if behavior.decoded_instruction is not None:
                decoded.append(behavior.decoded_instruction)
                evidence.extend(behavior.decoded_instruction.evidence)
        if len(decoded) > 1 or (decoded and observation.kind != Kind.INSTRUCTION_ENCODING_OBSERVED):
            raise ValueError("Ambiguous or misplaced deterministic decode")
        if observation.kind == Kind.INSTRUCTION_ENCODING_OBSERVED:
            attrs = InstructionAttributes(
                time=details.time, signal_id=details.host.signal,
                encoding_bits=details.host.value, encoding_width_bits=details.host.width,
                encoding_representation=details.encoding_representation,
                decoded_instruction=decoded[0] if decoded else None,
            )
        elif observation.kind in (Kind.LOCAL_EFFECT_OBSERVED, Kind.ARCHITECTURAL_PROPAGATION_OBSERVED):
            values = {"time": details.time}
            for side in ("host", "reference"):
                signal = getattr(details, side)
                for attr in ("signal", "width", "bit_range", "value"):
                    values[side + "_" + attr] = getattr(signal, attr)
            attrs = (LocalDifferenceAttributes(**values) if observation.kind == Kind.LOCAL_EFFECT_OBSERVED
                     else RegisterDifferenceAttributes(**values, register_name=details.register_name))
        elif observation.kind == Kind.FORMAL_RESULT:
            values = dict(raw_result=details.raw_result, interpretation_boundary=details.interpretation_boundary)
            attrs = (FormalCoverAttributes(**values, property_name=details.property_name, cycles=details.cycles)
                     if details.category == "cover_hit" else FormalErrorAttributes(**values, error_code=details.error_code))
        else:
            raise ValueError("Unsupported observation kind")
        artifact_ids = {a.artifact_id for a in inputs.case.hardware_artifacts}
        for ref in evidence:
            if ref.artifact_id not in artifact_ids:
                raise ValueError("Evidence belongs to an unavailable artifact")
            if ref.evidence_id in registry and registry[ref.evidence_id] != ref:
                raise ValueError("Conflicting evidence registry identity")
            registry[ref.evidence_id] = ref
        evidence_ids = sorted({e.evidence_id for e in evidence})
        relation = HardwareRelation(
            relation_id=hardware_relation_id(observation.observation_id, attrs.kind), kind=attrs.kind,
            source_observation_id=observation.observation_id, evidence_ids=evidence_ids,
            status=observation.epistemic_status,
            attributes=attrs, endpoints=derive_endpoints(attrs), capabilities=derive_capabilities(attrs, observation.epistemic_status),
        )
        relations.append(relation)
        identity.append({"observation_id": observation.observation_id, "status": observation.epistemic_status,
                         "attributes": attrs.model_dump(mode="json"), "evidence_ids": evidence_ids,
                         "behavior_ids": sorted(local_behavior_ids)})
        for d in decoded:
            decoders[canonical_json(d.decoder.model_dump(mode="json"))] = d.decoder
    evidence_json = [registry[k].model_dump(mode="json") for k in sorted(registry)]
    evidence_sha = sha256_text(canonical_json(evidence_json))
    architecture = inputs.case.target.architecture
    projection = {"case_id": inputs.case.case_id, "architecture": architecture,
                  "projection": projection_descriptor.model_dump(mode="json"),
                  "observations": sorted(identity, key=lambda o: o["observation_id"]),
                  "evidence_registry_sha256": evidence_sha}
    catalog = HardwareRelationCatalog(source=HardwareRelationSource(
        case_id=inputs.case.case_id, architecture=architecture,
        operational_projection=projection_descriptor,
        operational_projection_sha256=sha256_text(canonical_json(projection)),
        observation_count=len(relations), behavior_count=len(behavior_ids),
        evidence_registry_sha256=evidence_sha, evidence_registry_count=len(registry),
        evidence_ids=sorted(registry), decoder_descriptors=[decoders[k] for k in sorted(decoders)],
    ), relations=relations)
    # Return the same canonical order as the codec, even for shuffled producer input.
    from chipchain.tools.hardware.relations import parse_hardware_relation_catalog, serialize_hardware_relation_catalog
    return parse_hardware_relation_catalog(serialize_hardware_relation_catalog(catalog))
