"""B.1 projection policy for A1 outputs, not a new parser or causal analyzer."""

from chipchain.agents.contracts import HardwareAgentInput
from chipchain.domain.case import CaseBundle
from chipchain.domain.provenance import ToolDescriptor
from chipchain.tools.contracts import HardwareObservationKind as Kind, HardwareObservations, ObservationRole
from chipchain.tools.hardware.encorpus.ibex_driver import (
    ANALYZER_ID, ENCODINGS, FORMAL_BOUNDARY, GPR, HOST, LOCAL, REFERENCE,
)
from chipchain.tools.hardware.encorpus.models import EnCorpusIngestionResult

PROJECTION_DESCRIPTOR = ToolDescriptor(tool_name="encorpus-operational-projection",
                                       tool_version="v1", tool_role="hardware_input_projection")
OPERATIONAL_LIMITATIONS = [
    FORMAL_BOUNDARY,
    "DUT/reference differences are deterministic operational observations, not root-cause or trigger verification.",
    "Local-state signals are internal waveform observations available in this corpus test setup; on-chip visibility is not assumed.",
    "GPR packing uses the A0-checked Ibex 32-bit layout. Register-state differences do not establish read/write direction or retirement.",
    "Only the existing selected local-state and architectural comparisons are projected; missing or unknown values are not inferred.",
]


def _approved(observation, artifacts) -> bool:
    """Require supported source provenance and representation, not kind alone."""
    if observation.kind == Kind.MUTATION_PRESENT:
        return False
    refs = [*observation.evidence, *(e for b in observation.behaviors for e in b.evidence)]
    source_format = "log" if observation.kind == Kind.FORMAL_RESULT else "vcd"
    source_name = "verify.log" if source_format == "log" else "proof.vcd"
    if not refs or any(
        e.source_type != "deterministic_analyzer" or e.analyzer != ANALYZER_ID
        or e.artifact_id not in artifacts or artifacts[e.artifact_id].format != source_format
        or not e.artifact_id.endswith(":" + source_name)
        for e in refs
    ):
        return False
    details = observation.details
    if observation.kind == Kind.FORMAL_RESULT:
        return (details.interpretation_boundary == FORMAL_BOUNDARY and not observation.behaviors and (
            (details.category == "cover_hit" and details.property_name == "miter.i_miter.c_propagated")
            or (details.category == "trace_error" and details.error_code == "EVS053")
        ))
    if observation.kind == Kind.INSTRUCTION_ENCODING_OBSERVED:
        return details.host.signal in {HOST + name for name in ENCODINGS}
    if details.reference is None:
        return False
    pairs = LOCAL if observation.kind == Kind.LOCAL_EFFECT_OBSERVED else [GPR]
    return any(details.host.signal == HOST + name and details.reference.signal == REFERENCE + name
               for name in pairs)


def build_hardware_analysis_projection(result: EnCorpusIngestionResult) -> HardwareAgentInput:
    """Select existing facts losslessly and relabel copies; never disclose RTL anchors.

    A1's oracle container is a legacy collection of *both* comparisons/tool results
    and benchmark answers. Its contents are not automatically analysis eligible.
    No raw artifact contents, oracle limitations, mutation objects, or mutation IR
    are copied. Unsupported producers/signals remain excluded by default.
    """
    artifacts = {a.artifact_id: a for a in result.artifacts}
    selected = []
    for observation in [*result.observations.observations, *result.oracle.observations]:
        if _approved(observation, artifacts):
            data = observation.model_dump()
            data["role"] = ObservationRole.ANALYSIS_INPUT
            selected.append(type(observation).model_validate(data))
    used = {e.artifact_id for o in selected for e in [*o.evidence, *(e for b in o.behaviors for e in b.evidence)]}
    sources = [a.model_copy(deep=True) for a in result.artifacts
               if a.artifact_id in used or a.format == "vcd"]
    case = CaseBundle(case_id=result.observations.case_id, name=result.sample_identity,
                      target=result.target.model_copy(deep=True), hardware_artifacts=sources)
    return HardwareAgentInput(case=case, deterministic_observations=HardwareObservations(
        case_id=case.case_id, observations=selected,
        unresolved_questions=[*result.observations.unresolved_questions, *OPERATIONAL_LIMITATIONS],
    ))
