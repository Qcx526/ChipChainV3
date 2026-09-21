"""XL1 requirements, never a record that a deviation occurred.

Pure value contracts. Registries bind stable source identities and content hashes;
no filesystem access, model calls, matching, or runtime state is involved.
"""
from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, StrictBool, StrictInt, StrictStr, model_validator

from chipchain.cross_layer.trigger import (
    CSRTriggerAtom, InstructionTriggerAtom, MMIOTriggerAtom, OrderingTriggerAtom,
    PrivilegeTriggerAtom, TriggerAtom,
)
from chipchain.domain.case import TargetDescriptor
from chipchain.domain.common import Architecture, Contract, Identifier, Sha256
from chipchain.domain.evidence import EvidenceRef

SCHEMA_VERSION = 'hardware-behavior-contract/v1'


class FormalizationStatus(StrEnum):
    FORMALIZED = 'formalized'
    PARTIAL = 'partially_formalized'
    UNFORMALIZED = 'unformalized'
    UNKNOWN = 'unknown'


SourceKind = Literal[
    'encorpus_observation', 'rtl_mutation_description', 'formal_result',
    'cve_erratum_metadata', 'hardware_a3', 'xl0_trigger',
    'manual_research_input', 'synthetic_fixture',
]


class SourceArtifact(Contract):
    artifact_id: Identifier
    sha256: Sha256
    source_kind: SourceKind


class Provenance(Contract):
    source_kind: SourceKind
    source_artifact_ids: list[Identifier] = Field(min_length=1)
    source_ids: list[Identifier] = Field(default_factory=list)
    transformation: Literal['explicit_input', 'xl0_partial_v1'] = 'explicit_input'


class BoundRequirement(Contract):
    source_artifact_ids: list[Identifier] = Field(min_length=1)
    evidence_ids: list[Identifier] = Field(default_factory=list)
    provenance: list[Provenance] = Field(min_length=1)


class Platform(BoundRequirement):
    target: TargetDescriptor
    platform_id: Identifier | None = None
    rtl_identity: Identifier | None = None
    rtl_revision: Identifier | None = None
    silicon_revision: Identifier | None = None


Value = StrictStr | StrictInt | StrictBool


class Predicate(Contract):
    """A declared comparison, not a solver result. Operand order is significant."""
    subject: Identifier
    operator: Literal['eq', 'neq', 'masked_eq', 'in_range', 'present', 'before']
    operands: list[Value] = Field(default_factory=list)
    unit: Identifier | None = None

    @model_validator(mode='after')
    def operands_match(self):
        size = {'eq': 1, 'neq': 1, 'masked_eq': 2, 'in_range': 2, 'present': 0, 'before': 1}
        if len(self.operands) != size[self.operator]:
            raise ValueError('Predicate operands do not match operator')
        if self.operator in ('masked_eq', 'in_range'):
            if any(type(x) is not int for x in self.operands):
                raise ValueError('Numeric predicate requires integer operands')
            a, b = self.operands
            if self.operator == 'in_range' and a > b:
                raise ValueError('Reversed range')
            if self.operator == 'masked_eq' and (a < 0 or b < 0 or a & ~b):
                raise ValueError('Masked value must fit mask')
        return self


class Condition(BoundRequirement):
    condition_id: Identifier
    description: Identifier
    formalization_status: FormalizationStatus = FormalizationStatus.UNKNOWN


class Precondition(Condition):
    condition_kind: Literal[
        'privilege', 'execution_context', 'register_state', 'CSR_state',
        'memory_attribute', 'protection_state', 'microarchitectural_state',
        'hardware_mode', 'ordering_precondition', 'other',
    ]
    required_relation: Predicate | None = None

    @model_validator(mode='after')
    def completeness(self):
        if self.formalization_status == FormalizationStatus.FORMALIZED and self.required_relation is None:
            raise ValueError('Formalized precondition requires a structured relation')
        return self


class TriggerCondition(Condition):
    condition_kind: Literal[
        'instruction', 'instruction_sequence', 'register_state', 'CSR_access',
        'MMIO_access', 'memory_operation', 'interrupt', 'exception', 'ordering',
        'timing_window', 'concurrency', 'transaction', 'other',
    ]
    instructions: list[InstructionTriggerAtom] = Field(default_factory=list)
    access: CSRTriggerAtom | MMIOTriggerAtom | None = None
    ordering: OrderingTriggerAtom | None = None
    required_relation: Predicate | None = None

    @model_validator(mode='after')
    def typed_payload(self):
        present = {k for k in ('instructions', 'access', 'ordering', 'required_relation') if getattr(self, k)}
        expected = {'instruction': 'instructions', 'instruction_sequence': 'instructions',
                    'CSR_access': 'access', 'MMIO_access': 'access', 'ordering': 'ordering'}.get(
                        self.condition_kind, 'required_relation')
        if present - {expected}:
            raise ValueError('Trigger kind and payload disagree')
        if self.condition_kind == 'instruction' and len(self.instructions) > 1:
            raise ValueError('Single instruction requires one element')
        if self.access is not None and self.access.kind != self.condition_kind.lower():
            raise ValueError('Access kind mismatch')
        if self.formalization_status == FormalizationStatus.FORMALIZED and expected not in present:
            raise ValueError('Formalized trigger requires its typed payload')
        for atom in [*self.instructions, *([self.access] if self.access else []),
                     *([self.ordering] if self.ordering else [])]:
            if atom.purpose != 'required':
                raise ValueError('Verification metadata is not a trigger requirement')
        return self


class Deviation(Condition):
    deviation_kind: Literal[
        'wrong_value', 'missing_update', 'unexpected_update', 'missing_exception',
        'unexpected_exception', 'access_control_violation', 'ordering_violation',
        'protocol_violation', 'state_corruption', 'timing_deviation',
        'information_leakage', 'other', 'unknown',
    ]
    affected_component: Identifier | None = None
    expected_behavior: Predicate | None = None
    deviating_behavior: Predicate | None = None
    specification_ref: Identifier | None = None
    first_divergence_point: Identifier | None = None
    hardware_constraint_status: Literal['specified', 'partially_specified', 'unknown'] = 'unknown'

    @model_validator(mode='after')
    def completeness(self):
        if self.formalization_status == FormalizationStatus.FORMALIZED and (
            self.deviation_kind == 'unknown' or self.hardware_constraint_status != 'specified'
            or any(x is None for x in (self.affected_component, self.expected_behavior,
                                      self.deviating_behavior, self.specification_ref))
        ):
            raise ValueError('Formalized deviation requires expected/deviating behavior and specification')
        if self.expected_behavior is not None and self.expected_behavior == self.deviating_behavior:
            raise ValueError('Expected and deviating behavior must differ')
        return self


class ObservationRequirement(Condition):
    """Evidence below supports this specification, never an actual observation."""
    observable_kind: Literal[
        'architectural_state', 'RTL_signal', 'register_value', 'memory_value',
        'exception_state', 'protocol_event', 'timing_measurement',
        'statistical_measurement', 'board_trace', 'other',
    ]
    deviation_ids: list[Identifier] = Field(min_length=1)
    observable_target: Identifier | None = None
    judgement_kind: Literal['comparison', 'event_presence', 'ordering', 'statistical', 'unknown'] = 'unknown'
    required_backend: Identifier | None = None
    expected_observation: Predicate | None = None
    deviation_observation: Predicate | None = None
    evidence_requirement: Identifier | None = None

    @model_validator(mode='after')
    def completeness(self):
        if self.formalization_status == FormalizationStatus.FORMALIZED and (
            self.judgement_kind == 'unknown' or any(x is None for x in (
                self.observable_target, self.required_backend, self.expected_observation,
                self.deviation_observation, self.evidence_requirement))
        ):
            raise ValueError('Formalized observation requires a complete measurement specification')
        return self


class Scope(BoundRequirement):
    formalization_status: FormalizationStatus = FormalizationStatus.UNKNOWN
    applicable_architectures: list[Architecture] = Field(default_factory=list)
    applicable_platforms: list[Identifier] = Field(default_factory=list)
    rtl_revisions: list[Identifier] = Field(default_factory=list)
    silicon_revisions: list[Identifier] = Field(default_factory=list)
    applicability: Literal['synthetic_only', 'rtl_revision_only', 'specified_targets', 'unknown'] = 'unknown'
    silicon_applicability: Literal['specified_revisions', 'unknown'] = 'unknown'
    source_authority: Literal['synthetic_fixture', 'manual_research_input', 'upstream_record', 'unknown']
    assumptions: list[Identifier] = Field(default_factory=list)
    unmodeled_aspects: list[Identifier] = Field(default_factory=list)
    observation_blind_spots: list[Identifier] = Field(default_factory=list)
    known_limitations: list[Identifier] = Field(default_factory=list)

    @model_validator(mode='after')
    def boundaries(self):
        if self.applicability == 'synthetic_only' and self.source_authority != 'synthetic_fixture':
            raise ValueError('Synthetic scope must declare synthetic authority')
        if self.applicability == 'rtl_revision_only' and not self.rtl_revisions:
            raise ValueError('RTL revision scope requires revisions')
        if self.applicability == 'specified_targets' and not self.applicable_platforms:
            raise ValueError('Specified targets require platform identities')
        if bool(self.silicon_revisions) != (self.silicon_applicability == 'specified_revisions'):
            raise ValueError('Silicon revisions must agree with applicability')
        if self.formalization_status == FormalizationStatus.FORMALIZED and (
            self.applicability == 'unknown' or self.source_authority == 'unknown'
            or not self.applicable_architectures or Architecture.UNKNOWN in self.applicable_architectures
        ):
            raise ValueError('Unknown scope cannot be formalized')
        return self


class UnclassifiedAtom(BoundRequirement):
    atom: TriggerAtom
    reason: Literal['state_timing_unknown', 'ordering_endpoint_unclassified', 'verification_metadata']
    formalization_status: Literal['unknown'] = 'unknown'


class HardwareBehaviorContractInput(BoundRequirement):
    architecture: Architecture
    source_case_id: Identifier | None = None
    platform: Platform
    preconditions: list[Precondition] = Field(default_factory=list)
    trigger: list[TriggerCondition] = Field(default_factory=list)
    deviation: list[Deviation] = Field(default_factory=list)
    observation: list[ObservationRequirement] = Field(default_factory=list)
    scope: Scope
    unclassified_atoms: list[UnclassifiedAtom] = Field(default_factory=list)
    source_artifacts: list[SourceArtifact] = Field(min_length=1)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    limitations: list[Identifier] = Field(default_factory=list)

    @model_validator(mode='after')
    def consistency(self):
        def unique(values, label):
            if len(values) != len(set(values)):
                raise ValueError(f'Duplicate {label}')
        def walk(value):
            if isinstance(value, Contract):
                yield value
                for name in type(value).model_fields:
                    yield from walk(getattr(value, name))
            elif isinstance(value, list):
                for child in value:
                    yield from walk(child)
        sources = {x.artifact_id: x for x in self.source_artifacts}
        refs = {x.evidence_id: x for x in self.evidence}
        unique([x.artifact_id for x in self.source_artifacts], 'artifact ID')
        unique([x.evidence_id for x in self.evidence], 'evidence ID')
        conditions = [*self.preconditions, *self.trigger, *self.deviation, *self.observation]
        unique([x.condition_id for x in conditions] + [x.atom.atom_id for x in self.unclassified_atoms], 'condition ID')
        atom_ids = [a.atom_id for t in self.trigger for a in t.instructions]
        atom_ids += [t.access.atom_id for t in self.trigger if t.access]
        atom_ids += [t.ordering.atom_id for t in self.trigger if t.ordering]
        atom_ids += [x.atom.atom_id for x in self.unclassified_atoms]
        unique(atom_ids, 'atom ID')
        if set(self.source_artifact_ids) != set(sources) or set(self.evidence_ids) != set(refs):
            raise ValueError('Top-level references must match registries')
        if self.architecture != self.platform.target.architecture:
            raise ValueError('Contract and platform architecture differ')
        if self.scope.applicable_architectures and self.architecture not in self.scope.applicable_architectures:
            raise ValueError('Architecture outside scope')
        if self.scope.applicable_platforms and self.platform.platform_id not in self.scope.applicable_platforms:
            raise ValueError('Platform outside scope')
        if self.scope.rtl_revisions and self.platform.rtl_revision not in self.scope.rtl_revisions:
            raise ValueError('RTL revision outside scope')
        if self.scope.silicon_revisions and self.platform.silicon_revision not in self.scope.silicon_revisions:
            raise ValueError('Silicon revision outside scope')
        if self.scope.source_authority == 'synthetic_fixture' and not any(
            p.source_kind == 'synthetic_fixture' for p in self.scope.provenance
        ):
            # A synthetic XL0 fixture is also an explicitly marked synthetic source.
            if not (self.scope.applicability == 'synthetic_only' and any(
                p.source_kind == 'xl0_trigger' and p.transformation == 'xl0_partial_v1'
                for p in self.scope.provenance
            )):
                raise ValueError('Synthetic authority requires synthetic provenance')
        if self.scope.source_authority == 'manual_research_input' and not any(
            p.source_kind == 'manual_research_input' for p in self.scope.provenance
        ):
            raise ValueError('Manual authority requires manual provenance')
        for obj in walk(self):
            for field in ('source_artifact_ids', 'evidence_ids', 'source_ids', 'deviation_ids',
                          'applicable_architectures', 'applicable_platforms', 'rtl_revisions', 'silicon_revisions',
                          'assumptions', 'unmodeled_aspects', 'observation_blind_spots',
                          'known_limitations', 'limitations'):
                if hasattr(obj, field):
                    unique(getattr(obj, field), field)
            if isinstance(obj, BoundRequirement):
                unique([_json(_normalize(p.model_dump(mode='json'))) for p in obj.provenance], 'provenance')
                if not set(obj.source_artifact_ids) <= sources.keys() or not set(obj.evidence_ids) <= refs.keys():
                    raise ValueError('Unbound evidence or source artifact')
                if any(refs[e].artifact_id not in obj.source_artifact_ids for e in obj.evidence_ids):
                    raise ValueError('Evidence artifact not bound on requirement')
                covered = set()
                for origin in obj.provenance:
                    covered.update(origin.source_artifact_ids)
                    if not set(origin.source_artifact_ids) <= set(obj.source_artifact_ids):
                        raise ValueError('Provenance outside requirement sources')
                if covered != set(obj.source_artifact_ids):
                    raise ValueError('Each source needs provenance')
            if isinstance(obj, Provenance):
                if not set(obj.source_artifact_ids) <= sources.keys():
                    raise ValueError('Unknown provenance source')
                if any(sources[a].source_kind != obj.source_kind for a in obj.source_artifact_ids):
                    raise ValueError('Provenance source kind mismatch')
            if isinstance(obj, EvidenceRef):
                if obj.artifact_id not in sources:
                    raise ValueError('Evidence references unknown artifact')
                source_kind = sources[obj.artifact_id].source_kind
                required_type = {'manual_research_input': 'manual', 'synthetic_fixture': 'synthetic'}.get(source_kind)
                if required_type and obj.source_type != required_type:
                    raise ValueError('Manual/synthetic evidence cannot masquerade as analyzer output')
            if isinstance(obj, (InstructionTriggerAtom, PrivilegeTriggerAtom)) and obj.architecture != self.architecture:
                raise ValueError('Instruction architecture mismatch')
        for item in self.trigger:
            if item.formalization_status == FormalizationStatus.FORMALIZED and any(
                a.architecture == Architecture.UNKNOWN for a in item.instructions
            ):
                raise ValueError('Unknown instruction architecture cannot be formalized')
            unique([x.atom_id for x in item.instructions], 'instruction ID')
            if item.ordering:
                endpoints = {x.condition_id for x in self.trigger if x.condition_kind != 'ordering'}
                if not {item.ordering.before_atom_id, item.ordering.after_atom_id} <= endpoints:
                    raise ValueError('Ordering must reference trigger condition endpoints')
        for item in self.deviation:
            if item.specification_ref is not None and item.specification_ref not in item.source_artifact_ids:
                raise ValueError('Specification reference must bind a source artifact')
        for item in self.observation:
            if not set(item.deviation_ids) <= {x.condition_id for x in self.deviation}:
                raise ValueError('Observation references unknown deviation')
        return self


# These are sets; trigger, instructions, predicate operands, and ordering retain order.
_SET_FIELDS = frozenset({
    'source_artifact_ids', 'evidence_ids', 'source_ids', 'deviation_ids', 'provenance',
    'source_artifacts', 'evidence', 'preconditions', 'deviation', 'observation',
    'unclassified_atoms', 'limitations', 'applicable_architectures', 'applicable_platforms',
    'rtl_revisions', 'silicon_revisions', 'assumptions', 'unmodeled_aspects',
    'observation_blind_spots', 'known_limitations',
})


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _normalize(value, field=''):
    if isinstance(value, dict):
        return {k: _normalize(v, k) for k, v in value.items()}
    if isinstance(value, list):
        result = [_normalize(v) for v in value]
        return sorted(result, key=_json) if field in _SET_FIELDS else result
    return value


def canonical_payload(value: HardwareBehaviorContractInput) -> bytes:
    """Canonical authored contract, excluding only its own ID/hash.

    No timestamp/path/runtime/LLM fields exist. Descriptions are explicit source-
    bound research input and remain identity-bearing; editing them changes content.
    """
    fields = value.model_dump(mode='json', include=set(HardwareBehaviorContractInput.model_fields))
    return _json(_normalize({'schema_version': SCHEMA_VERSION, **fields})).encode('utf-8')


class HardwareBehaviorContract(HardwareBehaviorContractInput):
    schema_version: Literal['hardware-behavior-contract/v1'] = SCHEMA_VERSION
    contract_id: Identifier
    contract_sha256: Sha256

    @model_validator(mode='after')
    def identity(self):
        digest = hashlib.sha256(canonical_payload(self)).hexdigest()
        if self.contract_sha256 != digest or self.contract_id != 'hwbehavior:' + digest:
            raise ValueError('Hardware behavior contract identity mismatch')
        return self


def build_hardware_behavior_contract(value: HardwareBehaviorContractInput) -> HardwareBehaviorContract:
    value = HardwareBehaviorContractInput.model_validate(value.model_dump(mode='json'))
    payload = canonical_payload(value)
    digest = hashlib.sha256(payload).hexdigest()
    return HardwareBehaviorContract.model_validate({
        **json.loads(payload), 'contract_id': 'hwbehavior:' + digest, 'contract_sha256': digest,
    })


def serialize_hardware_behavior_contract(value: HardwareBehaviorContract) -> str:
    value = HardwareBehaviorContract.model_validate(value.model_dump(mode='json'))
    return _json(_normalize(value.model_dump(mode='json'))) + '\n'


def parse_hardware_behavior_contract(text: str) -> HardwareBehaviorContract:
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    return HardwareBehaviorContract.model_validate(json.loads(text, object_pairs_hook=unique_pairs))


class FormalizationCount(Contract):
    total: Annotated[int, Field(ge=0)] = 0
    formalized: Annotated[int, Field(ge=0)] = 0
    partially_formalized: Annotated[int, Field(ge=0)] = 0
    unformalized: Annotated[int, Field(ge=0)] = 0
    unknown: Annotated[int, Field(ge=0)] = 0
    missing: bool = False


def formalization_summary(value: HardwareBehaviorContract) -> dict[str, FormalizationCount]:
    value = HardwareBehaviorContract.model_validate(value.model_dump(mode='json'))
    result = {}
    for name in ('preconditions', 'trigger', 'deviation', 'observation', 'scope', 'unclassified_atoms'):
        items = [value.scope] if name == 'scope' else getattr(value, name)
        counts = {s.value: sum(x.formalization_status == s for x in items) for s in FormalizationStatus}
        result[name] = FormalizationCount(total=len(items), missing=not items, **counts)
    return result
