"""CAP0: source-bound firmware capabilities, not attacker powers or matching results.

Independent of frozen XL1. A structured declaration is not proof of feasibility.
"""
from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, StrictBool, StrictInt, StrictStr, model_validator

from chipchain.domain.case import TargetDescriptor
from chipchain.domain.common import Architecture, Contract, Identifier, Sha256
from chipchain.domain.evidence import EvidenceRef

VERSION = 'firmware-capability/v1'
Unsigned = Annotated[int, Field(strict=True, ge=0, le=0xffffffffffffffff)]
Positive = Annotated[int, Field(strict=True, gt=0)]
Formalization = Literal['formalized', 'partially_formalized', 'unformalized', 'unknown']
OriginKind = Literal['normal_behavior', 'vulnerability_derived', 'manual_research_input', 'synthetic_fixture', 'unknown']
SourceKind = Literal['firmware_a6', 'firmware_a5', 'firmware_a4', 'processor_behavior_ir',
                     'runtime_trace', 'firmware_mmio_static', 'fuzzware_observation', 'firmware_vulnerability_record',
                     'manual_research_input', 'synthetic_fixture']


class SourceArtifact(Contract):
    artifact_id: Identifier
    sha256: Sha256
    source_kind: SourceKind
    hash_kind: Literal['file_bytes', 'canonical_a6_payload'] = 'file_bytes'


class Provenance(Contract):
    source_kind: SourceKind
    source_artifact_ids: list[Identifier] = Field(min_length=1)
    source_ids: list[Identifier] = Field(default_factory=list)
    transformation: Literal['explicit_input', 'a6_partial_v1'] = 'explicit_input'


class Bound(Contract):
    source_artifact_ids: list[Identifier] = Field(min_length=1)
    evidence_ids: list[Identifier] = Field(default_factory=list)
    provenance: list[Provenance] = Field(min_length=1)


class Origin(Bound):
    kind: OriginKind
    finding_ids: list[Identifier] = Field(default_factory=list)

    @model_validator(mode='after')
    def finding_required(self):
        if (self.kind == 'vulnerability_derived') != bool(self.finding_ids):
            raise ValueError('Only vulnerability-derived origin requires finding IDs')
        return self


class Entry(Bound):
    entry_id: Identifier
    entry_kind: Literal['code_site', 'function', 'external_interface', 'interrupt_handler',
                        'exception_handler', 'boot_entry', 'callback', 'unknown']
    formalization_status: Formalization = 'unknown'
    pc: Unsigned | None = None
    function_id: Identifier | None = None
    function_name: Identifier | None = None
    interface_id: Identifier | None = None
    ownership_status: Literal['unique', 'ambiguous', 'missing', 'unknown'] = 'unknown'
    execution_status: Literal['static_only', 'source_instruction_retired', 'unknown'] = 'unknown'
    reachability_status: Literal['static_reachable', 'unknown'] = 'unknown'
    retirement_observation_ids: list[Identifier] = Field(default_factory=list)

    @model_validator(mode='after')
    def boundaries(self):
        if self.ownership_status in ('ambiguous', 'missing') and (self.function_id or self.function_name):
            raise ValueError('Unresolved ownership cannot select a function')
        if self.ownership_status == 'unique' and not self.function_id:
            raise ValueError('Unique ownership needs a function identity')
        if (self.execution_status == 'source_instruction_retired') != bool(self.retirement_observation_ids):
            raise ValueError('Retirement status requires bound observations')
        if self.formalization_status == 'formalized':
            if self.entry_kind == 'unknown':
                raise ValueError('Unknown entry cannot be formalized')
            required = self.interface_id if self.entry_kind == 'external_interface' else (
                self.function_id if self.entry_kind == 'function' else self.pc)
            if required is None:
                raise ValueError('Formalized entry lacks its typed identity')
        return self


class Predicate(Contract):
    subject: Identifier
    operator: Literal['eq', 'neq', 'in_range', 'present', 'before']
    operands: list[StrictStr | StrictInt | StrictBool] = Field(default_factory=list)

    @model_validator(mode='after')
    def arity(self):
        if len(self.operands) != {'eq': 1, 'neq': 1, 'in_range': 2, 'present': 0, 'before': 1}[self.operator]:
            raise ValueError('Predicate operand count mismatch')
        if self.operator == 'in_range' and (any(type(x) is not int for x in self.operands)
                                            or self.operands[0] > self.operands[1]):
            raise ValueError('Invalid range operands')
        return self


class Condition(Bound):
    condition_id: Identifier
    condition_kind: Literal['path', 'input', 'function_state', 'register_state', 'memory_state',
                            'privilege', 'execution_context', 'ordering', 'other']
    formalization_status: Formalization = 'unknown'
    predicate: Predicate | None = None
    description: Identifier

    @model_validator(mode='after')
    def structured(self):
        if self.formalization_status == 'formalized' and self.predicate is None:
            raise ValueError('Formalized condition needs a predicate')
        return self


class NumericDomain(Contract):
    """Bounds constrain possible values; controlled_bits does not establish control."""
    exact: Unsigned | None = None
    minimum: Unsigned | None = None
    maximum: Unsigned | None = None
    mask: Unsigned | None = None
    masked_value: Unsigned | None = None
    controlled_bits: Unsigned | None = None
    bit_width: Positive | None = None

    @model_validator(mode='after')
    def consistency(self):
        if (self.minimum is None) != (self.maximum is None):
            raise ValueError('Range requires both endpoints')
        if self.minimum is not None and self.minimum > self.maximum:
            raise ValueError('Reversed range')
        if self.exact is not None and self.minimum is not None:
            raise ValueError('Choose exact value or range')
        if (self.mask is None) != (self.masked_value is None):
            raise ValueError('Mask requires masked value')
        if self.mask is not None and self.masked_value & ~self.mask:
            raise ValueError('Masked value exceeds mask')
        if self.controlled_bits is not None and self.bit_width is None:
            raise ValueError('Controlled bits require explicit bit width')
        if self.bit_width is not None:
            if self.bit_width > 64:
                raise ValueError('CAP0 numeric domains support up to 64 bits')
            if any(x is not None and x >= 1 << self.bit_width for x in (
                self.exact, self.minimum, self.maximum, self.mask, self.masked_value, self.controlled_bits)):
                raise ValueError('Numeric domain exceeds bit width')
        if self.exact is not None and self.mask is not None and self.exact & self.mask != self.masked_value:
            raise ValueError('Exact and masked values disagree')
        if all(x is None for x in (self.exact, self.minimum, self.mask, self.controlled_bits)):
            raise ValueError('Empty numeric domain')
        return self


class ConstraintBase(Bound):
    constraint_id: Identifier
    formalization_status: Formalization = 'formalized'


class ResourceConstraint(ConstraintBase):
    kind: Literal['target_resource'] = 'target_resource'
    resource_kind: Literal['memory', 'mmio', 'csr', 'register', 'control_flow', 'instruction', 'other', 'unknown']
    identity: Identifier | None = None

    @model_validator(mode='after')
    def known(self):
        if self.formalization_status == 'formalized' and (self.resource_kind == 'unknown' or not self.identity):
            raise ValueError('Formalized resource requires kind and identity')
        return self


class NumericConstraint(ConstraintBase):
    kind: Literal['address', 'value', 'access_width', 'length']
    domain: NumericDomain

    @model_validator(mode='after')
    def size(self):
        if self.kind in ('access_width', 'length'):
            if self.domain.mask is not None or self.domain.controlled_bits is not None:
                raise ValueError('Width/length require numeric bounds, not bit masks')
            if self.kind == 'access_width' and self.domain.exact is None:
                raise ValueError('Access width must be exact in CAP0')
            if self.kind == 'access_width' and self.domain.exact == 0:
                raise ValueError('Access width must be positive')
        return self


class IdentityConstraint(ConstraintBase):
    kind: Literal['register', 'CSR', 'privilege', 'execution_context']
    identity: Identifier


class TargetSetConstraint(ConstraintBase):
    kind: Literal['target_set'] = 'target_set'
    targets: list[Unsigned] = Field(min_length=1)


class OrderingConstraint(ConstraintBase):
    kind: Literal['ordering'] = 'ordering'
    before_primitive_id: Identifier
    after_primitive_id: Identifier
    max_gap_events: Unsigned | None = None

    @model_validator(mode='after')
    def distinct(self):
        if self.before_primitive_id == self.after_primitive_id:
            raise ValueError('Ordering endpoints must differ')
        return self


Constraint = Annotated[ResourceConstraint | NumericConstraint | IdentityConstraint | TargetSetConstraint |
                       OrderingConstraint, Field(discriminator='kind')]


class PrimitiveKind(StrEnum):
    INSTRUCTION_EXECUTION = 'INSTRUCTION_EXECUTION'
    DIRECT_CONTROL_TRANSFER = 'DIRECT_CONTROL_TRANSFER'
    INDIRECT_CONTROL_TRANSFER = 'INDIRECT_CONTROL_TRANSFER'
    MEMORY_READ = 'MEMORY_READ'
    MEMORY_WRITE = 'MEMORY_WRITE'
    MMIO_READ = 'MMIO_READ'
    MMIO_WRITE = 'MMIO_WRITE'
    CSR_READ = 'CSR_READ'
    CSR_WRITE = 'CSR_WRITE'
    EXCEPTION_RETURN = 'EXCEPTION_RETURN'
    INTERRUPT_HANDLING = 'INTERRUPT_HANDLING'
    READ_OOB = 'READ_OOB'
    WRITE_OOB = 'WRITE_OOB'
    WRITE_BOUNDED = 'WRITE_BOUNDED'
    PARTIAL_ADDRESS_CONTROL = 'PARTIAL_ADDRESS_CONTROL'
    PARTIAL_VALUE_CONTROL = 'PARTIAL_VALUE_CONTROL'
    LENGTH_CONTROL = 'LENGTH_CONTROL'
    CONTROL_FLOW_INFLUENCE = 'CONTROL_FLOW_INFLUENCE'
    CONTROL_FLOW_HIJACK = 'CONTROL_FLOW_HIJACK'
    CALLBACK_INFLUENCE = 'CALLBACK_INFLUENCE'
    DENIAL_OF_SERVICE = 'DENIAL_OF_SERVICE'
    OTHER = 'OTHER'
    UNKNOWN = 'UNKNOWN'


class ControlAuthority(Bound):
    status: Literal['not_established', 'firmware_determined', 'input_influenced',
                    'bounded_external_control', 'full_external_control',
                    'vulnerability_derived_control', 'unknown'] = 'not_established'
    dimensions: list[Literal['address', 'value', 'length', 'target', 'execution_context']] = Field(default_factory=list)
    support_basis: Literal['not_established', 'explicit_research_definition', 'synthetic_definition',
                           'independent_capability_evidence'] = 'not_established'

    @model_validator(mode='after')
    def support_required(self):
        positive = self.status not in ('not_established', 'unknown')
        if positive and (not self.evidence_ids or self.support_basis == 'not_established' or not self.dimensions):
            raise ValueError('Control declaration needs dimensions and independent explicit support')
        if not positive and (self.dimensions or self.support_basis != 'not_established'):
            raise ValueError('Unknown control cannot declare controlled dimensions')
        return self


class Primitive(Bound):
    primitive_id: Identifier
    architecture: Architecture
    kind: PrimitiveKind
    entry_id: Identifier
    formalization_status: Formalization = 'unknown'
    basis: Literal['static_instruction', 'source_instruction_retirement', 'explicit_definition', 'unknown'] = 'unknown'
    control: ControlAuthority
    constraint_ids: list[Identifier] = Field(default_factory=list)
    condition_ids: list[Identifier] = Field(default_factory=list)
    source_pc: Unsigned | None = None
    instruction_sequence: list[Identifier] = Field(default_factory=list)
    source_registers: list[Identifier] = Field(default_factory=list)
    transfer_kind: Literal['direct_call', 'direct_jump', 'conditional_branch', 'indirect_call',
                           'indirect_jump', 'return', 'other_control_transfer'] | None = None
    target_status: Literal['resolved_direct', 'indirect_unknown', 'unknown', 'not_applicable'] = 'not_applicable'
    retirement_observation_ids: list[Identifier] = Field(default_factory=list)

    @model_validator(mode='after')
    def structured(self):
        if self.formalization_status == 'formalized' and (
            self.kind == PrimitiveKind.UNKNOWN or self.basis == 'unknown' or self.architecture == Architecture.UNKNOWN
        ):
            raise ValueError('Unknown primitive cannot be formalized')
        if self.kind == PrimitiveKind.DIRECT_CONTROL_TRANSFER and self.target_status != 'resolved_direct':
            raise ValueError('Direct transfer needs resolved target status')
        if self.kind == PrimitiveKind.INDIRECT_CONTROL_TRANSFER and self.target_status != 'indirect_unknown':
            raise ValueError('Indirect transfer target must remain unknown in CAP0')
        if self.basis == 'source_instruction_retirement' and not self.retirement_observation_ids:
            raise ValueError('Retirement basis requires observations')
        if self.retirement_observation_ids and self.basis != 'source_instruction_retirement':
            raise ValueError('Retirement references require corresponding basis')
        return self


class RetirementEvidence(Bound):
    observation_id: Identifier
    architecture: Architecture
    pc: Unsigned
    instruction_encoding: Identifier
    cycle: Unsigned
    trace_line: Annotated[int, Field(strict=True, ge=2)]
    interpretation: Literal['source_instruction_retired_only'] = 'source_instruction_retired_only'


class Scope(Bound):
    target: TargetDescriptor
    origin_kind: OriginKind
    firmware_artifact_ids: list[Identifier] = Field(min_length=1)
    platform_id: Identifier | None = None
    site_pcs: list[Unsigned] = Field(default_factory=list)
    function_ids: list[Identifier] = Field(default_factory=list)
    applicability: Literal['specified_firmware_sites', 'synthetic_only', 'unknown'] = 'unknown'
    formalization_status: Formalization = 'unknown'
    assumptions: list[Identifier] = Field(default_factory=list)
    unmodeled_aspects: list[Identifier] = Field(default_factory=list)
    known_limitations: list[Identifier] = Field(default_factory=list)

    @model_validator(mode='after')
    def structured(self):
        if self.applicability == 'synthetic_only' and self.origin_kind != 'synthetic_fixture':
            raise ValueError('Synthetic scope requires synthetic origin')
        if self.formalization_status == 'formalized' and (
            self.applicability == 'unknown' or self.target.architecture == Architecture.UNKNOWN
        ):
            raise ValueError('Unknown scope cannot be formalized')
        return self


_MEMORY = {'MEMORY_READ', 'MEMORY_WRITE', 'READ_OOB', 'WRITE_OOB', 'WRITE_BOUNDED'}
_MMIO = {'MMIO_READ', 'MMIO_WRITE'}
_CSR = {'CSR_READ', 'CSR_WRITE'}
_FLOW = {'DIRECT_CONTROL_TRANSFER', 'INDIRECT_CONTROL_TRANSFER', 'CONTROL_FLOW_INFLUENCE',
         'CONTROL_FLOW_HIJACK', 'CALLBACK_INFLUENCE', 'EXCEPTION_RETURN'}
_VULNERABILITY = {'READ_OOB', 'WRITE_OOB', 'CONTROL_FLOW_HIJACK', 'DENIAL_OF_SERVICE'}
_CONTROL_PRIMITIVES = {'PARTIAL_ADDRESS_CONTROL', 'PARTIAL_VALUE_CONTROL', 'LENGTH_CONTROL',
                       'CONTROL_FLOW_INFLUENCE', 'CONTROL_FLOW_HIJACK', 'CALLBACK_INFLUENCE'}


class FirmwareCapabilityInput(Bound):
    architecture: Architecture
    source_case_id: Identifier | None = None
    origin: Origin
    entry: Entry
    conditions: list[Condition] = Field(default_factory=list)
    primitives: list[Primitive] = Field(default_factory=list)
    constraints: list[Constraint] = Field(default_factory=list)
    scope: Scope
    source_artifacts: list[SourceArtifact] = Field(min_length=1)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    retirement_evidence: list[RetirementEvidence] = Field(default_factory=list)
    limitations: list[Identifier] = Field(default_factory=list)

    @model_validator(mode='after')
    def validate_bindings(self):
        def unique(values, name):
            if len(values) != len(set(values)):
                raise ValueError(f'Duplicate {name}')
        def walk(obj):
            if isinstance(obj, Contract):
                yield obj
                for name in type(obj).model_fields:
                    yield from walk(getattr(obj, name))
            elif isinstance(obj, list):
                for x in obj:
                    yield from walk(x)
        for items, field in ((self.source_artifacts, 'artifact_id'), (self.evidence, 'evidence_id'),
                             (self.conditions, 'condition_id'), (self.primitives, 'primitive_id'),
                             (self.constraints, 'constraint_id'), (self.retirement_evidence, 'observation_id')):
            unique([getattr(x, field) for x in items], field)
        sources = {x.artifact_id: x for x in self.source_artifacts}
        refs = {x.evidence_id: x for x in self.evidence}
        constraints = {x.constraint_id: x for x in self.constraints}
        observations = {x.observation_id: x for x in self.retirement_evidence}
        if set(self.source_artifact_ids) != sources.keys() or set(self.evidence_ids) != refs.keys():
            raise ValueError('Top-level reference sets differ from registries')
        if self.scope.target.architecture != self.architecture or self.scope.origin_kind != self.origin.kind:
            raise ValueError('Scope architecture/origin mismatch')
        if not set(self.scope.firmware_artifact_ids) <= sources.keys() or not set(self.scope.firmware_artifact_ids) <= set(self.scope.source_artifact_ids):
            raise ValueError('Unknown firmware artifact')
        if self.scope.site_pcs and self.entry.pc not in self.scope.site_pcs:
            raise ValueError('Entry outside site scope')
        if self.scope.function_ids and self.entry.function_id not in self.scope.function_ids:
            raise ValueError('Entry function outside scope')
        if self.origin.kind in ('synthetic_fixture', 'manual_research_input', 'vulnerability_derived'):
            required = {'vulnerability_derived': 'firmware_vulnerability_record'}.get(self.origin.kind, self.origin.kind)
            if not any(p.source_kind == required for p in self.origin.provenance):
                raise ValueError('Origin requires matching provenance')
        finding_refs = {i for p in self.origin.provenance if p.source_kind == 'firmware_vulnerability_record' for i in p.source_ids}
        if not set(self.origin.finding_ids) <= finding_refs:
            raise ValueError('Finding IDs require explicit vulnerability-source provenance')
        for obj in walk(self):
            for name in SET_FIELDS:
                if hasattr(obj, name):
                    values = getattr(obj, name)
                    if isinstance(values, list):
                        unique([_json(_normalize(x.model_dump(mode='json') if isinstance(x, Contract) else x)) for x in values], name)
            if isinstance(obj, Bound):
                if not set(obj.source_artifact_ids) <= sources.keys() or not set(obj.evidence_ids) <= refs.keys():
                    raise ValueError('Unknown source or evidence reference')
                if any(refs[e].artifact_id not in obj.source_artifact_ids for e in obj.evidence_ids):
                    raise ValueError('Evidence artifact/source mismatch')
                covered = {a for p in obj.provenance for a in p.source_artifact_ids}
                if covered != set(obj.source_artifact_ids):
                    raise ValueError('Provenance source coverage mismatch')
            if isinstance(obj, Provenance):
                if not set(obj.source_artifact_ids) <= sources.keys() or any(
                    sources[a].source_kind != obj.source_kind for a in obj.source_artifact_ids
                ):
                    raise ValueError('Provenance source mismatch')
            if isinstance(obj, EvidenceRef):
                if obj.artifact_id not in sources:
                    raise ValueError('Evidence source missing')
                kind = sources[obj.artifact_id].source_kind
                required = {'synthetic_fixture': 'synthetic', 'manual_research_input': 'manual'}.get(kind)
                if required and obj.source_type != required:
                    raise ValueError('Manual/synthetic evidence cannot impersonate analyzer evidence')
            if isinstance(obj, (Primitive, RetirementEvidence)) and obj.architecture != self.architecture:
                raise ValueError('Primitive/observation architecture mismatch')
            if isinstance(obj, (Primitive, Entry)):
                if not set(obj.retirement_observation_ids) <= observations.keys():
                    raise ValueError('Unknown retirement observation')
                pc = obj.source_pc if isinstance(obj, Primitive) else obj.pc
                for rid in obj.retirement_observation_ids:
                    if observations[rid].pc != pc or not set(observations[rid].evidence_ids) <= set(obj.evidence_ids):
                        raise ValueError('Retirement observation site/evidence mismatch')
            if isinstance(obj, RetirementEvidence) and (not obj.evidence_ids or not any(
                p.source_kind in ('runtime_trace', 'synthetic_fixture') for p in obj.provenance
            )):
                raise ValueError('Retirement requires trace evidence')
        for constraint in self.constraints:
            if isinstance(constraint, OrderingConstraint):
                if not {constraint.before_primitive_id, constraint.after_primitive_id} <= {p.primitive_id for p in self.primitives}:
                    raise ValueError('Ordering references unknown primitive')
        for primitive in self.primitives:
            if primitive.entry_id != self.entry.entry_id:
                raise ValueError('Primitive references unknown entry')
            if not set(primitive.condition_ids) <= {c.condition_id for c in self.conditions}:
                raise ValueError('Primitive references unknown condition')
            if not set(primitive.constraint_ids) <= constraints.keys():
                raise ValueError('Primitive references unknown constraint')
            if primitive.source_pc is not None and primitive.source_pc != self.entry.pc:
                raise ValueError('Primitive site differs from entry')
            selected = [constraints[i] for i in primitive.constraint_ids]
            kinds = {x.kind for x in selected}
            if len(kinds - {'ordering'}) != len([x for x in selected if x.kind != 'ordering']):
                raise ValueError('Multiple competing constraints of the same kind')
            resource = next((x for x in selected if x.kind == 'target_resource'), None)
            expected = ('memory' if primitive.kind in _MEMORY else 'mmio' if primitive.kind in _MMIO else
                        'csr' if primitive.kind in _CSR else 'control_flow' if primitive.kind in _FLOW else None)
            if resource and expected and resource.resource_kind != expected:
                raise ValueError('Constraint resource incompatible with primitive')
            if 'CSR' in kinds and primitive.kind not in _CSR:
                raise ValueError('CSR constraint incompatible with primitive')
            if kinds & {'address', 'length'} and primitive.kind not in _MEMORY | _MMIO | {'PARTIAL_ADDRESS_CONTROL', 'LENGTH_CONTROL'}:
                raise ValueError('Memory constraint incompatible with primitive')
            if 'target_set' in kinds and primitive.kind not in _FLOW:
                raise ValueError('Target set incompatible with primitive')
            if primitive.kind == PrimitiveKind.DIRECT_CONTROL_TRANSFER and 'target_set' not in kinds:
                raise ValueError('Direct transfer requires concrete target constraint')
            if primitive.kind == PrimitiveKind.INDIRECT_CONTROL_TRANSFER and 'target_set' in kinds:
                raise ValueError('Indirect target must remain unknown')
            if primitive.kind == PrimitiveKind.WRITE_BOUNDED:
                address = next((x.domain for x in selected if x.kind == 'address'), None)
                length = next((x.domain for x in selected if x.kind == 'length'), None)
                if not resource or address is None or length is None or (
                    address.exact is None and address.minimum is None
                ) or (length.exact is None and length.maximum is None):
                    raise ValueError('Bounded write requires resource, bounded addresses and length')
            if primitive.formalization_status == 'formalized':
                if expected and not resource:
                    raise ValueError('Formalized primitive requires target resource')
                required = {'CSR'} if primitive.kind in _CSR else {'address', 'access_width'} if primitive.kind in _MEMORY | _MMIO else set()
                if not required <= kinds:
                    raise ValueError('Formalized access lacks resource constraints')
            if primitive.kind in _VULNERABILITY and self.origin.kind not in ('vulnerability_derived', 'synthetic_fixture', 'manual_research_input'):
                raise ValueError('Normal behavior does not establish vulnerability capability')
            if primitive.kind in _VULNERABILITY | _CONTROL_PRIMITIVES and (
                primitive.basis != 'explicit_definition' or not primitive.evidence_ids
                or not any(sources[a].source_kind != 'firmware_vulnerability_record' for a in primitive.source_artifact_ids)
            ):
                raise ValueError('Finding alone does not establish a capability')
            width = next((c.domain.exact for c in selected if c.kind == 'access_width'), None)
            value_domain = next((c.domain for c in selected if c.kind == 'value'), None)
            if width is not None and value_domain is not None and any(
                x is not None and x.bit_length() > width for x in (
                    value_domain.exact, value_domain.minimum, value_domain.maximum,
                    value_domain.mask, value_domain.masked_value, value_domain.controlled_bits)
            ):
                raise ValueError('Value domain incompatible with access width')
            authority = primitive.control
            if authority.status not in ('not_established', 'unknown'):
                allowed = {'manual_research_input', 'synthetic_fixture'}
                # CAP0 has no validated automatic control-evidence extractor.
                # A4/A5/Fuzzware source labels alone cannot authorize control.
                if not any(sources[refs[e].artifact_id].source_kind in allowed for e in authority.evidence_ids):
                    raise ValueError('Control cannot be established by analyzer/retirement/finding source labels alone')
                if authority.support_basis == 'synthetic_definition' and self.origin.kind != 'synthetic_fixture':
                    raise ValueError('Synthetic control requires synthetic origin')
                if authority.status == 'vulnerability_derived_control' and self.origin.kind != 'vulnerability_derived':
                    raise ValueError('Vulnerability control requires vulnerability origin')
                dimensions = {'address': 'address', 'value': 'value', 'length': 'length', 'target': 'target_set',
                              'execution_context': 'execution_context'}
                if not {dimensions[d] for d in authority.dimensions} <= kinds:
                    raise ValueError('Control dimensions require typed constraints')
                if authority.status == 'full_external_control':
                    for dimension in ('address', 'value'):
                        if dimension in authority.dimensions:
                            domain = next(c.domain for c in selected if c.kind == dimension)
                            if domain.bit_width is None or domain.controlled_bits != (1 << domain.bit_width) - 1:
                                raise ValueError('Full control requires all bits of the declared dimension')
                            if domain.exact is not None or domain.mask not in (None, 0) or (
                                domain.minimum is not None and (domain.minimum != 0 or domain.maximum != (1 << domain.bit_width) - 1)
                            ):
                                raise ValueError('Full control conflicts with a restricted numeric domain')
        return self


SET_FIELDS = frozenset({
    'source_artifact_ids', 'evidence_ids', 'source_ids', 'finding_ids', 'constraint_ids', 'condition_ids',
    'dimensions', 'source_artifacts', 'evidence', 'provenance', 'conditions', 'primitives',
    'retirement_observation_ids', 'retirement_evidence', 'firmware_artifact_ids', 'site_pcs', 'function_ids',
    'targets', 'assumptions', 'unmodeled_aspects', 'known_limitations', 'limitations',
})


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def _normalize(value, field=''):
    if isinstance(value, dict):
        return {k: _normalize(v, k) for k, v in value.items()}
    if isinstance(value, list):
        items = [_normalize(v) for v in value]
        return sorted(items, key=_json) if field in SET_FIELDS else items
    return value


def canonical_payload(value: FirmwareCapabilityInput) -> bytes:
    fields = value.model_dump(mode='json', include=set(FirmwareCapabilityInput.model_fields))
    return _json(_normalize({'schema_version': VERSION, **fields})).encode()


class FirmwareCapability(FirmwareCapabilityInput):
    schema_version: Literal['firmware-capability/v1'] = VERSION
    capability_id: Identifier
    capability_sha256: Sha256

    @model_validator(mode='after')
    def identity(self):
        digest = hashlib.sha256(canonical_payload(self)).hexdigest()
        if self.capability_sha256 != digest or self.capability_id != 'fwcap:' + digest:
            raise ValueError('Capability identity mismatch')
        return self


def build_firmware_capability(value: FirmwareCapabilityInput) -> FirmwareCapability:
    value = FirmwareCapabilityInput.model_validate(value.model_dump(mode='json'))
    data = canonical_payload(value)
    digest = hashlib.sha256(data).hexdigest()
    return FirmwareCapability.model_validate({**json.loads(data), 'capability_id': 'fwcap:' + digest,
                                            'capability_sha256': digest})


def serialize_firmware_capability(value: FirmwareCapability) -> str:
    value = FirmwareCapability.model_validate(value.model_dump(mode='json'))
    return _json(_normalize(value.model_dump(mode='json'))) + '\n'


def parse_firmware_capability(text: str) -> FirmwareCapability:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    return FirmwareCapability.model_validate(json.loads(text, object_pairs_hook=unique))


class FormalizationCount(Contract):
    total: int
    formalized: int
    partially_formalized: int
    unformalized: int
    unknown: int
    missing: bool


def formalization_summary(value: FirmwareCapability) -> dict[str, FormalizationCount]:
    value = FirmwareCapability.model_validate(value.model_dump(mode='json'))
    result = {}
    for name in ('entry', 'conditions', 'primitives', 'constraints', 'scope'):
        items = [getattr(value, name)] if name in ('entry', 'scope') else getattr(value, name)
        result[name] = FormalizationCount(total=len(items), missing=not items, **{
            status: sum(x.formalization_status == status for x in items)
            for status in ('formalized', 'partially_formalized', 'unformalized', 'unknown')})
    return result
