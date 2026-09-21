"""XL2: deterministic comparison of declared requirements, never execution proof.

No IO, model calls, inference from prose, or mutation of frozen input contracts.
"""
from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from chipchain.domain.common import Architecture, Contract, Identifier, Sha256
from chipchain.firmware.capability import FirmwareCapability, NumericDomain
from chipchain.hardware.behavior_contract import HardwareBehaviorContract

SCHEMA_VERSION = 'capability-contract-compatibility/v1'
MATCHER_VERSION = 'xl2-typed-subset/v1'


class Outcome(StrEnum):
    COMPATIBLE = 'compatible'
    INCOMPATIBLE = 'incompatible'
    UNKNOWN = 'unknown'


def aggregate_required(outcomes):
    values = list(outcomes)
    if Outcome.INCOMPATIBLE in values:
        return Outcome.INCOMPATIBLE
    if values and all(x == Outcome.COMPATIBLE for x in values):
        return Outcome.COMPATIBLE
    return Outcome.UNKNOWN


def _alternatives(outcomes):
    values = list(outcomes)
    if Outcome.COMPATIBLE in values:
        return Outcome.COMPATIBLE
    if values and all(x == Outcome.INCOMPATIBLE for x in values):
        return Outcome.INCOMPATIBLE
    return Outcome.UNKNOWN


class FieldComparison(Contract):
    dimension: Identifier
    outcome: Outcome
    reason: Identifier
    coverage: Literal['checked', 'missing', 'unsupported'] = 'checked'

    @model_validator(mode='after')
    def coverage_consistency(self):
        if self.coverage != 'checked' and self.outcome != Outcome.UNKNOWN:
            raise ValueError('Missing/unsupported cannot become compatible or incompatible')
        return self


def _check(dimension, outcome, reason, coverage='checked'):
    return FieldComparison(dimension=dimension, outcome=outcome, reason=reason, coverage=coverage)


def _unknown(dimension, reason, coverage='missing'):
    return _check(dimension, Outcome.UNKNOWN, reason, coverage)


def _known(value):
    return value is not None and str(value).lower() not in ('', 'unknown', 'unspecified')


def _equal(dimension, provided, required):
    if not _known(provided) or not _known(required):
        return _unknown(dimension, 'MISSING_TYPED_VALUE')
    same = type(provided) is type(required) and provided == required
    return _check(dimension, Outcome.COMPATIBLE if same else Outcome.INCOMPATIBLE,
                  'EXACT_MATCH' if same else 'EXPLICIT_VALUE_CONFLICT')


def compare_numeric_domains(provided: NumericDomain | None, required: NumericDomain | None, *,
                            quantifier: Literal['unspecified', 'contains_all'] = 'unspecified',
                            dimension: str = 'numeric_domain') -> FieldComparison:
    """Direction: FW provided domain must contain the entire HW required domain.

    A singleton requirement is unambiguous. Range requirements need an explicit
    contains_all quantifier. XL1 in_range has no such quantifier: UNKNOWN.
    Masks/bit control alone are not numeric value availability or control proof.
    """
    if quantifier not in ('unspecified', 'contains_all'):
        raise ValueError('Unsupported domain quantifier')
    if provided is None or required is None:
        return _unknown(dimension, 'MISSING_NUMERIC_DOMAIN')
    provided = NumericDomain.model_validate(provided.model_dump())
    required = NumericDomain.model_validate(required.model_dump())
    if provided.mask is not None or required.mask is not None:
        return _unknown(dimension, 'MASK_DOMAIN_NOT_SUPPORTED', 'unsupported')
    def bounds(value):
        if value.exact is not None:
            return value.exact, value.exact
        if value.minimum is not None:
            return value.minimum, value.maximum
        return None
    fw, hw = bounds(provided), bounds(required)
    if fw is None or hw is None:
        return _unknown(dimension, 'MISSING_NUMERIC_BOUNDS')
    if hw[0] != hw[1] and quantifier == 'unspecified':
        return _unknown(dimension, 'RANGE_QUANTIFIER_UNSPECIFIED', 'unsupported')
    covered = fw[0] <= hw[0] and fw[1] >= hw[1]
    return _check(dimension, Outcome.COMPATIBLE if covered else Outcome.INCOMPATIBLE,
                  'REQUIRED_DOMAIN_CONTAINED' if covered else 'REQUIRED_DOMAIN_NOT_CONTAINED')


class Pointer(Contract):
    side: Literal['firmware', 'hardware']
    identity: Identifier


class SourceReference(Pointer):
    sha256: Sha256
    source_kind: Identifier
    hash_kind: Identifier


class EvidenceReference(Pointer):
    artifact_id: Identifier


class AlternativeComparison(Contract):
    firmware_primitive_id: Identifier
    firmware_constraint_ids: list[Identifier] = Field(default_factory=list)
    firmware_condition_ids: list[Identifier] = Field(default_factory=list)
    checks: list[FieldComparison] = Field(min_length=1)
    outcome: Outcome

    @model_validator(mode='after')
    def aggregation(self):
        if self.outcome != aggregate_required(c.outcome for c in self.checks):
            raise ValueError('Alternative outcome disagrees with field checks')
        if len({c.dimension for c in self.checks}) != len(self.checks):
            raise ValueError('Duplicate dimension within alternative')
        return self


class RequirementResult(Contract):
    requirement_id: Identifier
    section: Literal['platform', 'precondition', 'trigger', 'unclassified']
    checks: list[FieldComparison] = Field(default_factory=list)
    alternatives: list[AlternativeComparison] = Field(default_factory=list)
    outcome: Outcome
    matched_primitive_ids: list[Identifier] = Field(default_factory=list)
    context_primitive_ids: list[Identifier] = Field(default_factory=list)
    firmware_constraint_ids: list[Identifier] = Field(default_factory=list)
    firmware_condition_ids: list[Identifier] = Field(default_factory=list)
    artifact_refs: list[Pointer] = Field(default_factory=list)
    evidence_refs: list[Pointer] = Field(default_factory=list)

    @model_validator(mode='after')
    def aggregation(self):
        if self.checks and self.alternatives:
            raise ValueError('Choose required checks or primitive alternatives')
        expected = (_alternatives(a.outcome for a in self.alternatives) if self.alternatives
                    else aggregate_required(c.outcome for c in self.checks))
        if self.outcome != expected:
            raise ValueError('Requirement outcome disagrees with checks')
        matched = sorted(a.firmware_primitive_id for a in self.alternatives if a.outcome == Outcome.COMPATIBLE)
        if sorted(self.matched_primitive_ids) != matched:
            raise ValueError('Matched primitive IDs must follow compatible alternatives')
        if len({a.firmware_primitive_id for a in self.alternatives}) != len(self.alternatives):
            raise ValueError('Duplicate primitive alternative')
        if len({c.dimension for c in self.checks}) != len(self.checks):
            raise ValueError('Duplicate dimension')
        return self


class DownstreamRequirement(Contract):
    section: Literal['deviation', 'observation']
    requirement_ids: list[Identifier] = Field(default_factory=list)
    state: Literal['missing', 'present_not_assessed']

    @model_validator(mode='after')
    def missing(self):
        if bool(self.requirement_ids) != (self.state == 'present_not_assessed'):
            raise ValueError('Downstream presence mismatch')
        return self


def _coverage(platform, requirements):
    checked, unsupported, missing = [], [], []
    for row in [platform, *requirements]:
        groups = [('', row.checks), *((a.firmware_primitive_id + '/', a.checks) for a in row.alternatives)]
        for prefix, checks in groups:
            for c in checks:
                name = row.section + '/' + row.requirement_id + '/' + prefix + c.dimension
                {'checked': checked, 'unsupported': unsupported, 'missing': missing}[c.coverage].append(name)
    return sorted(set(checked)), sorted(set(unsupported)), sorted(set(missing))


class CompatibilityInput(Contract):
    matcher_version: Identifier
    firmware_capability_id: Identifier
    firmware_capability_sha256: Sha256
    hardware_contract_id: Identifier
    hardware_contract_sha256: Sha256
    firmware_primitive_ids: list[Identifier]
    firmware_constraint_ids: list[Identifier]
    firmware_condition_ids: list[Identifier]
    platform_result: RequirementResult
    requirement_results: list[RequirementResult]
    overall_result: Outcome
    checked_dimensions: list[Identifier]
    unsupported_dimensions: list[Identifier]
    missing_information: list[Identifier]
    source_references: list[SourceReference]
    evidence_references: list[EvidenceReference]
    provenance: Literal['derived_from_typed_contracts'] = 'derived_from_typed_contracts'
    downstream_verification_requirements: list[DownstreamRequirement]
    unassessed_contract_sections: list[Identifier]
    limitations: list[Identifier]

    @model_validator(mode='after')
    def consistency(self):
        if self.firmware_capability_id != 'fwcap:' + self.firmware_capability_sha256:
            raise ValueError('Firmware input ID/hash mismatch')
        if self.hardware_contract_id != 'hwbehavior:' + self.hardware_contract_sha256:
            raise ValueError('Hardware input ID/hash mismatch')
        if self.platform_result.section != 'platform' or any(r.section == 'platform' for r in self.requirement_results):
            raise ValueError('Platform result must be separate')
        for name in ('firmware_primitive_ids', 'firmware_constraint_ids', 'firmware_condition_ids',
                     'checked_dimensions', 'unsupported_dimensions', 'missing_information',
                     'unassessed_contract_sections', 'limitations'):
            values = getattr(self, name)
            if len(values) != len(set(values)):
                raise ValueError('Duplicate result set member')
        rows = [self.platform_result, *self.requirement_results]
        if len({(r.section, r.requirement_id) for r in rows}) != len(rows):
            raise ValueError('Duplicate requirement identity')
        if set(d.section for d in self.downstream_verification_requirements) != {'deviation', 'observation'} or len(self.downstream_verification_requirements) != 2:
            raise ValueError('Deviation/Observation must remain separate downstream requirements')
        expected = aggregate_required([r.outcome for r in rows] + ([] if self.requirement_results else [Outcome.UNKNOWN]))
        if self.overall_result != expected:
            raise ValueError('Overall outcome disagrees with required results')
        if tuple(sorted(v) for v in (self.checked_dimensions, self.unsupported_dimensions, self.missing_information)) != _coverage(self.platform_result, self.requirement_results):
            raise ValueError('Coverage differs from actual field checks')
        sources = {(s.side, s.identity) for s in self.source_references}
        evidence = {(e.side, e.identity) for e in self.evidence_references}
        if len(sources) != len(self.source_references) or len(evidence) != len(self.evidence_references):
            raise ValueError('Duplicate source/evidence identity')
        if any((e.side, e.artifact_id) not in sources for e in self.evidence_references):
            raise ValueError('Evidence source is unbound')
        for row in rows:
            for names, registry in ((row.context_primitive_ids, self.firmware_primitive_ids),
                                    (row.firmware_constraint_ids, self.firmware_constraint_ids),
                                    (row.firmware_condition_ids, self.firmware_condition_ids)):
                if len(names) != len(set(names)) or not set(names) <= set(registry):
                    raise ValueError('Unbound or duplicate requirement context')
            for refs, registry in ((row.artifact_refs, sources), (row.evidence_refs, evidence)):
                keys = [(r.side, r.identity) for r in refs]
                if len(keys) != len(set(keys)) or not set(keys) <= registry:
                    raise ValueError('Duplicate or unbound requirement references')
            for a in row.alternatives:
                if a.firmware_primitive_id not in self.firmware_primitive_ids or not set(a.firmware_constraint_ids) <= set(self.firmware_constraint_ids) or not set(a.firmware_condition_ids) <= set(self.firmware_condition_ids):
                    raise ValueError('Alternative references unknown firmware object')
        return self


_SET_FIELDS = {'firmware_primitive_ids', 'firmware_constraint_ids', 'firmware_condition_ids',
               'matched_primitive_ids', 'context_primitive_ids', 'checked_dimensions', 'unsupported_dimensions', 'missing_information',
               'source_references', 'evidence_references', 'artifact_refs', 'evidence_refs',
               'unassessed_contract_sections', 'limitations', 'alternatives'}


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _normalize(value, key=''):
    if isinstance(value, dict):
        return {k: _normalize(v, k) for k, v in value.items()}
    if isinstance(value, list):
        items = [_normalize(v) for v in value]
        return sorted(items, key=_json) if key in _SET_FIELDS else items
    return value


def _payload(value):
    fields = value.model_dump(mode='json', include=set(CompatibilityInput.model_fields))
    return _json(_normalize({'schema_version': SCHEMA_VERSION, **fields})).encode()


class CapabilityContractCompatibilityResult(CompatibilityInput):
    schema_version: Literal['capability-contract-compatibility/v1'] = SCHEMA_VERSION
    result_id: Identifier
    result_sha256: Sha256

    @model_validator(mode='after')
    def identity(self):
        digest = hashlib.sha256(_payload(self)).hexdigest()
        if self.result_sha256 != digest or self.result_id != 'xlcompat:' + digest:
            raise ValueError('Compatibility result identity mismatch')
        return self


def serialize_compatibility_result(value: CapabilityContractCompatibilityResult) -> str:
    value = CapabilityContractCompatibilityResult.model_validate(value.model_dump(mode='json'))
    return _json(_normalize(value.model_dump(mode='json'))) + '\n'


def parse_compatibility_result(text: str) -> CapabilityContractCompatibilityResult:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    return CapabilityContractCompatibilityResult.model_validate(json.loads(text, object_pairs_hook=unique))


def _row(identifier, section, *, checks=(), alternatives=(), objects=()):
    artifacts, evidence = set(), set()
    primitives, constraints, conditions = set(), set(), set()
    for side, obj in objects:
        artifacts.update((side, x) for x in obj.source_artifact_ids)
        evidence.update((side, x) for x in obj.evidence_ids)
        if side == 'firmware':
            for field, ids in (('primitive_id', primitives), ('constraint_id', constraints), ('condition_id', conditions)):
                if hasattr(obj, field):
                    ids.add(getattr(obj, field))
    alternatives = list(alternatives)
    return RequirementResult(requirement_id=identifier, section=section, checks=list(checks), alternatives=alternatives,
        outcome=_alternatives(a.outcome for a in alternatives) if alternatives else aggregate_required(c.outcome for c in checks),
        matched_primitive_ids=sorted(a.firmware_primitive_id for a in alternatives if a.outcome == Outcome.COMPATIBLE),
        context_primitive_ids=sorted(primitives), firmware_constraint_ids=sorted(constraints),
        firmware_condition_ids=sorted(conditions),
        artifact_refs=[Pointer(side=s, identity=i) for s, i in sorted(artifacts)],
        evidence_refs=[Pointer(side=s, identity=i) for s, i in sorted(evidence)])


def _platform(fw, hw):
    checks = [_equal('architecture', fw.architecture, hw.architecture)]
    allowed = hw.scope.applicable_platforms or ([hw.platform.platform_id] if hw.platform.platform_id else [])
    if not _known(fw.scope.platform_id) or not allowed or any(not _known(x) for x in allowed):
        checks.append(_unknown('platform', 'PLATFORM_IDENTITY_MISSING'))
    else:
        match = fw.scope.platform_id in allowed
        checks.append(_check('platform', Outcome.COMPATIBLE if match else Outcome.INCOMPATIBLE,
                             'PLATFORM_IN_SCOPE' if match else 'PLATFORM_OUTSIDE_SCOPE'))
    ftarget, htarget = fw.scope.target, hw.platform.target
    if _known(ftarget.processor_id) and ftarget.processor_id == htarget.processor_id:
        checks.append(_check('processor', Outcome.COMPATIBLE, 'PROCESSOR_IDENTITY_EQUAL'))
    elif _known(fw.scope.platform_id) and fw.scope.platform_id == hw.platform.platform_id:
        checks.append(_equal('processor', ftarget.processor_id, htarget.processor_id))
    else:
        checks.append(_unknown('processor', 'PROCESSOR_IDENTITY_NOT_COMPARABLE'))
    if hw.scope.applicability == 'unknown' or fw.scope.applicability == 'unknown':
        checks.append(_unknown('scope', 'APPLICABILITY_UNKNOWN'))
    elif hw.scope.applicability == 'synthetic_only' and fw.scope.applicability != 'synthetic_only':
        checks.append(_unknown('scope', 'SYNTHETIC_SCOPE_NOT_SHARED'))
    else:
        checks.append(_check('scope', Outcome.COMPATIBLE, 'DECLARED_SCOPE_KIND_COMPARABLE'))
    if htarget.word_size_bits is not None:
        checks.append(_equal('word_size', ftarget.word_size_bits, htarget.word_size_bits))
    if _known(htarget.endianness):
        checks.append(_equal('endianness', ftarget.endianness, htarget.endianness))
    if htarget.isa_variant is not None:
        checks.append(_unknown('isa_variant', 'ISA_VARIANT_SEMANTICS_UNSUPPORTED', 'unsupported'))
    for name, needed in (('rtl_identity', hw.platform.rtl_identity),
                         ('rtl_revision', hw.platform.rtl_revision or hw.scope.rtl_revisions),
                         ('silicon_revision', hw.platform.silicon_revision or hw.scope.silicon_revisions)):
        if needed:
            checks.append(_unknown(name, 'FW_REVISION_FIELD_UNAVAILABLE', 'unsupported'))
    return _row('platform-and-scope', 'platform', checks=checks,
                objects=[('firmware', fw.scope), ('hardware', hw.platform), ('hardware', hw.scope)])


# Exact enum mapping only; deliberately excludes control-transfer primitives.
_MAPPING = {'instruction': {'INSTRUCTION_EXECUTION'}, 'CSR_access': {'CSR_READ', 'CSR_WRITE'},
            'MMIO_access': {'MMIO_READ', 'MMIO_WRITE'}}
_RESOURCE = {'MEMORY_READ': 'memory', 'MEMORY_WRITE': 'memory', 'WRITE_BOUNDED': 'memory',
             'READ_OOB': 'memory', 'WRITE_OOB': 'memory', 'CSR_READ': 'csr', 'CSR_WRITE': 'csr',
             'MMIO_READ': 'mmio', 'MMIO_WRITE': 'mmio'}


def _constraints(fw, primitive):
    return [c for c in fw.constraints if c.constraint_id in primitive.constraint_ids]


def _numeric_requirement(value, dimension, provided):
    if value.operator == 'eq' and type(value.value) is int and 0 <= value.value < (1 << 64):
        return compare_numeric_domains(provided, NumericDomain(exact=value.value), dimension=dimension)
    # in_range lacks existential/universal quantifier in frozen XL1.
    return _unknown(dimension, 'RANGE_QUANTIFIER_UNSPECIFIED' if value.operator == 'in_range'
                    else 'VALUE_OPERATOR_UNSUPPORTED', 'unsupported')


def _trigger_alternative(fw, trigger, primitive):
    constraints = _constraints(fw, primitive)
    by_kind = {c.kind: c for c in constraints if c.kind != 'ordering' and c.formalization_status not in ('unknown', 'unformalized')}
    required_resource = {'CSR_access': 'csr', 'MMIO_access': 'mmio'}.get(trigger.condition_kind)
    checks = []
    if primitive.kind not in _MAPPING.get(trigger.condition_kind, set()):
        resource = _RESOURCE.get(primitive.kind)
        if required_resource and resource and resource != required_resource:
            checks.append(_check('resource', Outcome.INCOMPATIBLE, 'EXPLICIT_RESOURCE_CLASS_CONFLICT'))
        else:
            checks.append(_unknown('mapping', 'NO_SUPPORTED_MAPPING', 'unsupported'))
    else:
        checks.append(_check('mapping', Outcome.COMPATIBLE, 'WHITELIST_MAPPING'))
        for c in constraints:
            if c.formalization_status in ('unknown', 'unformalized'):
                checks.append(_unknown('fw_constraint:' + c.constraint_id, 'FW_CONSTRAINT_NOT_MODELED'))
        if trigger.formalization_status in ('unknown', 'unformalized'):
            checks.append(_unknown('definition', 'HW_REQUIREMENT_NOT_FORMALIZED'))
        if primitive.formalization_status in ('unknown', 'unformalized') or primitive.basis == 'unknown':
            checks.append(_unknown('fw_definition', 'FW_PRIMITIVE_NOT_FORMALIZED'))
        if trigger.condition_kind == 'instruction':
            if not trigger.instructions:
                checks.append(_unknown('instruction', 'HW_INSTRUCTION_MISSING'))
            for instruction in trigger.instructions:
                for field in ('mnemonic', 'encoding', 'encoding_mask', 'operand_pattern', 'stage_requirement'):
                    if getattr(instruction, field) is not None:
                        checks.append(_unknown('instruction.' + field, 'FW_TYPED_INSTRUCTION_FIELD_UNAVAILABLE', 'unsupported'))
        elif trigger.access is None:
            checks.append(_unknown('access', 'HW_ACCESS_MISSING'))
        else:
            access = trigger.access
            direction = 'read' if primitive.kind.endswith('_READ') else 'write'
            checks.append(_check('direction', Outcome.COMPATIBLE if access.access in (direction, 'either') else Outcome.INCOMPATIBLE,
                                 'ACCESS_DIRECTION_ALLOWED' if access.access in (direction, 'either') else 'ACCESS_DIRECTION_CONFLICT'))
            resource = by_kind.get('target_resource')
            checks.append(_equal('resource', resource.resource_kind if resource else None, required_resource))
            if trigger.condition_kind == 'CSR_access':
                csr = by_kind.get('CSR')
                if access.csr_identity is not None:
                    checks.append(_equal('csr_identity', csr.identity if csr else None, access.csr_identity))
                if access.csr_address is not None:
                    checks.append(_unknown('csr_address', 'FW_NUMERIC_CSR_ADDRESS_UNAVAILABLE', 'unsupported'))
            else:
                address = by_kind.get('address')
                checks.append(compare_numeric_domains(address.domain if address else None,
                    NumericDomain(exact=access.address), dimension='mmio_address') if access.address < (1 << 64)
                    else _unknown('mmio_address', 'NUMERIC_WIDTH_UNSUPPORTED', 'unsupported'))
                if access.width_bits is not None:
                    width = by_kind.get('access_width')
                    checks.append(_equal('width', width.domain.exact if width else None, access.width_bits))
            if access.value_constraint is not None:
                value = by_kind.get('value')
                checks.append(_numeric_requirement(access.value_constraint, 'value', value.domain if value else None))
        for condition in fw.conditions:
            if condition.condition_id in primitive.condition_ids and (
                condition.predicate is None or condition.formalization_status in ('unknown', 'unformalized')
            ):
                checks.append(_unknown('fw_condition:' + condition.condition_id, 'FW_CONDITION_NOT_MODELED'))
    return AlternativeComparison(firmware_primitive_id=primitive.primitive_id,
        firmware_constraint_ids=sorted(c.constraint_id for c in constraints),
        firmware_condition_ids=sorted(primitive.condition_ids), checks=checks,
        outcome=aggregate_required(c.outcome for c in checks))


def _trigger(fw, trigger):
    alternatives = [_trigger_alternative(fw, trigger, p) for p in sorted(fw.primitives, key=lambda p: p.primitive_id)]
    objects = [('hardware', trigger)] + [('firmware', p) for p in fw.primitives]
    objects += [('firmware', c) for c in fw.constraints] + [('firmware', c) for c in fw.conditions]
    return _row(trigger.condition_id, 'trigger', alternatives=alternatives,
                checks=[] if alternatives else [_unknown('mapping', 'NO_FW_PRIMITIVES')], objects=objects)


def _precondition(fw, pre, trigger_rows):
    objects = [('hardware', pre), ('firmware', fw)]
    predicate = pre.required_relation
    if predicate is None or pre.formalization_status in ('unknown', 'unformalized'):
        return _row(pre.condition_id, 'precondition', checks=[_unknown('predicate', 'HW_PRECONDITION_MISSING')], objects=objects)
    # Reserved exact typed subject vocabulary. No searching natural-language text.
    control_subjects = {'external_control.' + d: d for d in ('address', 'value', 'length', 'target', 'execution_context')}
    selected = {i for row in trigger_rows for i in row.matched_primitive_ids}
    unique_mapping = all(len(row.matched_primitive_ids) == 1 for row in trigger_rows) and bool(trigger_rows)
    if not unique_mapping or len(selected) != 1:
        return _row(pre.condition_id, 'precondition', checks=[_unknown('context', 'NO_UNAMBIGUOUS_TRIGGER_CONTEXT')], objects=objects)
    primitives = [p for p in fw.primitives if p.primitive_id in selected]
    objects += [('firmware', p) for p in primitives]
    checks = []
    if pre.condition_kind == 'other' and predicate.subject in control_subjects:
        if predicate.operator != 'eq' or predicate.operands != [True] or type(predicate.operands[0]) is not bool or predicate.unit is not None:
            checks = [_unknown('external_control', 'CONTROL_PREDICATE_UNSUPPORTED', 'unsupported')]
        else:
            dimension = control_subjects[predicate.subject]
            for p in primitives:
                established = p.control.status in ('bounded_external_control', 'full_external_control') and dimension in p.control.dimensions
                checks.append(_check('control:' + p.primitive_id, Outcome.COMPATIBLE, 'EXPLICIT_CONTROL_DECLARATION') if established
                              else _unknown('control:' + p.primitive_id, 'EXTERNAL_CONTROL_NOT_ESTABLISHED'))
                objects.append(('firmware', p.control))
    elif pre.condition_kind in ('privilege', 'register_state', 'execution_context'):
        if predicate.operator != 'eq' or predicate.unit is not None:
            checks = [_unknown('predicate', 'PRECONDITION_OPERATOR_UNSUPPORTED', 'unsupported')]
        else:
            required = predicate.operands[0]
            subjects = {'privilege': {'privilege', 'execution_mode'},
                        'execution_context': {'execution_context', 'mode'}}
            valid_subject = pre.condition_kind == 'register_state' or predicate.subject in subjects[pre.condition_kind]
            if not valid_subject:
                checks = [_unknown('predicate', 'PRECONDITION_SUBJECT_UNSUPPORTED', 'unsupported')]
            else:
                for p in primitives:
                    values = []
                    for c in _constraints(fw, p):
                        if c.kind == pre.condition_kind and pre.condition_kind != 'register_state' and c.formalization_status not in ('unknown', 'unformalized'):
                            values.append(c.identity)
                            objects.append(('firmware', c))
                    for c in fw.conditions:
                        if c.condition_id not in p.condition_ids or c.condition_kind != pre.condition_kind:
                            continue
                        if c.predicate and c.predicate.subject == predicate.subject and c.predicate.operator == 'eq' and c.formalization_status not in ('unknown', 'unformalized'):
                            values.append(c.predicate.operands[0])
                            objects.append(('firmware', c))
                    distinct = {(type(v).__name__, _json(v)) for v in values}
                    if len(distinct) > 1:
                        checks.append(_unknown('state:' + p.primitive_id, 'CONTRADICTORY_FW_STATE_REQUIREMENTS', 'unsupported'))
                    else:
                        checks.append(_equal('state:' + p.primitive_id, values[0] if values else None, required))
    else:
        checks = [_unknown('predicate', 'PRECONDITION_KIND_UNSUPPORTED', 'unsupported')]
    return _row(pre.condition_id, 'precondition', checks=checks, objects=objects)


def _ordering(fw, trigger, rows):
    atom = trigger.ordering
    objects = [('hardware', trigger), ('firmware', fw)]
    if atom is None or trigger.formalization_status in ('unknown', 'unformalized'):
        return _row(trigger.condition_id, 'trigger', checks=[_unknown('ordering', 'HW_ORDERING_MISSING')], objects=objects)
    before, after = rows.get(atom.before_atom_id), rows.get(atom.after_atom_id)
    if not before or not after or len(before.matched_primitive_ids) != 1 or len(after.matched_primitive_ids) != 1:
        checks = [_unknown('ordering', 'ORDER_ENDPOINT_MAPPING_NOT_ESTABLISHED')]
    else:
        a, b = before.matched_primitive_ids[0], after.matched_primitive_ids[0]
        objects += [('firmware', p) for p in fw.primitives if p.primitive_id in (a, b)]
        direct = [c for c in fw.constraints if c.kind == 'ordering' and (c.before_primitive_id, c.after_primitive_id) == (a, b)]
        reverse = [c for c in fw.constraints if c.kind == 'ordering' and (c.before_primitive_id, c.after_primitive_id) == (b, a)]
        objects += [('firmware', c) for c in direct + reverse]
        if a == b or len(direct) > 1 or (direct and reverse):
            checks = [_unknown('ordering', 'ORDER_OCCURRENCES_OR_DECLARATIONS_AMBIGUOUS', 'unsupported')]
        elif direct:
            c = direct[0]
            checks = [_check('ordering', Outcome.COMPATIBLE, 'MAPPED_DECLARED_ORDER_EQUAL')]
            if c.formalization_status in ('unknown', 'unformalized') or trigger.formalization_status in ('unknown', 'unformalized'):
                checks.append(_unknown('order_definition', 'ORDER_DEFINITION_NOT_MODELED'))
            if atom.max_gap_events is not None:
                checks.append(_check('max_gap_events', Outcome.COMPATIBLE, 'DECLARED_ORDER_BOUND_SUFFICIENT')
                              if c.max_gap_events is not None and c.max_gap_events <= atom.max_gap_events
                              else _unknown('max_gap_events', 'ORDER_BOUND_INSUFFICIENT'))
            if atom.max_gap_time is not None:
                checks.append(_unknown('max_gap_time', 'TIME_ORDER_BOUND_UNSUPPORTED', 'unsupported'))
        elif reverse and all(c.formalization_status not in ('unknown', 'unformalized') for c in reverse):
            checks = [_check('ordering', Outcome.INCOMPATIBLE, 'MAPPED_DECLARED_ORDER_REVERSED')]
        else:
            checks = [_unknown('ordering', 'NO_DECLARED_ORDER_FOR_MAPPED_ENDPOINTS')]
    return _row(trigger.condition_id, 'trigger', checks=checks, objects=objects)


def compare_capability_contract(firmware: FirmwareCapability, hardware: HardwareBehaviorContract) -> CapabilityContractCompatibilityResult:
    fw = FirmwareCapability.model_validate(firmware.model_dump(mode='json'))
    hw = HardwareBehaviorContract.model_validate(hardware.model_dump(mode='json'))
    platform = _platform(fw, hw)
    base = {t.condition_id: _trigger(fw, t) for t in hw.trigger if t.condition_kind != 'ordering'}
    preconditions = [_precondition(fw, p, list(base.values())) for p in sorted(hw.preconditions, key=lambda p: p.condition_id)]
    triggers = [base[t.condition_id] if t.condition_kind != 'ordering' else _ordering(fw, t, base) for t in hw.trigger]
    requirements = preconditions + triggers
    if not hw.trigger:
        requirements.append(_row('trigger-missing', 'trigger', checks=[_unknown('definition', 'NO_HW_TRIGGER_REQUIREMENTS')]))
    for u in sorted(hw.unclassified_atoms, key=lambda u: u.atom.atom_id):
        requirements.append(_row(u.atom.atom_id, 'unclassified',
            checks=[_unknown('role', 'UNCLASSIFIED_HW_REQUIREMENT', 'unsupported')], objects=[('hardware', u)]))
    checked, unsupported, missing = _coverage(platform, requirements)
    downstream = [DownstreamRequirement(section=k, requirement_ids=sorted(x.condition_id for x in getattr(hw, k)),
                    state='present_not_assessed' if getattr(hw, k) else 'missing') for k in ('deviation', 'observation')]
    unassessed = ['deviation', 'observation', 'runtime_execution', 'path_feasibility', 'joint_satisfiability', 'security_impact',
                  'external_control_without_explicit_requirement', 'scope_prose_assumptions']
    if not hw.preconditions:
        unassessed.append('preconditions_missing')
    if not hw.trigger:
        unassessed.append('trigger_missing')
    if any(c.formalization_status != 'formalized' for c in [*hw.preconditions, *hw.trigger]):
        unassessed.append('partial_or_unknown_requirement_definition')
    sources, evidence = [], []
    for side, obj in (('firmware', fw), ('hardware', hw)):
        sources += [SourceReference(side=side, identity=s.artifact_id, sha256=s.sha256, source_kind=s.source_kind,
                                    hash_kind=getattr(s, 'hash_kind', 'file_bytes')) for s in obj.source_artifacts]
        evidence += [EvidenceReference(side=side, identity=e.evidence_id, artifact_id=e.artifact_id) for e in obj.evidence]
    value = CompatibilityInput(matcher_version=MATCHER_VERSION, firmware_capability_id=fw.capability_id,
        firmware_capability_sha256=fw.capability_sha256, hardware_contract_id=hw.contract_id,
        hardware_contract_sha256=hw.contract_sha256, firmware_primitive_ids=sorted(p.primitive_id for p in fw.primitives),
        firmware_constraint_ids=sorted(c.constraint_id for c in fw.constraints),
        firmware_condition_ids=sorted(c.condition_id for c in fw.conditions), platform_result=platform,
        requirement_results=requirements, overall_result=aggregate_required([platform.outcome, *(r.outcome for r in requirements)]),
        checked_dimensions=checked, unsupported_dimensions=unsupported, missing_information=missing,
        source_references=sources, evidence_references=evidence, downstream_verification_requirements=downstream,
        unassessed_contract_sections=sorted(unassessed),
        limitations=['COMPATIBLE 只表示已支持字段的兼容；不是触发满足、运行证明或偏差验证',
                     'INCOMPATIBLE 仅针对本次输入对象及其显式要求，不证明整个固件没有其他能力',
                     '输入均是带来源的声明；比较记录不新增执行或漏洞证据',
                     '不评估联合可满足性、路径、隐式状态或未声明的外部控制需求'])
    payload = _payload(value)
    digest = hashlib.sha256(payload).hexdigest()
    return CapabilityContractCompatibilityResult.model_validate({**json.loads(payload), 'result_id': 'xlcompat:' + digest,
                                                                 'result_sha256': digest})


def validate_compatibility_replay(value: CapabilityContractCompatibilityResult,
                                  firmware: FirmwareCapability, hardware: HardwareBehaviorContract):
    """Verify a record against its actual inputs and current rules, not just hashes."""
    checked = CapabilityContractCompatibilityResult.model_validate(value.model_dump(mode='json'))
    expected = compare_capability_contract(firmware, hardware)
    if checked.result_id != expected.result_id:
        raise ValueError('Comparison record does not replay under the supplied inputs/current rules')
    return checked
