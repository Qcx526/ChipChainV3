"""Explicit typed necessary conditions; never extracted from report prose."""
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, model_validator

from chipchain.domain.common import Architecture, Contract, Identifier
from chipchain.domain.instruction import EncodingRepresentation
from .codec import digest, parse, serialize, sha256

TRIGGER_VERSION = 'hardware-trigger-condition/v1'
Integer = Annotated[int, Field(strict=True)]
Unsigned = Annotated[int, Field(strict=True, ge=0)]


class IntegerRange(Contract):
    minimum: Integer
    maximum: Integer

    @model_validator(mode='after')
    def ordered(self):
        if self.minimum > self.maximum:
            raise ValueError('Range minimum exceeds maximum')
        return self


class OperandPattern(Contract):
    destination_register: Identifier | None = None
    source_registers: list[Identifier] = Field(default_factory=list)
    base_register: Identifier | None = None
    immediate_exact: Integer | None = None
    immediate_range: IntegerRange | None = None

    @model_validator(mode='after')
    def consistent(self):
        if self.immediate_exact is not None and self.immediate_range is not None:
            raise ValueError('Choose exact immediate or range')
        if not any((self.destination_register, self.source_registers, self.base_register,
                    self.immediate_exact is not None, self.immediate_range)):
            raise ValueError('Empty operand pattern')
        return self


class ValueConstraint(Contract):
    operator: Literal['eq', 'neq', 'masked_eq', 'in_range']
    value: Integer | None = None
    mask: Unsigned | None = None
    range_min: Integer | None = None
    range_max: Integer | None = None

    @model_validator(mode='after')
    def operands(self):
        present = {k for k in ('value', 'mask', 'range_min', 'range_max') if getattr(self, k) is not None}
        expected = {'eq': {'value'}, 'neq': {'value'}, 'masked_eq': {'value', 'mask'},
                    'in_range': {'range_min', 'range_max'}}[self.operator]
        if present != expected:
            raise ValueError('Value fields do not match operator')
        if self.operator == 'masked_eq' and (self.value < 0 or self.value & ~self.mask):
            raise ValueError('Masked value must fit mask')
        if self.operator == 'in_range' and self.range_min > self.range_max:
            raise ValueError('Reversed range')
        return self


class Atom(Contract):
    atom_id: Identifier
    purpose: Literal['required', 'verification_only_metadata'] = 'required'


class InstructionTriggerAtom(Atom):
    kind: Literal['instruction'] = 'instruction'
    architecture: Architecture
    mnemonic: Identifier | None = None
    operand_pattern: OperandPattern | None = None
    encoding: Unsigned | None = None
    encoding_mask: Unsigned | None = None
    representation: EncodingRepresentation | None = None
    stage_requirement: Identifier | None = None

    @model_validator(mode='after')
    def precision(self):
        if self.mnemonic is None and self.encoding is None and self.operand_pattern is None:
            raise ValueError('Instruction requires typed instruction fields')
        if self.encoding_mask is not None and (self.encoding is None or self.encoding & ~self.encoding_mask):
            raise ValueError('Encoding value must fit mask')
        if self.encoding is not None and self.representation in (None, EncodingRepresentation.UNKNOWN):
            raise ValueError('Encoding comparison requires an explicit representation')
        return self


class RegisterStateTriggerAtom(Atom, ValueConstraint):
    model_config = ConfigDict(populate_by_name=True, serialize_by_alias=True)
    kind: Literal['register_state'] = 'register_state'
    register_name: Identifier = Field(alias='register')


class MMIOTriggerAtom(Atom):
    kind: Literal['mmio_access'] = 'mmio_access'
    address: Unsigned
    access: Literal['read', 'write', 'either']
    value_constraint: ValueConstraint | None = None
    width_bits: Annotated[int, Field(strict=True, gt=0)] | None = None


class CSRTriggerAtom(Atom):
    kind: Literal['csr_access'] = 'csr_access'
    csr_identity: Identifier | None = None
    csr_address: Unsigned | None = None
    access: Literal['read', 'write', 'either']
    value_constraint: ValueConstraint | None = None

    @model_validator(mode='after')
    def identity(self):
        if self.csr_identity is None and self.csr_address is None:
            raise ValueError('CSR identity or address is required')
        return self


class PrivilegeTriggerAtom(Atom):
    kind: Literal['privilege_state'] = 'privilege_state'
    architecture: Architecture
    required_mode: Identifier


class HardwareStateTriggerAtom(Atom, ValueConstraint):
    kind: Literal['hardware_state'] = 'hardware_state'
    state_identity: Identifier


class OrderingTriggerAtom(Atom):
    kind: Literal['ordering'] = 'ordering'
    before_atom_id: Identifier
    after_atom_id: Identifier
    max_gap_events: Unsigned | None = None
    max_gap_time: Unsigned | None = None
    time_unit: Identifier | None = None

    @model_validator(mode='after')
    def bounds(self):
        if self.before_atom_id == self.after_atom_id:
            raise ValueError('Ordering endpoints must differ')
        if (self.max_gap_time is None) != (self.time_unit is None):
            raise ValueError('Time bound requires explicit unit')
        return self


TriggerAtom = Annotated[InstructionTriggerAtom | RegisterStateTriggerAtom | MMIOTriggerAtom |
    CSRTriggerAtom | PrivilegeTriggerAtom | HardwareStateTriggerAtom | OrderingTriggerAtom,
    Field(discriminator='kind')]


class HardwareTriggerConditionInput(Contract):
    hardware_case_id: Identifier
    architecture: Architecture
    source_kind: Literal['hardware_relation', 'hardware_trigger_hypothesis', 'external_verified_spec',
                         'synthetic_fixture']
    source_ids: list[Identifier] = Field(min_length=1)
    source_hardware_hypothesis_id: Identifier | None = None
    epistemic_status: Literal['observed', 'derived', 'inferred', 'hypothesized']
    all_of_atoms: list[TriggerAtom] = Field(min_length=1)
    context_notes: list[str] = Field(default_factory=list)

    @model_validator(mode='after')
    def semantics(self):
        if len(self.source_ids) != len(set(self.source_ids)):
            raise ValueError('Duplicate source ID')
        if self.source_kind == 'hardware_trigger_hypothesis' or self.source_hardware_hypothesis_id:
            if self.epistemic_status != 'hypothesized':
                raise ValueError('Hardware hypotheses remain hypothesized')
        if self.source_hardware_hypothesis_id and self.source_hardware_hypothesis_id not in self.source_ids:
            raise ValueError('Hypothesis must be bound in source IDs')
        by_id = {a.atom_id: a for a in self.all_of_atoms}
        if len(by_id) != len(self.all_of_atoms):
            raise ValueError('Duplicate atom ID')
        if not any(a.purpose == 'required' for a in self.all_of_atoms):
            raise ValueError('Condition requires a necessary atom')
        for atom in self.all_of_atoms:
            if hasattr(atom, 'architecture') and atom.architecture != self.architecture:
                raise ValueError('Atom architecture differs from condition')
            if isinstance(atom, OrderingTriggerAtom):
                for key in (atom.before_atom_id, atom.after_atom_id):
                    other = by_id.get(key)
                    if other is None or isinstance(other, OrderingTriggerAtom) or other.purpose != 'required':
                        raise ValueError('Ordering references required non-ordering atoms')
        return self


class HardwareTriggerCondition(HardwareTriggerConditionInput):
    schema_version: Literal['hardware-trigger-condition/v1'] = TRIGGER_VERSION
    condition_id: Identifier

    @model_validator(mode='after')
    def canonical_identity(self):
        if self.condition_id != _identity(self):
            raise ValueError('Trigger condition identity mismatch')
        return self


def _fields(value):
    fields = value.model_dump(mode='json', include=set(HardwareTriggerConditionInput.model_fields))
    fields['all_of_atoms'].sort(key=lambda a: a['atom_id'])
    fields['source_ids'].sort()
    return fields


def _identity(value):
    return 'hwcondition:' + digest({'schema_version': TRIGGER_VERSION, **_fields(value)})


def build_hardware_trigger_condition(typed_input: HardwareTriggerConditionInput):
    typed_input = HardwareTriggerConditionInput.model_validate(typed_input.model_dump())
    return HardwareTriggerCondition(condition_id=_identity(typed_input), **_fields(typed_input))


def serialize_hardware_trigger_condition(value):
    return serialize(value)


def parse_hardware_trigger_condition(text):
    return parse(HardwareTriggerCondition, text)


hardware_trigger_condition_sha256 = sha256
