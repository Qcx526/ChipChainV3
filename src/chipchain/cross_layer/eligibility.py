"""Target compatibility plus explicit external binding, before any matching."""
from typing import Literal
from pydantic import Field, model_validator
from chipchain.domain.case import TargetDescriptor
from chipchain.domain.common import Architecture, Contract, Endianness, Identifier
from .codec import digest, parse, serialize, sha256

PAIR_VERSION = 'cross-layer-pair/v1'
BindingSource = Literal['explicit_manifest', 'shared_platform_identity', 'shared_session_identity',
                        'synthetic_test_fixture', 'unknown']
Eligibility = Literal['eligible', 'ineligible', 'unknown']


class CrossLayerPairManifest(Contract):
    """Caller-supplied metadata assertion, not inferred from processor model names."""
    manifest_id: Identifier
    firmware_case_id: Identifier
    hardware_case_id: Identifier
    binding_source: BindingSource
    firmware_identity: Identifier
    hardware_identity: Identifier
    evidence_ids: list[Identifier] = Field(min_length=1)

    @model_validator(mode='after')
    def binding(self):
        if self.binding_source == 'unknown':
            raise ValueError('A manifest must declare its deterministic binding source')
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError('Duplicate binding evidence')
        return self


def assess(firmware_target, hardware_target, manifest):
    reasons = []
    incompatible = False
    if Architecture.UNKNOWN in (firmware_target.architecture, hardware_target.architecture):
        reasons.append('architecture_unknown')
    elif firmware_target.architecture != hardware_target.architecture:
        reasons.append('architecture_mismatch')
        incompatible = True
    for field in ('isa_variant', 'word_size_bits', 'endianness'):
        a, b = getattr(firmware_target, field), getattr(hardware_target, field)
        if field == 'endianness':
            known = a != Endianness.UNKNOWN and b != Endianness.UNKNOWN
        else:
            known = a not in (None, '') and b not in (None, '')
        if known and a != b:
            reasons.append(field + '_mismatch')
            incompatible = True
    if manifest is None:
        reasons.append('target_identity_unbound')
    elif manifest.firmware_identity != manifest.hardware_identity:
        reasons.append('target_identity_mismatch')
        incompatible = True
    status = 'ineligible' if incompatible else 'unknown' if reasons else 'eligible'
    return status, sorted(reasons)


class CrossLayerPairDescriptor(Contract):
    schema_version: Literal['cross-layer-pair/v1'] = PAIR_VERSION
    pair_id: Identifier
    firmware_case_id: Identifier
    hardware_case_id: Identifier
    firmware_target: TargetDescriptor
    hardware_target: TargetDescriptor
    binding_source: BindingSource
    board_or_processor_identity: Identifier | None
    manifest: CrossLayerPairManifest | None
    eligibility: Eligibility
    reasons: list[Identifier]

    @model_validator(mode='after')
    def validate_binding(self):
        m = self.manifest
        if m and (m.firmware_case_id, m.hardware_case_id) != (self.firmware_case_id, self.hardware_case_id):
            raise ValueError('Manifest case IDs do not match pair')
        identity = m.firmware_identity if m and m.firmware_identity == m.hardware_identity else None
        if self.binding_source != (m.binding_source if m else 'unknown') or self.board_or_processor_identity != identity:
            raise ValueError('Binding declaration differs from manifest')
        if (self.eligibility, self.reasons) != assess(self.firmware_target, self.hardware_target, m):
            raise ValueError('Eligibility/reasons must be deterministically recomputed')
        fields = self.model_dump(mode='json', exclude={'pair_id'})
        if self.pair_id != 'xlpair:' + digest(fields):
            raise ValueError('Pair identity mismatch')
        return self


def build_cross_layer_pair(*, firmware_case_id, hardware_case_id, firmware_target,
                          hardware_target, manifest=None):
    firmware_target = TargetDescriptor.model_validate(firmware_target.model_dump())
    hardware_target = TargetDescriptor.model_validate(hardware_target.model_dump())
    if manifest is not None:
        manifest = CrossLayerPairManifest.model_validate(manifest.model_dump())
        manifest = manifest.model_copy(update={'evidence_ids': sorted(manifest.evidence_ids)})
    status, reasons = assess(firmware_target, hardware_target, manifest)
    fields = dict(schema_version=PAIR_VERSION, firmware_case_id=firmware_case_id,
                  hardware_case_id=hardware_case_id, firmware_target=firmware_target.model_dump(mode='json'),
                  hardware_target=hardware_target.model_dump(mode='json'),
                  binding_source=manifest.binding_source if manifest else 'unknown',
                  board_or_processor_identity=manifest.firmware_identity if manifest and
                      manifest.firmware_identity == manifest.hardware_identity else None,
                  manifest=manifest.model_dump(mode='json') if manifest else None,
                  eligibility=status, reasons=reasons)
    return CrossLayerPairDescriptor(pair_id='xlpair:' + digest(fields), **fields)


serialize_cross_layer_pair = serialize
cross_layer_pair_sha256 = sha256


def parse_cross_layer_pair(text):
    return parse(CrossLayerPairDescriptor, text)
