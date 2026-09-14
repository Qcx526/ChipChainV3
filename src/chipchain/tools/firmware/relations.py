"""A4 architecture-neutral static facts. No agent, execution or prose interpretation."""
import hashlib
import json
from enum import StrEnum
from typing import Annotated, Literal, Mapping, Self

from pydantic import Field, model_validator

from chipchain.domain.common import Contract, Sha256
from chipchain.domain.evidence import EvidenceRef
from chipchain.domain.provenance import ToolDescriptor
from chipchain.tools.firmware.ghidra.models import Address

VERSION = 'firmware-static-relations/v1'
Identifier = Annotated[str, Field(min_length=1)]


class RelationKind(StrEnum):
    DIRECT_CALL = 'direct_call'
    DIRECT_BRANCH = 'direct_branch'
    CONTROL_TRANSFER_UNRESOLVED = 'control_transfer_unresolved'
    VECTOR_DISPATCH = 'vector_dispatch'
    MMIO_FUNCTION_CONTAINMENT = 'mmio_function_containment'
    MMIO_ACCESS_DIRECTION = 'mmio_access_direction'


class RelationStatus(StrEnum):
    CONFIRMED_STATIC = 'confirmed_static'
    UNRESOLVED = 'unresolved'
    MISSING = 'missing'
    CONFLICT = 'conflict'


class TransferKind(StrEnum):
    DIRECT_CALL = 'direct_call'
    DIRECT_BRANCH = 'direct_branch'
    INDIRECT_CALL = 'indirect_call'
    INDIRECT_BRANCH = 'indirect_branch'
    COMPUTED_OR_AMBIGUOUS = 'computed_or_ambiguous'
    BOUNDARY_UNCONFIRMED = 'boundary_unconfirmed'
    DECODER_UNKNOWN = 'decoder_unknown'


class RelationEndpoint(Contract):
    entity_type: Literal['function', 'instruction_site', 'mmio_site', 'vector_entry', 'handler', 'address']
    entity_id: Identifier
    address: Address | None = None


class SupportCapabilities(Contract):
    supports_direct_call: bool = False
    supports_direct_branch: bool = False
    supports_static_dispatch: bool = False
    supports_mmio_containment: bool = False
    supports_mmio_direction: bool = False
    supports_runtime_execution: Literal[False] = False
    supports_runtime_reachability: Literal[False] = False
    supports_interrupt_occurrence: Literal[False] = False
    supports_handler_execution: Literal[False] = False
    supports_physical_interface: Literal[False] = False
    supports_input_consumption: Literal[False] = False


class RelationLimitation(StrEnum):
    STATIC_ONLY = 'static_only'
    NO_RUNTIME_REACHABILITY = 'no_runtime_reachability'
    NO_PHYSICAL_INTERFACE = 'no_physical_interface'
    NO_INPUT_CONSUMPTION = 'no_input_consumption'
    NO_INTERRUPT_OCCURRENCE = 'no_interrupt_occurrence'
    NO_HANDLER_EXECUTION = 'no_handler_execution'
    NOT_CONFIRMED_CALL = 'not_confirmed_call'
    LINEAR_BOUNDARY_ONLY = 'linear_instruction_boundary_not_cfg_proof'
    MISSING_CONTAINMENT = 'missing_containment_not_absence_proof'


class TransferDetails(Contract):
    detail_type: Literal['control_transfer'] = 'control_transfer'
    transfer_kind: TransferKind
    call_semantics: bool = False
    # Preserve the original A2 vocabulary exactly; no generic replacement reason.
    original_reason: Literal['computed_or_ambiguous', 'missing_caller', 'missing_callee',
        'callee_entry_conflict', 'caller_containment_conflict',
        'instruction_boundary_unconfirmed', 'decoder_disagreement'] | None = None
    original_target_address: Address | None = None
    mnemonic: str | None = None
    decoded_target_address: Address | None = None
    raw_encoding: str | None = Field(default=None, pattern=r'^(?:[0-9a-f]{2})+$')
    boundary_established: bool = False


class ContainmentDetails(Contract):
    detail_type: Literal['mmio_containment'] = 'mmio_containment'
    basis: Literal['static_address_containment'] = 'static_address_containment'


class DirectionDetails(Contract):
    detail_type: Literal['mmio_direction'] = 'mmio_direction'
    direction: Literal['read', 'write', 'unknown']
    mnemonic: str | None
    origin: Literal['A1'] = 'A1'


class VectorDetails(Contract):
    detail_type: Literal['vector_dispatch'] = 'vector_dispatch'
    vector_index: Annotated[int, Field(strict=True, ge=1)]
    binding_status: Literal['function_entry', 'inside_function', 'non_thumb',
                            'outside_executable', 'ambiguous', 'no_function']


RelationAttributes = Annotated[
    TransferDetails | ContainmentDetails | DirectionDetails | VectorDetails,
    Field(discriminator='detail_type'),
]


def capabilities_for(kind: RelationKind, status: RelationStatus) -> SupportCapabilities:
    flags = {
        RelationKind.DIRECT_CALL: 'supports_direct_call',
        RelationKind.DIRECT_BRANCH: 'supports_direct_branch',
        RelationKind.VECTOR_DISPATCH: 'supports_static_dispatch',
        RelationKind.MMIO_FUNCTION_CONTAINMENT: 'supports_mmio_containment',
        RelationKind.MMIO_ACCESS_DIRECTION: 'supports_mmio_direction',
    }
    return SupportCapabilities(**({flags[kind]: True}
        if status == RelationStatus.CONFIRMED_STATIC and kind in flags else {}))


class StaticRelationFact(Contract):
    relation_id: Identifier
    kind: RelationKind
    status: RelationStatus
    source: RelationEndpoint
    target: RelationEndpoint | None = None
    site_address: Address | None = None
    attributes: RelationAttributes
    evidence_ids: list[Identifier] = Field(min_length=1)
    capabilities: SupportCapabilities
    limitations: list[RelationLimitation] = Field(default_factory=lambda: [
        RelationLimitation.STATIC_ONLY, RelationLimitation.NO_RUNTIME_REACHABILITY,
        RelationLimitation.NO_PHYSICAL_INTERFACE, RelationLimitation.NO_INPUT_CONSUMPTION])

    @model_validator(mode='after')
    def semantics(self) -> Self:
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError('Duplicate relation evidence ID')
        if len(self.limitations) != len(set(self.limitations)):
            raise ValueError('Duplicate limitation')
        if RelationLimitation.STATIC_ONLY not in self.limitations:
            raise ValueError('A4 relations must be explicitly static only')
        if self.capabilities != capabilities_for(self.kind, self.status):
            raise ValueError('Capabilities do not match relation kind/status')
        d = self.attributes
        target_type = self.target.entity_type if self.target else None
        if self.site_address is None:
            raise ValueError('A4 relation requires its static site address')
        if self.source.entity_type in ('instruction_site', 'mmio_site', 'vector_entry') and self.source.address != self.site_address:
            raise ValueError('Source site address does not match relation site')
        if self.kind in (RelationKind.DIRECT_CALL, RelationKind.DIRECT_BRANCH,
                         RelationKind.CONTROL_TRANSFER_UNRESOLVED):
            if not isinstance(d, TransferDetails):
                raise ValueError('Control transfer needs typed transfer details')
            if self.kind == RelationKind.CONTROL_TRANSFER_UNRESOLVED:
                if self.status not in (RelationStatus.UNRESOLVED, RelationStatus.CONFLICT) or d.call_semantics:
                    raise ValueError('Unresolved transfer cannot assert call semantics')
                if self.source.entity_type not in ('function', 'instruction_site'):
                    raise ValueError('Invalid unresolved transfer source')
                if target_type not in (None, 'function', 'address'):
                    raise ValueError('Invalid unresolved transfer target')
                if d.original_reason is None:
                    raise ValueError('Unresolved transfer requires original A2 reason')
            else:
                if (self.status != RelationStatus.CONFIRMED_STATIC or self.source.entity_type != 'function'
                        or self.target is None or self.site_address is None):
                    raise ValueError('Direct transfer needs confirmed source/target/site')
                if d.transfer_kind.value != self.kind.value or d.call_semantics != (self.kind == RelationKind.DIRECT_CALL):
                    raise ValueError('Call and branch semantics cannot be interchanged')
                if target_type not in (('function',) if d.call_semantics else ('function', 'address')):
                    raise ValueError('Invalid direct transfer target')
                if d.original_reason == 'computed_or_ambiguous':
                    raise ValueError('Computed A2 transfer must remain unresolved')
                if d.original_reason is not None and (not d.boundary_established or d.decoded_target_address != self.target.address):
                    raise ValueError('Derived direct transfer needs decoded boundary and exact target')
        elif self.kind == RelationKind.MMIO_FUNCTION_CONTAINMENT:
            if not isinstance(d, ContainmentDetails) or self.source.entity_type != 'mmio_site':
                raise ValueError('Invalid containment details/source')
            if self.status == RelationStatus.CONFIRMED_STATIC:
                if target_type != 'function':
                    raise ValueError('Confirmed containment needs a function')
            elif self.status not in (RelationStatus.MISSING, RelationStatus.CONFLICT) or self.target is not None:
                raise ValueError('Missing/conflicting containment has no selected function')
        elif self.kind == RelationKind.MMIO_ACCESS_DIRECTION:
            if not isinstance(d, DirectionDetails) or self.source.entity_type != 'mmio_site' or self.target is not None:
                raise ValueError('Invalid direction details/endpoints')
            expected = RelationStatus.UNRESOLVED if d.direction == 'unknown' else RelationStatus.CONFIRMED_STATIC
            if self.status != expected:
                raise ValueError('Direction/status mismatch')
        elif self.kind == RelationKind.VECTOR_DISPATCH:
            if not isinstance(d, VectorDetails) or self.source.entity_type != 'vector_entry':
                raise ValueError('Invalid vector details/source')
            if self.source.entity_id != f'vector-{d.vector_index}':
                raise ValueError('Vector index/source identity mismatch')
            if d.binding_status == 'function_entry':
                if self.status != RelationStatus.CONFIRMED_STATIC or target_type != 'function':
                    raise ValueError('Static vector entry needs exact function binding')
            elif self.status != RelationStatus.UNRESOLVED:
                raise ValueError('Non-entry vector binding cannot establish function dispatch')
        return self


class RelationSourceIdentities(Contract):
    a1_version: Literal['firmware-analysis-projection/v1'] = 'firmware-analysis-projection/v1'
    a1_sha256: Sha256
    a2_semantic_hash_policy: Literal['recursively-sorted-source-collections/v1'] = 'recursively-sorted-source-collections/v1'
    a2_sha256: Sha256
    vectors_sha256: Sha256
    a3_version: Literal['firmware-relevant-static-structure/v1'] = 'firmware-relevant-static-structure/v1'
    a3_sha256: Sha256
    elf_artifact_id: Identifier
    elf_sha256: Sha256
    elf_size_bytes: Annotated[int, Field(strict=True, ge=1)]
    decoder: ToolDescriptor
    transfer_policy: Literal['thumb-m-linear-a2-bounds/v1'] = 'thumb-m-linear-a2-bounds/v1'


class RelationConstraints(Contract):
    static_only: Literal[True] = True
    evidence_policy: Literal['exact-a1-a3-reasoning-registry'] = 'exact-a1-a3-reasoning-registry'
    no_alternative_path_search: Literal[True] = True
    no_prose_interpretation: Literal[True] = True
    no_runtime_or_physical_inference: Literal[True] = True


class FirmwareStaticRelationCatalog(Contract):
    schema_version: Literal['firmware-static-relations/v1'] = VERSION
    case_id: Identifier
    source_identities: RelationSourceIdentities
    # Minimal identity table for referenced A2 functions, never symbol labels.
    function_endpoints: list[RelationEndpoint]
    relations: list[StaticRelationFact]
    constraints: RelationConstraints = Field(default_factory=RelationConstraints)
    evidence_ids: list[Identifier]
    warnings: list[Literal['linear_decode_is_not_cfg_proof', 'missing_relations_are_not_negative_proof',
                         'symbol_names_are_not_physical_interface_proof']]

    @model_validator(mode='after')
    def references(self) -> Self:
        for ids in ([r.relation_id for r in self.relations], self.evidence_ids,
                    [f.entity_id for f in self.function_endpoints]):
            if len(ids) != len(set(ids)):
                raise ValueError('Duplicate catalog identity')
        functions = {f.entity_id: f for f in self.function_endpoints}
        if any(f.entity_type != 'function' or f.address is None for f in functions.values()):
            raise ValueError('Function table requires function identities and entry addresses')
        evidence = set(self.evidence_ids)
        for relation in self.relations:
            if not set(relation.evidence_ids) <= evidence:
                raise ValueError('Unknown evidence ID')
            for endpoint in (relation.source, relation.target):
                if endpoint and endpoint.entity_type == 'function' and functions.get(endpoint.entity_id) != endpoint:
                    raise ValueError('Unknown or inconsistent function endpoint')
        return self


def serialize_firmware_static_relations(catalog: FirmwareStaticRelationCatalog) -> str:
    """Revalidate mutable nested values; canonicalize only set-like collections."""
    value = FirmwareStaticRelationCatalog.model_validate(catalog.model_dump()).model_dump(mode='json')
    value['relations'].sort(key=lambda r: (r['kind'], -1 if r['site_address'] is None else r['site_address'],
        r['source']['entity_id'], (r['target'] or {}).get('entity_id', ''), r['relation_id']))
    for r in value['relations']:
        r['evidence_ids'].sort()
        r['limitations'].sort()
    value['function_endpoints'].sort(key=lambda f: f['entity_id'])
    value['evidence_ids'].sort()
    value['warnings'].sort()
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def parse_firmware_static_relations(text: str, *, evidence_registry: Mapping[str, EvidenceRef]) -> FirmwareStaticRelationCatalog:
    """External exact registry is required: the serialized ID list is not authority."""
    result = FirmwareStaticRelationCatalog.model_validate_json(text)
    if set(result.evidence_ids) != set(evidence_registry) or any(k != v.evidence_id for k, v in evidence_registry.items()):
        raise ValueError('Catalog does not match the exact reasoning registry')
    return result


def firmware_static_relations_sha256(catalog: FirmwareStaticRelationCatalog) -> str:
    return hashlib.sha256(serialize_firmware_static_relations(catalog).encode('utf-8')).hexdigest()
