"""Resolve references against existing deterministic artifacts; no new truth store or IO.

Production behavior inputs expose only validated decoded-instruction fields. A4 exposes
MMIO direction but its instruction PC is NEVER reinterpreted as a resource address.
Additional state/access fields below are explicitly synthetic teaching fixtures in XL0.
"""
from dataclasses import dataclass
from copy import deepcopy
from typing import Literal

from pydantic import ConfigDict, Field

from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.domain.case import TargetDescriptor
from chipchain.domain.common import Contract, Identifier
from chipchain.tools.firmware.relations import FirmwareStaticRelationCatalog, firmware_static_relations_sha256
from chipchain.tools.firmware.static_reachability import (
    FirmwareAngrCFGResult, FirmwareStaticReachabilityCatalog,
    firmware_static_reachability_sha256, validate_reachability_witnesses,
)
from .adapters import architecture_adapter
from .codec import digest, sha256
from .contracts import FactCapabilities, FirmwareCrossLayerFactRef
from .trigger import Integer, Unsigned


class SyntheticBehaviorFields(Contract):
    """Strict scalar annotation for synthetic ProcessorBehavior fixtures only."""
    model_config = ConfigDict(populate_by_name=True, serialize_by_alias=True)
    fixture_schema: Literal['xl0-synthetic-comparable/v1']
    register_name: Identifier | None = Field(default=None, alias='register')
    state_value: Integer | None = None
    access: Literal['read', 'write', 'either'] | None = None
    address: Unsigned | None = None
    width_bits: int | None = Field(default=None, strict=True, gt=0)
    value: Integer | None = None
    csr_identity: Identifier | None = None
    csr_address: Unsigned | None = None
    mode: Identifier | None = None


@dataclass(frozen=True)
class ResolvedFact:
    ref: FirmwareCrossLayerFactRef
    fields: dict
    path: tuple[str, ...] = ()
    path_status: str | None = None


def function_path_id(source, target):
    return 'fwpath:' + digest([source, target])


class FirmwareFactSources:
    """In-memory view of frozen source contracts. All references are rebuilt on lookup.

    Callers supply deterministic tool artifacts, never agent-produced reports or IR.
    XL0 deliberately does not promote generic behavior attributes into real state facts.
    """
    def __init__(self, *, case_id, target: TargetDescriptor, processor_ir=None,
                 static_relations=None, static_reachability=None, cfg=None, synthetic=False):
        self.case_id = case_id
        self.target = TargetDescriptor.model_validate(target.model_dump())
        self.synthetic = synthetic
        self.adapter = architecture_adapter(self.target.architecture)
        self._facts = {}
        if processor_ir is not None:
            ir = ProcessorBehaviorIR.model_validate(processor_ir.model_dump())
            self._case(ir.case_id)
            for behavior in ir.behaviors:
                if behavior.origin != 'firmware' or behavior.architecture != self.target.architecture:
                    raise ValueError('Firmware behavior origin/architecture mismatch')
                if behavior.epistemic_status not in ('observed', 'derived') or not behavior.evidence:
                    raise ValueError('Comparable behaviors need deterministic evidence, not report hypotheses')
                fields = {}
                addresses = {e.location.address for e in behavior.evidence if e.location and e.location.address is not None}
                site = f'address:{next(iter(addresses))}' if len(addresses) == 1 else None
                decoded = behavior.decoded_instruction
                if behavior.kind == 'instruction' and decoded is not None:
                    if decoded.architecture != self.target.architecture:
                        raise ValueError('Decoder architecture mismatch')
                    registry = {e.evidence_id: e for e in behavior.evidence}
                    if any(registry.get(e.evidence_id) != e for e in decoded.evidence):
                        raise ValueError('Decoder evidence differs from the deterministic behavior')
                    if decoded.status == 'decoded':
                        fields = {'kind': 'instruction', 'mnemonic': decoded.mnemonic,
                                  'representation': decoded.representation.value, 'stage': decoded.source_stage}
                        # Encoding is numeric only when the decoder supplied an exact word.
                        if decoded.raw_encoding.startswith('0x'):
                            try:
                                fields['encoding'] = int(decoded.raw_encoding, 16)
                            except ValueError:
                                pass
                        fields.update(self.adapter.decoded_fields(decoded))
                attrs = behavior.attributes
                if 'fixture_schema' in attrs:
                    if not synthetic:
                        raise ValueError('Synthetic annotations require explicit synthetic sources')
                    typed = SyntheticBehaviorFields.model_validate(attrs)
                    fields = typed.model_dump(exclude_none=True, exclude={'fixture_schema'})
                    fields['kind'] = {'register_access': 'register_state', 'mmio_access': 'mmio_access',
                                      'csr_access': 'csr_access', 'privilege': 'privilege_state'}.get(behavior.kind)
                    if fields['kind'] is None:
                        raise ValueError('Synthetic annotation kind unsupported')
                self._add('processor_behavior', behavior.behavior_id, sha256(ir), site, fields)
        if static_relations is not None:
            catalog = FirmwareStaticRelationCatalog.model_validate(static_relations.model_dump())
            self._case(catalog.case_id)
            for relation in catalog.relations:
                fields = {}
                if relation.kind == 'mmio_access_direction' and relation.capabilities.supports_mmio_direction:
                    fields = {'kind': 'mmio_access', 'access': relation.attributes.direction}
                self._add('firmware_static_relation', relation.relation_id,
                          firmware_static_relations_sha256(catalog), f'address:{relation.site_address}', fields)
        if static_reachability is not None:
            if cfg is None:
                raise ValueError('A5 references require the bound CFG for witness validation')
            catalog = FirmwareStaticReachabilityCatalog.model_validate(static_reachability.model_dump())
            graph = FirmwareAngrCFGResult.model_validate(cfg.model_dump())
            self._case(catalog.identities.case_id)
            validate_reachability_witnesses(catalog, graph)
            if static_relations is not None and catalog.identities.a4_sha256 != firmware_static_relations_sha256(static_relations):
                raise ValueError('A4/A5 source mismatch')
            source_hash = firmware_static_reachability_sha256(catalog)
            for fact in catalog.function_reachability:
                path = tuple(f'address:{a}' for a in fact.witness_function_addresses)
                self._add('firmware_static_reachability', function_path_id(fact.source_function_id, fact.target_function_id),
                          source_hash, None, {}, path, fact.status)
            nodes = {n.node_id: n for n in graph.nodes}
            for fact in catalog.site_reachability:
                # Node addresses establish node ordering only. Never invent intra-block order.
                path = tuple(f'address:{nodes[n].canonical_address}' for n in fact.witness_node_ids)
                self._add('firmware_static_reachability', fact.site_id, source_hash,
                          f'address:{fact.site_address}', {}, path, fact.status)

    def _case(self, case_id):
        if self.case_id != case_id:
            raise ValueError('Firmware fact source case mismatch')

    def _add(self, kind, identity, source_hash, site, fields, path=(), status=None):
        positive = bool(status and status.startswith('reachable_static'))
        ref = FirmwareCrossLayerFactRef(source_kind=kind, source_id=identity, case_id=self.case_id,
            architecture=self.target.architecture, source_sha256=source_hash, site_id=site,
            capabilities=FactCapabilities(comparable_fields=sorted(k for k in fields if k != 'kind'),
                supports_static_ordering=positive and len(path) > 1, supports_static_reachability=positive))
        key = (kind, identity)
        if key in self._facts:
            raise ValueError('Duplicate source identity')
        self._facts[key] = ResolvedFact(ref, fields, path, status)

    def reference(self, source_kind, source_id):
        try:
            return self._facts[(source_kind, source_id)].ref.model_copy(deep=True)
        except KeyError as exc:
            raise ValueError('Unknown deterministic source ID') from exc

    def resolve(self, ref):
        ref = FirmwareCrossLayerFactRef.model_validate(ref.model_dump())
        result = self._facts.get((ref.source_kind, ref.source_id))
        if result is None or ref != result.ref:
            raise ValueError('Unbound, stale or modified firmware fact reference')
        return deepcopy(result)
