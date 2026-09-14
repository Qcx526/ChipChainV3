"""Lossless compact A4 transport plus A3 display labels and exact evidence delta."""
import json
from typing import Literal

from chipchain.agents.firmware_evidence import collect_firmware_reasoning_evidence
from chipchain.agents.projections.firmware import build_firmware_analysis_projection, firmware_projection_sha256
from chipchain.agents.projections.firmware_envelope import compact, digest, neutral
from chipchain.domain.common import Contract, Sha256
from chipchain.domain.evidence import EvidenceRef
from chipchain.tools.firmware.relations import TransferDetails, DirectionDetails, ContainmentDetails, VectorDetails
from chipchain.tools.firmware.relations import (
    FirmwareStaticRelationCatalog, capabilities_for, firmware_static_relations_sha256,
    parse_firmware_static_relations, serialize_firmware_static_relations,
)
from chipchain.tools.firmware.structure_projection import _table, _untable, relevant_structure_sha256

VERSION = 'firmware-relation-projection/v1'
MAX_RELATION_CHARS = 17000
ATTRIBUTE_KEYS = set().union(*(m.model_fields for m in (TransferDetails,DirectionDetails,ContainmentDetails,VectorDetails)))
SEMANTICS = {
    'confirmed_static': 'Static fact only, not execution. Catalog common_limitations apply to every row.',
    'direct_call': 'Confirmed direct_call supports exact direct-call claims.',
    'direct_branch': 'Confirmed direct_branch supports branch claims, never direct-call claims.',
    'control_transfer_unresolved': 'Not a confirmed direct transfer; its unresolved fact can be stated exactly.',
    'vector_dispatch': 'Static vector binding only; no interrupt occurrence or handler execution.',
    'mmio_function_containment': 'Static address containment; missing is not absence proof.',
    'mmio_access_direction': 'A1 read/write/unknown only.',
    'all_relations': 'No runtime execution/reachability, physical interface, or input consumption proof.',
    'function_labels': 'Display labels only. Symbol/name != semantic proof.',
    'wire_format': 'Named columns + common fields; zero-based dictionary indices. Function endpoint addresses resolve via function_endpoints; instruction/mmio/vector source addresses equal site_address. Group evidence_from_relation_id means evidence_ids=[relation_id]; source_id_policy=relation_id copies relation_id; mmio_site_hex means mmio-{site_address:x}. Label entry addresses resolve via function_endpoints. Evidence address_from_relation_site resolves the unique referenced relation site. MMIO evidence resolves by site_address in mmio_evidence_bindings.',
}


class FunctionLabel(Contract):
    function_id: str
    entry_address: int
    name: str | None


class FirmwareRelationProjection(Contract):
    projection_version: Literal['firmware-relation-projection/v1'] = VERSION
    catalog_sha256: Sha256
    catalog: FirmwareStaticRelationCatalog
    function_labels: list[FunctionLabel]
    evidence_delta: list[EvidenceRef]


def _evidence_wire(refs, catalog):
    records = [r.model_dump(mode='json') for r in refs]
    profiles = sorted({compact({k:v for k,v in r.items() if k not in ('evidence_id','location')}):
                       {k:v for k,v in r.items() if k not in ('evidence_id','location')} for r in records}.values(), key=compact)
    indices = {compact(p):i for i,p in enumerate(profiles)}
    sites = {}
    for relation in catalog.relations:
        for eid in relation.evidence_ids: sites.setdefault(eid,set()).add(relation.site_address)
    address_alias = bool(records) and all(sites.get(r['evidence_id']) == {r['location']['address']} for r in records)
    keys = sorted({k for r in records for k,v in r['location'].items() if v is not None and not (k=='address' and address_alias)})
    return dict(address_from_relation_site=address_alias,profiles=_table(profiles), entries=_table([
        dict(evidence_id=r['evidence_id'], profile=indices[compact({k:v for k,v in r.items() if k not in ('evidence_id','location')})],
             **{'location.'+k:r['location'][k] for k in keys}) for r in records]))


def _evidence_parse(value, catalog):
    if set(value) != {'profiles','entries','address_from_relation_site'}:
        raise ValueError('Invalid evidence delta')
    profiles = _untable(value['profiles'])
    sites = {}
    for relation in catalog['relations']:
        for eid in relation['evidence_ids']: sites.setdefault(eid,set()).add(relation['site_address'])
    refs = []
    for row in _untable(value['entries']):
        index = row.pop('profile')
        if type(index) is not int or not 0 <= index < len(profiles):
            raise ValueError('Invalid evidence profile index')
        eid = row.pop('evidence_id')
        if any(not k.startswith('location.') for k in row):
            raise ValueError('Invalid evidence location column')
        if value['address_from_relation_site']:
            if len(sites.get(eid,set())) != 1: raise ValueError('Ambiguous evidence site address')
            row['location.address'] = next(iter(sites[eid]))
        refs.append(EvidenceRef(**profiles[index], evidence_id=eid,
            location={k.removeprefix('location.'):v for k,v in row.items()}))
    return refs


def projection_registry(projection, base):
    registry = {r.evidence_id:r for r in base.evidence_catalog}
    if len(registry) != len(base.evidence_catalog):
        raise ValueError('Duplicate base evidence')
    for ref in projection.evidence_delta:
        if ref.evidence_id in registry:
            raise ValueError('Evidence delta overlaps or duplicates base/other delta')
        if ref.artifact_id not in {a.artifact_id for a in base.artifacts}:
            raise ValueError('Undeclared evidence artifact')
        registry[ref.evidence_id] = ref
    if (firmware_projection_sha256(base) != projection.catalog.source_identities.a1_sha256
            or base.case.case_id != projection.catalog.case_id):
        raise ValueError('A1/relation source mismatch')
    parse_firmware_static_relations(serialize_firmware_static_relations(projection.catalog), evidence_registry=registry)
    return dict(sorted(registry.items()))


def _wire(projection):
    projection = FirmwareRelationProjection.model_validate(projection.model_dump())
    labels = projection.function_labels
    functions = {f.entity_id:f for f in projection.catalog.function_endpoints}
    if len({f.function_id for f in labels}) != len(labels) or any(
            f.function_id not in functions or f.entry_address != functions[f.function_id].address for f in labels):
        raise ValueError('Invalid display label identity')
    if firmware_static_relations_sha256(projection.catalog) != projection.catalog_sha256:
        raise ValueError('A4 catalog hash mismatch')
    catalog = json.loads(serialize_firmware_static_relations(projection.catalog))
    catalog.pop('evidence_ids')  # Recovered exactly from external base + delta.
    relations = catalog.pop('relations')
    common_limits = sorted(set.intersection(*(set(r['limitations']) for r in relations))) if relations else []
    catalog['common_limitations'] = common_limits
    groups = {}
    mmio_evidence = {}
    for r in relations:
        # Capabilities are exactly derivable from frozen A4 kind/status validation.
        r.pop('capabilities')
        r['limitations'] = [x for x in r['limitations'] if x not in common_limits]
        attrs = r.pop('attributes')
        source, target = r.pop('source'), r.pop('target')
        row = {**r, **attrs,
               **{'source.'+k:v for k,v in source.items()},
               **{'target.'+k:(target[k] if target else None) for k in ('entity_type','entity_id','address')}}
        row.pop('source.address')
        if target is None or target['entity_type'] == 'function':
            row['target.address'] = None  # Recover function entry from the identity table.
        if r['kind'] in ('mmio_access_direction','mmio_function_containment'):
            old = mmio_evidence.setdefault(r['site_address'],r['evidence_ids'])
            if old != r['evidence_ids']:
                raise ValueError('MMIO relations disagree on shared site evidence')
            row.pop('evidence_ids')
        groups.setdefault(r['kind'], []).append(row)
    tables = {}
    for kind,rows in sorted(groups.items()):
        evidence_alias = all(row.get('evidence_ids') == [row['relation_id']] for row in rows)
        source_policy = ('relation_id' if all(row['source.entity_id'] == row['relation_id'] for row in rows) else
            'mmio_site_hex' if all(row['source.entity_type']=='mmio_site' and row['source.entity_id']==f"mmio-{row['site_address']:x}" for row in rows) else 'explicit')
        for row in rows:
            if evidence_alias: row.pop('evidence_ids')
            if source_policy != 'explicit': row.pop('source.entity_id')
        tables[kind] = dict(table=_table(rows),evidence_from_relation_id=evidence_alias,source_id_policy=source_policy)
    catalog['relations'] = tables
    catalog['mmio_evidence_bindings'] = _table([dict(site_address=pc,evidence_ids=ids) for pc,ids in sorted(mmio_evidence.items())])
    catalog['function_endpoints'] = _table(catalog['function_endpoints'])
    return dict(projection_version=VERSION, catalog_sha256=projection.catalog_sha256,
        relation_semantics=SEMANTICS, catalog=catalog,
        function_labels=_table([f.model_dump(exclude={'entry_address'}) for f in sorted(projection.function_labels,key=lambda f:f.function_id)]),
        evidence_delta=_evidence_wire(sorted(projection.evidence_delta,key=lambda e:e.evidence_id),projection.catalog))


def serialize_firmware_relation_projection(projection):
    text = compact(_wire(projection))
    neutral(json.loads(text))
    if len(text) > MAX_RELATION_CHARS:
        raise ValueError('Relation projection exceeds character budget; no truncation')
    return text


def parse_firmware_relation_projection(text, *, base):
    data = json.loads(text)
    if set(data) != {'projection_version','catalog_sha256','relation_semantics','catalog','function_labels','evidence_delta'} or data.pop('relation_semantics') != SEMANTICS:
        raise ValueError('Unknown relation projection fields/semantics')
    catalog = data['catalog']
    rows = []
    common_limits = catalog.pop('common_limitations')
    functions = _untable(catalog['function_endpoints'])
    addresses = {f['entity_id']:f['address'] for f in functions}
    mmio_rows = _untable(catalog.pop('mmio_evidence_bindings'))
    mmio = {r['site_address']:r['evidence_ids'] for r in mmio_rows}
    if len(mmio) != len(mmio_rows): raise ValueError('Duplicate MMIO evidence binding')
    for kind, group in catalog['relations'].items():
        if set(group) != {'table','evidence_from_relation_id','source_id_policy'}:
            raise ValueError('Invalid relation group')
        for r in _untable(group['table']):
            if group['evidence_from_relation_id']: r['evidence_ids'] = [r['relation_id']]
            if group['source_id_policy']=='relation_id': r['source.entity_id'] = r['relation_id']
            elif group['source_id_policy']=='mmio_site_hex': r['source.entity_id'] = f"mmio-{r['site_address']:x}"
            elif group['source_id_policy']!='explicit': raise ValueError('Invalid source ID policy')
            if kind in ('mmio_access_direction','mmio_function_containment'):
                r['evidence_ids'] = mmio[r['site_address']]
            r['source.address'] = addresses[r['source.entity_id']] if r['source.entity_type']=='function' else r['site_address']
            if r['target.entity_type']=='function': r['target.address'] = addresses[r['target.entity_id']]
            r['limitations'] = sorted(common_limits+r['limitations'])
            attrs = {k:r.pop(k) for k in list(r) if k in ATTRIBUTE_KEYS}
            source = {k:r.pop('source.'+k) for k in ('entity_type','entity_id','address')}
            target = {k:r.pop('target.'+k) for k in ('entity_type','entity_id','address')}
            if r['kind'] != kind:
                raise ValueError('Relation kind/table mismatch')
            if target['entity_type'] is None and any(v is not None for v in target.values()):
                raise ValueError('Invalid null target')
            rows.append(dict(**r, attributes=attrs, source=source,
                target=target if target['entity_type'] else None,
                capabilities=capabilities_for(r['kind'],r['status']).model_dump()))
    catalog['relations'] = rows
    catalog['function_endpoints'] = _untable(catalog['function_endpoints'])
    delta = _evidence_parse(data['evidence_delta'],catalog)
    catalog['evidence_ids'] = sorted([e.evidence_id for e in base.evidence_catalog]+[e.evidence_id for e in delta])
    result = FirmwareRelationProjection(projection_version=data['projection_version'], catalog_sha256=data['catalog_sha256'],
        catalog=catalog, function_labels=[dict(**f,entry_address=addresses[f['function_id']]) for f in _untable(data['function_labels'])], evidence_delta=delta)
    projection_registry(result,base)
    if serialize_firmware_relation_projection(result) != text:
        raise ValueError('Noncanonical relation projection')
    return result


def firmware_relation_projection_sha256(projection):
    return digest(serialize_firmware_relation_projection(projection))


def build_firmware_relation_projection(inputs, relevant, catalog):
    base = build_firmware_analysis_projection(inputs)
    registry = collect_firmware_reasoning_evidence(inputs,relevant)
    catalog = parse_firmware_static_relations(serialize_firmware_static_relations(catalog),evidence_registry=registry)
    if relevant_structure_sha256(relevant) != catalog.source_identities.a3_sha256:
        raise ValueError('A3/A4 source mismatch')
    functions = {f.entity_id:f for f in catalog.function_endpoints}
    labels = [FunctionLabel(function_id=f.function_id,entry_address=f.entry_address,name=f.name)
              for f in relevant.functions if f.function_id in functions]
    if any(functions[f.function_id].address != f.entry_address for f in labels):
        raise ValueError('Function label identity mismatch')
    base_ids = {r.evidence_id for r in base.evidence_catalog}
    projection = FirmwareRelationProjection(catalog_sha256=firmware_static_relations_sha256(catalog),catalog=catalog,
        function_labels=labels,evidence_delta=[ref for eid,ref in registry.items() if eid not in base_ids])
    return parse_firmware_relation_projection(serialize_firmware_relation_projection(projection),base=base)
