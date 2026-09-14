"""A3 static relevance only: no IO, agent invocation, IR creation or reachability."""
import hashlib
import json
from collections import defaultdict
from typing import Literal

from pydantic import Field

from chipchain.agents.contracts import FirmwareAgentInput
from chipchain.agents.firmware_evidence import collect_firmware_evidence
from chipchain.domain.common import Contract, Sha256
from chipchain.domain.evidence import EvidenceRef
from chipchain.domain.provenance import ToolDescriptor
from chipchain.tools.architecture.cortex_m import CortexMVectorResult
from chipchain.tools.contracts import MmioModelDetails, StaticInstructionSiteDetails
from chipchain.tools.firmware.ghidra.associations import associate_mmio
from chipchain.tools.firmware.ghidra.models import GhidraStaticStructureResult

VERSION = 'firmware-relevant-static-structure/v1'
MAX_STRUCTURE_CHARS = 18000
SEED_POLICY = ['mmio_unique_containment', 'bounded_vector_handlers',
               'one_hop_confirmed_calls', 'unresolved_caller_seed_only']


class StructureProjectionError(ValueError):
    """Invalid canonical inputs or a lossless projection exceeding its budget."""


class RelevantFunction(Contract):
    function_id: str
    entry_address: int
    name: str | None
    source_type: str
    seed_reasons: list[Literal['mmio_site', 'vector_handler']]
    role: Literal['seed', 'one_hop_neighbor']


class RelevantMmioSite(Contract):
    pc: int
    static_instruction_observation_id: str
    mnemonic: str | None
    direction: Literal['read', 'write', 'unknown']
    function_id: str | None
    containment_status: Literal['unique', 'missing', 'ambiguous']
    mmio_behavior_ids: list[str]
    evidence_ids: list[str]


class RelevantDirectCall(Contract):
    edge_id: str
    call_site_address: int
    caller_function_id: str
    callee_function_id: str
    evidence_ids: list[str]


class RelevantUnresolvedCall(Contract):
    call_site_address: int
    caller_function_id: str | None
    target_address: int | None
    reason: str
    evidence_ids: list[str]


class VectorHandlerGroup(Contract):
    handler_address: int
    function_id: str | None
    binding_status: str
    vector_indices: list[int]
    core_exception_names: list[str]
    external_irq_numbers: list[int]
    symbol_names: list[str]
    shared_handler: bool
    evidence_ids: list[str]


class UnresolvedConstraint(Contract):
    constraint_id: str
    status: Literal['not_established', 'missing_relation', 'missing_containment']
    statement: str
    pcs: list[int] = Field(default_factory=list)


class SeedNeighborhood(Contract):
    function_id: str
    incoming_edge_count: int
    outgoing_edge_count: int
    unresolved_outgoing_count: int


class SourceStructure(Contract):
    schema_version: Literal['static-structure/v1']
    tool: ToolDescriptor
    semantic_hash_policy: Literal['recursively-sorted-source-collections/v1']
    structure_sha256: Sha256
    vectors_sha256: Sha256


class FirmwareRelevantStaticStructure(Contract):
    projection_version: Literal['firmware-relevant-static-structure/v1'] = VERSION
    case_id: str
    source_structure: SourceStructure
    seed_policy: list[str]
    functions: list[RelevantFunction]
    mmio_sites: list[RelevantMmioSite]
    direct_call_edges: list[RelevantDirectCall]
    unresolved_call_sites: list[RelevantUnresolvedCall]
    vector_handler_groups: list[VectorHandlerGroup]
    null_vector_indices: list[int]
    evidence_catalog: list[EvidenceRef]
    seed_neighborhoods: list[SeedNeighborhood]
    unresolved_constraints: list[UnresolvedConstraint]
    warnings: list[str]


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def _canonical(value):
    """Source identity independent of incidental input collection ordering."""
    if isinstance(value, dict):
        return {k: _canonical(v) for k, v in value.items()}
    if isinstance(value, list):
        return sorted((_canonical(v) for v in value), key=_json)
    return value


def _hash(value) -> str:
    return hashlib.sha256(_json(_canonical(value)).encode('utf-8')).hexdigest()


def build_relevant_static_structure(
    inputs: FirmwareAgentInput,
    structure: GhidraStaticStructureResult,
    vectors: CortexMVectorResult,
) -> FirmwareRelevantStaticStructure:
    """Complete fixed selection policy. Canonical inputs remain untouched."""
    if inputs.case.case_id != structure.case_id or inputs.deterministic_observations.case_id != structure.case_id:
        raise StructureProjectionError('A1/A2 case identity mismatch')
    artifacts = {a.artifact_id: a for a in inputs.case.firmware_artifacts}
    artifact = artifacts.get(structure.program.artifact_id)
    if artifact is None or (artifact.sha256, artifact.size_bytes) != (structure.program.sha256, structure.program.size_bytes):
        raise StructureProjectionError('A1/A2 ELF identity mismatch')
    # Revalidate mutable nested canonical contracts before selecting any facts.
    structure = GhidraStaticStructureResult.model_validate(structure.model_dump())
    vectors = CortexMVectorResult.model_validate(vectors.model_dump())
    a1 = collect_firmware_evidence(inputs)
    registry = dict(a1)
    used: dict[str, EvidenceRef] = {}

    def register(refs, *, select=False):
        ids = set()
        for ref in refs:
            if ref.artifact_id not in artifacts:
                raise StructureProjectionError('Static evidence references an undeclared artifact')
            old = registry.get(ref.evidence_id)
            if old is not None and old != ref:
                raise StructureProjectionError('Conflicting A1/A2 evidence identity')
            registry[ref.evidence_id] = ref
            if select:
                used[ref.evidence_id] = ref.model_copy(deep=True)
            ids.add(ref.evidence_id)
        return sorted(ids)

    associations = associate_mmio(structure, inputs.deterministic_observations)
    # Check collisions even on unselected source facts; never select a winner.
    for fact in [*structure.direct_call_edges, *structure.unresolved_call_sites,
                 *vectors.bindings, *associations.bindings]:
        register(fact.evidence)
    functions = {f.function_id: f for f in structure.functions}
    reasons = defaultdict(set)
    for binding in associations.bindings:
        if binding.binding_status == 'unique':
            if binding.function_id not in functions:
                raise StructureProjectionError('Unknown MMIO function reference')
            reasons[binding.function_id].add('mmio_site')
    if len({b.vector_index for b in vectors.bindings}) != len(vectors.bindings):
        raise StructureProjectionError('Duplicate vector index')
    if vectors.status != 'bounded' and vectors.bindings:
        raise StructureProjectionError('Unbounded vector result contains dispatch entries')
    if vectors.status == 'bounded':
        if vectors.extent is None or len(vectors.bindings)*4 != vectors.extent.end-vectors.extent.start:
            raise StructureProjectionError('Vector extent/count mismatch')
        if sorted(b.vector_index for b in vectors.bindings) != list(range(len(vectors.bindings))):
            raise StructureProjectionError('Incomplete bounded vector index set')
        for b in vectors.bindings:
            if b.vector_index and b.raw_handler_value and b.canonical_handler_address != b.raw_handler_value & ~1:
                raise StructureProjectionError('Vector canonical address mismatch')
            if b.binding_status == 'function_entry':
                f = functions.get(b.function_id)
                if f is None or f.entry_address != b.canonical_handler_address:
                    raise StructureProjectionError('Vector/function entry identity mismatch')
                reasons[b.function_id].add('vector_handler')
    seeds = set(reasons)
    calls = [e for e in structure.direct_call_edges
             if e.caller_function_id in seeds or e.callee_function_id in seeds]
    # Unresolved v1 policy is caller-seed ONLY; no speculative target expansion.
    unresolved = [c for c in structure.unresolved_call_sites if c.caller_function_id in seeds]
    selected = seeds | {fid for e in calls for fid in (e.caller_function_id, e.callee_function_id)}
    relevant_functions = [RelevantFunction(
        function_id=f.function_id, entry_address=f.entry_address, name=f.name,
        source_type=f.source_type, seed_reasons=sorted(reasons.get(f.function_id, set())),
        role='seed' if f.function_id in seeds else 'one_hop_neighbor',
    ) for f in sorted((functions[fid] for fid in selected), key=lambda f: (f.entry_address, f.function_id))]
    sites = {}; models = defaultdict(list)
    for observation in inputs.deterministic_observations.observations:
        details = getattr(observation, 'details', None)
        if isinstance(details, StaticInstructionSiteDetails):
            if details.address in sites:
                raise StructureProjectionError('Duplicate static instruction PC')
            sites[details.address] = observation
        elif isinstance(details, MmioModelDetails):
            models[details.pc].append(observation)
    comparisons = {s.pc: s for s in associations.sites}
    bindings = defaultdict(list)
    for b in associations.bindings:
        bindings[b.pc].append(b)
    projected_sites = []
    for pc in sorted(models):
        if pc not in sites:
            raise StructureProjectionError('MMIO PC lacks a canonical static instruction site')
        observation = sites[pc]
        directions = {b.attributes.get('direction', 'unknown') for o in models[pc] for b in o.behaviors}
        if len(directions) != 1 or not directions <= {'read', 'write', 'unknown'}:
            raise StructureProjectionError('Conflicting or invalid A1 MMIO directions')
        mnemonic = {b.decoded_instruction.mnemonic for b in observation.behaviors if b.decoded_instruction}
        if len(mnemonic) > 1:
            raise StructureProjectionError('Conflicting A1 instruction mnemonics')
        refs = list(observation.evidence)
        for b in observation.behaviors:
            refs.extend(b.evidence)
            if b.decoded_instruction:
                refs.extend(b.decoded_instruction.evidence)
        for o in models[pc]:
            refs.extend(o.evidence)
            for b in o.behaviors:
                refs.extend(b.evidence)
        for b in bindings[pc]:
            refs.extend(b.evidence)
        comparison = comparisons[pc]
        projected_sites.append(RelevantMmioSite(
            pc=pc, static_instruction_observation_id=observation.observation_id,
            mnemonic=next(iter(mnemonic), None), direction=next(iter(directions)),
            function_id=comparison.function_ids[0] if comparison.containment == 'unique' else None,
            containment_status=comparison.containment,
            mmio_behavior_ids=sorted(b.behavior_id for o in models[pc] for b in o.behaviors),
            evidence_ids=register(refs, select=True),
        ))
    grouped = defaultdict(list)
    for b in vectors.bindings:
        if b.vector_index and b.raw_handler_value:
            if b.canonical_handler_address is None:
                raise StructureProjectionError('Non-null dispatch has no canonical address')
            grouped[(b.canonical_handler_address, b.function_id, b.binding_status)].append(b)
    groups = []
    for (address, fid, status), entries in sorted(grouped.items(), key=lambda pair: (pair[0][0], pair[0][1] or '', pair[0][2])):
        groups.append(VectorHandlerGroup(
            handler_address=address, function_id=fid, binding_status=status,
            vector_indices=sorted(b.vector_index for b in entries),
            core_exception_names=sorted({b.core_exception_name for b in entries if b.core_exception_name}),
            external_irq_numbers=sorted(b.external_irq_number for b in entries if b.external_irq_number is not None),
            symbol_names=sorted({name for b in entries for name in b.symbol_names}), shared_handler=len(entries)>1,
            evidence_ids=register([ref for b in entries for ref in b.evidence], select=True),
        ))
    constraints = [
        UnresolvedConstraint(constraint_id='static_execution', status='not_established',
            statement='Static call edges do not establish runtime execution.'),
        UnresolvedConstraint(constraint_id='interrupt_occurrence', status='not_established',
            statement='Vector bindings do not establish interrupt occurrence.'),
        UnresolvedConstraint(constraint_id='symbol_semantics', status='not_established',
            statement='Function/symbol names are static labels, not verified physical-interface semantics.'),
        UnresolvedConstraint(constraint_id='opaque_input_relation', status='missing_relation',
            statement='The opaque environment input is not deterministically linked to any function, MMIO site, vector or handler.'),
        UnresolvedConstraint(constraint_id='trigger_handler_relation', status='missing_relation',
            statement='No deterministic relation currently connects the Fuzzware interrupt-trigger configuration to any Cortex-M vector entry or handler execution.'),
    ]
    missing = [s.pc for s in projected_sites if s.containment_status == 'missing']
    if missing:
        constraints.append(UnresolvedConstraint(constraint_id='missing_mmio_containment', status='missing_containment',
            statement='MMIO PCs lack Ghidra function-body containment; no function is guessed.', pcs=missing))
    result = FirmwareRelevantStaticStructure(
        case_id=structure.case_id,
        source_structure={'schema_version': structure.schema_version,
            'tool': structure.tool.model_dump(mode='json'),
            'semantic_hash_policy': 'recursively-sorted-source-collections/v1',
            'structure_sha256': _hash(structure.model_dump(mode='json')),
            'vectors_sha256': _hash(vectors.model_dump(mode='json'))},
        seed_policy=list(SEED_POLICY),
        functions=relevant_functions, mmio_sites=projected_sites,
        direct_call_edges=[RelevantDirectCall(edge_id=e.edge_id, call_site_address=e.call_site_address,
            caller_function_id=e.caller_function_id, callee_function_id=e.callee_function_id,
            evidence_ids=register(e.evidence, select=True)) for e in sorted(calls, key=lambda e: e.call_site_address)],
        unresolved_call_sites=[RelevantUnresolvedCall(call_site_address=c.call_site_address,
            caller_function_id=c.caller_function_id, target_address=c.target_address, reason=c.reason,
            evidence_ids=register(c.evidence, select=True)) for c in sorted(unresolved, key=lambda c: c.call_site_address)],
        vector_handler_groups=groups,
        null_vector_indices=sorted(b.vector_index for b in vectors.bindings if b.binding_status == 'null_entry'),
        evidence_catalog=[],
        seed_neighborhoods=[SeedNeighborhood(function_id=f.function_id,
            incoming_edge_count=sum(e.callee_function_id==f.function_id for e in calls),
            outgoing_edge_count=sum(e.caller_function_id==f.function_id for e in calls),
            unresolved_outgoing_count=sum(c.caller_function_id==f.function_id for c in unresolved))
            for f in relevant_functions if f.function_id in seeds],
        unresolved_constraints=sorted(constraints, key=lambda c: c.constraint_id),
        warnings=['Static relevance is not runtime reachability; missing relations are not negative proofs.'],
    )
    result.evidence_catalog = [used[key] for key in sorted(used)]
    serialize_relevant_static_structure(result)  # No partially truncated success.
    return result


def _table(records: list[dict]) -> dict:
    """Lossless named-column rows, common fields and economical value dictionaries."""
    if not records:
        return {'columns': [], 'rows': []}
    keys = list(records[0])
    if any(set(r) != set(keys) for r in records):
        raise StructureProjectionError('Inconsistent compact table fields')
    common = {k: records[0][k] for k in keys if all(r[k] == records[0][k] for r in records)}
    columns = [k for k in keys if k not in common]
    rows = [[r[k] for k in columns] for r in records]
    dictionaries = {}
    for index, key in enumerate(columns):
        values = sorted({_json(row[index]): row[index] for row in rows}.values(), key=_json)
        lookup = {_json(value): i for i, value in enumerate(values)}
        encoded = [lookup[_json(row[index])] for row in rows]
        if len(_json(values)) + len(_json(encoded)) + len(key) + 8 < len(_json([row[index] for row in rows])):
            dictionaries[key] = values
            for row, value in zip(rows, encoded):
                row[index] = value
    result = {'columns': columns, 'rows': rows}
    if common:
        result['common'] = common
    if dictionaries:
        result['dictionaries'] = dictionaries
    return result


def _untable(table: dict) -> list[dict]:
    if not isinstance(table, dict) or set(table) - {'columns', 'rows', 'common', 'dictionaries'}:
        raise StructureProjectionError('Invalid compact table')
    columns = table['columns']; common = table.get('common', {}); dictionaries = table.get('dictionaries', {})
    if len(columns) != len(set(columns)) or set(columns) & set(common) or not set(dictionaries) <= set(columns):
        raise StructureProjectionError('Invalid compact table columns')
    result = []
    for row in table['rows']:
        if len(row) != len(columns):
            raise StructureProjectionError('Invalid compact row length')
        record = dict(common)
        for key, value in zip(columns, row):
            if key in dictionaries:
                if type(value) is not int or not 0 <= value < len(dictionaries[key]):
                    raise StructureProjectionError('Invalid compact dictionary reference')
                value = dictionaries[key][value]
            record[key] = value
        result.append(record)
    return result


TABLE_FIELDS = ('functions', 'mmio_sites', 'direct_call_edges', 'unresolved_call_sites',
                'vector_handler_groups', 'seed_neighborhoods', 'unresolved_constraints')


def _wire(result: FirmwareRelevantStaticStructure) -> dict:
    data = result.model_dump(mode='json')
    evidence = data.pop('evidence_catalog')
    # Exact EvidenceRef values are factored, never rewritten. Location null
    # defaults reconstruct through EvidenceRef; all non-null location fields survive.
    profiles = sorted({_json({k: v for k, v in ref.items() if k not in ('evidence_id', 'location')}):
                       {k: v for k, v in ref.items() if k not in ('evidence_id', 'location')}
                       for ref in evidence}.values(), key=_json)
    indices = {_json(p): i for i, p in enumerate(profiles)}
    location_keys = sorted({k for ref in evidence for k, v in ref['location'].items() if v is not None})
    rows = []
    for ref in evidence:
        profile = {k: v for k, v in ref.items() if k not in ('evidence_id', 'location')}
        rows.append({'evidence_id': ref['evidence_id'], 'profile': indices[_json(profile)],
                     **{'location.' + k: ref['location'][k] for k in location_keys}})
    data['evidence_catalog'] = {'profiles': _table(profiles), 'entries': _table(rows)}
    for field in TABLE_FIELDS:
        data[field] = _table(data[field])
    data['wire_format'] = 'named-column-tables/v1'
    return data


def _validate(result: FirmwareRelevantStaticStructure) -> None:
    if result.seed_policy != SEED_POLICY:
        raise StructureProjectionError('Selection policy differs from projection v1')
    catalogs = [(result.functions, 'function_id'), (result.mmio_sites, 'pc'),
                (result.direct_call_edges, 'edge_id'), (result.unresolved_call_sites, 'call_site_address'),
                (result.evidence_catalog, 'evidence_id')]
    for records, key in catalogs:
        ids = [getattr(record, key) for record in records]
        if len(ids) != len(set(ids)):
            raise StructureProjectionError('Duplicate projection identity')
    functions = {f.function_id for f in result.functions}
    seeds = {f.function_id for f in result.functions if f.seed_reasons}
    evidence = {ref.evidence_id for ref in result.evidence_catalog}
    referenced = set()
    for fact in [*result.mmio_sites, *result.direct_call_edges, *result.unresolved_call_sites, *result.vector_handler_groups]:
        referenced.update(fact.evidence_ids)
    if referenced != evidence:
        raise StructureProjectionError('Dangling or unused projection evidence')
    for edge in result.direct_call_edges:
        if not {edge.caller_function_id, edge.callee_function_id} <= functions or not {edge.caller_function_id, edge.callee_function_id} & seeds:
            raise StructureProjectionError('Call edge is not a confirmed seed neighborhood reference')
    if any(c.caller_function_id not in seeds for c in result.unresolved_call_sites):
        raise StructureProjectionError('Unresolved caller is not a seed')
    if any(s.function_id is not None and s.function_id not in functions for s in result.mmio_sites):
        raise StructureProjectionError('Unknown MMIO function')
    expected_reasons = defaultdict(set)
    for site in result.mmio_sites:
        if (site.containment_status == 'unique') != (site.function_id is not None):
            raise StructureProjectionError('Inconsistent MMIO containment identity')
        if site.function_id:
            expected_reasons[site.function_id].add('mmio_site')
    for group in result.vector_handler_groups:
        if group.shared_handler != (len(group.vector_indices) > 1):
            raise StructureProjectionError('Inconsistent shared-handler status')
        if group.binding_status == 'function_entry':
            function = next((f for f in result.functions if f.function_id == group.function_id), None)
            if function is None or function.entry_address != group.handler_address:
                raise StructureProjectionError('Unknown vector handler function entry')
            expected_reasons[group.function_id].add('vector_handler')
    endpoints = {fid for e in result.direct_call_edges for fid in (e.caller_function_id, e.callee_function_id)}
    if functions != set(expected_reasons) | endpoints:
        raise StructureProjectionError('Function catalog contains an unselected neighbor')
    for function in result.functions:
        if function.seed_reasons != sorted(expected_reasons.get(function.function_id, set())):
            raise StructureProjectionError('Inconsistent seed reasons')
        if function.role != ('seed' if function.seed_reasons else 'one_hop_neighbor'):
            raise StructureProjectionError('Inconsistent function role')
    if {n.function_id for n in result.seed_neighborhoods} != seeds or len(result.seed_neighborhoods) != len(seeds):
        raise StructureProjectionError('Seed neighborhood catalog mismatch')
    for n in result.seed_neighborhoods:
        counts = (sum(e.callee_function_id == n.function_id for e in result.direct_call_edges),
                  sum(e.caller_function_id == n.function_id for e in result.direct_call_edges),
                  sum(c.caller_function_id == n.function_id for c in result.unresolved_call_sites))
        if counts != (n.incoming_edge_count, n.outgoing_edge_count, n.unresolved_outgoing_count):
            raise StructureProjectionError('Seed neighborhood counts mismatch')
    indices = [i for g in result.vector_handler_groups for i in g.vector_indices]
    if len(indices) != len(set(indices)) or set(indices) & set(result.null_vector_indices):
        raise StructureProjectionError('Duplicate or conflicting vector indices')


def serialize_relevant_static_structure(result: FirmwareRelevantStaticStructure) -> str:
    _validate(result)
    text = _json(_wire(result))
    if len(text) > MAX_STRUCTURE_CHARS:
        raise StructureProjectionError(f'Lossless relevant structure exceeds 18000 characters: {len(text)}')
    return text


def parse_relevant_static_structure(text: str) -> FirmwareRelevantStaticStructure:
    """Decode the documented tables back to typed records and exact EvidenceRefs."""
    if len(text) > MAX_STRUCTURE_CHARS:
        raise StructureProjectionError('Relevant structure exceeds 18000 characters')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise StructureProjectionError('Duplicate JSON key')
            result[key] = value
        return result
    try:
        data = json.loads(text, object_pairs_hook=pairs)
        if data.pop('wire_format') != 'named-column-tables/v1':
            raise StructureProjectionError('Unknown compact wire format')
        for field in TABLE_FIELDS:
            data[field] = _untable(data[field])
        catalog = data['evidence_catalog']
        if set(catalog) != {'profiles', 'entries'}:
            raise StructureProjectionError('Invalid compact evidence catalog')
        profiles = _untable(catalog['profiles'])
        refs = []
        for row in _untable(catalog['entries']):
            index = row.pop('profile'); identifier = row.pop('evidence_id')
            if type(index) is not int or not 0 <= index < len(profiles):
                raise StructureProjectionError('Invalid evidence profile reference')
            if any(not key.startswith('location.') for key in row):
                raise StructureProjectionError('Invalid evidence location column')
            refs.append(EvidenceRef(**profiles[index], evidence_id=identifier,
                                    location={k.removeprefix('location.'): v for k, v in row.items()}))
        data['evidence_catalog'] = refs
        result = FirmwareRelevantStaticStructure.model_validate(data)
        _validate(result)
        if serialize_relevant_static_structure(result) != text:
            raise StructureProjectionError('Noncanonical compact serialization')
        return result
    except (KeyError, TypeError, ValueError, IndexError) as error:
        if isinstance(error, StructureProjectionError):
            raise
        raise StructureProjectionError('Invalid relevant structure JSON') from None


def relevant_structure_sha256(result: FirmwareRelevantStaticStructure) -> str:
    return hashlib.sha256(serialize_relevant_static_structure(result).encode('utf-8')).hexdigest()
