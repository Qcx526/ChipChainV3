"""Explicit ELF bytes + frozen A1/A2/A3 -> A4. Pure computation; no file writes."""
import hashlib

from chipchain.agents.contracts import FirmwareAgentInput
from chipchain.agents.firmware_evidence import collect_firmware_reasoning_evidence
from chipchain.agents.projections.firmware import build_firmware_analysis_projection, firmware_projection_sha256
from chipchain.tools.architecture.arm import ArmThumbInstructionDecoder
from chipchain.tools.architecture.cortex_m import CortexMVectorResult
from chipchain.tools.firmware.ghidra.elf import ElfMetadata, parse_elf
from chipchain.tools.firmware.ghidra.models import GhidraStaticStructureResult
from chipchain.tools.firmware.structure_projection import (
    FirmwareRelevantStaticStructure, build_relevant_static_structure,
    serialize_relevant_static_structure, relevant_structure_sha256,
)
from chipchain.tools.firmware.relations import (
    ContainmentDetails, DirectionDetails, FirmwareStaticRelationCatalog,
    RelationEndpoint, RelationKind as K, RelationStatus as S, RelationLimitation as L,
    RelationSourceIdentities, StaticRelationFact, TransferDetails, TransferKind as T,
    VectorDetails, capabilities_for, parse_firmware_static_relations,
    serialize_firmware_static_relations,
)


def classify_thumb_transfer(meta: ElfMetadata, caller, site, decoder, evidence) -> TransferDetails:
    """Decode from A2 entry through a contiguous body prefix, never from PC alone.

    A known A2 computed target is retained as metadata, not promoted to a decoded
    immediate. Linear decode proves instruction boundaries, not reachability/ABI.
    """
    details = dict(original_reason=site.reason, original_target_address=site.target_address)
    if caller is None:
        return TransferDetails(transfer_kind=T.BOUNDARY_UNCONFIRMED, **details)
    start = caller.entry_address
    end = start
    for region in sorted(caller.ranges, key=lambda r: r.start):
        if region.start <= end < region.end:
            end = region.end
        elif region.start > end:
            break
    if not start <= site.call_site_address < end:
        return TransferDetails(transfer_kind=T.BOUNDARY_UNCONFIRMED, **details)
    try:
        decoded = decoder.decode_site(function_bytes=meta.read_code(start, end-start),
            function_address=start, pc=site.call_site_address,
            observation_id=f'a4-transfer-{site.call_site_address:x}', evidence=evidence)
    except ValueError:
        return TransferDetails(transfer_kind=T.BOUNDARY_UNCONFIRMED, **details)
    mnemonic = (decoded.mnemonic or '').removesuffix('.w').removesuffix('.n')
    operands = decoded.operands
    single_immediate = len(operands) == 1 and operands[0].kind == 'immediate'
    target = operands[0].immediate if single_immediate and mnemonic in ('bl', 'blx', 'b') else None
    if mnemonic in ('bl', 'blx'):
        kind = T.DIRECT_CALL if target is not None else T.INDIRECT_CALL
    elif mnemonic == 'b':
        kind = T.DIRECT_BRANCH if target is not None else T.DECODER_UNKNOWN
    elif mnemonic == 'bx':
        kind = T.INDIRECT_BRANCH
    elif mnemonic in ('tbb', 'tbh') or any(o.register == 'r15' for o in operands if o.kind == 'register'):
        kind = T.COMPUTED_OR_AMBIGUOUS
    else:
        kind = T.DECODER_UNKNOWN
    return TransferDetails(transfer_kind=kind, mnemonic=decoded.mnemonic,
        decoded_target_address=target, raw_encoding=decoded.raw_encoding,
        boundary_established=True, **details)


def build_firmware_static_relations(
    inputs: FirmwareAgentInput,
    structure: GhidraStaticStructureResult,
    vectors: CortexMVectorResult,
    relevant: FirmwareRelevantStaticStructure,
    *, elf_bytes: bytes,
) -> FirmwareStaticRelationCatalog:
    """Bind every derivation to canonical inputs and the exact A1+A3 registry.

    Rebuilding A3 detects stale selections, changed directions, forged evidence and
    mismatched source identities. It does not change the frozen A3 implementation.
    """
    rebuilt = build_relevant_static_structure(inputs, structure, vectors)
    if serialize_relevant_static_structure(rebuilt) != serialize_relevant_static_structure(relevant):
        raise ValueError('A3 does not match canonical A1/A2/vector inputs')
    program = structure.program
    if len(elf_bytes) != program.size_bytes or hashlib.sha256(elf_bytes).hexdigest() != program.sha256:
        raise ValueError('Explicit ELF bytes do not match canonical fingerprint')
    if (program.architecture, program.word_size_bits, program.endianness, program.language_id) != (
            'arm', 32, 'little', 'ARM:LE:32:Cortex'):
        raise ValueError('A4 current transfer adapter requires little-endian Cortex-M Thumb')
    registry = collect_firmware_reasoning_evidence(inputs, relevant)
    meta = parse_elf(elf_bytes)
    decoder = ArmThumbInstructionDecoder()
    functions = {f.function_id: f for f in structure.functions}
    by_address = {f.entry_address: f for f in structure.functions}
    used_functions = {}
    facts = []

    def function(fid):
        if fid not in functions:
            raise ValueError('Unknown function endpoint')
        endpoint = RelationEndpoint(entity_type='function', entity_id=fid, address=functions[fid].entry_address)
        used_functions[fid] = endpoint
        return endpoint

    def address_target(address):
        if address is None:
            return None
        if address in by_address:
            return function(by_address[address].function_id)
        return RelationEndpoint(entity_type='address', entity_id=f'address-{address:x}', address=address)

    def add(rid, kind, status, source, target, pc, attributes, ids, extra=()):
        facts.append(StaticRelationFact(relation_id=rid, kind=kind, status=status,
            source=source, target=target, site_address=pc, attributes=attributes,
            evidence_ids=sorted(set(ids)), capabilities=capabilities_for(kind, status),
            limitations=[L.STATIC_ONLY, L.NO_RUNTIME_REACHABILITY, L.NO_PHYSICAL_INTERFACE,
                         L.NO_INPUT_CONSUMPTION, *extra]))

    for edge in relevant.direct_call_edges:
        add(edge.edge_id, K.DIRECT_CALL, S.CONFIRMED_STATIC,
            function(edge.caller_function_id), function(edge.callee_function_id), edge.call_site_address,
            TransferDetails(transfer_kind=T.DIRECT_CALL, call_semantics=True), edge.evidence_ids)

    for site in relevant.unresolved_call_sites:
        pc = site.call_site_address
        caller = functions.get(site.caller_function_id)
        if site.caller_function_id is not None and caller is None:
            raise ValueError('Unknown unresolved caller function')
        details = classify_thumb_transfer(meta, caller, site, decoder, [registry[e] for e in site.evidence_ids])
        kind, status = K.CONTROL_TRANSFER_UNRESOLVED, S.UNRESOLVED
        target = address_target(site.target_address)
        decoded_target = details.decoded_target_address
        # A computed/ambiguous A2 site stays unresolved even if a displayed target exists.
        # Other conflicts also stay unresolved: A4 does not repair caller/entry evidence.
        if site.reason in ('decoder_disagreement', 'instruction_boundary_unconfirmed') and (
                decoded_target is not None and site.target_address in (None, decoded_target)):
            if details.transfer_kind == T.DIRECT_BRANCH:
                kind, status, target = K.DIRECT_BRANCH, S.CONFIRMED_STATIC, address_target(decoded_target)
            elif details.transfer_kind == T.DIRECT_CALL and decoded_target in by_address:
                kind, status, target = K.DIRECT_CALL, S.CONFIRMED_STATIC, address_target(decoded_target)
                details.call_semantics = True
        source = function(site.caller_function_id) if caller else RelationEndpoint(
            entity_type='instruction_site', entity_id=f'instruction-{pc:x}', address=pc)
        add(f'call-{pc:x}', kind, status, source, target, pc, details, site.evidence_ids,
            (L.LINEAR_BOUNDARY_ONLY,) + ((L.NOT_CONFIRMED_CALL,) if kind != K.DIRECT_CALL else ()))

    for site in relevant.mmio_sites:
        source = RelationEndpoint(entity_type='mmio_site', entity_id=f'mmio-{site.pc:x}', address=site.pc)
        status = {'unique': S.CONFIRMED_STATIC, 'missing': S.MISSING, 'ambiguous': S.CONFLICT}[site.containment_status]
        add(f'mmio-containment-{site.pc:x}', K.MMIO_FUNCTION_CONTAINMENT, status, source,
            function(site.function_id) if status == S.CONFIRMED_STATIC else None, site.pc,
            ContainmentDetails(), site.evidence_ids, (L.MISSING_CONTAINMENT,) if status == S.MISSING else ())
        # Rebuilt A3 already verifies the unmodified A1 direction sources and conflicts.
        add(f'mmio-direction-{site.pc:x}', K.MMIO_ACCESS_DIRECTION,
            S.UNRESOLVED if site.direction == 'unknown' else S.CONFIRMED_STATIC,
            source, None, site.pc, DirectionDetails(direction=site.direction, mnemonic=site.mnemonic), site.evidence_ids)

    selected_indices = {i for group in relevant.vector_handler_groups for i in group.vector_indices}
    for binding in vectors.bindings:
        if binding.vector_index not in selected_indices:
            continue
        pc = vectors.extent.start + binding.vector_index*4
        source = RelationEndpoint(entity_type='vector_entry', entity_id=f'vector-{binding.vector_index}', address=pc)
        status = S.CONFIRMED_STATIC if binding.binding_status == 'function_entry' else S.UNRESOLVED
        target = function(binding.function_id) if status == S.CONFIRMED_STATIC else (
            RelationEndpoint(entity_type='address', entity_id=f'address-{binding.canonical_handler_address:x}',
                             address=binding.canonical_handler_address)
            if binding.canonical_handler_address is not None else None)
        add(f'vector-{binding.vector_index}', K.VECTOR_DISPATCH, status, source, target, pc,
            VectorDetails(vector_index=binding.vector_index, binding_status=binding.binding_status),
            [e.evidence_id for e in binding.evidence], (L.NO_INTERRUPT_OCCURRENCE, L.NO_HANDLER_EXECUTION))

    catalog = FirmwareStaticRelationCatalog(case_id=inputs.case.case_id,
        source_identities=RelationSourceIdentities(
            a1_sha256=firmware_projection_sha256(build_firmware_analysis_projection(inputs)),
            a2_sha256=relevant.source_structure.structure_sha256,
            vectors_sha256=relevant.source_structure.vectors_sha256,
            a3_sha256=relevant_structure_sha256(relevant), elf_artifact_id=program.artifact_id,
            elf_sha256=program.sha256, elf_size_bytes=program.size_bytes, decoder=decoder.descriptor),
        function_endpoints=list(used_functions.values()), relations=facts, evidence_ids=sorted(registry),
        warnings=['linear_decode_is_not_cfg_proof', 'missing_relations_are_not_negative_proof',
                  'symbol_names_are_not_physical_interface_proof'])
    return parse_firmware_static_relations(serialize_firmware_static_relations(catalog), evidence_registry=registry)
