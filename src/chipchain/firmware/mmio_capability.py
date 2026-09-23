"""Static MMIO facts and replayed execution evidence -> existing CAP0 objects.

One capability per source PC and optional evidence context, as CAP0 requires.
No IO, simulation, model calls, trigger matching or runtime-to-static inference.
"""
from __future__ import annotations

from collections.abc import Mapping

from chipchain.domain.case import TargetDescriptor
from chipchain.domain.evidence import EvidenceLocation, EvidenceRef
from chipchain.firmware import capability as cap
from chipchain.firmware import mmio_execution_bridge as bridge_api
from chipchain.firmware import mmio_grounding as grounding


def materialize_mmio(
    static: grounding.FirmwareMmioStaticCatalog,
    *,
    elf_bytes: bytes,
    bridge: bridge_api.BridgeSet | None = None,
    replay_inputs: Mapping[str, object] | None = None,
) -> tuple[cap.FirmwareCapability, ...]:
    """Return resolved target-site capabilities, optionally with BOUND evidence.

    With a bridge, replay_inputs must supply the frozen bridge materializer's
    runtime, platform, inputs, bus_bytes, processor_bytes, stdout_bytes and
    stderr_bytes. Caller verifies platform/source/executable pins (e.g. frozen
    collector.prepare). This adapter replays ELF and raw evidence, then requires
    exact equality with the submitted BridgeSet. No serialized ID is authority
    on its own. Absence of bridge means static-only; incomplete replay is error.
    """
    static = grounding.FirmwareMmioStaticCatalog.model_validate(static.model_dump(mode='json'))
    rebuilt = grounding.extract_rv32_mmio_static_facts(
        elf_bytes, static.target_binding, instruction_count=static.instruction_count)
    grounding.require(grounding.serialize(rebuilt) == grounding.serialize(static), 'STATIC_REPLAY_MISMATCH')
    grounding.require((bridge is None) == (replay_inputs is None), 'BRIDGE_REPLAY_REQUIRED')
    if bridge is not None:
        bridge = bridge_api.BridgeSet.model_validate(bridge.model_dump(mode='json'))
        grounding.require(set(replay_inputs) == {
            'runtime', 'platform', 'inputs', 'bus_bytes', 'processor_bytes', 'stdout_bytes', 'stderr_bytes'
        }, 'REPLAY_INPUT_FIELDS')
        replayed = bridge_api.materialize_bridge(
            joint=bridge.joint_run, static=static, elf_bytes=elf_bytes, **replay_inputs)
        grounding.require(grounding.serialize(replayed) == grounding.serialize(bridge), 'BRIDGE_REPLAY_MISMATCH')
    return tuple(_site(static, fact, bridge) for fact in static.static_facts
                 if fact.scope_status == 'in_target' and fact.address_status == 'resolved_exact')


def _site(static, fact, bridge):
    # Hash_kind=file_bytes hashes these exact serialized catalog bytes, not the
    # catalog's internal payload hash. No new scientific identity scheme.
    catalog_source = cap.SourceArtifact(
        artifact_id=static.catalog_id, sha256=grounding.bytes_sha(grounding.serialize(static).encode()),
        source_kind='firmware_mmio_static')
    firmware_source = cap.SourceArtifact(
        artifact_id=static.firmware_artifact.artifact_id, sha256=static.firmware_artifact.sha256,
        source_kind='firmware_mmio_static')
    sources = {s.artifact_id: s for s in (catalog_source, firmware_source)}
    refs = {fact.fact_id: EvidenceRef(
        evidence_id=fact.fact_id, source_type='deterministic_analyzer', artifact_id=static.catalog_id,
        analyzer='rv32-lui-addi-lw-sw/v1', location=EvidenceLocation(address=fact.instruction_pc),
        summary='Resolved target MMIO instruction; static semantics only.', epistemic_status='derived')}

    def bound(source_ids, evidence_ids, provenance_ids):
        return dict(source_artifact_ids=sorted(set(source_ids)), evidence_ids=sorted(set(evidence_ids)),
                    provenance=[cap.Provenance(source_kind=sources[s].source_kind,
                        source_artifact_ids=[s], source_ids=sorted(set(provenance_ids))) for s in sorted(set(source_ids))])

    static_bound = bound(sources, [fact.fact_id], [static.catalog_id, fact.fact_id])
    selected = None
    if bridge is not None:
        matches = [b for b in bridge.bindings if b.static_fact_id == fact.fact_id]
        grounding.require(len(matches) == 1, 'STATIC_FACT_BRIDGE_REF')
        if matches[0].overall_status == 'bound':
            selected = matches[0]
    retirements = []
    runtime_ids = []
    provenance_ids = [static.catalog_id, fact.fact_id]
    if selected is not None:
        proc = next(p for p in bridge.processor_observations if p.observation_id == selected.processor_observation_id)
        bus = next(b for b in bridge.bus_observations if b.observation_id == selected.runtime_observation_id)
        raw_bus = bus.runtime_observation
        artifacts = {a.artifact_id: a for a in bridge.source_artifacts}
        processor_source = artifacts[proc.processor_trace_artifact_id]
        bus_source = next(a for a in artifacts.values() if a.role == 'bus_trace')
        for artifact in (processor_source, bus_source):
            sources[artifact.artifact_id] = cap.SourceArtifact(
                artifact_id=artifact.artifact_id, sha256=artifact.sha256, source_kind='runtime_trace')
        # Stable references locate original objects; no raw observations/values
        # or entire bridge/joint payload is copied into the capability.
        records = (
            (proc.observation_id, processor_source, 'Source instruction runtime execution observed.'),
            (raw_bus.observation_id, bus_source, 'Accepted/completed MMIO transaction observed.'),
            (bus.observation_id, bus_source, 'Joint-bound bus observation reference.'),
            (selected.binding_id, processor_source, 'BOUND static/processor/bus execution binding reference.'),
            (bridge.joint_run.joint_run_id, processor_source, 'Joint execution evidence reference.'),
        )
        for identity, source, summary in records:
            refs[identity] = EvidenceRef(
                evidence_id=identity, source_type='deterministic_analyzer', artifact_id=source.artifact_id,
                analyzer=selected.binding_rule_version, location=EvidenceLocation(
                    address=raw_bus.address if source is bus_source else fact.instruction_pc),
                summary=summary, epistemic_status='observed' if identity in (
                    proc.observation_id, raw_bus.observation_id) else 'derived')
        runtime_ids = [r[0] for r in records]
        provenance_ids += [bridge.set_id, *runtime_ids]
        retirements = [cap.RetirementEvidence(
            observation_id=proc.observation_id, architecture=fact.architecture, pc=proc.pc,
            instruction_encoding=proc.instruction_encoding, cycle=proc.processor_cycle,
            trace_line=proc.trace_sequence + 2,
            **bound([processor_source.artifact_id], [proc.observation_id], provenance_ids))]
    all_bound = bound(sources, refs, provenance_ids)
    entry_id = 'entry:' + fact.fact_id
    constraints = [cap.ResourceConstraint(
        constraint_id='resource:' + fact.fact_id, resource_kind='mmio',
        identity=static.target_binding.map_id, **static_bound)]
    for kind, value in (('address', fact.address), ('access_width', fact.width_bits),
                        ('value', fact.value if fact.operation == 'write' else None)):
        if value is not None:
            constraints.append(cap.NumericConstraint(
                constraint_id=kind + ':' + fact.fact_id, kind=kind,
                domain=cap.NumericDomain(exact=value, bit_width=32), **static_bound))
    condition = cap.Condition(
        condition_id='condition:' + fact.fact_id, condition_kind='path', formalization_status='unknown',
        description='Execution reaching this site is not established for arbitrary inputs or future runs.',
        **static_bound)
    primitive = cap.Primitive(
        primitive_id='primitive:' + fact.fact_id, architecture=fact.architecture,
        kind='MMIO_WRITE' if fact.operation == 'write' else 'MMIO_READ', entry_id=entry_id,
        source_pc=fact.instruction_pc, formalization_status='formalized' if fact.value_status != 'unresolved' else 'partially_formalized',
        basis='static_instruction', control=cap.ControlAuthority(status='not_established', **static_bound),
        constraint_ids=[c.constraint_id for c in constraints], condition_ids=[condition.condition_id],
        instruction_sequence=[fact.instruction_encoding], source_registers=list(fact.source_registers), **static_bound)
    # CAP0 primitive retirement refs require retirement basis. Keep the primitive
    # purely static; its shared Entry holds retirement status/evidence instead.
    entry = cap.Entry(
        entry_id=entry_id, entry_kind='code_site', formalization_status='formalized', pc=fact.instruction_pc,
        execution_status='source_instruction_retired' if selected else 'static_only',
        retirement_observation_ids=[r.observation_id for r in retirements], **all_bound)
    scope = cap.Scope(
        target=TargetDescriptor(architecture=fact.architecture, processor_id=static.target_binding.map_id,
            firmware_id=static.firmware_artifact.artifact_id, word_size_bits=32, endianness='little'),
        origin_kind='normal_behavior', firmware_artifact_ids=[firmware_source.artifact_id],
        platform_id=static.target_binding.map_id, site_pcs=[fact.instruction_pc],
        applicability='specified_firmware_sites', formalization_status='partially_formalized',
        assumptions=['Bounded static target map; execution evidence limited to its attested joint run.'],
        unmodeled_aspects=['external_input_control', 'general_path_feasibility', 'hardware_trigger',
                          'deviation_verification', 'attack_chain'], **static_bound)
    return cap.build_firmware_capability(cap.FirmwareCapabilityInput(
        architecture=fact.architecture, origin=cap.Origin(kind='normal_behavior', **static_bound),
        entry=entry, conditions=[condition], primitives=[primitive], constraints=constraints, scope=scope,
        source_artifacts=list(sources.values()), evidence=list(refs.values()), retirement_evidence=retirements,
        limitations=['Normal firmware behavior is not external control or a verified hardware trigger.',
                     'An absent value constraint on a WRITE means unresolved, never a runtime-filled value.',
                     'Static-only does not imply nonexecution; UNKNOWN/NOT_SAME never authorize execution evidence.'],
        **all_bound))
