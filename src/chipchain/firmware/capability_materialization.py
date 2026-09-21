"""Explicit A6 -> partial normal-behavior capability; no finding/text extraction."""
from chipchain.firmware.control_flow_grounding import FirmwareControlFlowGroundingCatalog
from chipchain.firmware.riscv_control_flow import resolve_transfer
from .capability import (
    Condition, ControlAuthority, Entry, FirmwareCapability, FirmwareCapabilityInput,
    Origin, Primitive, Provenance, ResourceConstraint, RetirementEvidence, Scope,
    SourceArtifact, TargetSetConstraint, build_firmware_capability,
)


def materialize_a6(catalog: FirmwareControlFlowGroundingCatalog, *, fact_id: str) -> FirmwareCapability:
    """One selected transfer; hash checked input, no IO or workflow integration.

    This adapter currently accepts the existing A6 RV32IC transfer resolver only.
    Source hashes identify caller-supplied records; real file verification belongs
    to the explicit caller. Retirement remains a source-site event, never an edge.
    """
    catalog = FirmwareControlFlowGroundingCatalog.model_validate(catalog.model_dump(mode='json'))
    selected = [f for f in catalog.transfer_facts if f.fact_id == fact_id]
    if len(selected) != 1:
        raise ValueError('Select exactly one existing A6 transfer fact')
    fact = selected[0]
    if fact.resolution_status not in ('resolved_direct', 'indirect'):
        raise ValueError('Unsupported/unresolved instruction cannot establish transfer capability')
    if (fact.architecture != 'riscv' or fact.provenance.word_size_bits != 32
        or fact.resolution_method != 'encoding-sign-extended-pc-relative-rv32-ic/v1'):
        raise ValueError('CAP0 materializer supports the frozen A6 RV32IC resolver only')
    checked = resolve_transfer(case_id=fact.case_id, pc=fact.instruction_pc,
        encoding=bytes.fromhex(fact.instruction_encoding), architecture=fact.architecture,
        artifact_id=fact.source_artifact_id, evidence_ids=fact.evidence_ids,
        source_sha256=fact.provenance.input_sha256, word_size_bits=32,
        runtime_selection_sha256=fact.provenance.runtime_selection_sha256)
    fields = ('resolution_status', 'resolved_target_pc', 'transfer_kind', 'decoded_immediate',
              'destination_register', 'fallthrough_pc', 'fallthrough_semantics')
    if any(getattr(fact, k) != getattr(checked, k) for k in fields):
        raise ValueError('A6 transfer target/semantics disagree with static instruction bytes')
    # Frozen A6 IDs precede insertion of Pydantic defaults; replay its producer
    # instead of inventing a different hash recipe for indirect facts.
    if fact.fact_id != checked.fact_id:
        raise ValueError('A6 transfer producer identity mismatch')
    owners = [o for o in catalog.ownership_facts if o.site_pc == fact.instruction_pc]
    owner = owners[0] if len(owners) == 1 else None
    unique_owner = owner is not None and owner.ownership_status == 'unique'
    events = sorted((e for e in catalog.runtime_observations if e.instruction_pc == fact.instruction_pc),
                    key=lambda e: e.observation_id)
    source_map = {s.artifact_id: s for s in catalog.source_artifacts}
    ref_map = {r.evidence_id: r for r in catalog.evidence_catalog}
    evidence_ids = set(fact.evidence_ids)
    for o in owners:
        evidence_ids.update(o.evidence_ids)
    for e in events:
        evidence_ids.update(e.evidence_ids)
    source_ids = {ref_map[e].artifact_id for e in evidence_ids} | set(fact.source_artifact_ids)
    for o in owners:
        source_ids.update(o.source_ids)
    catalog_id = 'a6-catalog:' + catalog.catalog_sha256
    sources = [SourceArtifact(artifact_id=catalog_id, sha256=catalog.catalog_sha256,
                              source_kind='firmware_a6', hash_kind='canonical_a6_payload')]
    sources += [SourceArtifact(artifact_id=i, sha256=source_map[i].sha256,
                    source_kind='runtime_trace' if source_map[i].format == 'ibex-rvfi-text' else 'firmware_a6')
                for i in sorted(source_ids)]
    kinds = {s.artifact_id: s.source_kind for s in sources}

    def binding(ids, refs=(), fact_ids=()):
        ids = sorted(set(ids) | {catalog_id})
        return dict(source_artifact_ids=ids, evidence_ids=sorted(set(refs)), provenance=[
            Provenance(source_kind=kinds[i], source_artifact_ids=[i], source_ids=sorted(set(fact_ids)),
                       transformation='a6_partial_v1') for i in ids])

    static = binding(fact.source_artifact_ids, fact.evidence_ids, [fact.fact_id])
    all_binding = binding(source_ids, evidence_ids, [fact.fact_id, *(o.fact_id for o in owners),
                                                   *(e.observation_id for e in events)])
    retirements = [RetirementEvidence(observation_id=e.observation_id, architecture=e.architecture,
        pc=e.instruction_pc, instruction_encoding=e.instruction_encoding, cycle=e.cycle, trace_line=e.line,
        **binding([e.source_artifact_id], e.evidence_ids, [e.observation_id])) for e in events]
    entry_id = 'entry:' + fact.fact_id
    entry = Entry(entry_id=entry_id, entry_kind='code_site', pc=fact.instruction_pc,
        formalization_status='partially_formalized',
        function_id=owner.owner_function_id if unique_owner else None,
        function_name=owner.owner_function_name if unique_owner else None,
        ownership_status=owner.ownership_status if owner else ('ambiguous' if owners else 'missing'),
        execution_status='source_instruction_retired' if events else 'static_only',
        reachability_status='unknown', retirement_observation_ids=[e.observation_id for e in events], **all_binding)
    resource = ResourceConstraint(constraint_id='resource:' + fact.fact_id,
        resource_kind='control_flow', identity='program_counter', **static)
    constraints = [resource]
    direct = fact.resolution_status == 'resolved_direct'
    if direct:
        constraints.append(TargetSetConstraint(constraint_id='target:' + fact.fact_id,
            targets=[fact.resolved_target_pc], **static))
    condition = Condition(condition_id='condition:site-execution', condition_kind='path',
        formalization_status='unknown', predicate=None,
        description='执行到该指令及满足分支条件的路径前提尚未建立；退休记录仅对应已有轨迹中的源指令。', **static)
    primitive = Primitive(primitive_id='primitive:' + fact.fact_id, architecture=fact.architecture,
        kind='DIRECT_CONTROL_TRANSFER' if direct else 'INDIRECT_CONTROL_TRANSFER', entry_id=entry_id,
        source_pc=fact.instruction_pc, formalization_status='partially_formalized',
        basis='source_instruction_retirement' if events else 'static_instruction',
        control=ControlAuthority(status='not_established', **static),
        constraint_ids=[c.constraint_id for c in constraints], condition_ids=[condition.condition_id],
        instruction_sequence=[fact.instruction_encoding], transfer_kind=fact.transfer_kind,
        target_status='resolved_direct' if direct else 'indirect_unknown',
        retirement_observation_ids=[e.observation_id for e in events], **all_binding)
    scope = Scope(target=catalog.target, origin_kind='normal_behavior',
        firmware_artifact_ids=fact.source_artifact_ids, site_pcs=[fact.instruction_pc],
        function_ids=[owner.owner_function_id] if unique_owner else [],
        applicability='specified_firmware_sites', formalization_status='partially_formalized',
        assumptions=['仅适用于来源镜像、静态指令语义及显式绑定的退休轨迹'],
        unmodeled_aspects=['external_input_control', 'path_feasibility', 'runtime_taken_edge', 'security_impact'],
        known_limitations=['函数归属仅提供上下文；源指令退休不证明目标边被取用'], **all_binding)
    return build_firmware_capability(FirmwareCapabilityInput(
        architecture=catalog.architecture, source_case_id=catalog.case_id,
        origin=Origin(kind='normal_behavior', **static), entry=entry, conditions=[condition],
        primitives=[primitive], constraints=constraints, scope=scope,
        source_artifacts=sources, evidence=[ref_map[i] for i in sorted(evidence_ids)],
        retirement_evidence=retirements,
        limitations=['部分能力说明，不是漏洞或攻击者控制能力',
                     'A6 只支持源指令语义及上下文；不证明外部入口可达性'], **all_binding,
    ))
