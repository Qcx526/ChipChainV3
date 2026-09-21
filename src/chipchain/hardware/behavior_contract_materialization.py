"""Explicit one-way XL0 adapter. Conversion is not trigger-causality discovery."""
from typing import Literal

from chipchain.cross_layer.trigger import (
    HardwareTriggerCondition, hardware_trigger_condition_sha256,
)
from chipchain.domain.evidence import EvidenceRef
from .behavior_contract import (
    HardwareBehaviorContract, HardwareBehaviorContractInput, Platform, Precondition,
    Predicate, Provenance, Scope, SourceArtifact, TriggerCondition, UnclassifiedAtom,
    build_hardware_behavior_contract,
)


def materialize_xl0(
    condition: HardwareTriggerCondition, *, platform: Platform,
    source_artifacts: list[SourceArtifact], evidence: list[EvidenceRef],
    xl0_artifact_id: str,
    state_roles: dict[str, Literal['precondition', 'trigger']] | None = None,
    role_provenance: Provenance | None = None,
) -> HardwareBehaviorContract:
    """State timing is unknown unless explicitly classified by a manual source.

    Caller supplies source registries and target identity. Only the XL0 artifact's
    digest can be verified here; other hashes are caller assertions, not file reads.
    """
    condition = HardwareTriggerCondition.model_validate(condition.model_dump(mode='json'))
    platform = Platform.model_validate(platform.model_dump(mode='json'))
    sources = [SourceArtifact.model_validate(s.model_dump()) for s in source_artifacts]
    refs = [EvidenceRef.model_validate(e.model_dump()) for e in evidence]
    by_id = {s.artifact_id: s for s in sources}
    upstream = by_id.get(xl0_artifact_id)
    if upstream is None or upstream.source_kind != 'xl0_trigger':
        raise ValueError('Explicit XL0 source artifact required')
    if upstream.sha256 != hardware_trigger_condition_sha256(condition):
        raise ValueError('XL0 source digest mismatch')
    if condition.source_kind == 'hardware_trigger_hypothesis' or condition.source_hardware_hypothesis_id:
        raise ValueError('Hypothesis sources are outside this deterministic adapter')
    if platform.target.architecture != condition.architecture:
        raise ValueError('XL0 and platform architecture differ')
    roles = dict(state_roles or {})
    state_kinds = {'register_state', 'hardware_state', 'privilege_state'}
    eligible = {a.atom_id for a in condition.all_of_atoms
                if a.kind in state_kinds and a.purpose == 'required'}
    if not roles.keys() <= eligible or any(v not in ('precondition', 'trigger') for v in roles.values()):
        raise ValueError('Only required state atoms accept explicit roles')
    if roles and (role_provenance is None or role_provenance.source_kind != 'manual_research_input'):
        raise ValueError('State role classification requires manual research provenance')
    if role_provenance is not None:
        role_provenance = Provenance.model_validate(role_provenance.model_dump())
        if not set(role_provenance.source_artifact_ids) <= by_id.keys():
            raise ValueError('Unbound role provenance')
        if any(by_id[a].source_kind != 'manual_research_input' for a in role_provenance.source_artifact_ids):
            raise ValueError('Role sources must be manual research input')
    origins = [Provenance(
        source_kind=s.source_kind, source_artifact_ids=[s.artifact_id],
        source_ids=[condition.condition_id, *condition.source_ids] if s.artifact_id == xl0_artifact_id else [],
        transformation='xl0_partial_v1' if s.artifact_id == xl0_artifact_id else 'explicit_input',
    ) for s in sources]
    binding = dict(source_artifact_ids=[s.artifact_id for s in sources],
                   evidence_ids=[e.evidence_id for e in refs], provenance=origins)
    preconditions, triggers, unclassified = [], [], []
    atoms = sorted(condition.all_of_atoms, key=lambda a: a.atom_id)
    for atom in atoms:
        if atom.kind == 'ordering' and atom.purpose == 'required':
            continue
        if atom.purpose != 'required':
            unclassified.append(UnclassifiedAtom(atom=atom, reason='verification_metadata', **binding))
            continue
        common = dict(condition_id=atom.atom_id, description=f'XL0 显式条件：{atom.kind}',
                      formalization_status='partially_formalized', **binding)
        if atom.kind == 'instruction':
            triggers.append(TriggerCondition(condition_kind='instruction', instructions=[atom], **common))
        elif atom.kind in ('csr_access', 'mmio_access'):
            triggers.append(TriggerCondition(condition_kind={'csr_access': 'CSR_access', 'mmio_access': 'MMIO_access'}[atom.kind],
                                             access=atom, **common))
        elif atom.atom_id not in roles:
            unclassified.append(UnclassifiedAtom(atom=atom, reason='state_timing_unknown', **binding))
        else:
            # The caller, not the converter, supplies the temporal interpretation.
            if atom.kind == 'privilege_state':
                relation = Predicate(subject='execution_mode', operator='eq', operands=[atom.required_mode])
            else:
                operands = {'eq': [atom.value], 'neq': [atom.value],
                            'masked_eq': [atom.value, atom.mask],
                            'in_range': [atom.range_min, atom.range_max]}[atom.operator]
                relation = Predicate(subject=atom.register_name if atom.kind == 'register_state' else atom.state_identity,
                                     operator=atom.operator, operands=operands)
            common['provenance'] = origins if role_provenance in origins else [*origins, role_provenance]
            if roles[atom.atom_id] == 'precondition':
                kind = {'register_state': 'register_state', 'hardware_state': 'microarchitectural_state',
                        'privilege_state': 'privilege'}[atom.kind]
                preconditions.append(Precondition(condition_kind=kind, required_relation=relation, **common))
            else:
                kind = 'register_state' if atom.kind == 'register_state' else 'other'
                triggers.append(TriggerCondition(condition_kind=kind, required_relation=relation, **common))
    mapped = {t.condition_id for t in triggers}
    for atom in atoms:
        if atom.kind != 'ordering' or atom.purpose != 'required':
            continue
        if {atom.before_atom_id, atom.after_atom_id} <= mapped:
            triggers.append(TriggerCondition(condition_id=atom.atom_id, condition_kind='ordering',
                description='XL0 事件先后要求；未证明执行或因果关系',
                formalization_status='partially_formalized', ordering=atom, **binding))
        else:
            unclassified.append(UnclassifiedAtom(atom=atom, reason='ordering_endpoint_unclassified', **binding))
    synthetic = condition.source_kind == 'synthetic_fixture'
    scope = Scope(
        applicable_architectures=[condition.architecture],
        source_authority='synthetic_fixture' if synthetic else 'upstream_record',
        applicability='synthetic_only' if synthetic else 'unknown',
        formalization_status='partially_formalized',
        assumptions=['XL0 条件仅作待研究要求，不代表已验证的硬件触发因果关系'],
        unmodeled_aspects=['hardware_deviation', 'observation_requirement', 'input_controllability'],
        observation_blind_spots=['未建立实际偏差观测记录'], **binding,
    )
    return build_hardware_behavior_contract(HardwareBehaviorContractInput(
        architecture=condition.architecture, source_case_id=condition.hardware_case_id,
        platform=platform, preconditions=preconditions, trigger=triggers,
        scope=scope, unclassified_atoms=unclassified,
        source_artifacts=sources, evidence=refs,
        limitations=['XL0 partial materialization；不证明触发成功、偏差发生或输入可控',
                     '未提供的 Deviation / Observation 保持 missing'], **binding,
    ))
