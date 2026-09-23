"""Controlled synthetic Type-II runtime verifier for frozen Ibex MMIO evidence.

Consumes existing CAP0/XL1/B1/BRIDGE1 types. No IO, model calls, source
inference from labels, general platform claim or historical XL2 rewrite.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import model_validator

from chipchain.cross_layer.trigger import MMIOTriggerAtom, OrderingTriggerAtom
from chipchain.firmware import capability as cap
from chipchain.firmware import mmio_execution_bridge as bridge_api
from chipchain.firmware import mmio_grounding as b1
from chipchain.firmware.mmio_capability import materialize_mmio
from chipchain.hardware import behavior_contract as hw
from chipchain.firmware.mmio_grounding import Content, identified, require
from chipchain.domain.common import Identifier, Sha256

RULE = 'controlled-ibex-type2-runtime/v1'
PERIPHERAL = 'examples/simple_system/rtl/synthetic_mmio.sv'
REF_TREE, VAR_TREE = bridge_api.APPROVED_TREES
VARIANT_PATCH_SHA = 'acd5a0b8eebe1bf47f739a82ce212d605df01a17ecbabf598db7c312d3d86272'
Status = Literal['supported', 'contradicted', 'unknown']


class StateBinding(Content):
    id_field = 'binding_id'
    prefix = 'type2-state-binding'
    binding_id: Identifier
    source_artifact_id: Identifier
    source_sha256: Sha256
    enable_subject: Identifier
    enable_address: int
    enable_reset_value: int
    status_subject: Identifier
    status_address: int
    status_reset_value: int


class ObservationBinding(Content):
    id_field = 'binding_id'
    prefix = 'type2-observation-binding'
    binding_id: Identifier
    joint_run_id: Identifier
    runtime_attestation_id: Identifier
    raw_trace_sha256: Sha256
    rtl_tree_sha256: Sha256
    map_id: Identifier


@dataclass(frozen=True)
class RunEvidence:
    static: b1.FirmwareMmioStaticCatalog
    bridge: bridge_api.BridgeSet
    runtime: b1.RuntimeMmioObservationSet
    platform: bridge_api.PlatformProof
    capabilities: tuple[cap.FirmwareCapability, ...]
    inputs: dict[str, str]
    elf_bytes: bytes
    bus_bytes: bytes
    processor_bytes: bytes
    stdout_bytes: bytes
    stderr_bytes: bytes
    observation_binding: ObservationBinding | None = None


def observation_binding_for(run: RunEvidence):
    """Caller explicitly chooses this link; verifier never recovers a missing one."""
    return identified(ObservationBinding,
        joint_run_id=run.bridge.joint_run.joint_run_id,
        runtime_attestation_id=run.runtime.source_attestation.attestation_id,
        raw_trace_sha256=run.bridge.joint_run.bus_trace_sha256,
        rtl_tree_sha256=run.bridge.joint_run.rtl_tree_sha256,
        map_id=run.static.target_binding.map_id)


@dataclass(frozen=True)
class ControlledSourceEvidence:
    delta_bytes: bytes
    reference_manifest_bytes: bytes
    variant_manifest_bytes: bytes
    reference_peripheral_bytes: bytes
    variant_peripheral_bytes: bytes
    variant_patch_bytes: bytes


def verify_controlled_source(evidence: ControlledSourceEvidence):
    """Exact reviewed trees, one changed peripheral and pinned mutation patch."""
    delta = b1.read_json(evidence.delta_bytes)
    reference = b1.read_json(evidence.reference_manifest_bytes)
    variant = b1.read_json(evidence.variant_manifest_bytes)
    require(isinstance(delta, dict) and set(delta) == {'reference_tree_sha256','variant_tree_sha256','changed_files'},
            'CONTROLLED_DELTA_SHAPE')
    require(delta == {'reference_tree_sha256': REF_TREE, 'variant_tree_sha256': VAR_TREE,
                      'changed_files': [PERIPHERAL]}, 'UNREVIEWED_DELTA')
    require(isinstance(reference, dict) and isinstance(variant, dict) and
            b1.digest(reference) == REF_TREE and b1.digest(variant) == VAR_TREE, 'SOURCE_MANIFEST_IDENTITY')
    require(set(reference) == set(variant) and
            [name for name in sorted(reference) if reference[name] != variant[name]] == [PERIPHERAL],
            'UNCONTROLLED_SOURCE_CHANGE')
    require(reference[PERIPHERAL] == b1.bytes_sha(evidence.reference_peripheral_bytes) and
            variant[PERIPHERAL] == b1.bytes_sha(evidence.variant_peripheral_bytes), 'PERIPHERAL_SOURCE_MISMATCH')
    require(b1.bytes_sha(evidence.variant_patch_bytes) == VARIANT_PATCH_SHA, 'VARIANT_PATCH_IDENTITY')
    marker = b'  // Observation only:'
    require(evidence.reference_peripheral_bytes.count(marker) == 1 and
            evidence.variant_peripheral_bytes.count(marker) == 1 and
            evidence.reference_peripheral_bytes.split(marker)[1] ==
            evidence.variant_peripheral_bytes.split(marker)[1], 'MONITOR_CHANGED')
    return 'type2-controlled-source:' + b1.digest({'delta_sha':b1.bytes_sha(evidence.delta_bytes),
        'reference_tree':REF_TREE, 'variant_tree':VAR_TREE, 'variant_patch_sha':VARIANT_PATCH_SHA})


class ConditionVerification(Content):
    id_field = 'verification_id'
    prefix = 'type2-condition'
    verification_id: Identifier
    requirement_id: Identifier
    status: Status
    evidence_ids: tuple[Identifier, ...]
    reason_code: Identifier
    missing_requirements: tuple[Identifier, ...]
    scope: Identifier

    @model_validator(mode='after')
    def evidence_for_decision(self):
        require(self.status=='unknown' or bool(self.evidence_ids), 'DECISION_WITHOUT_EVIDENCE')
        return self


def condition(requirement_id, status, reason, evidence=(), missing=(), scope='controlled-ibex-synthetic-only'):
    evidence = tuple(sorted(set(evidence))); missing = tuple(sorted(set(missing)))
    require(status != 'supported' or evidence, 'SUPPORTED_WITHOUT_EVIDENCE')
    return identified(ConditionVerification, requirement_id=requirement_id, status=status,
        reason_code=reason, evidence_ids=evidence, missing_requirements=missing, scope=scope)


class TriggerVerification(Content):
    id_field = 'verification_id'
    prefix = 'type2-trigger'
    verification_id: Identifier
    conditions: tuple[ConditionVerification, ...]
    status: Status


class DeviationVerification(Content):
    id_field = 'verification_id'
    prefix = 'type2-deviation'
    verification_id: Identifier
    condition: ConditionVerification
    status: Status


class ReferenceControlVerification(Content):
    id_field = 'verification_id'
    prefix = 'type2-reference-control'
    verification_id: Identifier
    reference_joint_run_id: Identifier | None
    trigger_status: Status
    expected_behavior_status: Status
    deviation_observed: bool | None
    evidence_ids: tuple[Identifier, ...]
    reason_code: Identifier
    trigger_condition: ConditionVerification
    expected_condition: ConditionVerification
    no_deviation_condition: ConditionVerification

    @model_validator(mode='after')
    def consistent(self):
        require(self.trigger_status==self.trigger_condition.status and
                self.expected_behavior_status==self.expected_condition.status and
                ((self.deviation_observed is False)==(self.no_deviation_condition.status=='supported')),
                'REFERENCE_CONTROL_STATUS_MISMATCH')
        return self


class ControlledDifferentialVerification(Content):
    requirement_id: Literal['type2:controlled-differential'] = 'type2:controlled-differential'
    scope: Literal['controlled_synthetic_ibex_variant_only'] = 'controlled_synthetic_ibex_variant_only'
    id_field = 'verification_id'
    prefix = 'type2-differential'
    verification_id: Identifier
    status: Status
    evidence_ids: tuple[Identifier, ...]
    reason_code: Identifier
    missing_requirements: tuple[Identifier, ...]
    source_proof_id: Identifier | None

    @model_validator(mode='after')
    def evidence_for_support(self):
        require(self.status!='supported' or bool(self.evidence_ids and self.source_proof_id),
                'DIFFERENTIAL_WITHOUT_PROOF')
        return self


class Type2VerificationResult(Content):
    id_field = 'result_id'
    prefix = 'type2-verification'
    result_id: Identifier
    schema_version: Literal['controlled-type2-verification/v1'] = 'controlled-type2-verification/v1'
    rule_version: Literal['controlled-ibex-type2-runtime/v1'] = RULE
    contract_id: Identifier
    target_joint_run_id: Identifier
    capability_ids: tuple[Identifier, ...]
    trigger: TriggerVerification
    deviation: DeviationVerification
    observation: ConditionVerification
    reference_control: ReferenceControlVerification
    differential: ControlledDifferentialVerification
    final_status: Literal['verified_controlled_type2_chain','trigger_contradicted',
                          'deviation_contradicted','unknown']
    scope: Literal['controlled_synthetic_ibex_variant_only'] = 'controlled_synthetic_ibex_variant_only'

    @model_validator(mode='after')
    def final_gate(self):
        if self.final_status=='verified_controlled_type2_chain':
            require(all(x=='supported' for x in (self.trigger.status,self.deviation.status,
                    self.observation.status,self.differential.status,
                    self.reference_control.trigger_status,
                    self.reference_control.expected_behavior_status)) and
                    self.reference_control.deviation_observed is False, 'POSITIVE_GATE_INCOMPLETE')
        elif self.final_status=='trigger_contradicted':
            require(self.trigger.status=='contradicted','TRIGGER_NEGATIVE_GATE')
        elif self.final_status=='deviation_contradicted':
            require(self.trigger.status=='supported' and self.deviation.status=='contradicted' and
                    self.observation.status=='supported', 'DEVIATION_NEGATIVE_GATE')
        return self


def _validate_run(run):
    # Invalid bytes/IDs are errors. Lack of an optional observation link is not.
    b1.require(isinstance(run, RunEvidence), 'RUN_EVIDENCE_TYPE')
    replay = dict(runtime=run.runtime,platform=run.platform,inputs=run.inputs,
                  bus_bytes=run.bus_bytes,processor_bytes=run.processor_bytes,
                  stdout_bytes=run.stdout_bytes,stderr_bytes=run.stderr_bytes)
    expected = materialize_mmio(run.static,elf_bytes=run.elf_bytes,bridge=run.bridge,replay_inputs=replay)
    actual = tuple(cap.FirmwareCapability.model_validate(c.model_dump(mode='json')) for c in run.capabilities)
    require({c.capability_id for c in actual} == {c.capability_id for c in expected} and
            len(actual) == len(expected), 'CAPABILITY_REPLAY_MISMATCH')
    raw = b1.parse_apparatus_trace(run.bus_bytes.decode('ascii'))
    require(run.runtime.run_binding.raw_trace_sha256 == b1.bytes_sha(run.bus_bytes), 'RUN_TRACE_MISMATCH')
    return raw


def _linked(run):
    link = run.observation_binding
    if link is None:
        return False
    link = ObservationBinding.model_validate(link.model_dump(mode='json'))
    return link == observation_binding_for(run)


def _capability_transactions(run):
    """Map CAP0 sites through explicit BOUND bridge IDs; never use tuple order."""
    by_fact = {binding.static_fact_id:binding for binding in run.bridge.bindings}
    by_bus = {b.observation_id:b.runtime_observation for b in run.bridge.bus_observations}
    result=[]
    for capability in run.capabilities:
        p = capability.primitives
        if len(p) != 1 or p[0].kind not in ('MMIO_WRITE','MMIO_READ'):
            continue
        fact_ids = [e.evidence_id for e in capability.evidence if e.evidence_id in by_fact]
        if len(fact_ids) != 1:
            continue
        binding=by_fact[fact_ids[0]]
        if (binding.overall_status != 'bound' or capability.entry.execution_status != 'source_instruction_retired'
            or binding.binding_id not in capability.evidence_ids or
            run.bridge.joint_run.joint_run_id not in capability.evidence_ids):
            continue
        if binding.runtime_observation_id not in by_bus:
            continue
        o=by_bus[binding.runtime_observation_id]
        constraints={c.kind:c.domain.exact for c in capability.constraints
                     if isinstance(c,cap.NumericConstraint)}
        result.append((capability,o,binding,constraints))
    return result


def _access_atom(atom, requirement_id, run, pairs):
    if not isinstance(atom,MMIOTriggerAtom) or atom.access not in ('read','write') or atom.width_bits is None or (
        atom.access == 'write' and (atom.value_constraint is None or atom.value_constraint.operator != 'eq')):
        return condition(requirement_id,'unknown','UNSUPPORTED_ACCESS_PREDICATE',missing=('exact_access_requirement',)) , None
    want=(atom.access,atom.address,atom.width_bits,
          atom.value_constraint.value if atom.value_constraint else None)
    exact=[]; conflicting=[]
    for c,o,b,cs in pairs:
        value=o.write_value if o.operation=='write' else o.read_value
        actual=(o.operation,o.address,o.width_bits,value)
        declared=(c.primitives[0].kind.value,o.address,cs.get('access_width'),cs.get('value'))
        if declared[0] != ('MMIO_WRITE' if o.operation=='write' else 'MMIO_READ') or (
            cs.get('address') != o.address or cs.get('access_width') != o.width_bits or
            (o.operation=='write' and cs.get('value') != value)):
            continue
        if actual == want:
            exact.append((c,o,b))
        elif o.operation==atom.access:
            comparisons = [o.address==atom.address,o.width_bits==atom.width_bits]
            if atom.value_constraint:
                comparisons.append(value==atom.value_constraint.value)
            if sum(comparisons)>=2:
                conflicting.append((c,o,b))
    if len(exact)==1:
        c,o,b=exact[0]
        return condition(requirement_id,'supported','EXACT_EXECUTED_MMIO',
            (c.capability_id,b.binding_id,o.observation_id,run.bridge.joint_run.joint_run_id)),exact[0]
    if not exact and len(conflicting)==1:
        c,o,b=conflicting[0]
        return condition(requirement_id,'contradicted','EXECUTED_CONFLICTING_MMIO',
            (c.capability_id,b.binding_id,o.observation_id,run.bridge.joint_run.joint_run_id)),None
    return condition(requirement_id,'unknown','NO_UNIQUE_EXECUTED_ACCESS',missing=('unique_completed_matching_transaction',)),None


def _state_before(parsed, command, binding):
    """Accepted request stream, reset epoch and intervening writes determine pre-state."""
    if binding is None:
        return None,None,'STATE_BINDING_MISSING'
    completed={(t['request']['reset_epoch'],t['request']['transaction_id']):t for t in parsed['transactions']}
    value=None; last_enable=None; state_epoch=None
    for event in parsed['events']:
        if event['phase']=='reset_assert':
            value=binding.enable_reset_value;last_enable=None;state_epoch=event['reset_epoch']
        if event['phase']!='request':
            continue
        tx=completed.get((event['reset_epoch'],event['transaction_id']))
        if tx is None:
            return None,None,'REQUEST_NOT_COMPLETED'
        if event['transaction_id']==command.transaction_id and event['reset_epoch']==command.reset_epoch:
            return (value,last_enable,'PRESTATE_OBSERVED') if state_epoch==command.reset_epoch else (None,None,'RESET_EPOCH_MISMATCH')
        if event['address']==binding.enable_address and event['write_enable']==1:
            value=event['write_data'];last_enable=event
    return None,None,'COMMAND_REQUEST_MISSING'


def _predicate_eq(predicate,subject):
    return (predicate is not None and predicate.subject==subject and predicate.operator=='eq' and
            len(predicate.operands)==1 and type(predicate.operands[0]) is int)


def _sample_read(run,parsed,read_address,command,link_required=True):
    if link_required and not _linked(run):
        return None,(), 'OBSERVATION_BINDING_MISSING'
    reads=[o for o in run.runtime.runtime_observations if o.operation=='read' and o.address==read_address
           and o.reset_epoch==command.reset_epoch and o.request_cycle>command.request_cycle]
    if len(reads)!=1:
        return None,(), 'STATUS_READ_MISSING_OR_AMBIGUOUS'
    read=reads[0]
    if not any(o.observation_id==read.observation_id for _,o,_,_ in _capability_transactions(run)):
        return None,(), 'STATUS_READ_NOT_BOUND_TO_CAPABILITY'
    samples=[e for e in parsed['events'] if e['phase']=='status_sample' and
             e['reset_epoch']==command.reset_epoch and e['cycle']==command.request_cycle]
    if len(samples)!=1:
        return None,(), 'POST_UPDATE_SAMPLE_MISSING'
    sample=samples[0]
    ids=(run.bridge.joint_run.joint_run_id,read.observation_id,run.observation_binding.binding_id,
         f"{read.raw_trace_artifact_id}:status-sample:{sample['sequence']}")
    if sample['status_value']!=read.read_value:
        return None,ids,'SAMPLE_READ_CONFLICT'
    return read.read_value,ids,'SAMPLE_READ_AGREE'


def _deviation_value(value, expected, deviating):
    return 'supported' if value==deviating else 'contradicted' if value==expected else 'unknown'


def _final_status(trigger, deviation, observation, differential):
    if trigger=='contradicted':
        return 'trigger_contradicted'
    if trigger=='supported' and deviation=='contradicted' and observation=='supported':
        return 'deviation_contradicted'
    if all(x=='supported' for x in (trigger,deviation,observation,differential)):
        return 'verified_controlled_type2_chain'
    return 'unknown'


def _aggregate(items):
    values={x.status for x in items}
    return 'contradicted' if 'contradicted' in values else 'unknown' if 'unknown' in values else 'supported'


def verify_type2(*, contract: hw.HardwareBehaviorContract, target: RunEvidence,
                 reference: RunEvidence | None, state_binding: StateBinding | None,
                 controlled_source: ControlledSourceEvidence | None) -> Type2VerificationResult:
    """Verify one target and optional independent Reference control, without IO."""
    contract=hw.HardwareBehaviorContract.model_validate(contract.model_dump(mode='json'))
    target_parsed=_validate_run(target)
    reference_parsed=_validate_run(reference) if reference else None
    source_id=verify_controlled_source(controlled_source) if controlled_source else None
    hbc_source={x.artifact_id:x for x in contract.source_artifacts}
    source_ok=(state_binding is not None and source_id is not None and
               state_binding.source_artifact_id in hbc_source and
               hbc_source[state_binding.source_artifact_id].source_kind=='synthetic_fixture' and
               hbc_source[state_binding.source_artifact_id].sha256==state_binding.source_sha256==
               b1.bytes_sha(controlled_source.reference_peripheral_bytes) and
               state_binding.enable_reset_value==state_binding.status_reset_value==0)
    if state_binding is not None:
        state_binding=StateBinding.model_validate(state_binding.model_dump(mode='json'))
    accesses=[r for r in contract.trigger if r.condition_kind=='MMIO_access' and r.access]
    orders=[r for r in contract.trigger if r.condition_kind=='ordering' and r.ordering]
    enable_reqs=[r for r in accesses if state_binding and r.access.address==state_binding.enable_address]
    command_reqs=[r for r in accesses if state_binding and r.access.address!=state_binding.enable_address]
    shape_ok=(len(contract.trigger)==3 and len(accesses)==2 and len(orders)==1 and
              len(contract.preconditions)==len(contract.deviation)==len(contract.observation)==1 and
              len(enable_reqs)==len(command_reqs)==1 and
              orders[0].ordering.before_atom_id==enable_reqs[0].condition_id and
              orders[0].ordering.after_atom_id==command_reqs[0].condition_id)
    scope_ok=(shape_ok and contract.scope.formalization_status==hw.FormalizationStatus.FORMALIZED and
              contract.scope.applicability=='synthetic_only' and
              contract.scope.source_authority=='synthetic_fixture' and
              contract.platform.rtl_identity=='rtl-tree:'+VAR_TREE and
              contract.platform.rtl_revision=='rtl-tree:'+target.bridge.joint_run.rtl_tree_sha256 and
              contract.platform.rtl_revision in contract.scope.rtl_revisions and
              contract.platform.platform_id==target.static.target_binding.map_id and
              contract.platform.platform_id in contract.scope.applicable_platforms and
              target.bridge.joint_run.rtl_tree_sha256==VAR_TREE and
              contract.architecture==target.static.architecture and
              contract.platform.target.processor_id==target.bridge.platform_proof.rule)
    scope=condition('type2:target-scope','supported' if scope_ok and source_ok else 'unknown',
        'PINNED_VARIANT_SCOPE' if scope_ok and source_ok else 'SCOPE_OR_SOURCE_BINDING_MISSING',
        (contract.contract_id,target.bridge.joint_run.joint_run_id,source_id,state_binding.binding_id)
        if scope_ok and source_ok else (), missing=() if scope_ok and source_ok else ('variant_revision','synthetic_spec_source','state_binding'))
    pairs=_capability_transactions(target)
    by_condition={}; selected={}
    for req in contract.trigger:
        if req.condition_kind=='MMIO_access' and req.access:
            outcome,pair=_access_atom(req.access,req.condition_id,target,pairs) if (
                req.formalization_status==hw.FormalizationStatus.FORMALIZED) else (
                condition(req.condition_id,'unknown','UNFORMALIZED_TRIGGER',missing=('formalized_trigger',)),None)
            by_condition[req.condition_id]=outcome
            if pair:selected[req.condition_id]=pair
    # Precondition and ordering are looked up by typed endpoints/subjects, never list position.
    for req in contract.trigger:
        if req.condition_kind!='ordering':continue
        atom=req.ordering
        if (req.formalization_status!=hw.FormalizationStatus.FORMALIZED or not atom or
            atom.max_gap_time is not None):
            by_condition[req.condition_id]=condition(req.condition_id,'unknown',
                'UNSUPPORTED_ORDERING_TIME_OR_FORMALIZATION',missing=('formalized_cycle_order',))
            continue
        before=selected.get(atom.before_atom_id) if atom else None
        after=selected.get(atom.after_atom_id) if atom else None
        if before and after:
            left,right=before[1],after[1]
            good=(left.reset_epoch==right.reset_epoch and left.request_cycle<right.request_cycle and
                  (atom.max_gap_events is None or right.transaction_id-left.transaction_id<=atom.max_gap_events))
            by_condition[req.condition_id]=condition(req.condition_id,'supported' if good else 'contradicted',
                'ACCEPTED_REQUEST_ORDER' if good else 'ORDER_OR_EPOCH_CONFLICT',
                (left.observation_id,right.observation_id,target.bridge.joint_run.joint_run_id))
        else:by_condition[req.condition_id]=condition(req.condition_id,'unknown','ORDER_ENDPOINT_MISSING',
                missing=('two_bound_endpoint_transactions',))
    pre_results=[]
    for pre in contract.preconditions:
        if (not source_ok or not state_binding or
            pre.formalization_status!=hw.FormalizationStatus.FORMALIZED or
            not _predicate_eq(pre.required_relation,state_binding.enable_subject)):
            pre_results.append(condition(pre.condition_id,'unknown','STATE_BINDING_OR_PREDICATE_MISSING',
                missing=('synthetic_spec_state_binding',)))
            continue
        commands=[selected.get(req.condition_id) for req in contract.trigger if req.access and
                  req.access.address!=state_binding.enable_address and req.access.access=='write']
        commands=[x for x in commands if x]
        if len(commands)!=1:
            pre_results.append(condition(pre.condition_id,'unknown','COMMAND_ENDPOINT_MISSING',missing=('bound_command',)))
            continue
        command=commands[0][1]
        value,last,reason=_state_before(target_parsed,command,state_binding)
        if value is None:
            pre_results.append(condition(pre.condition_id,'unknown',reason,missing=('complete_enable_state_history',)))
        else:
            want=pre.required_relation.operands[0]
            accepted=(last is not None and last['reset_epoch']==command.reset_epoch and
                      last['cycle']<command.request_cycle and value==want)
            pre_results.append(condition(pre.condition_id,'supported' if accepted else 'contradicted',
                'ACCEPTED_ENABLE_PRESTATE' if accepted else 'ENABLE_PRESTATE_CONFLICT',
                (command.observation_id,target.bridge.joint_run.joint_run_id,
                 f"{target.bridge.joint_run.bus_trace_sha256}:enable-request:{last['sequence']}") if last else
                (command.observation_id,target.bridge.joint_run.joint_run_id)))
    conditions=tuple([scope,*[by_condition.get(x.condition_id,condition(x.condition_id,'unknown','UNSUPPORTED_TRIGGER',
        missing=('supported_trigger_kind',))) for x in contract.trigger],*pre_results])
    trigger_status=_aggregate(conditions) if scope.status=='supported' else 'unknown'
    trigger=identified(TriggerVerification,conditions=conditions,status=trigger_status)
    deviation_req=contract.deviation[0] if len(contract.deviation)==1 else None
    observation_req=contract.observation[0] if len(contract.observation)==1 else None
    command_candidates=[selected.get(req.condition_id) for req in contract.trigger if req.access and
                        state_binding and req.access.address!=state_binding.enable_address and req.access.access=='write']
    command_candidates=[x for x in command_candidates if x]
    command=command_candidates[0][1] if len(command_candidates)==1 else None
    if (scope.status!='supported' or not deviation_req or not observation_req or
        not state_binding or not source_ok or not command or
        deviation_req.formalization_status!=hw.FormalizationStatus.FORMALIZED or
        deviation_req.deviation_kind!='wrong_value' or deviation_req.hardware_constraint_status!='specified' or
        observation_req.formalization_status!=hw.FormalizationStatus.FORMALIZED or
        observation_req.judgement_kind!='comparison' or
        observation_req.required_backend!='controlled-syn-mmio-postupdate+busread/v1' or
        observation_req.observable_target!=state_binding.status_subject or
        not _predicate_eq(deviation_req.expected_behavior,state_binding.status_subject) or
        not _predicate_eq(deviation_req.deviating_behavior,state_binding.status_subject) or
        deviation_req.specification_ref!=state_binding.source_artifact_id or
        observation_req.deviation_ids!=[deviation_req.condition_id] or
        not _predicate_eq(observation_req.expected_observation,state_binding.status_subject) or
        not _predicate_eq(observation_req.deviation_observation,state_binding.status_subject)):
        obs=condition(observation_req.condition_id if observation_req else 'type2:observation','unknown',
            'OBSERVATION_SPEC_INCOMPLETE',missing=('formalized_status_spec','source_bound_post_update_and_bus_read'))
        dev_condition=condition(deviation_req.condition_id if deviation_req else 'type2:deviation','unknown',
            'DEVIATION_SPEC_INCOMPLETE',missing=('formalized_expected_and_deviating_values',))
    else:
        value,evidence,reason=_sample_read(target,target_parsed,state_binding.status_address,command)
        expected=deviation_req.expected_behavior.operands[0]
        deviating=deviation_req.deviating_behavior.operands[0]
        if (value is None or observation_req.expected_observation.operands[0]!=expected or
            observation_req.deviation_observation.operands[0]!=deviating or reason!='SAMPLE_READ_AGREE'):
            obs=condition(observation_req.condition_id,'unknown',reason, evidence,
                missing=('consistent_bound_status_sample_and_bus_response',))
            dev_condition=condition(deviation_req.condition_id,'unknown',reason,evidence,
                missing=('reliable_status_observation',))
        else:
            obs=condition(observation_req.condition_id,'supported','INTERNAL_AND_BUS_STATUS_AGREE',evidence)
            status=_deviation_value(value,expected,deviating)
            dev_condition=condition(deviation_req.condition_id,status,
                'FORMALIZED_DEVIATING_VALUE' if status=='supported' else
                'FORMALIZED_EXPECTED_VALUE' if status=='contradicted' else 'UNSPECIFIED_STATUS_VALUE',evidence,
                () if status!='unknown' else ('status_in_formalized_domain',))
    deviation=identified(DeviationVerification,condition=dev_condition,status=dev_condition.status)
    # Reference never satisfies Variant contract scope; it is checked only as a control.
    if reference and command and deviation_req and state_binding and source_id:
        ref_pairs=_capability_transactions(reference)
        reference_atoms=[req for req in contract.trigger if req.access and isinstance(req.access,MMIOTriggerAtom)]
        ref_access=[_access_atom(req.access,req.condition_id,reference,ref_pairs)[0] if
            req.formalization_status==hw.FormalizationStatus.FORMALIZED else
            condition(req.condition_id,'unknown','UNFORMALIZED_TRIGGER',missing=('formalized_trigger',))
            for req in reference_atoms]
        ref_selected={req.condition_id:_access_atom(req.access,req.condition_id,reference,ref_pairs)[1]
                      for req in reference_atoms}
        ref_commands=[ref_selected[req.condition_id] for req in reference_atoms
                      if req.access.address!=state_binding.enable_address and req.access.access=='write'
                      and ref_selected[req.condition_id]]
        ref_cmd=ref_commands[0][1] if len(ref_commands)==1 else None
        ref_trigger='supported' if len(ref_access)==2 and all(x.status=='supported' for x in ref_access) and ref_cmd else 'unknown'
        ref_order=[req.ordering for req in contract.trigger if req.ordering]
        if any(req.formalization_status!=hw.FormalizationStatus.FORMALIZED or
               req.ordering.max_gap_time is not None for req in contract.trigger if req.ordering):
            ref_trigger='unknown'
        for order in ref_order:
            before,after=ref_selected.get(order.before_atom_id),ref_selected.get(order.after_atom_id)
            if not before or not after or before[1].reset_epoch!=after[1].reset_epoch or (
                before[1].request_cycle>=after[1].request_cycle) or (
                order.max_gap_events is not None and
                after[1].transaction_id-before[1].transaction_id>order.max_gap_events):
                ref_trigger='unknown'
        if ref_cmd:
            val,last,_= _state_before(reference_parsed,ref_cmd,state_binding)
            want=next((pre.required_relation.operands[0] for pre in contract.preconditions
                if _predicate_eq(pre.required_relation,state_binding.enable_subject)),None)
            if val!=want or last is None or last['reset_epoch']!=ref_cmd.reset_epoch:
                ref_trigger='unknown'
        ref_value,ref_ids,ref_reason=_sample_read(reference,reference_parsed,state_binding.status_address,ref_cmd) if ref_cmd else (None,(),'NO_REF_COMMAND')
        expected=deviation_req.expected_behavior.operands[0]
        ref_expected='supported' if ref_value==expected and ref_reason=='SAMPLE_READ_AGREE' else 'unknown'
        ref_no_deviation=True if ref_expected=='supported' and ref_value!=deviation_req.deviating_behavior.operands[0] else None
        ref_evidence=tuple(sorted(set((*ref_ids,*(i for item in ref_access for i in item.evidence_ids)))))
        control=identified(ReferenceControlVerification,reference_joint_run_id=reference.bridge.joint_run.joint_run_id,
            trigger_status=ref_trigger,expected_behavior_status=ref_expected,deviation_observed=False if ref_no_deviation else None,
            evidence_ids=ref_evidence,reason_code='REFERENCE_TRIGGER_EXPECTED_NO_DEVIATION' if ref_trigger==ref_expected=='supported' else 'REFERENCE_INCOMPLETE',
            trigger_condition=condition('type2:reference-trigger',ref_trigger,
                'REFERENCE_EXECUTED_TRIGGER' if ref_trigger=='supported' else 'REFERENCE_TRIGGER_INCOMPLETE',
                ref_evidence if ref_trigger=='supported' else (),
                () if ref_trigger=='supported' else ('reference_trigger_and_prestate',)),
            expected_condition=condition('type2:reference-expected',ref_expected,
                'REFERENCE_EXPECTED_STATUS' if ref_expected=='supported' else 'REFERENCE_STATUS_INCOMPLETE',
                ref_ids if ref_expected=='supported' else (),
                () if ref_expected=='supported' else ('reference_bound_status_observation',)),
            no_deviation_condition=condition('type2:reference-no-deviation',
                'supported' if ref_no_deviation else 'unknown',
                'EXPECTED_NOT_DEVIATING' if ref_no_deviation else 'REFERENCE_DEVIATION_UNASSESSED',
                ref_ids if ref_no_deviation else (),
                () if ref_no_deviation else ('reference_expected_not_deviating',)))
    else:
        control=identified(ReferenceControlVerification,reference_joint_run_id=reference.bridge.joint_run.joint_run_id if reference else None,
            trigger_status='unknown',expected_behavior_status='unknown',deviation_observed=None,evidence_ids=(),reason_code='REFERENCE_MISSING_OR_UNASSESSED',
            trigger_condition=condition('type2:reference-trigger','unknown','REFERENCE_MISSING',missing=('reference_trigger',)),
            expected_condition=condition('type2:reference-expected','unknown','REFERENCE_MISSING',missing=('reference_status',)),
            no_deviation_condition=condition('type2:reference-no-deviation','unknown','REFERENCE_MISSING',missing=('reference_status',)))
    paired=(reference is not None and source_id is not None and
            target.bridge.joint_run.firmware_sha256==reference.bridge.joint_run.firmware_sha256 and
            target.bridge.joint_run.input_sha256==reference.bridge.joint_run.input_sha256 and
            target.bridge.joint_run.execution_context_sha256==reference.bridge.joint_run.execution_context_sha256 and
            target.static.target_binding.map_id==reference.static.target_binding.map_id and
            reference.bridge.joint_run.rtl_tree_sha256==REF_TREE and
            target.bridge.joint_run.rtl_tree_sha256==VAR_TREE)
    target_behavior=tuple((o.operation,o.address,o.width_bits,o.write_value,o.reset_epoch)
        for _,o,_,_ in sorted(_capability_transactions(target),key=lambda x:x[1].request_cycle))
    reference_behavior=tuple((o.operation,o.address,o.width_bits,o.write_value,o.reset_epoch)
        for _,o,_,_ in sorted(_capability_transactions(reference),key=lambda x:x[1].request_cycle)) if reference else ()
    diff_ok=(paired and target_behavior==reference_behavior and
             trigger_status=='supported' and deviation.status=='supported' and
             control.trigger_status=='supported' and control.expected_behavior_status=='supported' and
             control.deviation_observed is False and obs.status=='supported')
    diff=identified(ControlledDifferentialVerification,status='supported' if diff_ok else 'unknown',
        evidence_ids=tuple(sorted(set((target.bridge.joint_run.joint_run_id,reference.bridge.joint_run.joint_run_id,
                   source_id,*obs.evidence_ids,*control.evidence_ids)))) if diff_ok else (),
        reason_code='PINNED_CONTROLLED_REFERENCE_VARIANT_DIFFERENCE' if diff_ok else 'DIFFERENTIAL_REQUIREMENTS_MISSING',
        missing_requirements=() if diff_ok else ('same_input_context_map','source_delta','reference_expected','target_deviation'),
        source_proof_id=source_id)
    final=_final_status(trigger.status,deviation.status,obs.status,diff.status)
    return identified(Type2VerificationResult,contract_id=contract.contract_id,
        target_joint_run_id=target.bridge.joint_run.joint_run_id,
        capability_ids=tuple(sorted(c.capability_id for c in target.capabilities)),
        trigger=trigger,deviation=deviation,observation=obs,reference_control=control,
        differential=diff,final_status=final)
