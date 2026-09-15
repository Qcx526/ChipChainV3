"""Explicit-site deterministic comparisons. No path search, execution or model calls."""
from .codec import digest, serialize, sha256
from .contracts import (
    MATCH_VERSION, CandidateCapabilities, CrossLayerAtomMatch, CrossLayerTriggerCandidate,
    FirmwareAtomBinding, MatcherDescriptor, aggregate_status,
)
from .eligibility import CrossLayerPairDescriptor
from .trigger import HardwareTriggerCondition, ValueConstraint


class PairNotEligible(ValueError):
    """No candidate may be created for an unknown or incompatible pairing."""


def _value(constraint, actual):
    if actual is None:
        return None
    if constraint.operator == 'eq':
        return actual == constraint.value
    if constraint.operator == 'neq':
        return actual != constraint.value
    if constraint.operator == 'masked_eq':
        return actual & constraint.mask == constraint.value
    return constraint.range_min <= actual <= constraint.range_max


def _requirements(atom, fields, adapter):
    checks = {}

    def eq(key, expected, actual_key=None):
        actual = fields.get(actual_key or key)
        checks[key] = None if actual is None else actual == expected

    if atom.kind == 'instruction':
        if atom.mnemonic is not None:
            actual = fields.get('mnemonic')
            checks['mnemonic'] = None if actual is None else (
                adapter.normalize_instruction(actual) == adapter.normalize_instruction(atom.mnemonic))
        if atom.operand_pattern is not None:
            for i, result in enumerate(adapter.compare_operand_pattern(atom.operand_pattern, fields)):
                checks[f'operand_constraint:{i}'] = result
        if atom.encoding is not None:
            actual = fields.get('encoding')
            if actual is None or fields.get('representation') != atom.representation:
                checks['encoding_representation'] = None
            else:
                checks['encoding'] = (actual & atom.encoding_mask if atom.encoding_mask is not None else actual) == atom.encoding
        elif atom.representation is not None:
            checks['representation'] = True if fields.get('representation') == atom.representation else None
        if atom.stage_requirement is not None:
            # A static decode cannot attest execution stages that were not observed.
            checks['stage_requirement'] = True if fields.get('stage') == atom.stage_requirement else None
    elif atom.kind == 'register_state':
        actual = fields.get('register')
        a, b = adapter.normalize_register(atom.register_name), adapter.normalize_register(actual) if actual else None
        checks['register'] = a == b if a is not None and b is not None else None
        constraint = ValueConstraint.model_validate(atom.model_dump(include=set(ValueConstraint.model_fields)))
        checks['state_value'] = _value(constraint, fields.get('state_value'))
    elif atom.kind in ('mmio_access', 'csr_access'):
        if atom.kind == 'mmio_access':
            eq('address', atom.address)
            if atom.width_bits is not None:
                eq('width_bits', atom.width_bits)
        else:
            for key in ('csr_identity', 'csr_address'):
                if getattr(atom, key) is not None:
                    eq(key, getattr(atom, key))
        access = fields.get('access')
        checks['access'] = None if access is None or (access == 'either' and atom.access != 'either') else (
            atom.access == 'either' or access == atom.access)
        if atom.value_constraint is not None:
            checks['value'] = _value(atom.value_constraint, fields.get('value'))
    elif atom.kind == 'privilege_state':
        actual = fields.get('mode')
        a = adapter.normalize_privilege(atom.required_mode)
        b = adapter.normalize_privilege(actual) if actual else None
        checks['privilege_mode'] = a == b if a is not None and b is not None else None
    return checks


def _result(atom, refs, checks=None, *, reason=None, strength='static_fields'):
    checks = checks or {}
    if False in checks.values():
        status, reason = 'conflict', 'same_site_field_conflict'
    elif checks and all(v is True for v in checks.values()):
        status, reason = 'matched', 'deterministic_fields_agree'
    elif True in checks.values():
        status, reason = 'partial', 'required_fields_missing'
    else:
        status, reason = 'unknown', reason or 'no_comparable_fields'
    return CrossLayerAtomMatch(atom_id=atom.atom_id, required=True, status=status,
        firmware_fact_refs=refs, reason_code=reason,
        evidence_strength=strength if checks else 'none',
        missing_fields=sorted(k for k, v in checks.items() if v is None))


def _ordering(atom, bindings, paths):
    before, after = bindings.get(atom.before_atom_id), bindings.get(atom.after_atom_id)
    refs = [p.ref for p in paths]
    if before is None or after is None:
        return _result(atom, refs, reason='ordering_endpoints_unbound')
    # An explicit witness supports this order along that static graph path only.
    witnesses = [p for p in paths if p.ref.capabilities.supports_static_ordering and
                 before.site_id in p.path and after.site_id in p.path and
                 p.path.index(before.site_id) < p.path.index(after.site_id)]
    if not witnesses:
        return _result(atom, refs, reason='no_explicit_static_ordering_witness')
    checks = {'static_ordering': True}
    if atom.max_gap_events is not None:
        checks['max_gap_events'] = None  # Graph edges are not executed events.
    if atom.max_gap_time is not None:
        checks['max_gap_time'] = None
    return _result(atom, refs, checks, strength='static_path')


def match_trigger_condition(*, pair, condition, sources, bindings=(), firmware_path_refs=()):
    pair = CrossLayerPairDescriptor.model_validate(pair.model_dump())
    if pair.eligibility != 'eligible':
        raise PairNotEligible(f'Pair is {pair.eligibility}: {",".join(pair.reasons)}')
    condition = HardwareTriggerCondition.model_validate(condition.model_dump())
    if (condition.hardware_case_id != pair.hardware_case_id or condition.architecture != pair.hardware_target.architecture):
        raise ValueError('Condition does not belong to the hardware target/case')
    if sources.case_id != pair.firmware_case_id or sources.target != pair.firmware_target:
        raise ValueError('Firmware source target/case differs from eligible pair')
    bound = {}
    atoms = {a.atom_id: a for a in condition.all_of_atoms}
    for raw in bindings:
        binding = FirmwareAtomBinding.model_validate(raw.model_dump())
        if binding.atom_id in bound or binding.atom_id not in atoms:
            raise ValueError('Duplicate or unknown bound atom')
        if atoms[binding.atom_id].kind == 'ordering' or atoms[binding.atom_id].purpose != 'required':
            raise ValueError('Ordering uses path refs; metadata does not take fact bindings')
        if len({serialize(r) for r in binding.firmware_fact_refs}) != len(binding.firmware_fact_refs):
            raise ValueError('Duplicate atom fact reference')
        for ref in binding.firmware_fact_refs:
            resolved = sources.resolve(ref)
            if resolved.ref.architecture != pair.firmware_target.architecture:
                raise ValueError('Fact architecture mismatch')
            if resolved.ref.site_id != binding.site_id:
                raise ValueError('Fact does not describe explicitly selected candidate site')
        binding.firmware_fact_refs.sort(key=serialize)
        bound[binding.atom_id] = binding
    paths = [sources.resolve(r) for r in sorted(firmware_path_refs, key=serialize)]
    if len({serialize(p.ref) for p in paths}) != len(paths):
        raise ValueError('Duplicate path reference')
    if any(p.ref.source_kind != 'firmware_static_reachability' for p in paths):
        raise ValueError('Path refs require A5 facts')
    # Paths must mention a selected site (a nonpositive site query carries site_id).
    selected = {b.site_id for b in bound.values()}
    for path in paths:
        if path.path and not selected.intersection(path.path) and path.ref.site_id not in selected:
            raise ValueError('Path does not bind any selected firmware site')
    matches = []
    for atom in sorted(atoms.values(), key=lambda a: a.atom_id):
        if atom.purpose == 'verification_only_metadata':
            result = CrossLayerAtomMatch(atom_id=atom.atom_id, required=False, status='not_applicable',
                firmware_fact_refs=[], reason_code='explicit_verification_only_metadata', evidence_strength='metadata_only')
        elif atom.kind == 'ordering':
            result = _ordering(atom, bound, paths)
        elif atom.kind == 'hardware_state':
            refs = bound[atom.atom_id].firmware_fact_refs if atom.atom_id in bound else []
            result = _result(atom, refs, reason='firmware_cannot_establish_internal_hardware_state')
        elif atom.atom_id not in bound:
            result = _result(atom, [], reason='no_comparable_firmware_facts')
        else:
            refs = bound[atom.atom_id].firmware_fact_refs
            fields, inconsistent = {}, False
            for ref in refs:
                fact = sources.resolve(ref)
                if fact.fields.get('kind') != atom.kind:
                    continue
                for key, value in fact.fields.items():
                    if key in fields and fields[key] != value:
                        inconsistent = True
                    fields[key] = value
            result = (_result(atom, refs, reason='conflicting_firmware_sources') if inconsistent else
                      _result(atom, refs, _requirements(atom, fields, sources.adapter)))
        matches.append(result)
    overall = aggregate_status(matches)
    missing = [f'{m.atom_id}:{field}' for m in matches if m.required and m.status in ('unknown', 'partial')
               for field in (m.missing_fields or [m.reason_code])]
    missing += [f'path:{p.ref.source_id}:{p.path_status}' for p in paths
                if not p.ref.capabilities.supports_static_reachability]
    limits = ['static_abstraction_only', 'not_runtime_trigger', 'not_path_feasible', 'not_vulnerability',
              'not_attack_chain', 'association_not_causality']
    synthetic = sources.synthetic or pair.binding_source == 'synthetic_test_fixture' or condition.source_kind == 'synthetic_fixture'
    if synthetic:
        limits.append('synthetic_not_real_vulnerability')
    if any(p.path_status == 'reachable_static_with_fakeret' for p in paths):
        limits.append('static_path_assumes_callee_returns')
    refs = {serialize(r): r for m in matches for r in m.firmware_fact_refs}
    refs.update({serialize(p.ref): p.ref for p in paths})
    fields = dict(schema_version=MATCH_VERSION, pair_id=pair.pair_id,
        hardware_trigger_condition_id=condition.condition_id, firmware_case_id=pair.firmware_case_id,
        hardware_case_id=pair.hardware_case_id, pair_descriptor_sha256=sha256(pair),
        trigger_condition_sha256=sha256(condition),
        firmware_fact_source_identities=[refs[k].model_dump(mode='json') for k in sorted(refs)],
        matcher=MatcherDescriptor(adapter_version=sources.adapter.version).model_dump(mode='json'),
        atom_matches=[m.model_dump(mode='json') for m in matches], overall_status=overall,
        firmware_path_refs=[p.ref.model_dump(mode='json') for p in paths],
        missing_constraints=sorted(missing), limitations=sorted(limits), epistemic_status='hypothesized',
        synthetic=synthetic,
        capabilities=CandidateCapabilities(supports_static_cross_layer_match=overall == 'full_static_match').model_dump(mode='json'))
    return CrossLayerTriggerCandidate(candidate_id='xlcandidate:' + digest(fields), **fields)


def revalidate_candidate(candidate, *, pair, condition, sources, bindings=()):
    """Recompute semantic support at a trust boundary, not merely parse JSON hashes."""
    rebuilt = match_trigger_condition(pair=pair, condition=condition, sources=sources,
        bindings=bindings, firmware_path_refs=candidate.firmware_path_refs)
    if serialize(rebuilt) != serialize(candidate):
        raise ValueError('Candidate differs from deterministic recomputation')
    return rebuilt
