"""Read-only A4/A5 overlap diagnostics; never replace their frozen semantics."""
from chipchain.domain.common import Contract
from typing import Literal


class CompatibilityDiagnostic(Contract):
    source: Literal['A4', 'A5']
    source_id: str
    status: Literal['agree', 'conflict', 'not_comparable']
    reason: str


def compare_a4(catalog, a4):
    from chipchain.tools.firmware.relations import FirmwareStaticRelationCatalog
    a4 = FirmwareStaticRelationCatalog.model_validate(a4.model_dump())
    digest = next(a.sha256 for a in catalog.source_artifacts if a.format == 'elf')
    if digest != a4.source_identities.elf_sha256 or catalog.case_id != a4.case_id:
        return [CompatibilityDiagnostic(source='A4',source_id=a4.case_id,status='conflict',reason='source_identity_mismatch')]
    transfers={f.instruction_pc:f for f in catalog.transfer_facts}
    owners={f.site_pc:f for f in catalog.ownership_facts}
    result=[]
    for rel in a4.relations:
        status,reason='not_comparable','no_overlapping_supported_fact'
        if rel.kind in ('direct_call','direct_branch') and rel.status=='confirmed_static':
            fact=transfers.get(rel.site_address)
            if fact and fact.resolution_status=='resolved_direct':
                same=fact.resolved_target_pc==rel.target.address
                status,reason=('agree','direct_target_equal') if same else ('conflict','direct_target_mismatch')
        elif rel.kind=='mmio_function_containment' and rel.status=='confirmed_static':
            fact=owners.get(rel.site_address)
            if fact and fact.ownership_status=='unique':
                same=fact.function_start==rel.target.address
                status,reason=('agree','function_entry_equal') if same else ('conflict','function_entry_mismatch')
        result.append(CompatibilityDiagnostic(source='A4',source_id=rel.relation_id,status=status,reason=reason))
    return result


def compare_a5(catalog, cfg):
    from chipchain.tools.firmware.static_reachability import FirmwareAngrCFGResult
    cfg=FirmwareAngrCFGResult.model_validate(cfg.model_dump())
    digest=next(a.sha256 for a in catalog.source_artifacts if a.format=='elf')
    if digest!=cfg.identities.elf_sha256 or catalog.case_id!=cfg.identities.case_id:
        return [CompatibilityDiagnostic(source='A5',source_id=cfg.identities.case_id,status='conflict',reason='source_identity_mismatch')]
    starts={f.start for f in catalog.functions}
    results=[]
    for binding in cfg.function_bindings:
        status,reason='not_comparable','no_matching_symbol_entry_or_nonexact_cfg_binding'
        if binding.binding_status=='exact' and binding.expected_entry_address in starts:
            same=binding.angr_canonical_address==binding.expected_entry_address
            status,reason=('agree','entry_identity_equal_not_reachability') if same else ('conflict','entry_identity_mismatch')
        results.append(CompatibilityDiagnostic(source='A5',source_id=binding.function_id,status=status,reason=reason))
    return results


class GroundingCompatibilityConflict(ValueError):
    """A frozen deterministic fact conflicts; no model call may proceed."""


def compatibility_preflight(catalog, *, write, a4=None, a5=None):
    from chipchain.firmware.control_flow_grounding import FirmwareControlFlowGroundingCatalog
    catalog = FirmwareControlFlowGroundingCatalog.model_validate(catalog.model_dump())
    checks = []
    for source, prior, compare in [('A4', a4, compare_a4), ('A5', a5, compare_a5)]:
        checks.extend(compare(catalog, prior) if prior is not None else [CompatibilityDiagnostic(
            source=source, source_id=catalog.case_id, status='not_comparable',
            reason='no_frozen_catalog_for_this_paired_source')])
    conflict = any(item.status == 'conflict' for item in checks)
    result = dict(schema_version='firmware-a6-compatibility/v1', case_id=catalog.case_id,
        catalog_sha256=catalog.catalog_sha256, blocked=conflict,
        results=[item.model_dump(mode='json') for item in checks])
    write('firmware_grounding_compatibility.json', result)
    if conflict:
        raise GroundingCompatibilityConflict('Frozen A4/A5 conflict; regression blocked before model invocation')
    return result
