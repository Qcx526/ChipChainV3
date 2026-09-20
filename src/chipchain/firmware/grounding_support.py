"""Exact A6 fact-ID support; no interpretation of natural-language statements."""
import json
from typing import Annotated, Literal
from pydantic import Field
from chipchain.domain.common import Contract, Identifier
from chipchain.domain.evidence import EvidenceRef
from chipchain.domain.firmware import FirmwareAnalysisReport, FirmwareFinding
from chipchain.firmware.control_flow_grounding import (
    Address, FirmwareControlFlowGroundingCatalog, ControlTransferFact, FunctionOwnershipFact,
    canonical, sha256,
)


class TargetClaim(Contract):
    claim_id: Identifier
    claim_type: Literal['control_transfer_target']
    fact_id: Identifier
    instruction_pc: Address
    claimed_target_pc: Address
    raw_model_summary: str = Field(max_length=2048)


class OwnershipClaim(Contract):
    claim_id: Identifier
    claim_type: Literal['function_ownership']
    fact_id: Identifier
    site_pc: Address
    owner_function_id: Identifier
    raw_model_summary: str = Field(max_length=2048)


GroundingClaim = Annotated[TargetClaim | OwnershipClaim, Field(discriminator='claim_type')]


class GroundedFirmwareModelReport(Contract):
    case_id: Identifier
    claims: list[GroundingClaim] = Field(max_length=32)
    diagnostic_questions: list[str] = Field(max_length=24)


class SupportResult(Contract):
    claim_id: Identifier
    fact_id: Identifier
    status: Literal['supported', 'incompatible', 'unsupported']
    reason_code: Identifier
    canonical_interpretation: str | None
    evidence: list[EvidenceRef]


class FirmwareGroundingSupportReport(Contract):
    schema_version: Literal['firmware-control-flow-support/v1'] = 'firmware-control-flow-support/v1'
    case_id: Identifier
    catalog_sha256: str
    results: list[SupportResult]
    accepted_claim_ids: list[str]
    rejected_claim_ids: list[str]
    raw_prose_policy: Literal['diagnostic-only-never-canonical'] = 'diagnostic-only-never-canonical'


def fact_text(fact):
    if isinstance(fact, ControlTransferFact):
        if fact.resolution_status == 'resolved_direct':
            return f'静态指令 {fact.instruction_pc:#x} 的直接目标为 {fact.resolved_target_pc:#x}；不证明实际采取该分支或路径可达。'
        return f'指令 {fact.instruction_pc:#x} 的目标解析状态为 {fact.resolution_status}，没有确定的直接目标。'
    if fact.ownership_status == 'unique':
        name = fact.owner_function_name or '(无名称)'
        return (f'位置 {fact.site_pc:#x} 属于函数 {name}，ID={fact.owner_function_id}，'
                f'半开区间 [{fact.function_start:#x}, {fact.function_end_exclusive:#x})；函数归属不证明可达性。')
    return f'位置 {fact.site_pc:#x} 的函数归属为 {fact.ownership_status}，没有唯一确定的 owner。'


def evaluate_claim(claim, catalog):
    """Public semantic gate uses the canonical catalog, never the projection."""
    facts = {f.fact_id:f for f in [*catalog.transfer_facts, *catalog.ownership_facts]}
    fact = facts.get(claim.fact_id)
    status, reason = 'unsupported', 'unknown_fact_id'
    if isinstance(claim, TargetClaim) and isinstance(fact, ControlTransferFact):
        if claim.instruction_pc != fact.instruction_pc:
            status, reason = 'incompatible', 'control_transfer_site_mismatch'
        elif fact.resolution_status != 'resolved_direct':
            reason = ('indirect_target_not_deterministically_resolved' if fact.resolution_status == 'indirect'
                      else 'control_transfer_target_not_resolved')
        elif claim.claimed_target_pc != fact.resolved_target_pc:
            status, reason = 'incompatible', 'control_transfer_target_mismatch'
        else:
            status, reason = 'supported', 'exact_control_transfer_target'
    elif isinstance(claim, OwnershipClaim) and isinstance(fact, FunctionOwnershipFact):
        if claim.site_pc != fact.site_pc:
            status, reason = 'incompatible', 'function_ownership_site_mismatch'
        elif fact.ownership_status != 'unique':
            reason = 'function_ownership_' + fact.ownership_status
        elif claim.owner_function_id != fact.owner_function_id:
            status, reason = 'incompatible', 'function_ownership_mismatch'
        else:
            status, reason = 'supported', 'exact_function_ownership'
    elif fact is not None:
        status, reason = 'incompatible', 'wrong_fact_kind'
    registry = {e.evidence_id:e for e in catalog.evidence_catalog}
    refs = [] if fact is None else [registry[e].model_copy(deep=True) for e in fact.evidence_ids]
    return SupportResult(claim_id=claim.claim_id, fact_id=claim.fact_id, status=status,
        reason_code=reason, canonical_interpretation=fact_text(fact) if fact else None, evidence=refs)


def validate_claims(model_report, catalog, *, allowed_fact_ids):
    catalog = FirmwareControlFlowGroundingCatalog.model_validate(catalog.model_dump())
    model_report = GroundedFirmwareModelReport.model_validate(model_report.model_dump())
    if model_report.case_id != catalog.case_id:
        raise ValueError('A6 claim case mismatch')
    ids = [c.claim_id for c in model_report.claims]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate A6 claim IDs')
    results = []
    for claim in model_report.claims:
        result = evaluate_claim(claim, catalog)
        if claim.fact_id not in allowed_fact_ids:
            result = SupportResult(claim_id=claim.claim_id, fact_id=claim.fact_id, status='unsupported',
                reason_code='fact_not_in_selected_context', canonical_interpretation=None, evidence=[])
        results.append(result)
    audit = FirmwareGroundingSupportReport(case_id=catalog.case_id, catalog_sha256=sha256(catalog),
        results=results, accepted_claim_ids=[r.claim_id for r in results if r.status=='supported'],
        rejected_claim_ids=[r.claim_id for r in results if r.status!='supported'])
    # No model prose or questions are copied into canonical fields. This is an
    # explicit typed claim -> canonical statement projection, not silent repair.
    report = FirmwareAnalysisReport(case_id=catalog.case_id, findings=[FirmwareFinding(
        finding_id='a6-fw-'+r.claim_id, summary=r.canonical_interpretation, evidence=r.evidence,
        epistemic_status='derived') for r in results if r.status=='supported'],
        unresolved_questions=[
            'A6只接受通过确定性校验的直接目标和函数归属；原始模型叙述仅保存在诊断文件。',
            'A6没有验证完整CFG、运行时路径、间接目标或外部输入可控性。',
            f'本次接受 {len(audit.accepted_claim_ids)} 条结构化声明，拒绝 {len(audit.rejected_claim_ids)} 条。'])
    return report, audit


def build_projection(catalog, sites, *, max_facts=48, max_chars=28000):
    transfers = [f for f in catalog.transfer_facts if f.instruction_pc in sites]
    owner_sites = set(sites) | {f.resolved_target_pc for f in transfers if f.resolved_target_pc is not None}
    owners = [f for f in catalog.ownership_facts if f.site_pc in owner_sites]
    if len(transfers)+len(owners) > max_facts:
        raise ValueError('A6 projection exceeds fact budget')
    ids = {e for f in [*transfers,*owners] for e in f.evidence_ids}
    view = dict(schema_version='firmware-control-flow-grounding-projection/v1', case_id=catalog.case_id,
        catalog_sha256=sha256(catalog), architecture=catalog.architecture.value,
        target=catalog.target.model_dump(mode='json'),
        transfer_facts=[f.model_dump(mode='json') for f in transfers],
        ownership_facts=[f.model_dump(mode='json') for f in owners],
        evidence_catalog=[e.model_dump(mode='json') for e in catalog.evidence_catalog if e.evidence_id in ids],
        capabilities=catalog.capabilities.model_dump(), limitations=catalog.limitations)
    if len(canonical(view)) > max_chars:
        raise ValueError('A6 projection exceeds character budget')
    return json.loads(canonical(view))
