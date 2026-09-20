"""A6 canonical static facts. Function intervals are half-open [start, end)."""

import hashlib
import json
from typing import Annotated, Literal, Self
from pydantic import Field, model_validator
from chipchain.domain.common import Architecture, Contract, Identifier, Sha256
from chipchain.domain.evidence import EvidenceRef
from chipchain.domain.case import TargetDescriptor

VERSION = 'firmware-control-flow-grounding/v1'
Address = Annotated[int, Field(strict=True, ge=0, le=0xffffffffffffffff)]
TransferKind = Literal['direct_call', 'direct_jump', 'conditional_branch', 'indirect_call',
                       'indirect_jump', 'return', 'other_control_transfer']
ResolutionStatus = Literal['resolved_direct', 'indirect', 'ambiguous', 'unsupported', 'invalid']


def canonical(value) -> str:
    """Object keys and set-like evidence references have stable order; no timestamps."""
    if isinstance(value, Contract):
        value = type(value).model_validate(value.model_dump()).model_dump(mode='json')
    def normalize(v, key=''):
        if isinstance(v, dict):
            return {k: normalize(x, k) for k, x in v.items()}
        if isinstance(v, list):
            values = [normalize(x) for x in v]
            if key in {'evidence_ids', 'source_ids', 'source_artifact_ids', 'candidate_function_ids', 'limitations'}:
                return sorted(values)
            if key in {'transfer_facts', 'ownership_facts'}:
                return sorted(values, key=lambda f: f['fact_id'])
            if key == 'runtime_observations':
                return sorted(values, key=lambda f: f['observation_id'])
            if key in {'functions', 'source_artifacts', 'evidence_catalog'}:
                ident = {'functions': 'function_id', 'source_artifacts': 'artifact_id', 'evidence_catalog': 'evidence_id'}[key]
                return sorted(values, key=lambda f: f[ident])
            return values
        return v
    return json.dumps(normalize(value), sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def sha256(value) -> str:
    if isinstance(value, FirmwareControlFlowGroundingCatalog):
        return FirmwareControlFlowGroundingCatalog.model_validate(value.model_dump()).catalog_sha256
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def identity(prefix, data):
    return prefix + ':' + sha256(data)[:24]


class FactProvenance(Contract):
    adapter_version: Literal['firmware-control-flow-grounding/v1'] = VERSION
    scope: Literal['static_instruction', 'static_function_interval']
    method: Identifier
    input_sha256: Sha256
    architecture: Architecture
    word_size_bits: int = Field(gt=0, strict=True)
    # Runtime trace supplies site selection only, never static path feasibility.
    runtime_selection_sha256: Sha256 | None = None


class ControlTransferFact(Contract):
    fact_id: Identifier
    case_id: Identifier
    architecture: Architecture
    instruction_pc: Address
    instruction_encoding: str = Field(pattern=r'^(?:[0-9a-f]{2})*$')
    instruction_width_bits: int = Field(ge=0, strict=True)
    mnemonic: str
    operands: str
    transfer_kind: TransferKind
    resolution_status: ResolutionStatus
    resolved_target_pc: Address | None
    fallthrough_pc: Address | None
    decoder_backend: Identifier
    decoder_version: Identifier
    resolution_method: Identifier
    decoder_mode: Identifier
    decoded_immediate: int | None = None
    destination_register: str | None = Field(default=None, pattern=r'^x(?:[0-9]|[12][0-9]|3[01])$')
    fallthrough_semantics: Literal['conditional_not_taken', 'sequential_address_not_branch_alternative', 'none'] = 'none'
    source_artifact_ids: list[Identifier] = Field(min_length=1)
    source_artifact_id: Identifier  # Retained singular alias for the initial A6 API.
    evidence_ids: list[Identifier] = Field(min_length=1)
    provenance: FactProvenance
    reason: Identifier

    @model_validator(mode='after')
    def consistency(self) -> Self:
        if self.architecture != self.provenance.architecture or self.source_artifact_ids != [self.source_artifact_id]:
            raise ValueError('Transfer architecture or source aliases disagree')
        if self.resolution_method != self.provenance.method:
            raise ValueError('Resolution method differs from provenance')
        if self.instruction_width_bits != len(self.instruction_encoding) * 4:
            raise ValueError('Instruction width differs from encoding')
        if (self.resolution_status == 'resolved_direct') != (self.resolved_target_pc is not None):
            raise ValueError('Only resolved direct facts have a concrete target')
        if self.resolution_status == 'resolved_direct' and self.transfer_kind not in (
                'direct_call', 'direct_jump', 'conditional_branch'):
            raise ValueError('Resolved target requires direct transfer kind')
        if self.resolution_status == 'indirect' and self.transfer_kind not in (
                'indirect_call', 'indirect_jump', 'return', 'other_control_transfer'):
            raise ValueError('Indirect status conflicts with transfer kind')
        if self.provenance.scope != 'static_instruction':
            raise ValueError('Transfer provenance must be static')
        return self


class FunctionInterval(Contract):
    function_id: Identifier
    function_name: str | None
    start: Address
    end_exclusive: Address | None
    source_kind: Literal['elf_symbol', 'static_structure', 'cfg_metadata']
    source_ids: list[Identifier] = Field(min_length=1)
    evidence_ids: list[Identifier] = Field(min_length=1)

    @model_validator(mode='after')
    def interval(self) -> Self:
        if self.end_exclusive is not None and self.end_exclusive <= self.start:
            raise ValueError('Function interval must have positive known extent')
        return self


class FunctionOwnershipFact(Contract):
    fact_id: Identifier
    case_id: Identifier
    architecture: Architecture
    site_pc: Address
    ownership_status: Literal['unique', 'ambiguous', 'missing']
    owner_function_id: Identifier | None
    owner_function_name: str | None
    function_start: Address | None
    function_end_exclusive: Address | None
    ownership_method: Identifier
    source_ids: list[Identifier] = Field(min_length=1)
    evidence_ids: list[Identifier] = Field(min_length=1)
    candidate_function_ids: list[Identifier]
    provenance: FactProvenance

    @model_validator(mode='after')
    def ownership(self) -> Self:
        if self.architecture != self.provenance.architecture:
            raise ValueError('Ownership architecture mismatch')
        if self.ownership_status == 'unique':
            if (self.owner_function_id is None or self.function_start is None or self.function_end_exclusive is None
                    or not self.function_start <= self.site_pc < self.function_end_exclusive
                    or self.candidate_function_ids != [self.owner_function_id]):
                raise ValueError('Unique owner needs one containing half-open interval')
        elif any(x is not None for x in (self.owner_function_id, self.owner_function_name,
                                         self.function_start, self.function_end_exclusive)):
            raise ValueError('Unresolved ownership cannot select an owner')
        if self.provenance.scope != 'static_function_interval':
            raise ValueError('Ownership is not reachability')
        return self


class SourceArtifact(Contract):
    artifact_id: Identifier
    sha256: Sha256
    size_bytes: int = Field(ge=0, strict=True)
    format: Identifier


class RuntimeRetirementObservation(Contract):
    """RVFI event evidence, not a static edge or a taken-branch assertion."""
    observation_id: Identifier
    case_id: Identifier
    architecture: Literal[Architecture.RISCV] = Architecture.RISCV
    instruction_pc: Address
    instruction_encoding: str = Field(pattern=r'^(?:[0-9a-f]{4}|[0-9a-f]{8})$')
    cycle: int = Field(ge=0, strict=True)
    line: int = Field(ge=2, strict=True)
    retired: Literal[True] = True
    source_stage: Literal['ibex_rvfi_retirement'] = 'ibex_rvfi_retirement'
    source_artifact_id: Identifier
    source_sha256: Sha256
    evidence_ids: list[Identifier] = Field(min_length=1)


class Capabilities(Contract):
    supports_direct_target_resolution: bool
    supports_function_ownership: bool = True
    supports_runtime_target_resolution: Literal[False] = False
    supports_indirect_target_resolution: Literal[False] = False
    supports_path_feasibility: Literal[False] = False
    supports_input_controllability: Literal[False] = False
    supports_indirect_runtime_resolution: Literal[False] = False
    supports_external_input_controllability: Literal[False] = False
    supports_runtime_reachability_from_interface: Literal[False] = False
    supports_security_impact: Literal[False] = False


class FirmwareControlFlowGroundingCatalog(Contract):
    schema_version: Literal['firmware-control-flow-grounding/v1'] = VERSION
    case_id: Identifier
    architecture: Architecture
    target: TargetDescriptor | None = None
    catalog_sha256: Sha256 | None = None
    runtime_observations: list[RuntimeRetirementObservation] = Field(default_factory=list)
    transfer_facts: list[ControlTransferFact]
    ownership_facts: list[FunctionOwnershipFact]
    functions: list[FunctionInterval]
    source_artifacts: list[SourceArtifact]
    evidence_catalog: list[EvidenceRef]
    capabilities: Capabilities
    limitations: list[str]

    @model_validator(mode='after')
    def references(self) -> Self:
        if self.target is None:
            object.__setattr__(self, 'target', TargetDescriptor(architecture=self.architecture, processor_id='unspecified'))
        if self.target.architecture != self.architecture:
            raise ValueError('Catalog target architecture mismatch')
        for values in ([f.fact_id for f in [*self.transfer_facts, *self.ownership_facts]],
                       [f.function_id for f in self.functions], [e.evidence_id for e in self.evidence_catalog],
                       [a.artifact_id for a in self.source_artifacts], [r.observation_id for r in self.runtime_observations]):
            if len(values) != len(set(values)):
                raise ValueError('Duplicate A6 identity')
        source_map = {a.artifact_id:a for a in self.source_artifacts}
        sources = set(source_map)
        evidence = {e.evidence_id: e for e in self.evidence_catalog}
        functions = {f.function_id: f for f in self.functions}
        if any(e.artifact_id not in sources for e in evidence.values()):
            raise ValueError('Evidence references unknown source artifact')
        for f in [*self.transfer_facts, *self.ownership_facts, *self.functions]:
            if len(f.evidence_ids) != len(set(f.evidence_ids)):
                raise ValueError('Duplicate fact evidence')
            refs = [f.source_artifact_id] if isinstance(f, ControlTransferFact) else f.source_ids
            if not set(refs) <= sources or not set(f.evidence_ids) <= evidence.keys():
                raise ValueError('Unknown fact source or evidence')
            if any(evidence[e].artifact_id not in refs for e in f.evidence_ids):
                raise ValueError('Evidence is not bound to fact sources')
            if isinstance(f, FunctionInterval):
                continue
            if f.provenance.input_sha256 not in {source_map[r].sha256 for r in refs}:
                raise ValueError('Fact provenance differs from source identity')
            if f.case_id != self.case_id or f.provenance.architecture != self.architecture:
                raise ValueError('Fact case or architecture mismatch')
            if isinstance(f, FunctionOwnershipFact):
                if not set(f.candidate_function_ids) <= functions.keys():
                    raise ValueError('Unknown ownership candidate')
                if f.ownership_status == 'unique':
                    owner = functions[f.owner_function_id]
                    if (owner.start, owner.end_exclusive, owner.function_name) != (
                            f.function_start, f.function_end_exclusive, f.owner_function_name):
                        raise ValueError('Owner interval differs from function catalog')
        transfers = {f.instruction_pc:f for f in self.transfer_facts}
        for event in self.runtime_observations:
            source = source_map.get(event.source_artifact_id)
            if (source is None or source.sha256 != event.source_sha256 or source.format != 'ibex-rvfi-text'
                    or event.case_id != self.case_id or event.architecture != self.architecture
                    or not set(event.evidence_ids) <= evidence.keys()):
                raise ValueError('Runtime event source/case mismatch')
            if any(evidence[e].artifact_id != event.source_artifact_id for e in event.evidence_ids):
                raise ValueError('Runtime evidence must reference its trace source')
            fact = transfers.get(event.instruction_pc)
            if fact is None or fact.instruction_encoding != event.instruction_encoding:
                raise ValueError('Runtime instruction differs from static bytes')
        payload = self.model_dump(mode='json', exclude={'catalog_sha256'})
        computed = hashlib.sha256(canonical(payload).encode()).hexdigest()
        if self.catalog_sha256 is not None and self.catalog_sha256 != computed:
            raise ValueError('Catalog SHA does not match canonical payload')
        object.__setattr__(self, 'catalog_sha256', computed)
        return self


def serialize_catalog(catalog):
    return canonical(catalog)


def parse_catalog(text):
    return FirmwareControlFlowGroundingCatalog.model_validate_json(text)
