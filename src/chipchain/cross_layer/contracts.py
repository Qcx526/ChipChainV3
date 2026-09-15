"""Reference-only firmware inputs and conservative match artifacts."""
from typing import Literal
from pydantic import Field, model_validator
from chipchain.domain.common import Architecture, Contract, Identifier, Sha256
from .codec import digest, parse, serialize, sha256
from .eligibility import CrossLayerPairDescriptor, CrossLayerPairManifest

MATCH_VERSION = 'cross-layer-trigger-match/v1'
FactSourceKind = Literal['firmware_static_relation', 'firmware_static_reachability', 'processor_behavior']
# Reserved vocabulary only; intentionally excluded from FactSourceKind in XL0.
FUTURE_FACT_SOURCE_KIND = 'firmware_constrained_path'
MatchStatus = Literal['matched', 'partial', 'conflict', 'unknown', 'not_applicable']
OverallStatus = Literal['full_static_match', 'partial_static_match', 'conflict', 'insufficient_information']


class FactCapabilities(Contract):
    comparable_fields: list[Identifier] = Field(default_factory=list)
    supports_static_ordering: bool = False
    supports_static_reachability: bool = False
    supports_runtime_order: Literal[False] = False
    supports_runtime_trigger: Literal[False] = False
    supports_path_feasibility: Literal[False] = False


class FirmwareCrossLayerFactRef(Contract):
    source_kind: FactSourceKind
    source_id: Identifier
    case_id: Identifier
    architecture: Architecture
    source_sha256: Sha256
    site_id: Identifier | None = None
    capabilities: FactCapabilities


class FirmwareAtomBinding(Contract):
    """Explicit candidate site selection; addresses never identify cross-target resources."""
    atom_id: Identifier
    site_id: Identifier
    firmware_fact_refs: list[FirmwareCrossLayerFactRef] = Field(min_length=1)


class CrossLayerAtomMatch(Contract):
    atom_id: Identifier
    required: bool
    status: MatchStatus
    firmware_fact_refs: list[FirmwareCrossLayerFactRef]
    reason_code: Identifier
    evidence_strength: Literal['static_fields', 'static_path', 'none', 'metadata_only']
    missing_fields: list[Identifier] = Field(default_factory=list)

    @model_validator(mode='after')
    def semantics(self):
        if (self.status == 'not_applicable') != (not self.required):
            raise ValueError('Only verification-only metadata may be not_applicable')
        if self.status in ('matched', 'partial', 'conflict') and not self.firmware_fact_refs:
            raise ValueError('Comparable results require source references')
        return self


def aggregate_status(matches):
    statuses = [m.status for m in matches if m.required]
    if not statuses:
        raise ValueError('Candidate requires necessary atoms')
    if 'conflict' in statuses:
        return 'conflict'
    if all(s == 'matched' for s in statuses):
        return 'full_static_match'
    if 'matched' in statuses:
        return 'partial_static_match'
    # Even all-partial lacks a single fully matched required atom.
    return 'insufficient_information'


class CandidateCapabilities(Contract):
    supports_static_cross_layer_match: bool
    static_path_only: Literal[True] = True
    supports_runtime_order: Literal[False] = False
    supports_runtime_trigger: Literal[False] = False
    supports_path_feasibility: Literal[False] = False
    supports_exploitability: Literal[False] = False
    supports_vulnerability_verification: Literal[False] = False


class MatcherDescriptor(Contract):
    name: Literal['chipchain.cross_layer.deterministic'] = 'chipchain.cross_layer.deterministic'
    version: Literal['1'] = '1'
    policy: Literal['explicit-site-all-of-static/v1'] = 'explicit-site-all-of-static/v1'
    adapter_version: Identifier


class CrossLayerTriggerCandidate(Contract):
    schema_version: Literal['cross-layer-trigger-match/v1'] = MATCH_VERSION
    candidate_id: Identifier
    pair_id: Identifier
    hardware_trigger_condition_id: Identifier
    firmware_case_id: Identifier
    hardware_case_id: Identifier
    pair_descriptor_sha256: Sha256
    trigger_condition_sha256: Sha256
    firmware_fact_source_identities: list[FirmwareCrossLayerFactRef]
    matcher: MatcherDescriptor
    atom_matches: list[CrossLayerAtomMatch] = Field(min_length=1)
    overall_status: OverallStatus
    firmware_path_refs: list[FirmwareCrossLayerFactRef]
    missing_constraints: list[Identifier]
    limitations: list[Identifier]
    epistemic_status: Literal['hypothesized'] = 'hypothesized'
    synthetic: bool
    capabilities: CandidateCapabilities

    @model_validator(mode='after')
    def aggregation(self):
        if len({a.atom_id for a in self.atom_matches}) != len(self.atom_matches):
            raise ValueError('Duplicate atom match')
        if self.overall_status != aggregate_status(self.atom_matches):
            raise ValueError('Candidate status is derived from all necessary atoms')
        if self.capabilities.supports_static_cross_layer_match != (self.overall_status == 'full_static_match'):
            raise ValueError('Static match capability must reflect full match')
        refs = [r for a in self.atom_matches for r in a.firmware_fact_refs] + self.firmware_path_refs
        canonical_refs = {serialize(r) for r in refs}
        if canonical_refs != {serialize(r) for r in self.firmware_fact_source_identities}:
            raise ValueError('Candidate source references are incomplete')
        if any(r.case_id != self.firmware_case_id for r in refs):
            raise ValueError('Candidate references a different firmware case')
        if any(r.source_kind != 'firmware_static_reachability' for r in self.firmware_path_refs):
            raise ValueError('Path refs require A5 static reachability')
        required_limits = {'static_abstraction_only', 'not_runtime_trigger', 'not_path_feasible',
                           'not_vulnerability', 'not_attack_chain', 'association_not_causality'}
        if self.synthetic:
            required_limits |= {'synthetic_not_real_vulnerability'}
        if not required_limits <= set(self.limitations):
            raise ValueError('Missing scientific limitations')
        if self.candidate_id != 'xlcandidate:' + digest(self.model_dump(mode='json', exclude={'candidate_id'})):
            raise ValueError('Candidate identity mismatch')
        return self


serialize_cross_layer_candidate = serialize
cross_layer_candidate_sha256 = sha256


def parse_cross_layer_candidate(text):
    return parse(CrossLayerTriggerCandidate, text)
