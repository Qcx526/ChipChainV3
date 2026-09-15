"""Real local deterministic B2 preflight only; never calls a model."""
from collections import Counter
import os
from pathlib import Path

import pytest

from chipchain.agents.hardware_support import validate_supported_hardware_report, HardwareSupportError
from chipchain.agents.projections.hardware_relations import serialize_hardware_relation_projection
from chipchain.agents.projections.hardware_envelope import serialize_hardware_envelope
from chipchain.integrations.deepseek_hardware_supported import prepare_supported_hardware, FROZEN_A3
from chipchain.tools.hardware.relation_claims import HardwareClaimKind as Claim
from chipchain.tools.hardware.relations import HardwareRelationKind as Kind, serialize_hardware_relation_catalog, hardware_relation_catalog_sha256, canonical_json
from tests.unit.test_hardware_supported_agent import grounded_report,semantic_support


@pytest.fixture(params=['743','820'])
def real(request):
    root=os.environ.get('CHIPCHAIN_ENCORPUS_IBEX_ROOT')
    if not root: pytest.skip('Set CHIPCHAIN_ENCORPUS_IBEX_ROOT for offline local B2 preflight')
    path=Path(root)/'driver'/request.param
    return request.param,path,prepare_supported_hardware(path)


def test_real_frozen_preflight_projection_and_envelope(real):
    name,path,p=real
    assert (len(serialize_hardware_relation_catalog(p.catalog)),hardware_relation_catalog_sha256(p.catalog))==FROZEN_A3[name]
    expected={Kind.INSTRUCTION:3,Kind.LOCAL:3,Kind.REGISTER:2,Kind.COVER:1,Kind.ERROR:1} if name=='743' else {
        Kind.LOCAL:6,Kind.REGISTER:1,Kind.COVER:1,Kind.ERROR:1}
    assert Counter(r.kind for r in p.projection.relations)==Counter(expected)
    assert len(serialize_hardware_relation_projection(p.projection))<=(18000 if name=='743' else 14000)
    assert len(serialize_hardware_envelope(p.envelope))<=64000
    fresh=prepare_supported_hardware(path)
    assert serialize_hardware_relation_projection(p.projection)==serialize_hardware_relation_projection(fresh.projection)
    assert serialize_hardware_envelope(p.envelope)==serialize_hardware_envelope(fresh.envelope)
    assert p.identities()==fresh.identities()
    print(canonical_json(p.identities()))


def test_real_all_facts_hydrate_and_support(real):
    _,_,p=real
    for r in p.catalog.relations:
        report=grounded_report(p.inputs,p.catalog,relation=r)
        output,audit=validate_supported_hardware_report(report,p.inputs,p.catalog)
        assert audit.referenced_supported_count==1
        assert [e.evidence_id for e in output.report.findings[0].evidence]==r.evidence_ids


def test_real_historical_semantic_regressions(real):
    name,_,p=real
    r=next(r for r in p.catalog.relations if r.kind==Kind.REGISTER and r.attributes.register_name=='x10')
    kinds=[Claim.READ,Claim.WRITE,Claim.CAUSAL,Claim.TRIGGER,Claim.SAME_CONFIGURATION,Claim.FORMAL_CAUSAL,
           Claim.MUTATION_LOCATION,Claim.MUTATION_CONNECTION,Claim.MUTATION_FAMILY,Claim.ROOT_CAUSE]
    if name=='743': kinds += [Claim.INTERVAL,Claim.EXECUTED,Claim.RETIRED]
    else: kinds += [Claim.ENCODING,Claim.DECODED]
    for kind in kinds:
        support=semantic_support(kind,[] if kind in [Claim.ENCODING,Claim.DECODED] else [r])
        report=grounded_report(p.inputs,p.catalog,relation=r,support=support)
        with pytest.raises(HardwareSupportError) as caught:
            validate_supported_hardware_report(report,p.inputs,p.catalog)
        assert caught.value.failed_count==1
        assert caught.value.failure_diagnostic.failed_referenced_supports[0].result=='unsupported'
