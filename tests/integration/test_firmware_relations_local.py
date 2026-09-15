"""Opt-in fresh Heat_Press B3 preflight + real-relation fake-model regressions; no API."""
import json
import os
from collections import Counter
from pathlib import Path
import subprocess

import pytest

from chipchain.agents.projections.firmware import build_firmware_analysis_projection
from chipchain.agents.projections.firmware_relations import (
    build_firmware_relation_projection, serialize_firmware_relation_projection, parse_firmware_relation_projection,
)
from chipchain.agents.projections.firmware_envelope_v3 import parse_firmware_envelope_v3, envelope_v3_components
from chipchain.agents.relation_support import RelationSupportError
from chipchain.integrations.deepseek_firmware import prepare_firmware_input
from chipchain.integrations.firmware_relations import prepare_relation_context, validate_relation_baseline, COUNTS, A4_SHA
from tests.unit.test_firmware_relations import payload_for, invoke

_POPEN = subprocess.Popen


def test_real_relation_v3_preflight_and_fake_model(tmp_path,monkeypatch):
    root=os.environ.get('CHIPCHAIN_FUZZWARE_ROOT');ghidra=os.environ.get('CHIPCHAIN_GHIDRA_HOME')
    if not root or not ghidra:
        pytest.skip('Set explicit corpus and Ghidra home for local deterministic preflight')
    root,ghidra=Path(root),Path(ghidra)
    def explicit_headless(argv,**settings):
        assert argv[0]==str((ghidra/'support/analyzeHeadless').resolve())
        assert settings['shell'] is False
        return _POPEN(argv,**settings)
    monkeypatch.setattr(subprocess,'Popen',explicit_headless)
    inputs=prepare_firmware_input(root)
    before=inputs.model_dump_json()
    relevant,source,catalog,p,context,metadata=prepare_relation_context(inputs,ghidra)
    validate_relation_baseline(catalog)
    assert len(context)<=58000 and len(context)<=64000
    assert metadata['relation_projection_characters']<=17000
    assert metadata['a4_catalog_sha256']==A4_SHA and metadata['a4_relation_counts']==COUNTS
    e=parse_firmware_envelope_v3(context);base,restored,registry=envelope_v3_components(e)
    assert restored.catalog==catalog and len(registry)==174
    assert len(base.evidence_catalog)==57 and len(relevant.evidence_catalog)==172
    assert len(set(r.evidence_id for r in base.evidence_catalog)&set(r.evidence_id for r in relevant.evidence_catalog))==55
    assert len(p.evidence_delta)==117
    wire=serialize_firmware_relation_projection(p)
    assert wire==serialize_firmware_relation_projection(build_firmware_relation_projection(inputs,relevant,catalog))
    assert parse_firmware_relation_projection(wire,base=build_firmware_analysis_projection(inputs)).catalog==catalog
    # Invoke only official fake chat model. These are test responses, not provider calls.
    components=((inputs,source,None,relevant),catalog,p)
    outcomes=Counter()
    for rid in ('call-80afa','call-80f88','call-80abe','mmio-direction-80eba','mmio-containment-80d4e','vector-1'):
        _,audit,_=invoke(components,payload_for(components,rid))
        assert audit.support_claims[0].result=='supported'
        outcomes['supported']+=1
    for rid in ('call-80f88','call-80abe','call-80ad2','call-80ade','call-80aea','vector-1'):
        payload=payload_for(components,rid)
        payload['support_claims'][0].update(expected_kind='direct_call',expected_status='confirmed_static',
            expected_source_entity_id='f80f34',expected_target_entity_id='f80eac',expected_transfer_kind='direct_call')
        with pytest.raises(RelationSupportError) as caught:invoke(components,payload)
        diagnostic=caught.value.failure_diagnostic
        assert diagnostic.referenced_incompatible_count==1
        failed=diagnostic.failed_referenced_supports[0]
        actual=failed.actual_relations[0].actual
        assert actual.relation_id==rid and failed.expected.expected_kind=='direct_call'
        if rid=='call-80f88':
            assert (actual.kind,actual.status,actual.attributes.transfer_kind,actual.attributes.mnemonic)==(
                'control_transfer_unresolved','unresolved','indirect_call','blx')
        elif rid=='vector-1':
            assert actual.kind=='vector_dispatch' and actual.target.entity_id=='f80f34'
        else:
            assert actual.kind=='direct_branch' and actual.attributes.mnemonic=='b.w'
        outcomes['rejected']+=1
    for pc in (0x80eba,0x80eca,0x80ed2,0x80eda,0x80ee6,0x80ef2,0x80efe,0x80f0a):
        payload=payload_for(components,f'mmio-direction-{pc:x}')
        payload['support_claims'][0]['expected_direction']='write'
        with pytest.raises(RelationSupportError) as caught:invoke(components,payload)
        failed=caught.value.failure_diagnostic.failed_referenced_supports[0]
        assert failed.reason_code=='relation_fact_mismatch' and failed.mismatch_detail=='direction_mismatch'
        assert failed.actual_relations[0].actual.attributes.direction=='read'
        assert failed.actual_relations[0].actual.attributes.mnemonic=='ldr'
        outcomes['rejected']+=1
    # R2: the same invalid real relation is diagnostic only when unreferenced.
    payload=payload_for(components,'call-80afa')
    orphan=payload_for(components,'call-80f88')['support_claims'][0]
    orphan.update(support_claim_id='orphan-reset-call',expected_kind='direct_call',
        expected_status='confirmed_static',expected_target_entity_id='f80eac',expected_transfer_kind='direct_call')
    payload['support_claims'].append(orphan)
    output,audit,_=invoke(components,payload)
    assert len(output.report.findings)==1 and audit.referenced_supported_count==1
    assert audit.orphan_incompatible_count==1
    assert audit.support_claims[1].usage_status=='orphaned'
    assert not audit.support_claims[1].referencing_firmware_claims
    assert inputs.model_dump_json()==before
    assert outcomes=={'supported':6,'rejected':14}
    import hashlib
    metrics={**metadata,'context_characters':len(context),'context_sha256':hashlib.sha256(context.encode()).hexdigest(),
             'fake_model_regressions':dict(outcomes),'orphan_incompatible_retained':1,'safe_failure_diagnostics_checked':14}
    (tmp_path/'preflight.json').write_text(json.dumps(metrics,indent=2))
    print(json.dumps(metrics,sort_keys=True))
