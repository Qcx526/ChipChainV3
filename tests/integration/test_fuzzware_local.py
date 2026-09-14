"""Opt-in local Heat_Press verification: four inputs, no emulation or model."""

from collections import Counter
import json
import os
from pathlib import Path

import pytest

from chipchain.agents.context import firmware_context
from chipchain.agents.contracts import FirmwareAgentInput
from chipchain.agents.firmware import FirmwareSecurityAgent
from chipchain.agents.firmware_evidence import collect_firmware_evidence
from chipchain.agents.projections.firmware import (
    build_firmware_analysis_projection, serialize_firmware_analysis_projection, firmware_projection_sha256,
)
from chipchain.domain.case import CaseBundle, TargetDescriptor
from chipchain.tools.firmware.fuzzware import FuzzwareHeatPressScenarioAnalyzer
from tests.firmware_fakes import reference

ARTIFACTS = [
    ('02-comparison-with-state-of-the-art/P2IM/Heat_Press/Heat_Press.elf','firmware_binary','elf',261365,'73f667524ed0ff8f24b460d4678b74f15eec13d954b93cdc92c839c2c3f1044e'),
    ('02-comparison-with-state-of-the-art/P2IM/Heat_Press/Heat_Press.bin','firmware_binary','bin',24896,'1f7654deeec0d26307f35ea683c891965aa671fd891ae24af1aa8949ede43620'),
    ('04-crash-analysis/13/config.yml','firmware_config','yaml',4253,'2d91c058a4326ddde28be2bc27afd6a073b9b8aabf1816f6bac22e76dcc33bc2'),
    ('04-crash-analysis/13/crashing_input','firmware_input','opaque',6009,'0eca471106cf883c5941a03376c4ee3aa4b6cebd26636fc401e50c168644ee22'),
]


def test_local_heat_press_scenario_13():
    root=os.environ.get('CHIPCHAIN_FUZZWARE_ROOT')
    if not root:
        pytest.skip('Set CHIPCHAIN_FUZZWARE_ROOT explicitly for four-file local verification')
    artifacts=[]
    for path,kind,fmt,size,sha in ARTIFACTS:
        ref=reference(Path(root)/path,kind,fmt)
        assert (ref.size_bytes,ref.sha256)==(size,sha)
        artifacts.append(ref)
    case=CaseBundle(case_id='fuzzware:heat-press:scenario-13',name='Heat_Press scenario 13',firmware_artifacts=artifacts,
        target=TargetDescriptor(processor_id='sam3x',firmware_id='heat-press',architecture='arm',
                                word_size_bits=32,endianness='little',isa_variant='ARMv7-M Thumb'))
    analyzer=FuzzwareHeatPressScenarioAnalyzer()
    batch=analyzer.analyze(case_id=case.case_id,target=case.target,artifacts=artifacts)
    kinds=Counter(o.kind.value for o in batch.observations)
    scopes=Counter(o.scope.value for o in batch.observations)
    assert kinds=={'static_instruction_site':23,'mmio_model':32,'environment_input':2}
    assert scopes=={'static':23,'configuration':33,'artifact':1}
    models=[o.details for o in batch.observations if o.kind=='mmio_model']
    assert len({m.pc for m in models})==23 and len({m.mmio_address for m in models})==19
    assert Counter(m.model_kind.value for m in models)=={'bitextract':2,'constant':5,'passthrough':9,'set':5,'unmodeled':11}
    sites=[o for o in batch.observations if o.kind=='static_instruction_site']
    assert all(o.behaviors[0].decoded_instruction.status=='decoded' for o in sites)
    assert not any('configuration retained' in q for q in batch.unresolved_questions)
    inp=next(o for o in batch.observations if o.details.kind=='opaque_input')
    assert inp.details.size_bytes==6009 and not inp.behaviors
    inputs=FirmwareAgentInput(case=case,deterministic_observations=batch)
    assert FirmwareAgentInput.model_validate_json(inputs.model_dump_json())==inputs
    output=FirmwareSecurityAgent().invoke(inputs)
    counts=Counter(b.kind.value for b in output.processor_behavior_ir.behaviors)
    assert counts=={'instruction':23,'mmio_access':32}
    refs={e.evidence_id:e for o in batch.observations for e in [*o.evidence,*(e for b in o.behaviors for e in b.evidence)]}
    assert len(refs)==57 and {e.artifact_id for e in refs.values()} <= {a.artifact_id for a in artifacts}
    from chipchain.integrations.deepseek_firmware import prepare_firmware_input, validate_firmware_baseline
    prepared=prepare_firmware_input(Path(root))
    assert prepared==inputs
    validate_firmware_baseline(prepared,firmware_context(prepared))
    from chipchain.agents.runtime import AgentExecutionError
    changed=prepared.model_copy(deep=True)
    changed.case.target.processor_id='sam3y'  # same length/counts, different exact context
    assert len(firmware_context(changed))==39438
    with pytest.raises(AgentExecutionError,match='projection and sent context disagree'):
        validate_firmware_baseline(changed,firmware_context(changed))
    before=inputs.model_dump_json()
    projection=build_firmware_analysis_projection(inputs)
    text=firmware_context(inputs);context=json.loads(text)
    assert text==serialize_firmware_analysis_projection(projection)==firmware_context(inputs)
    assert inputs.model_dump_json()==before
    assert len(text)<=40000 and len(context['observations'])==57
    assert {o['observation_id'] for o in context['observations']}=={o.observation_id for o in batch.observations}
    assert len(context['behaviors'])==55
    assert {b['behavior_id'] for b in context['behaviors']}=={b.behavior_id for b in output.processor_behavior_ir.behaviors}
    assert len(context['evidence_catalog'])==57
    assert {e.evidence_id:e for e in projection.evidence_catalog}==collect_firmware_evidence(inputs)
    for marker in ('CVE-', 'known root cause', 'expected crash', 'exploitability', 'crash-analysis', 'crashing_input', '/home/'):
        assert marker not in text
    assert not output.report.findings and not output.report.issue_anchors
    assert not output.report.external_input_paths and not output.report.reachable_behaviors
    assert all(o.role=='analysis_input' and o.scope!='runtime' for o in batch.observations)
    assert 'HardFault' not in text and 'crash_observed' not in text
    print(json.dumps({'observations':kinds,'scopes':scopes,'behaviors':counts,'successful_decodes':len(sites),
                      'unresolved_sites':0,'unique_evidence':len(refs),'context_characters':len(text),
                      'dependencies':analyzer.dependency_versions, 'projection_sha256':firmware_projection_sha256(projection),
                      'reduction_characters':62793-len(text), 'reduction_percent':(62793-len(text))*100/62793,
                      'headroom':64000-len(text)},sort_keys=True))
