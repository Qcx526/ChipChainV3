"""Opt-in reproducible A1 -> fresh Ghidra A2 -> two lossless A3 builds. No agent."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from chipchain.agents.contracts import FirmwareAgentInput
from chipchain.agents.projections.firmware import build_firmware_analysis_projection, serialize_firmware_analysis_projection, firmware_projection_sha256
from chipchain.domain.case import CaseBundle, TargetDescriptor
from chipchain.tools.firmware.fuzzware import FuzzwareHeatPressScenarioAnalyzer
from chipchain.tools.firmware.ghidra.api import extract_heat_press_structure
from chipchain.tools.firmware.ghidra.associations import associate_mmio
from chipchain.tools.firmware.structure_projection import build_relevant_static_structure, serialize_relevant_static_structure, parse_relevant_static_structure, relevant_structure_sha256
from tests.firmware_fakes import reference
from tests.integration.test_fuzzware_local import ARTIFACTS

_POPEN = subprocess.Popen


def test_real_relevant_static_structure(tmp_path,monkeypatch):
    ghidra=os.environ.get('CHIPCHAIN_GHIDRA_HOME');root=os.environ.get('CHIPCHAIN_FUZZWARE_ROOT')
    if not ghidra or not root:
        pytest.skip('Set both CHIPCHAIN_GHIDRA_HOME and CHIPCHAIN_FUZZWARE_ROOT explicitly')
    ghidra=Path(ghidra);root=Path(root)
    refs=[reference(root/p,k,f) for p,k,f,_,_ in ARTIFACTS]
    for ref,(_,_,_,size,sha) in zip(refs,ARTIFACTS):
        assert (ref.size_bytes,ref.sha256)==(size,sha)
    case=CaseBundle(case_id='fuzzware:heat-press:scenario-13',name='Heat_Press scenario 13',firmware_artifacts=refs,
        target=TargetDescriptor(processor_id='sam3x',firmware_id='heat-press',architecture='arm',
                                word_size_bits=32,endianness='little',isa_variant='ARMv7-M Thumb'))
    batch=FuzzwareHeatPressScenarioAnalyzer().analyze(case_id=case.case_id,target=case.target,artifacts=refs)
    inputs=FirmwareAgentInput(case=case,deterministic_observations=batch)
    a1=build_firmware_analysis_projection(inputs)
    a1_text=serialize_firmware_analysis_projection(a1)
    assert len(a1_text)==39438
    assert firmware_projection_sha256(a1)=='48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803'
    assert len(batch.observations)==57 and sum(len(o.behaviors) for o in batch.observations)==55
    assert not any(o.scope=='runtime' for o in batch.observations)
    def explicit_headless(argv,**settings):
        assert argv[0]==str((ghidra/'support/analyzeHeadless').resolve())
        assert settings['shell'] is False and settings['cwd'].is_relative_to(tmp_path)
        assert str(root) not in str(argv)
        return _POPEN(argv,**settings)
    monkeypatch.setattr(subprocess,'Popen',explicit_headless)
    temporary=tmp_path/'projects';temporary.mkdir()
    s,v=extract_heat_press_structure(Path(refs[0].path),ghidra_home=ghidra,
        script_path=Path(__file__).resolve().parents[2]/'scripts/ghidra/ExportFirmwareStructure.java',temporary_parent=temporary)
    assert not list(temporary.iterdir())
    assert (len(s.functions),len(s.direct_call_edges),len(s.unresolved_call_sites))==(183,238,68)
    assert (v.extent.start,v.extent.end,len(v.bindings))==(0x80000,0x800f4,61)
    associations=associate_mmio(s,batch)
    assert Counter(site.containment for site in associations.sites)=={'unique':20,'missing':3}
    before=[x.model_dump_json() for x in (inputs,s,v,associations)]
    first=build_relevant_static_structure(inputs,s,v);second=build_relevant_static_structure(inputs,s,v)
    text=serialize_relevant_static_structure(first)
    assert text==serialize_relevant_static_structure(second)
    assert relevant_structure_sha256(first)==relevant_structure_sha256(second)
    assert parse_relevant_static_structure(text)==first
    assert [x.model_dump_json() for x in (inputs,s,v,associations)]==before
    assert serialize_firmware_analysis_projection(build_firmware_analysis_projection(inputs))==a1_text
    mmio={b.function_id for b in associations.bindings if b.binding_status=='unique'}
    handlers={b.function_id for b in v.bindings if b.binding_status=='function_entry'}
    seeds=mmio|handlers
    expected_edges={e.edge_id for e in s.direct_call_edges if e.caller_function_id in seeds or e.callee_function_id in seeds}
    assert {e.edge_id for e in first.direct_call_edges}==expected_edges
    expected_neighbors={f for e in first.direct_call_edges for f in (e.caller_function_id,e.callee_function_id)}-seeds
    assert {f.function_id for f in first.functions}==seeds|expected_neighbors
    assert {c.call_site_address for c in first.unresolved_call_sites}=={c.call_site_address for c in s.unresolved_call_sites if c.caller_function_id in seeds}
    assert len(first.mmio_sites)==23
    assert [site.pc for site in first.mmio_sites if site.containment_status=='missing']==[0x80d4e,0x80d50,0x80d5a]
    dispatch={b.vector_index:b.canonical_handler_address for b in v.bindings if b.vector_index and b.raw_handler_value}
    assert {index:g.handler_address for g in first.vector_handler_groups for index in g.vector_indices}==dispatch
    assert len(dispatch)==51 and len(first.vector_handler_groups)==14
    system=[site for site in first.mmio_sites if site.pc in {0x80eba,0x80eca,0x80ed2,0x80eda,0x80ee6,0x80ef2,0x80efe,0x80f0a}]
    assert len(system)==8 and all(site.mnemonic=='ldr' and site.direction=='read' and site.function_id=='f80eac' for site in system)
    assert len(text)<=18000
    for ref in refs:
        assert hashlib.sha256(Path(ref.path).read_bytes()).hexdigest()==ref.sha256
    metrics=dict(mmio_seeds=len(mmio),vector_seeds=len(handlers),overlap=sorted(mmio&handlers),
        seed_union=len(seeds),neighbors=len(expected_neighbors),functions=len(first.functions),
        confirmed_calls=len(first.direct_call_edges),unresolved_calls=len(first.unresolved_call_sites),
        mmio_sites=len(first.mmio_sites),vector_groups=len(first.vector_handler_groups),vector_indices=len(dispatch),
        evidence=len(first.evidence_catalog),characters=len(text),sha256=relevant_structure_sha256(first),
        a1_characters=len(a1_text),a1_sha256=firmware_projection_sha256(a1),
        combined_characters=len(a1_text)+len(text),headroom=64000-len(a1_text)-len(text),
        seed_neighborhoods=[n.model_dump() for n in first.seed_neighborhoods],
        byte_identical=True,exact_evidence_roundtrip=True,canonical_inputs_unchanged=True)
    audit=tmp_path/'audit';audit.mkdir()
    (audit/'relevant_static_structure.json').write_text(text,encoding='utf-8')
    (audit/'metrics.json').write_text(json.dumps(metrics,indent=2,sort_keys=True),encoding='utf-8')
    print(json.dumps({'audit_directory':str(audit),**{k:value for k,value in metrics.items() if k!='seed_neighborhoods'}},sort_keys=True))
