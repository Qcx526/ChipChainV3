"""Explicit local Ghidra/ELF test; no model, .env, download, or agent invocation."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from chipchain.domain.case import TargetDescriptor
from chipchain.tools.firmware.fuzzware import FuzzwareHeatPressScenarioAnalyzer
from chipchain.tools.firmware.ghidra.api import extract_heat_press_structure
from chipchain.tools.firmware.ghidra.associations import associate_mmio
from chipchain.tools.firmware.ghidra.models import semantic_json
from tests.firmware_fakes import reference
from tests.integration.test_fuzzware_local import ARTIFACTS

_POPEN = subprocess.Popen


def test_real_heat_press_structure_twice(tmp_path,monkeypatch):
    ghidra=os.environ.get('CHIPCHAIN_GHIDRA_HOME')
    corpus=os.environ.get('CHIPCHAIN_FUZZWARE_ROOT')
    if not ghidra or not corpus:
        pytest.skip('Set both CHIPCHAIN_GHIDRA_HOME and CHIPCHAIN_FUZZWARE_ROOT explicitly')
    corpus=Path(corpus);ghidra=Path(ghidra)
    artifacts=[]
    for relative,kind,fmt,size,sha in ARTIFACTS:
        ref=reference(corpus/relative,kind,fmt)
        assert (ref.size_bytes,ref.sha256)==(size,sha)
        artifacts.append(ref)
    target=TargetDescriptor(processor_id='sam3x',firmware_id='heat-press',architecture='arm',
                            word_size_bits=32,endianness='little',isa_variant='ARMv7-M Thumb')
    case_id='fuzzware:heat-press:scenario-13'
    baseline=FuzzwareHeatPressScenarioAnalyzer().analyze(case_id=case_id,target=target,artifacts=artifacts)
    before=baseline.model_dump_json()
    assert len(baseline.observations)==57
    assert sum(len(o.behaviors) for o in baseline.observations)==55
    assert not any(o.scope=='runtime' for o in baseline.observations)
    # Restore only this exact backend launcher. Python socket guards stay active.
    def explicit_headless(argv,**settings):
        assert argv[0]==str((ghidra/'support/analyzeHeadless').resolve())
        assert settings['shell'] is False and settings['cwd'].is_relative_to(tmp_path)
        assert str(corpus) not in str(argv)
        return _POPEN(argv,**settings)
    monkeypatch.setattr(subprocess,'Popen',explicit_headless)
    temporary=tmp_path/'projects';temporary.mkdir()
    script=Path(__file__).resolve().parents[2]/'scripts/ghidra/ExportFirmwareStructure.java'
    results=[]
    for _ in range(2):
        structure,vectors=extract_heat_press_structure(Path(artifacts[0].path),ghidra_home=ghidra,
            script_path=script,temporary_parent=temporary)
        assert not list(temporary.iterdir())
        results.append((structure,vectors))
    first,second=results
    assert semantic_json(first[0])==semantic_json(second[0])
    assert first[1].model_dump_json()==second[1].model_dump_json()
    structure,vectors=first
    associations=associate_mmio(structure,baseline)
    assert len(associations.sites)==23 and len(associations.bindings)==32
    assert Counter(s.containment for s in associations.sites)=={'unique':20,'missing':3}
    assert [s.pc for s in associations.sites if s.containment=='missing']==[0x80d4e,0x80d50,0x80d5a]
    assert all(s.entry_match for s in associations.sites if s.containment=='unique')
    assert len(associations.neighborhoods)==10
    system=[s for s in associations.sites if s.a1_name=='SystemInit']
    assert len(system)==8
    assert all(s.directions==['read'] and s.mnemonic=='ldr' for s in system)
    assert vectors.status=='bounded' and (vectors.extent.start,vectors.extent.end)==(0x80000,0x800f4)
    assert len(vectors.bindings)==61
    assert len(structure.functions)==183 and len(structure.direct_call_edges)==238
    assert len(structure.unresolved_call_sites)==68
    assert baseline.model_dump_json()==before
    for ref,(_,_,_,size,sha) in zip(artifacts,ARTIFACTS):
        actual=Path(ref.path).read_bytes()
        assert len(actual)==size and hashlib.sha256(actual).hexdigest()==sha
    # Explicit test artifacts remain within pytest's temporary audit directory.
    audit=tmp_path/'audit';audit.mkdir()
    for name,text in [('ghidra_static_structure.json',semantic_json(structure)),
                      ('cortex_m_vectors.json',vectors.model_dump_json(indent=2)),
                      ('mmio_function_associations.json',associations.model_dump_json(indent=2))]:
        (audit/name).write_text(text,encoding='utf-8')
    print(json.dumps(dict(audit_directory=str(audit),functions=len(structure.functions),
        direct_call_edges=len(structure.direct_call_edges),unresolved=Counter(c.reason for c in structure.unresolved_call_sites),
        sites=len(associations.sites),entry_matches=sum(s.entry_match is True for s in associations.sites),
        name_matches=sum(s.name_match is True for s in associations.sites),
        vectors=Counter(b.binding_status for b in vectors.bindings),
        semantic_sha256=hashlib.sha256(semantic_json(structure).encode()).hexdigest(),
        byte_identical=True,corpus_unchanged=True,temporary_projects_removed=True),sort_keys=True))
