"""Opt-in fresh Ghidra + two independent CFGFast workers; zero network/model calls."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import json
import pytest
from chipchain.integrations.angr_static_reachability import prepare_a5,run_a5,summary
from chipchain.tools.firmware.static_reachability import (
    serialize_firmware_angr_cfg,serialize_firmware_static_reachability,parse_firmware_static_reachability,
)
_POPEN=subprocess.Popen


def test_real_angr_static_reachability(tmp_path,monkeypatch):
    root=os.environ.get('CHIPCHAIN_FUZZWARE_ROOT');ghidra=os.environ.get('CHIPCHAIN_GHIDRA_HOME')
    if not root or not ghidra:pytest.skip('Set explicit corpus and Ghidra paths for A5 real integration')
    if importlib.util.find_spec('angr') is None:pytest.skip('Install optional angr extra on Python >=3.12')
    def allowed(argv,**kwargs):
        assert kwargs.get('shell',False) is False
        assert argv[0]==str((Path(ghidra)/'support/analyzeHeadless').resolve()) or argv[:3]==[sys.executable,'-m','chipchain.tools.firmware.angr_cfg']
        return _POPEN(argv,**kwargs)
    monkeypatch.setattr(subprocess,'Popen',allowed)
    data=prepare_a5(root,ghidra);before=[x.model_dump_json() for x in data]
    cfg,r=run_a5(*data);cfg2,r2=run_a5(*data)
    assert serialize_firmware_angr_cfg(cfg)==serialize_firmware_angr_cfg(cfg2)
    assert serialize_firmware_static_reachability(r)==serialize_firmware_static_reachability(r2)
    assert [x.model_dump_json() for x in data]==before
    assert len(cfg.function_bindings)==34 and len(cfg.transfer_comparisons)==34
    assert len(r.function_reachability)==1122 and len(r.site_reachability)==57
    assert len([s for s in r.site_reachability if s.site_kind=='mmio'])==23
    for pc in (0x80d4e,0x80d50,0x80d5a):
        site=next(s for s in r.site_reachability if s.site_address==pc)
        assert site.status=='owner_mapping_missing'
    assert parse_firmware_static_reachability(serialize_firmware_static_reachability(r),cfg=cfg)==r
    (tmp_path/'firmware_angr_cfg.json').write_text(serialize_firmware_angr_cfg(cfg))
    (tmp_path/'firmware_static_reachability.json').write_text(serialize_firmware_static_reachability(r))
    print(json.dumps(summary(cfg,r),sort_keys=True))
    print('A5_TEST_ARTIFACT_DIRECTORY',str(tmp_path))
