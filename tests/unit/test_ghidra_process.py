"""Fake backend boundary plus isolated stdlib children for process limits (no Ghidra)."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

from chipchain.tools.firmware.ghidra import process
from tests.ghidra_fakes import exported

_POPEN = subprocess.Popen


def home(root):
    files={'support/analyzeHeadless':'#!/bin/sh\n', 'Ghidra/application.properties':'application.version=test\n',
           'Ghidra/Processors/ARM/data/languages/ARM.ldefs':'<language id="ARM:LE:32:Cortex"/>'}
    for name,content in files.items():
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(content)
    (root/'support/analyzeHeadless').chmod(0o700)
    return root


@pytest.mark.parametrize('failure',[False,True])
def test_explicit_elf_only_env_bounds_and_project_cleanup(tmp_path,monkeypatch,failure):
    elf,_=exported();source=tmp_path/'corpus/image.elf';source.parent.mkdir();source.write_bytes(elf)
    for name in ('config.yml','crashing_input','README','bug-details','run.sh'):
        (source.parent/name).write_text('MUST NOT READ')
    monkeypatch.setattr(process,'ELF_SIZE',len(elf))
    import hashlib
    monkeypatch.setattr(process,'ELF_SHA256',hashlib.sha256(elf).hexdigest())
    script=tmp_path/'ExportFirmwareStructure.java';script.write_text('synthetic script')
    selected=home(tmp_path/'ghidra');temporary=tmp_path/'temporary';temporary.mkdir()
    monkeypatch.setenv('JAVA_TOOL_OPTIONS','SECRET_DEBUG_SETTING')
    monkeypatch.setenv('JDK_JAVA_OPTIONS','SECRET_SETTING')
    real_open=Path.open
    def guarded_open(path,*args,**kwargs):
        assert path.parent!=source.parent or path==source
        return real_open(path,*args,**kwargs)
    monkeypatch.setattr(Path,'open',guarded_open)
    def backend(argv,*,cwd,environment,timeout):
        assert isinstance(argv,list) and argv[0]==str(selected/'support/analyzeHeadless')
        assert set(environment)=={'PATH','LANG','LC_ALL','JAVA_TOOL_OPTIONS'}
        assert 'SECRET' not in str(environment) and str(source.parent) not in str(argv)
        isolated=Path(argv[argv.index('-import')+1])
        assert isolated.read_bytes()==elf and isolated.parent==cwd
        assert not isolated.stat().st_mode & 0o222
        assert '-deleteProject' in argv
        (cwd/'projects/structure.gpr').write_text('fake project')
        (cwd/'projects/structure.rep').mkdir()
        if failure:raise process.GhidraError('Headless process failed')
        Path(argv[argv.index('-postScript')+2]).write_bytes(b'{}')
    monkeypatch.setattr(process,'bounded_process',backend)
    if failure:
        with pytest.raises(process.GhidraError):process.export_heat_press(source,ghidra_home=selected,script_path=script,temporary_parent=temporary)
    else:
        raw,version,sha=process.export_heat_press(source,ghidra_home=selected,script_path=script,temporary_parent=temporary)
        assert raw==b'{}' and version=='test' and len(sha)==64
    assert not list(temporary.iterdir()) and source.read_bytes()==elf


def test_invalid_explicit_installation_fails(tmp_path):
    with pytest.raises(process.GhidraError,match='Invalid explicitly'):process.installation(tmp_path)


def test_wrong_elf_fingerprint_fails_before_process(tmp_path):
    elf=tmp_path/'same-name.elf';elf.write_bytes(b'wrong ELF')
    with pytest.raises(ValueError):
        process.export_heat_press(elf,ghidra_home=home(tmp_path/'ghidra'),script_path=tmp_path/'unused.java')


@pytest.mark.parametrize('code,kwargs,expected',[
    ('import time; time.sleep(30)',{'timeout':0.1},'timeout'),
    ('import sys; print("SECRET"); sys.exit(3)',{},'process failed'),
    ('print("SECRET"*10000)',{'log_limit':64},'diagnostic size exceeded'),
    ('import os,time; os.close(1);os.close(2);time.sleep(30)',{'timeout':0.1},'timeout'),
])
def test_process_limits_sanitized_and_reaped(tmp_path,monkeypatch,code,kwargs,expected):
    children=[]
    def isolated_child(argv,**settings):
        assert argv[:2]==[sys.executable,'-c'] and settings['shell'] is False
        assert settings['start_new_session'] is True
        child=_POPEN(argv,**settings);children.append(child);return child
    monkeypatch.setattr(subprocess,'Popen',isolated_child)
    with pytest.raises(process.GhidraError,match=expected) as error:
        process.bounded_process([sys.executable,'-c',code],cwd=tmp_path,environment={'PATH':'/usr/bin:/bin'},**kwargs)
    assert 'SECRET' not in str(error.value)
    assert all(child.poll() is not None for child in children)


def test_process_success_and_launch_failure(tmp_path,monkeypatch):
    def stdlib_only(argv,**kw):
        assert argv==[sys.executable,'-c','pass']
        return _POPEN(argv,**kw)
    monkeypatch.setattr(subprocess,'Popen',stdlib_only)
    process.bounded_process([sys.executable,'-c','pass'],cwd=tmp_path,environment={})
    def failed(*a,**kw):raise OSError('SECRET path')
    monkeypatch.setattr(subprocess,'Popen',failed)
    with pytest.raises(process.GhidraError,match='Cannot start headless') as error:
        process.bounded_process(['fake'],cwd=tmp_path,environment={})
    assert 'SECRET' not in str(error.value)
