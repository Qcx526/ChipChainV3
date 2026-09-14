"""Bounded headless process boundary; explicit installation, isolated temporary project."""

import hashlib
import os
from pathlib import Path
import selectors
import signal
import subprocess
import tempfile
import time

ELF_SIZE = 261365
ELF_SHA256 = '73f667524ed0ff8f24b460d4678b74f15eec13d954b93cdc92c839c2c3f1044e'
LANGUAGE = 'ARM:LE:32:Cortex'
COMPILER = 'default'
MAX_EXPORT = 16 * 1024 * 1024


class GhidraError(ValueError):
    """Fixed diagnostics only; no raw backend log or program content."""


def installation(home: Path) -> tuple[Path, str]:
    headless = home / 'support/analyzeHeadless'
    properties = home / 'Ghidra/application.properties'
    languages = home / 'Ghidra/Processors/ARM/data/languages/ARM.ldefs'
    if not headless.is_file() or not os.access(headless, os.X_OK) or not properties.is_file() or not languages.is_file():
        raise GhidraError('Invalid explicitly selected Ghidra installation')
    version = next((line.split('=', 1)[1] for line in properties.read_text().splitlines()
                    if line.startswith('application.version=')), '')
    if not version or f'id="{LANGUAGE}"' not in languages.read_text():
        raise GhidraError('Selected Ghidra lacks version or Cortex language support')
    return headless.resolve(), version


def bounded_process(argv: list[str], *, cwd: Path, environment: dict[str, str],
                    timeout: float = 300, log_limit: int = 1024 * 1024) -> None:
    if not 0 < timeout <= 600 or not 0 < log_limit <= 4 * 1024 * 1024:
        raise GhidraError('Invalid process bounds')
    try:
        proc = subprocess.Popen(argv, shell=False, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    except OSError:
        raise GhidraError('Cannot start headless process') from None
    total = 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (proc.stdout, proc.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise GhidraError('Headless process timeout')
                for key, _ in selector.select(min(0.1, max(0, deadline-time.monotonic()))):
                    data = os.read(key.fileobj.fileno(), 8192)
                    total += len(data)
                    if total > log_limit:
                        raise GhidraError('Headless diagnostic size exceeded')
                    if not data:
                        selector.unregister(key.fileobj)
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise GhidraError('Headless process timeout')
            if proc.wait(timeout=remaining) != 0:
                raise GhidraError('Headless process failed')
    except subprocess.TimeoutExpired:
        raise GhidraError('Headless process timeout') from None
    finally:
        # Also reap descendants if the launcher exits before the Java process.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        proc.stdout.close()
        proc.stderr.close()


def export_heat_press(elf_path: Path, *, ghidra_home: Path, script_path: Path,
                      timeout: float = 300, temporary_parent: Path | None = None) -> tuple[bytes, str, str]:
    """Only reads the explicit ELF and trusted installation/script; no corpus discovery."""
    headless, version = installation(ghidra_home)
    from chipchain.domain.case import ArtifactRef
    from chipchain.tools.firmware.fuzzware.readers import read_artifact
    data = read_artifact(ArtifactRef(artifact_id='elf', artifact_type='firmware_binary', format='elf',
        path=str(elf_path), size_bytes=ELF_SIZE, sha256=ELF_SHA256), ELF_SIZE)
    script = script_path.read_bytes()
    script_hash = hashlib.sha256(script).hexdigest()
    with tempfile.TemporaryDirectory(prefix='chipchain-ghidra-', dir=temporary_parent) as folder:
        work = Path(folder)
        for name in ('scripts', 'home', 'cache', 'projects'):
            (work/name).mkdir()
        # Copy the one input into isolation: the backend never receives a corpus path.
        source = work/'image.elf'
        source.write_bytes(data)
        source.chmod(0o400)
        (work/'scripts/ExportFirmwareStructure.java').write_bytes(script)
        result = work/'ghidra_static_structure.json'
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
               'JAVA_TOOL_OPTIONS': f'"-Duser.home={work}/home" "-Djava.io.tmpdir={work}/cache" '
                                    f'"-Dapplication.cachedir={work}/cache" -Djava.awt.headless=true'}
        argv = [str(headless), str(work/'projects'), 'structure', '-import', str(source),
                '-processor', LANGUAGE, '-cspec', COMPILER, '-max-cpu', '1', '-analysisTimeoutPerFile', '240',
                '-scriptPath', str(work/'scripts'), '-preScript', 'ExportFirmwareStructure.java', 'configure',
                '-postScript', 'ExportFirmwareStructure.java', str(result), '-deleteProject',
                '-log', str(work/'headless.log'), '-scriptlog', str(work/'script.log')]
        bounded_process(argv, cwd=work, environment=env, timeout=timeout)
        if not result.is_file() or result.is_symlink() or result.stat().st_size > MAX_EXPORT:
            raise GhidraError('Missing or oversized structure export')
        with result.open('rb') as stream:
            output = stream.read(MAX_EXPORT + 1)
        if len(output) > MAX_EXPORT:
            raise GhidraError('Oversized structure export')
        if source.read_bytes() != data:
            raise GhidraError('Backend modified isolated ELF input')
    if read_artifact(ArtifactRef(artifact_id='elf', artifact_type='firmware_binary', format='elf',
            path=str(elf_path), size_bytes=ELF_SIZE, sha256=ELF_SHA256), ELF_SIZE) != data:
        raise GhidraError('Source ELF changed during analysis')
    return output, version, script_hash
