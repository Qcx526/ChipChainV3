"""Controlled subprocess tests for the customer Python environment setup."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess

import pytest


SOURCE_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "setup_env.sh"
LOCAL_POPEN = subprocess.Popen  # Capture before the suite-wide external-tool guard.


@pytest.fixture
def setup_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    shutil.copy2(SOURCE_SCRIPT, repo / "scripts" / "setup_env.sh")
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "chipchain"\nrequires-python = ">=3.11"\n'
    )
    return repo


def run_script(
    repo: Path, *args: str, cwd: Path | None = None, path: str | None = None
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if path is not None:
        env["PATH"] = path
    command = ["/usr/bin/bash", str(repo / "scripts" / "setup_env.sh"), *args]
    with LOCAL_POPEN(
        command, cwd=cwd or repo, env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) as process:
        stdout, stderr = process.communicate()
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def fake_python(
    path: Path,
    version: str,
    *,
    prefix: Path | None = None,
    log: Path | None = None,
    venv_template: Path | None = None,
    venv_supported: bool = True,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    effective_prefix = str(prefix or Path("/usr"))
    logfile = str(log or path.parent / "calls.log")
    template = str(venv_template or path)
    script = f"""#!/bin/sh
printf '%s|%s\\n' "$0" "$*" >> {shlex.quote(logfile)}
if [ "$1" = '-B' ] && [ "$2" = '-c' ]; then
  case "$3" in
    *sys.version_info*)
      printf '%s\\n' {shlex.quote(f'{version}|{path}|{effective_prefix}|/usr')}
      exit 0 ;;
    *'import venv'*) exit {0 if venv_supported else 1} ;;
    *'import chipchain'*) exit 0 ;;
  esac
fi
if [ "$1" = '-m' ] && [ "$2" = 'venv' ]; then
  mkdir -p "$3/bin"
  cp {shlex.quote(template)} "$3/bin/python"
  : > "$3/bin/activate"
  : > "$3/pyvenv.cfg"
  exit 0
fi
if [ "$1" = '-m' ] && [ "$2" = 'pip' ]; then exit 0; fi
if [ "$1" = '-B' ] && [ "$2" = '-m' ] && [ "$3" = 'chipchain.cli' ]; then exit 0; fi
exit 22
"""
    path.write_text(script)
    path.chmod(0o755)
    return path


def fake_venv(repo: Path, *, version: str = "3.12.13", directory: Path | None = None) -> Path:
    root = directory or repo / ".venv"
    (root / "bin").mkdir(parents=True)
    (root / "pyvenv.cfg").write_text("home = /usr\n")
    (root / "bin" / "activate").write_text("# synthetic\n")
    fake_python(root / "bin" / "python", version, prefix=root, log=root.parent / "venv-calls.log")
    return root


def fake_candidate(repo: Path, tmp_path: Path, version: str, *, venv_supported: bool = True) -> Path:
    template = tmp_path / "venv-template-python"
    fake_python(template, version, prefix=repo / ".venv")
    return fake_python(
        tmp_path / f"candidate-{version}", version,
        venv_template=template, venv_supported=venv_supported,
    )


def test_help_succeeds(setup_repo: Path) -> None:
    result = run_script(setup_repo, "--help")
    assert result.returncode == 0
    assert "--verify-only" in result.stdout


def test_python_310_rejected_without_creating_venv(setup_repo: Path, tmp_path: Path) -> None:
    candidate = fake_candidate(setup_repo, tmp_path, "3.10.12")
    result = run_script(setup_repo, "--python", str(candidate))
    assert result.returncode != 0
    assert "Required Python: >=3.11" in result.stdout
    assert "3.10.12 (too old)" in result.stderr
    assert not (setup_repo / ".venv").exists()


def test_compatible_python_creates_environment_and_uses_venv_pip(setup_repo: Path, tmp_path: Path) -> None:
    candidate = fake_candidate(setup_repo, tmp_path, "3.11.9")
    result = run_script(setup_repo, "--python", str(candidate), cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "Selected Python: 3.11.9" in result.stdout
    assert "Environment setup PASS" in result.stdout
    calls = (setup_repo / ".venv" / "bin" / "calls.log")
    # The template logs next to itself, so inspect the candidate and template logs.
    logs = "".join(p.read_text() for p in tmp_path.glob("*.log"))
    assert "-m pip install --upgrade pip" in logs
    assert f"-m pip install -e {setup_repo}" in logs
    assert not calls.exists()


def test_discovery_prefers_compatible_interpreter_over_python3_310(setup_repo: Path, tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    template = tmp_path / "venv-template-python"
    fake_python(template, "3.11.9", prefix=setup_repo / ".venv")
    for name in ("python3.15", "python3.14", "python3.13", "python3.12", "python3"):
        fake_python(bin_dir / name, "3.10.12")
    fake_python(bin_dir / "python3.11", "3.11.9", venv_template=template)
    result = run_script(setup_repo, path=f"{bin_dir}:{os.environ['PATH']}")
    assert result.returncode == 0, result.stderr
    assert "Selected Python: 3.11.9" in result.stdout


def test_incompatible_existing_venv_preserved_without_recreate(setup_repo: Path) -> None:
    root = fake_venv(setup_repo, version="3.10.12")
    marker = root / "customer-file"
    marker.write_text("preserve")
    result = run_script(setup_repo)
    assert result.returncode != 0
    assert "Existing environment uses Python 3.10.12" in result.stderr
    assert "--recreate" in result.stderr
    assert marker.read_text() == "preserve"


def test_recreate_checks_replacement_before_deletion(setup_repo: Path, tmp_path: Path) -> None:
    root = fake_venv(setup_repo, version="3.10.12")
    marker = root / "customer-file"
    marker.write_text("preserve")
    candidate = fake_candidate(setup_repo, tmp_path, "3.10.12")
    result = run_script(setup_repo, "--recreate", "--python", str(candidate))
    assert result.returncode != 0
    assert marker.read_text() == "preserve"


def test_recreate_with_compatible_python_replaces_only_venv(setup_repo: Path, tmp_path: Path) -> None:
    root = fake_venv(setup_repo, version="3.10.12")
    marker = root / "customer-file"
    marker.write_text("replace")
    outside = setup_repo / "unrelated"
    outside.write_text("preserve")
    candidate = fake_candidate(setup_repo, tmp_path, "3.11.9")
    result = run_script(setup_repo, "--recreate", "--python", str(candidate))
    assert result.returncode == 0, result.stderr
    assert "Replacing incompatible environment" in result.stdout
    assert not marker.exists()
    assert outside.read_text() == "preserve"


def test_compatible_existing_venv_reused(setup_repo: Path) -> None:
    root = fake_venv(setup_repo)
    marker = root / "customer-file"
    marker.write_text("preserve")
    result = run_script(setup_repo)
    assert result.returncode == 0, result.stderr
    assert "Reusing compatible environment" in result.stdout
    assert marker.read_text() == "preserve"
    assert "-m venv" not in (root.parent / "venv-calls.log").read_text()


def test_verify_only_does_not_run_pip_or_change_venv_files(setup_repo: Path) -> None:
    root = fake_venv(setup_repo)
    before = {p: p.stat().st_mtime_ns for p in root.rglob("*") if p.is_file()}
    result = run_script(setup_repo, "--verify-only")
    assert result.returncode == 0, result.stderr
    after = {p: p.stat().st_mtime_ns for p in root.rglob("*") if p.is_file()}
    assert before == after
    calls = (root.parent / "venv-calls.log").read_text()
    assert "-m pip" not in calls
    assert "-m venv" not in calls


def test_missing_venv_module_fails_cleanly(setup_repo: Path, tmp_path: Path) -> None:
    candidate = fake_candidate(setup_repo, tmp_path, "3.11.9", venv_supported=False)
    result = run_script(setup_repo, "--python", str(candidate))
    assert result.returncode != 0
    assert "venv module is unavailable" in result.stderr
    assert not (setup_repo / ".venv").exists()


def test_relative_venv_dir_resolves_from_repo(setup_repo: Path, tmp_path: Path) -> None:
    target = setup_repo / "custom" / "env"
    template = tmp_path / "venv-template-python"
    fake_python(template, "3.11.9", prefix=target)
    candidate = fake_python(tmp_path / "candidate", "3.11.9", venv_template=template)
    result = run_script(setup_repo, "--python", str(candidate), "--venv-dir", "custom/env", cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert target.is_dir()
    assert not (tmp_path / "custom").exists()


@pytest.mark.parametrize("unsafe", ["/", ".", "data"])
def test_unsafe_recreate_targets_preserved(setup_repo: Path, tmp_path: Path, unsafe: str) -> None:
    data = setup_repo / "data"
    data.mkdir()
    marker = data / "important"
    marker.write_text("keep")
    candidate = fake_candidate(setup_repo, tmp_path, "3.11.9")
    result = run_script(setup_repo, "--venv-dir", unsafe, "--recreate", "--python", str(candidate))
    assert result.returncode != 0
    assert marker.read_text() == "keep"


def test_with_test_uses_venv_pip_and_quoted_editable_extra(setup_repo: Path, tmp_path: Path) -> None:
    root = fake_venv(setup_repo)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    global_pip_marker = tmp_path / "global-pip-called"
    global_pip = fake_bin / "pip"
    global_pip.write_text(f"#!/bin/sh\n: > {shlex.quote(str(global_pip_marker))}\n")
    global_pip.chmod(0o755)
    result = run_script(setup_repo, "--with-test", path=f"{fake_bin}:{os.environ['PATH']}")
    assert result.returncode == 0, result.stderr
    assert f"-m pip install -e {setup_repo}[test]" in (root.parent / "venv-calls.log").read_text()
    assert not global_pip_marker.exists()


def test_unsupported_python_requirement_fails_closed(setup_repo: Path) -> None:
    (setup_repo / "pyproject.toml").write_text(
        '[project]\nname = "chipchain"\nrequires-python = ">=3.11,<4"\n'
    )
    result = run_script(setup_repo)
    assert result.returncode != 0
    assert "Unsupported requires-python expression" in result.stderr
    assert not (setup_repo / ".venv").exists()
