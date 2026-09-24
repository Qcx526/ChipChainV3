"""Small local-distribution tests for the customer Ghidra setup script."""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

import pytest


SOURCE_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "setup_ghidra.sh"
REVISION = "d6192cb3f900f74152a4eeec1aa6758b6143b093"
LOCAL_POPEN = subprocess.Popen  # Captured before the suite's subprocess guard is installed.


@pytest.fixture
def setup_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / "tools" / "ghidra").mkdir(parents=True)
    shutil.copy2(SOURCE_SCRIPT, repo / "scripts" / "setup_ghidra.sh")
    (repo / "tools" / "ghidra" / "VERSION").write_text(
        f"Ghidra 12.3 DEV\nupstream_revision={REVISION}\nminimum_java=25\n"
    )
    (repo / "tools" / "ghidra" / "SOURCE").write_text(
        "Local bundle SHA256: " + "0" * 64 + "\n"
    )
    (repo / "tools" / "ghidra" / "SHA256SUMS").write_text(
        "0" * 64 + "  absent-fixture-file\n"
    )
    return repo


def fake_java(tmp_path: Path, version: str = "25.0.4") -> str:
    binary_dir = tmp_path / "fake-bin"
    binary_dir.mkdir(exist_ok=True)
    java = binary_dir / "java"
    specification = version.split(".")[0]
    java.write_text(
        "#!/bin/sh\n"
        f"printf '    java.specification.version = {specification}\\n"
        f"    java.version = {version}\\n' >&2\n"
    )
    java.chmod(0o755)
    return f"{binary_dir}:{os.environ['PATH']}"


def run_script(repo: Path, *args: str, cwd: Path | None = None, path: str | None = None) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    if path is not None:
        environment["PATH"] = path
    command = ["/usr/bin/bash", str(repo / "scripts" / "setup_ghidra.sh"), *args]
    with LOCAL_POPEN(
        command, cwd=cwd or repo, env=environment, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) as process:
        stdout, stderr = process.communicate()
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def make_install(repo: Path, root: Path, *, revision: str = REVISION) -> None:
    (root / "support").mkdir(parents=True)
    (root / "Ghidra").mkdir()
    (root / "support" / "analyzeHeadless").write_text("#!/bin/sh\n")
    (root / "Ghidra" / "application.properties").write_text(
        f"application.version=12.3\napplication.release.name=DEV\n"
        f"application.revision.ghidra={revision}\n"
    )
    checksums = []
    for relative in ("Ghidra/application.properties", "support/analyzeHeadless"):
        data = (root / relative).read_bytes()
        checksums.append(f"{hashlib.sha256(data).hexdigest()}  {relative}\n")
    (repo / "tools" / "ghidra" / "SHA256SUMS").write_text("".join(checksums))


def make_archive(path: Path, source: Path, *, prefix: str = "custom/ghidra") -> None:
    with tarfile.open(path, "w:gz") as archive:
        archive.add(source, arcname=prefix)


def test_help_succeeds_without_metadata_or_java(setup_repo: Path, tmp_path: Path) -> None:
    binary_dir = tmp_path / "help-bin"
    binary_dir.mkdir()
    for name in ("dirname", "cat"):
        (binary_dir / name).symlink_to(shutil.which(name))
    result = run_script(setup_repo, "--help", cwd=tmp_path, path=str(binary_dir))
    assert result.returncode == 0
    assert "--verify-only" in result.stdout


def test_missing_install_fails_with_local_archive_instruction(setup_repo: Path, tmp_path: Path) -> None:
    result = run_script(setup_repo, "--verify-only", cwd=tmp_path, path=fake_java(tmp_path))
    assert result.returncode != 0
    assert "Ghidra is not installed" in result.stderr
    assert "--archive /path/to/archive.tar.gz" in result.stderr
    assert not (setup_repo / "tools" / "ghidra" / "install").exists()


def test_missing_archive_fails_without_creating_install(setup_repo: Path, tmp_path: Path) -> None:
    result = run_script(setup_repo, path=fake_java(tmp_path))
    assert result.returncode != 0
    assert "local archive is missing" in result.stderr
    assert "--archive /path/to/archive.tar.gz" in result.stderr
    assert not (setup_repo / "tools" / "ghidra" / "install").exists()


def test_missing_java_does_not_touch_install(setup_repo: Path, tmp_path: Path) -> None:
    binary_dir = tmp_path / "only-dirname"
    binary_dir.mkdir()
    (binary_dir / "dirname").symlink_to(shutil.which("dirname"))
    result = run_script(setup_repo, "--verify-only", path=str(binary_dir))
    assert result.returncode != 0
    assert "Java: unavailable" in result.stderr
    assert "required" not in result.stderr or ">=25" in result.stdout
    assert not (setup_repo / "tools" / "ghidra" / "install").exists()


def test_old_java_does_not_touch_install(setup_repo: Path, tmp_path: Path) -> None:
    install = setup_repo / "tools" / "ghidra" / "install"
    install.mkdir()
    marker = install / "keep"
    marker.write_text("untouched")
    result = run_script(setup_repo, "--verify-only", path=fake_java(tmp_path, "17.0.2"))
    assert result.returncode != 0
    assert "Java 17 is too old" in result.stderr
    assert "required >=25" in result.stderr
    assert marker.read_text() == "untouched"


def test_unsafe_archive_entry_is_rejected(setup_repo: Path, tmp_path: Path) -> None:
    archive_path = tmp_path / "unsafe.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        content = b"escape"
        entry = tarfile.TarInfo("../escape")
        entry.size = len(content)
        archive.addfile(entry, io.BytesIO(content))
    result = run_script(setup_repo, "--archive", str(archive_path), path=fake_java(tmp_path))
    assert result.returncode != 0
    assert "unsafe archive entry" in result.stderr
    assert not (setup_repo / "tools" / "ghidra" / "install").exists()
    assert not list((setup_repo / "tools" / "ghidra").glob(".chipchain-ghidra-stage.*"))
    assert not (tmp_path / "escape").exists()


def test_wrong_revision_rejected_before_checksums(setup_repo: Path, tmp_path: Path) -> None:
    install = setup_repo / "tools" / "ghidra" / "install"
    make_install(setup_repo, install, revision="f" * 40)
    result = run_script(setup_repo, "--verify-only", path=fake_java(tmp_path))
    assert result.returncode != 0
    assert "Ghidra version/revision mismatch" in result.stderr
    assert (install / "Ghidra" / "application.properties").exists()


def test_changed_installed_file_fails_checksum(setup_repo: Path, tmp_path: Path) -> None:
    install = setup_repo / "tools" / "ghidra" / "install"
    make_install(setup_repo, install)
    (install / "support" / "analyzeHeadless").write_text("changed\n")
    result = run_script(setup_repo, "--verify-only", path=fake_java(tmp_path))
    assert result.returncode != 0
    assert "Installed-file checksum verification failed" in result.stderr
    assert "Existing installation is invalid" in result.stderr


def test_failed_install_does_not_destroy_existing_directory(setup_repo: Path, tmp_path: Path) -> None:
    install = setup_repo / "tools" / "ghidra" / "install"
    install.mkdir()
    marker = install / "customer-file"
    marker.write_text("preserve")
    archive_path = tmp_path / "bad.tar.gz"
    archive_path.write_bytes(b"not an archive")
    result = run_script(setup_repo, "--archive", str(archive_path), path=fake_java(tmp_path))
    assert result.returncode != 0
    assert "Existing installation is invalid; it was left untouched" in result.stderr
    assert marker.read_text() == "preserve"


def test_install_verify_idempotent_and_cwd_independent(setup_repo: Path, tmp_path: Path) -> None:
    source = tmp_path / "source"
    make_install(setup_repo, source)
    archive_path = tmp_path / "archive.tar.gz"
    make_archive(archive_path, source, prefix="another-name/nested")
    environment_path = fake_java(tmp_path)
    install_result = run_script(setup_repo, "--archive", str(archive_path), cwd=tmp_path, path=environment_path)
    assert install_result.returncode == 0, install_result.stderr
    assert "Verifying 2 files" in install_result.stdout
    installed = setup_repo / "tools" / "ghidra" / "install"
    original_mtime = (installed / "Ghidra" / "application.properties").stat().st_mtime_ns
    verify_result = run_script(setup_repo, "--verify-only", cwd=Path("/"), path=environment_path)
    assert verify_result.returncode == 0, verify_result.stderr
    assert "Ghidra setup PASS" in verify_result.stdout
    repeat_result = run_script(setup_repo, "--archive", str(archive_path), cwd=tmp_path, path=environment_path)
    assert repeat_result.returncode == 0, repeat_result.stderr
    assert "already installed" in repeat_result.stdout
    assert (installed / "Ghidra" / "application.properties").stat().st_mtime_ns == original_mtime
