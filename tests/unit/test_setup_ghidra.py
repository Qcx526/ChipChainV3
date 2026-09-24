"""Small local-distribution tests for the customer Ghidra setup script."""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile

import pytest


SOURCE_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "setup_ghidra.sh"
REVISION = "d6192cb3f900f74152a4eeec1aa6758b6143b093"
RELEASE_URL = (
    "https://github.com/Qcx526/ChipChainV3/releases/download/"
    "v3-ghidra-setup-stable/ghidra_12.3_DEV-local.tar.gz"
)
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
        f"chipchain_release_asset_url={RELEASE_URL}\n"
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


def pin_bundle_sha(repo: Path, archive: Path) -> None:
    source_file = repo / "tools" / "ghidra" / "SOURCE"
    source_file.write_text(
        source_file.read_text().replace("0" * 64, hashlib.sha256(archive.read_bytes()).hexdigest())
    )


def fake_downloader(tmp_path: Path, name: str, archive: Path, *, fail: bool = False) -> Path:
    binary_dir = tmp_path / "fake-bin"
    binary_dir.mkdir(exist_ok=True)
    marker = tmp_path / f"{name}-calls.log"
    downloader = binary_dir / name
    action = (
        'printf "partial" > "$destination"\nexit 7'
        if fail else f"cp {shlex.quote(str(archive))} \"$destination\""
    )
    downloader.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(marker))}\n"
        "destination=''\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  case \"$1\" in\n"
        "    --output) shift; destination=$1 ;;\n"
        "    --output-document=*) destination=${1#*=} ;;\n"
        "  esac\n"
        "  shift\n"
        "done\n"
        f"{action}\n"
    )
    downloader.chmod(0o755)
    return marker


def controlled_path(tmp_path: Path) -> str:
    binary_dir = tmp_path / "fake-bin"
    binary_dir.mkdir(exist_ok=True)
    for name in ("dirname", "wc", "sha256sum", "mktemp", "mv", "find", "python3",
                 "rm", "mkdir", "cp", "cat"):
        target = binary_dir / name
        if not target.exists():
            target.symlink_to(shutil.which(name))
    fake_java(tmp_path)
    return str(binary_dir)


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
    result = run_script(setup_repo, "--offline", path=fake_java(tmp_path))
    assert result.returncode != 0
    assert "Offline mode forbids download" in result.stderr
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


def test_valid_existing_install_never_downloads(setup_repo: Path, tmp_path: Path) -> None:
    make_install(setup_repo, setup_repo / "tools" / "ghidra" / "install")
    marker = fake_downloader(tmp_path, "curl", tmp_path / "unused.tar.gz")
    result = run_script(setup_repo, path=fake_java(tmp_path))
    assert result.returncode == 0, result.stderr
    assert "already installed" in result.stdout
    assert not marker.exists()


def test_verify_only_never_downloads(setup_repo: Path, tmp_path: Path) -> None:
    marker = fake_downloader(tmp_path, "curl", tmp_path / "unused.tar.gz")
    result = run_script(setup_repo, "--verify-only", path=fake_java(tmp_path))
    assert result.returncode != 0
    assert "Ghidra is not installed" in result.stderr
    assert not marker.exists()


def test_explicit_archive_never_downloads(setup_repo: Path, tmp_path: Path) -> None:
    source = tmp_path / "source"
    make_install(setup_repo, source)
    archive = tmp_path / "external.tar.gz"
    make_archive(archive, source)
    marker = fake_downloader(tmp_path, "curl", tmp_path / "unused.tar.gz")
    result = run_script(setup_repo, "--archive", str(archive), path=fake_java(tmp_path))
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


def test_cached_canonical_archive_prevents_download(setup_repo: Path, tmp_path: Path) -> None:
    source = tmp_path / "source"
    make_install(setup_repo, source)
    cache = setup_repo / "tools" / "ghidra" / "ghidra_12.3_DEV-local.tar.gz"
    make_archive(cache, source)
    pin_bundle_sha(setup_repo, cache)
    marker = fake_downloader(tmp_path, "curl", tmp_path / "unused.tar.gz")
    result = run_script(setup_repo, path=fake_java(tmp_path))
    assert result.returncode == 0, result.stderr
    assert "Archive SHA256 PASS" in result.stdout
    assert not marker.exists()


def test_default_download_uses_curl_and_caches_only_verified_archive(setup_repo: Path, tmp_path: Path) -> None:
    source = tmp_path / "source"
    make_install(setup_repo, source)
    archive = tmp_path / "download-source.tar.gz"
    make_archive(archive, source)
    pin_bundle_sha(setup_repo, archive)
    marker = fake_downloader(tmp_path, "curl", archive)
    path = fake_java(tmp_path)
    first = run_script(setup_repo, cwd=Path("/"), path=path)
    assert first.returncode == 0, first.stderr
    assert "Downloading pinned Ghidra 12.3 DEV" in first.stdout
    assert "Archive SHA256 PASS" in first.stdout
    assert RELEASE_URL in marker.read_text()
    cache = setup_repo / "tools" / "ghidra" / "ghidra_12.3_DEV-local.tar.gz"
    assert cache.read_bytes() == archive.read_bytes()
    assert not list(cache.parent.glob(".chipchain-download.*"))
    second = run_script(setup_repo, path=path)
    assert second.returncode == 0, second.stderr
    assert "already installed" in second.stdout
    assert len(marker.read_text().splitlines()) == 1


def test_wget_fallback_when_curl_absent(setup_repo: Path, tmp_path: Path) -> None:
    source = tmp_path / "source"
    make_install(setup_repo, source)
    archive = tmp_path / "download-source.tar.gz"
    make_archive(archive, source)
    pin_bundle_sha(setup_repo, archive)
    marker = fake_downloader(tmp_path, "wget", archive)
    result = run_script(setup_repo, path=controlled_path(tmp_path))
    assert result.returncode == 0, result.stderr
    assert RELEASE_URL in marker.read_text()


def test_no_downloader_fails_clearly(setup_repo: Path, tmp_path: Path) -> None:
    result = run_script(setup_repo, path=controlled_path(tmp_path))
    assert result.returncode != 0
    assert "Neither curl nor wget is available" in result.stderr
    assert "--archive" in result.stderr


def test_offline_never_downloads(setup_repo: Path, tmp_path: Path) -> None:
    marker = fake_downloader(tmp_path, "curl", tmp_path / "unused.tar.gz")
    result = run_script(setup_repo, "--offline", path=fake_java(tmp_path))
    assert result.returncode != 0
    assert "Offline mode forbids download" in result.stderr
    assert not marker.exists()


def test_failed_download_cleans_temporary_file(setup_repo: Path, tmp_path: Path) -> None:
    marker = fake_downloader(tmp_path, "curl", tmp_path / "unused.tar.gz", fail=True)
    result = run_script(setup_repo, path=fake_java(tmp_path))
    assert result.returncode != 0
    assert marker.exists()
    metadata = setup_repo / "tools" / "ghidra"
    assert not list(metadata.glob(".chipchain-download.*"))
    assert not (metadata / "ghidra_12.3_DEV-local.tar.gz").exists()
    assert not (metadata / "install").exists()


def test_wrong_downloaded_sha_rejected_before_cache_or_extraction(setup_repo: Path, tmp_path: Path) -> None:
    bad_archive = tmp_path / "bad.tar.gz"
    bad_archive.write_bytes(b"wrong checksum and not an archive")
    marker = fake_downloader(tmp_path, "curl", bad_archive)
    result = run_script(setup_repo, path=fake_java(tmp_path))
    assert result.returncode != 0
    assert marker.exists()
    assert "Archive SHA256 mismatch" in result.stderr
    metadata = setup_repo / "tools" / "ghidra"
    assert not list(metadata.glob(".chipchain-download.*"))
    assert not list(metadata.glob(".chipchain-ghidra-stage.*"))
    assert not (metadata / "ghidra_12.3_DEV-local.tar.gz").exists()


def test_explicit_canonical_name_requires_pinned_sha(setup_repo: Path, tmp_path: Path) -> None:
    archive = tmp_path / "ghidra_12.3_DEV-local.tar.gz"
    archive.write_bytes(b"wrong checksum")
    result = run_script(setup_repo, "--archive", str(archive), path=fake_java(tmp_path))
    assert result.returncode != 0
    assert "Archive SHA256 mismatch" in result.stderr
    assert not (setup_repo / "tools" / "ghidra" / "install").exists()
