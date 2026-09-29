"""Small fake-bundle tests for the project-managed QEMU installer."""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "setup_qemu.sh"
BUNDLE_NAME = "qemu_11.1.1-chipchain-linux-x86_64.tar.xz"
EXECUTABLES = (
    "qemu-system-arm", "qemu-system-aarch64", "qemu-system-riscv32",
    "qemu-system-riscv64", "qemu-system-ppc", "qemu-system-ppc64",
)
PLUGIN = "lib/qemu/plugins/libexeclog.so"
LOCAL_POPEN = subprocess.Popen


@pytest.fixture
def setup_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    metadata = repo / "tools" / "qemu"
    metadata.mkdir(parents=True)
    shutil.copy2(SCRIPT, repo / "scripts" / "setup_qemu.sh")
    (metadata / "VERSION").write_text(
        "QEMU 11.1.1\n"
        "supported_guest_families=arm,riscv,powerpc\n"
        "supported_system_targets=arm-softmmu,aarch64-softmmu,riscv32-softmmu,"
        "riscv64-softmmu,ppc-softmmu,ppc64-softmmu\n"
        "supported_host=linux-x86_64\n"
        "minimum_glibc=2.35\n"
    )
    (metadata / "SOURCE").write_text(
        "official_source_url=https://download.qemu.org/qemu-11.1.1.tar.xz\n"
        "official_version=11.1.1\n"
        f"official_source_sha256={'1' * 64}\n"
        f"chipchain_bundle_filename={BUNDLE_NAME}\n"
        f"chipchain_bundle_sha256={'0' * 64}\n"
        "chipchain_release_asset_url=https://github.com/Qcx526/ChipChainV3/"
        f"releases/download/v3-qemu-runtime-foundation-stable/{BUNDLE_NAME}\n"
        "build_host=Linux x86_64\n"
        "build_glibc=2.35\n"
        "build_configuration=tcg plugins capstone\n"
        "plugin_configuration=libexeclog.so\n"
        "capstone_status=enabled\n"
    )
    (metadata / "SHA256SUMS").write_text(
        "".join(f"{'0' * 64}  bin/{name}\n" for name in EXECUTABLES)
        + f"{'0' * 64}  {PLUGIN}\n"
    )
    return repo


def run_script(
    repo: Path, *args: str, cwd: Path | None = None, path: str | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    if path is not None:
        environment["PATH"] = path
    command = ["/usr/bin/bash", str(repo / "scripts" / "setup_qemu.sh"), *args]
    with LOCAL_POPEN(
        command, cwd=cwd or repo, env=environment, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) as process:
        stdout, stderr = process.communicate()
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def refresh_manifest(repo: Path, root: Path) -> None:
    lines = []
    for path in sorted(file for file in root.rglob("*") if file.is_file()):
        relative = path.relative_to(root).as_posix()
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}\n")
    (repo / "tools" / "qemu" / "SHA256SUMS").write_text("".join(lines))


def make_install(repo: Path, root: Path) -> None:
    (root / "bin").mkdir(parents=True, exist_ok=True)
    (root / PLUGIN).parent.mkdir(parents=True, exist_ok=True)
    (root / PLUGIN).write_bytes(b"fake plugin for bounded installer tests\n")
    for name in EXECUTABLES:
        binary = root / "bin" / name
        binary.write_text(
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "  --version) printf 'QEMU emulator version 11.1.1 (test)\\n'; exit 0 ;;\n"
            "  -machine)\n"
            "    if [ \"$2\" = help ]; then\n"
            "      printf 'Supported machines are:\\nnone empty machine\\nvirt test machine\\n'\n"
            "      exit 0\n"
            "    fi ;;\n"
            "esac\n"
            "plugin=''\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  if [ \"$1\" = -plugin ]; then shift; plugin=$1; fi\n"
            "  shift\n"
            "done\n"
            "[ -f \"$plugin\" ] || exit 5\n"
            "exit 124\n"
        )
        binary.chmod(0o755)
    refresh_manifest(repo, root)


def make_archive(path: Path, source: Path) -> None:
    with tarfile.open(path, "w:xz") as archive:
        for child in source.iterdir():
            archive.add(child, arcname=child.name)


def pin_archive(repo: Path, archive: Path) -> None:
    source = repo / "tools" / "qemu" / "SOURCE"
    source.write_text(
        source.read_text().replace("0" * 64, hashlib.sha256(archive.read_bytes()).hexdigest())
    )


def fake_network(tmp_path: Path) -> tuple[str, Path]:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(exist_ok=True)
    marker = tmp_path / "download-called"
    for name in ("curl", "wget"):
        binary = fake_bin / name
        binary.write_text(f"#!/bin/sh\nprintf called >> '{marker}'\nexit 9\n")
        binary.chmod(0o755)
    return f"{fake_bin}:{os.environ['PATH']}", marker


def test_help_requires_no_metadata(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    shutil.copy2(SCRIPT, repo / "scripts" / "setup_qemu.sh")
    result = run_script(repo, "--help")
    assert result.returncode == 0
    assert "--verify-only" in result.stdout


@pytest.mark.parametrize("filename", ["VERSION", "SOURCE", "SHA256SUMS"])
def test_malformed_metadata_fails_before_install(setup_repo: Path, filename: str) -> None:
    (setup_repo / "tools" / "qemu" / filename).write_text("malformed\n")
    result = run_script(setup_repo, "--offline")
    assert result.returncode != 0
    assert "metadata" in result.stderr or "manifest" in result.stderr
    assert not (setup_repo / "tools" / "qemu" / "install").exists()


def test_unsupported_host_fails_closed(setup_repo: Path, tmp_path: Path) -> None:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    uname = fake_bin / "uname"
    uname.write_text("#!/bin/sh\ncase \"$1\" in -s) echo Darwin ;; -m) echo arm64 ;; esac\n")
    uname.chmod(0o755)
    result = run_script(setup_repo, "--offline", path=f"{fake_bin}:{os.environ['PATH']}")
    assert result.returncode != 0
    assert "Unsupported host Darwin/arm64" in result.stderr


def test_old_glibc_fails_closed(setup_repo: Path, tmp_path: Path) -> None:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    getconf = fake_bin / "getconf"
    getconf.write_text("#!/bin/sh\nprintf 'glibc 2.31\\n'\n")
    getconf.chmod(0o755)
    result = run_script(setup_repo, "--offline", path=f"{fake_bin}:{os.environ['PATH']}")
    assert result.returncode != 0
    assert "glibc 2.31 is too old" in result.stderr


def test_offline_missing_bundle_never_downloads(setup_repo: Path, tmp_path: Path) -> None:
    path, marker = fake_network(tmp_path)
    result = run_script(setup_repo, "--offline", path=path)
    assert result.returncode != 0
    assert "Offline mode forbids download" in result.stderr
    assert not marker.exists()


def test_explicit_archive_requires_pinned_sha(setup_repo: Path, tmp_path: Path) -> None:
    source = tmp_path / "source"
    make_install(setup_repo, source)
    archive = tmp_path / "other-name.tar.xz"
    make_archive(archive, source)
    result = run_script(setup_repo, "--offline", "--archive", str(archive))
    assert result.returncode != 0
    assert "Archive SHA256 mismatch" in result.stderr
    assert not (setup_repo / "tools" / "qemu" / "install").exists()


def test_offline_uses_only_pinned_cached_bundle(setup_repo: Path, tmp_path: Path) -> None:
    source = tmp_path / "source"
    make_install(setup_repo, source)
    cache = setup_repo / "tools" / "qemu" / BUNDLE_NAME
    make_archive(cache, source)
    pin_archive(setup_repo, cache)
    path, marker = fake_network(tmp_path)
    result = run_script(setup_repo, "--offline", path=path)
    assert result.returncode == 0, result.stderr
    assert "Archive SHA256 PASS" in result.stdout
    assert (setup_repo / "tools" / "qemu" / "install" / "bin" / EXECUTABLES[0]).exists()
    assert not marker.exists()


def test_bad_cached_bundle_is_preserved(setup_repo: Path) -> None:
    cache = setup_repo / "tools" / "qemu" / BUNDLE_NAME
    cache.write_bytes(b"untrusted cached bytes")
    result = run_script(setup_repo, "--offline")
    assert result.returncode != 0
    assert "Archive SHA256 mismatch" in result.stderr
    assert cache.read_bytes() == b"untrusted cached bytes"
    assert not (setup_repo / "tools" / "qemu" / "install").exists()


@pytest.mark.parametrize("attack", ["traversal", "symlink"])
def test_unsafe_archive_rejected(setup_repo: Path, tmp_path: Path, attack: str) -> None:
    archive = tmp_path / "unsafe.tar.xz"
    with tarfile.open(archive, "w:xz") as bundle:
        entry = tarfile.TarInfo("../escape" if attack == "traversal" else "bin/qemu-system-arm")
        if attack == "traversal":
            data = b"escape"
            entry.size = len(data)
            bundle.addfile(entry, io.BytesIO(data))
        else:
            entry.type = tarfile.SYMTYPE
            entry.linkname = "/bin/sh"
            bundle.addfile(entry)
    pin_archive(setup_repo, archive)
    result = run_script(setup_repo, "--offline", "--archive", str(archive))
    assert result.returncode != 0
    assert "unsafe archive entry" in result.stderr
    assert not (tmp_path / "escape").exists()
    assert not (setup_repo / "tools" / "qemu" / "install").exists()
    assert not list((setup_repo / "tools" / "qemu").glob(".chipchain-qemu-stage.*"))


def test_invalid_existing_install_is_preserved(setup_repo: Path, tmp_path: Path) -> None:
    install = setup_repo / "tools" / "qemu" / "install"
    install.mkdir()
    marker = install / "customer-file"
    marker.write_text("preserve")
    result = run_script(setup_repo, "--offline")
    assert result.returncode != 0
    assert "Existing installation is invalid; it was left untouched" in result.stderr
    assert marker.read_text() == "preserve"


def test_install_reuse_and_verify_only_are_nonmodifying(setup_repo: Path, tmp_path: Path) -> None:
    source = tmp_path / "source"
    make_install(setup_repo, source)
    archive = tmp_path / "pinned.tar.xz"
    make_archive(archive, source)
    pin_archive(setup_repo, archive)
    alternate = setup_repo / "alternate" / "qemu"
    first = run_script(setup_repo, "--offline", "--archive", str(archive),
                       "--install-dir", "alternate/qemu", cwd=tmp_path)
    assert first.returncode == 0, first.stderr
    assert first.stdout.count("Verified qemu-system-") == 6
    assert first.stdout.count("Plugin load smoke passed") == 3
    binary = alternate / "bin" / "qemu-system-arm"
    before = binary.stat().st_mtime_ns
    network_path, marker = fake_network(tmp_path)
    second = run_script(setup_repo, "--verify-only", "--install-dir", str(alternate),
                        cwd=Path("/"), path=network_path)
    assert second.returncode == 0, second.stderr
    reused = run_script(setup_repo, "--install-dir", str(alternate), path=network_path)
    assert reused.returncode == 0, reused.stderr
    assert "already installed" in reused.stdout
    assert binary.stat().st_mtime_ns == before
    assert not marker.exists()


def test_six_binaries_are_required(setup_repo: Path, tmp_path: Path) -> None:
    install = setup_repo / "tools" / "qemu" / "install"
    make_install(setup_repo, install)
    (install / "bin" / "qemu-system-ppc64").unlink()
    result = run_script(setup_repo, "--verify-only")
    assert result.returncode != 0
    assert "missing installed file: bin/qemu-system-ppc64" in result.stderr


def test_wrong_version_fails_after_integrity_check(setup_repo: Path) -> None:
    install = setup_repo / "tools" / "qemu" / "install"
    make_install(setup_repo, install)
    binary = install / "bin" / "qemu-system-riscv64"
    binary.write_text(binary.read_text().replace("11.1.1", "10.0.0"))
    refresh_manifest(setup_repo, install)
    result = run_script(setup_repo, "--verify-only")
    assert result.returncode != 0
    assert "QEMU version mismatch" in result.stderr


def test_machine_and_plugin_smoke_are_required(setup_repo: Path) -> None:
    install = setup_repo / "tools" / "qemu" / "install"
    make_install(setup_repo, install)
    binary = install / "bin" / "qemu-system-aarch64"
    binary.write_text(binary.read_text().replace("virt test machine", ""))
    refresh_manifest(setup_repo, install)
    machines = run_script(setup_repo, "--verify-only")
    assert machines.returncode != 0
    assert "No supported machine listed" in machines.stderr
    make_install(setup_repo, install)
    binary.write_text(binary.read_text().replace("exit 124", "exit 5"))
    refresh_manifest(setup_repo, install)
    plugin = run_script(setup_repo, "--verify-only")
    assert plugin.returncode != 0
    assert "Plugin smoke failed for qemu-system-aarch64" in plugin.stderr


def test_path_qemu_is_never_used(setup_repo: Path, tmp_path: Path) -> None:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    marker = tmp_path / "path-qemu-used"
    for name in EXECUTABLES:
        binary = fake_bin / name
        binary.write_text(f"#!/bin/sh\nprintf used >> '{marker}'\nexit 0\n")
        binary.chmod(0o755)
    result = run_script(setup_repo, "--verify-only", path=f"{fake_bin}:{os.environ['PATH']}")
    assert result.returncode != 0
    assert "QEMU is not installed" in result.stderr
    assert not marker.exists()
    install = setup_repo / "tools" / "qemu" / "install"
    make_install(setup_repo, install)
    result = run_script(setup_repo, "--verify-only", path=f"{fake_bin}:{os.environ['PATH']}")
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


def test_verify_only_archive_combination_rejected(setup_repo: Path) -> None:
    result = run_script(setup_repo, "--verify-only", "--archive", "unused.tar.xz")
    assert result.returncode != 0
    assert "cannot be combined" in result.stderr
