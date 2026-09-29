"""Profile selection and local QEMU command construction boundaries."""

from __future__ import annotations

from dataclasses import fields
from pathlib import Path
import subprocess

import pytest

from chipchain.runtime import qemu_profile
from chipchain.runtime.qemu_profile import (
    ArchitectureFamily, BootStrategy, QemuInstallError, QemuProfileError,
    QemuRunProfile, QemuRuntimeBackend, RISCV64_FW_FEASIBILITY,
)


@pytest.mark.parametrize(
    ("family", "width", "executable"),
    [
        (ArchitectureFamily.ARM, 32, "qemu-system-arm"),
        (ArchitectureFamily.ARM, 64, "qemu-system-aarch64"),
        (ArchitectureFamily.RISCV, 32, "qemu-system-riscv32"),
        (ArchitectureFamily.RISCV, 64, "qemu-system-riscv64"),
        (ArchitectureFamily.POWERPC, 32, "qemu-system-ppc"),
        (ArchitectureFamily.POWERPC, 64, "qemu-system-ppc64"),
    ],
)
def test_profile_covers_exact_supported_family_binary_pairs(
    family: ArchitectureFamily, width: int, executable: str,
) -> None:
    profile = QemuRunProfile(
        architecture=family, bit_width=width, executable=executable,
        machine="declared-board", cpu=None, boot_strategy=BootStrategy.KERNEL,
    )
    assert profile.architecture is family
    assert profile.executable == executable
    assert profile.machine == "declared-board"


def test_profile_rejects_machine_guessing_and_cross_architecture_binary() -> None:
    with pytest.raises(TypeError, match="machine"):
        QemuRunProfile(  # type: ignore[call-arg]
            architecture=ArchitectureFamily.ARM, bit_width=64,
            executable="qemu-system-aarch64", cpu=None, boot_strategy=BootStrategy.KERNEL,
        )
    with pytest.raises(QemuProfileError, match="machine"):
        QemuRunProfile(
            architecture=ArchitectureFamily.ARM, bit_width=64,
            executable="qemu-system-aarch64", machine="", cpu=None,
            boot_strategy=BootStrategy.KERNEL,
        )
    with pytest.raises(QemuProfileError, match="does not match"):
        QemuRunProfile(
            architecture=ArchitectureFamily.POWERPC, bit_width=64,
            executable="qemu-system-riscv64", machine="declared-board", cpu=None,
            boot_strategy=BootStrategy.KERNEL,
        )


def test_profile_rejects_extra_args_that_override_declared_machine() -> None:
    with pytest.raises(QemuProfileError, match="override"):
        QemuRunProfile(
            architecture=ArchitectureFamily.ARM, bit_width=32,
            executable="qemu-system-arm", machine="declared-board", cpu=None,
            boot_strategy=BootStrategy.KERNEL,
            extra_args=("-machine", "other-board"),
        )


def _local_binary(install_dir: Path, executable: str) -> Path:
    binary = install_dir / "bin" / executable
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text("#!/bin/sh\nexit 99\n")
    binary.chmod(0o755)
    return binary


def _stub_version(monkeypatch: pytest.MonkeyPatch, expected: Path, version: str = "11.1.1") -> list[str]:
    checked: list[str] = []

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert argv == [str(expected), "--version"]
        assert kwargs["timeout"] == 5
        checked.append(argv[0])
        return subprocess.CompletedProcess(argv, 0, f"QEMU emulator version {version}\n", "")

    monkeypatch.setattr(qemu_profile.subprocess, "run", fake_run)
    return checked


def test_riscv_feasibility_command_uses_explicit_local_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    install = tmp_path / "tools" / "qemu" / "install"
    binary = _local_binary(install, "qemu-system-riscv64")
    checked = _stub_version(monkeypatch, binary)
    firmware = tmp_path / "firmware.elf"
    firmware.write_bytes(b"ELF fixture")

    backend = QemuRuntimeBackend.for_project(tmp_path)
    assert backend.command(RISCV64_FW_FEASIBILITY, firmware) == (
        str(binary), "-M", "virt", "-accel", "tcg", "-smp", "1",
        "-nographic", "-bios", "none", "-device",
        f"loader,file={firmware},cpu-num=0",
    )
    assert checked == [str(binary)]


def test_non_riscv_kernel_profile_keeps_its_own_board_and_cpu(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    install = tmp_path / "qemu-install"
    binary = _local_binary(install, "qemu-system-ppc64")
    _stub_version(monkeypatch, binary)
    firmware = tmp_path / "firmware.elf"
    firmware.write_bytes(b"ELF fixture")
    profile = QemuRunProfile(
        architecture=ArchitectureFamily.POWERPC, bit_width=64,
        executable="qemu-system-ppc64", machine="declared-board", cpu="declared-cpu",
        boot_strategy=BootStrategy.KERNEL, extra_args=("-no-reboot",),
    )

    command = QemuRuntimeBackend(install).command(profile, firmware)
    assert command == (
        str(binary), "-M", "declared-board", "-accel", "tcg", "-smp", "1",
        "-nographic", "-cpu", "declared-cpu", "-kernel", str(firmware),
        "-no-reboot",
    )


def test_no_path_fallback_when_local_binary_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    system = tmp_path / "system-bin"
    system.mkdir()
    fake_host_binary = system / "qemu-system-riscv64"
    fake_host_binary.write_text("#!/bin/sh\nexit 0\n")
    fake_host_binary.chmod(0o755)
    monkeypatch.setenv("PATH", f"{system}:/usr/bin")
    monkeypatch.setattr(
        qemu_profile.subprocess, "run",
        lambda *args, **kwargs: pytest.fail("host QEMU must never be queried"),
    )
    firmware = tmp_path / "firmware.elf"
    firmware.write_bytes(b"ELF fixture")

    with pytest.raises(QemuInstallError, match="Missing project-managed"):
        QemuRuntimeBackend(tmp_path / "missing-install").command(
            RISCV64_FW_FEASIBILITY, firmware,
        )


def test_symlink_to_host_binary_and_wrong_version_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    outside = _local_binary(tmp_path / "host", "qemu-system-riscv64")
    install = tmp_path / "install"
    (install / "bin").mkdir(parents=True)
    (install / "bin" / "qemu-system-riscv64").symlink_to(outside)
    backend = QemuRuntimeBackend(install)
    with pytest.raises(QemuInstallError, match="Missing project-managed"):
        backend.verified_executable(RISCV64_FW_FEASIBILITY)

    (install / "bin" / "qemu-system-riscv64").unlink()
    binary = _local_binary(install, "qemu-system-riscv64")
    _stub_version(monkeypatch, binary, version="11.1.10")
    with pytest.raises(QemuInstallError, match="pinned version"):
        backend.verified_executable(RISCV64_FW_FEASIBILITY)


def test_install_root_and_bin_symlinks_cannot_redirect_to_host_tree(tmp_path: Path) -> None:
    host_tree = tmp_path / "host-qemu"
    _local_binary(host_tree, "qemu-system-riscv64")
    project = tmp_path / "project"
    project.mkdir()
    (project / "install").symlink_to(host_tree, target_is_directory=True)

    backend = QemuRuntimeBackend(project / "install")
    assert backend.install_dir == project / "install"
    with pytest.raises(QemuInstallError, match="contains a symlink"):
        backend.executable_path(RISCV64_FW_FEASIBILITY)

    (project / "install").unlink()
    (project / "install").mkdir()
    (project / "install" / "bin").symlink_to(host_tree / "bin", target_is_directory=True)
    with pytest.raises(QemuInstallError, match="bin directory is a symlink"):
        backend.executable_path(RISCV64_FW_FEASIBILITY)


def test_profile_contains_no_architecture_specific_scientific_fields() -> None:
    names = {field.name for field in fields(QemuRunProfile)}
    assert names == {
        "architecture", "bit_width", "executable", "machine", "cpu",
        "boot_strategy", "bios", "vcpus", "extra_args",
    }
    assert not hasattr(RISCV64_FW_FEASIBILITY, "sfence_vma")
