"""Explicit QEMU launch profiles for diagnostic runtime acquisition.

This module only selects a project-managed emulator and constructs a command.
It does not parse observations or create scientific runtime evidence. The QEMU
installation's full checksum and plugin validation belongs to setup_qemu.sh.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path
import re
import subprocess


PINNED_QEMU_VERSION = "11.1.1"


class QemuProfileError(ValueError):
    """A run profile is incomplete or internally inconsistent."""


class QemuInstallError(RuntimeError):
    """The explicitly selected QEMU installation cannot be used."""


class ArchitectureFamily(str, Enum):
    ARM = "arm"
    RISCV = "riscv"
    POWERPC = "powerpc"


class BootStrategy(str, Enum):
    GENERIC_LOADER = "generic_loader"
    KERNEL = "kernel"


_EXECUTABLES = {
    (ArchitectureFamily.ARM, 32): "qemu-system-arm",
    (ArchitectureFamily.ARM, 64): "qemu-system-aarch64",
    (ArchitectureFamily.RISCV, 32): "qemu-system-riscv32",
    (ArchitectureFamily.RISCV, 64): "qemu-system-riscv64",
    (ArchitectureFamily.POWERPC, 32): "qemu-system-ppc",
    (ArchitectureFamily.POWERPC, 64): "qemu-system-ppc64",
}
_NAME = re.compile(r"[A-Za-z0-9_.+-]+\Z")
_RESERVED_EXTRA_OPTIONS = {
    "-M", "-machine", "-cpu", "-accel", "-bios", "-kernel", "-smp",
    "-version", "--version", "-help", "--help",
}


@dataclass(frozen=True, slots=True, kw_only=True)
class QemuRunProfile:
    """One declared machine and loading policy, independent of scientific IR.

    ``cpu=None`` deliberately accepts this profile's QEMU machine default.
    A caller must still select the profile explicitly; the backend never
    infers a machine or CPU from an ELF architecture.
    """

    architecture: ArchitectureFamily
    bit_width: int
    executable: str
    machine: str
    cpu: str | None
    boot_strategy: BootStrategy
    bios: str | None = None
    vcpus: int = 1
    extra_args: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        try:
            architecture = ArchitectureFamily(self.architecture)
            strategy = BootStrategy(self.boot_strategy)
        except ValueError as exc:
            raise QemuProfileError("Unsupported architecture or boot strategy") from exc
        object.__setattr__(self, "architecture", architecture)
        object.__setattr__(self, "boot_strategy", strategy)

        if type(self.bit_width) is not int or (architecture, self.bit_width) not in _EXECUTABLES:
            raise QemuProfileError("Unsupported architecture and bit-width pair")
        if self.executable != _EXECUTABLES[(architecture, self.bit_width)]:
            raise QemuProfileError("QEMU executable does not match architecture and bit width")
        if not isinstance(self.machine, str) or not _NAME.fullmatch(self.machine):
            raise QemuProfileError("An explicit QEMU machine name is required")
        if self.cpu is not None and (not isinstance(self.cpu, str) or not _NAME.fullmatch(self.cpu)):
            raise QemuProfileError("CPU must be a QEMU CPU name or None")
        if self.bios is not None and (not isinstance(self.bios, str) or not self.bios or "\x00" in self.bios):
            raise QemuProfileError("BIOS must be an explicit QEMU value or None")
        if type(self.vcpus) is not int or self.vcpus < 1:
            raise QemuProfileError("vcpus must be a positive integer")

        if isinstance(self.extra_args, (str, bytes)):
            raise QemuProfileError("extra_args must contain complete argv tokens")
        try:
            extra_args = tuple(self.extra_args)
        except TypeError as exc:
            raise QemuProfileError("extra_args must be an iterable of argv tokens") from exc
        for arg in extra_args:
            if not isinstance(arg, str) or not arg or "\x00" in arg:
                raise QemuProfileError("extra_args contains an invalid argv token")
            if any(arg == option or arg.startswith(option + "=") for option in _RESERVED_EXTRA_OPTIONS):
                raise QemuProfileError(f"extra_args cannot override profile option {arg}")
        object.__setattr__(self, "extra_args", extra_args)


class QemuRuntimeBackend:
    """Resolve only binaries beneath an explicitly chosen QEMU install root."""

    def __init__(self, install_dir: Path | str):
        # abspath removes relative components without following symlinks. A
        # resolved path would conceal a link from tools/qemu/install to a host
        # QEMU tree, making that tree appear to be the selected installation.
        self.install_dir = Path(os.path.abspath(install_dir))

    @classmethod
    def for_project(cls, repository_root: Path | str) -> QemuRuntimeBackend:
        return cls(Path(repository_root) / "tools" / "qemu" / "install")

    def executable_path(self, profile: QemuRunProfile) -> Path:
        if not isinstance(profile, QemuRunProfile):
            raise TypeError("An explicit QemuRunProfile is required")
        for component in (self.install_dir, *self.install_dir.parents):
            if component.is_symlink():
                raise QemuInstallError(f"QEMU installation path contains a symlink: {component}")
        binary = self.install_dir / "bin" / profile.executable
        if binary.parent.is_symlink():
            raise QemuInstallError(f"QEMU installation bin directory is a symlink: {binary.parent}")
        if binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK):
            raise QemuInstallError(f"Missing project-managed QEMU executable: {binary}")
        if not binary.resolve().is_relative_to(self.install_dir):
            raise QemuInstallError(f"QEMU executable escapes installation: {binary}")
        return binary

    def verified_executable(self, profile: QemuRunProfile) -> Path:
        binary = self.executable_path(profile)
        try:
            result = subprocess.run(
                [str(binary), "--version"], capture_output=True, text=True,
                timeout=5, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise QemuInstallError(f"Cannot verify project-managed QEMU executable: {binary}") from exc
        version = re.escape(PINNED_QEMU_VERSION)
        if result.returncode != 0 or not re.match(
            rf"^QEMU emulator version {version}(?:\s|$)", result.stdout,
        ):
            raise QemuInstallError(f"QEMU executable is not pinned version {PINNED_QEMU_VERSION}: {binary}")
        return binary

    def command(self, profile: QemuRunProfile, firmware: Path | str) -> tuple[str, ...]:
        """Build argv after checking the local emulator and firmware file.

        For ``GENERIC_LOADER``, a comma in a path would be parsed as another
        QEMU device property, so it is rejected instead of guessed/escaped.
        """
        binary = self.verified_executable(profile)
        firmware_path = Path(firmware).resolve(strict=True)
        if not firmware_path.is_file():
            raise QemuProfileError(f"Firmware is not a regular file: {firmware_path}")

        argv = [str(binary), "-M", profile.machine, "-accel", "tcg",
                "-smp", str(profile.vcpus), "-nographic"]
        if profile.cpu is not None:
            argv.extend(("-cpu", profile.cpu))
        if profile.bios is not None:
            argv.extend(("-bios", profile.bios))
        if profile.boot_strategy is BootStrategy.GENERIC_LOADER:
            if "," in str(firmware_path):
                raise QemuProfileError("Generic loader firmware path cannot contain a comma")
            argv.extend(("-device", f"loader,file={firmware_path},cpu-num=0"))
        elif profile.boot_strategy is BootStrategy.KERNEL:
            argv.extend(("-kernel", str(firmware_path)))
        else:  # Defensive against bypassing the frozen dataclass constructor.
            raise QemuProfileError("Unsupported boot strategy")
        argv.extend(profile.extra_args)
        return tuple(argv)


# The only V1 firmware sample has an explicit RV64 QEMU feasibility profile.
# This profile is not selected automatically for other RISC-V firmware.
RISCV64_FW_FEASIBILITY = QemuRunProfile(
    architecture=ArchitectureFamily.RISCV,
    bit_width=64,
    executable="qemu-system-riscv64",
    machine="virt",
    cpu=None,
    boot_strategy=BootStrategy.GENERIC_LOADER,
    bios="none",
)
