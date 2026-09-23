"""Deterministically rebuild the three tracked, freestanding assembly ELF samples."""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools/toolchains/install"
SAMPLES = ROOT / "samples/firmware"
OBJECTS = ROOT / "output/firmware-build"


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def displayed(command: list[str]) -> list[str]:
    return [str(Path(arg).relative_to(ROOT)) if arg.startswith(str(ROOT)) else arg for arg in command]


def build() -> None:
    OBJECTS.mkdir(parents=True, exist_ok=True)
    arm = TOOLS / "arm-binutils/usr/bin"
    ppc = TOOLS / "powerpc-binutils/usr/bin"
    riscv = TOOLS / "riscv32-lowrisc/bin"
    ppc_env = os.environ.copy()
    ppc_env["LD_LIBRARY_PATH"] = str(TOOLS / "powerpc-binutils/usr/lib/x86_64-linux-gnu")
    for architecture in ("arm", "riscv", "powerpc"):
        source = SAMPLES / architecture / "source.S"
        elf = SAMPLES / architecture / "sample.elf"
        obj = OBJECTS / f"{architecture}.o"
        if architecture == "arm":
            commands = [
                [str(arm / "arm-none-eabi-as"), "-mcpu=cortex-m3", "-mthumb", "-o", str(obj), str(source)],
                [str(arm / "arm-none-eabi-ld"), "--build-id=none", "-Ttext=0x10000", "-e", "_start",
                 "-o", str(elf), str(obj)],
            ]
        elif architecture == "riscv":
            commands = [
                [str(riscv / "riscv32-unknown-elf-as"), "-march=rv32im_zicsr", "-mabi=ilp32",
                 "-o", str(obj), str(source)],
                [str(riscv / "riscv32-unknown-elf-ld"), "--build-id=none", "--no-relax",
                 "-m", "elf32lriscv", "-Ttext=0x10000", "-e", "_start", "-o", str(elf), obj.name],
            ]
        else:
            commands = [
                [str(ppc / "powerpc-linux-gnu-as"), "-mppc", "-o", str(obj), str(source)],
                [str(ppc / "powerpc-linux-gnu-ld"), "--build-id=none", "-m", "elf32ppc",
                 "-Ttext=0x10000", "-e", "_start", "-o", str(elf), str(obj)],
            ]
        for index, command in enumerate(commands):
            subprocess.run(command,
                           cwd=OBJECTS if architecture == "riscv" and index == 1 else ROOT,
                           env=ppc_env if architecture == "powerpc" else None, check=True)
        manifest = {
            "architecture": architecture,
            "sample_kind": "synthetic_fixture",
            "source_sha256": digest(source),
            "elf_sha256": digest(elf),
            "commands": [displayed(command) for command in commands],
            "link_working_directory": "output/firmware-build" if architecture == "riscv" else ".",
            "toolchain_manifest": "tools/toolchains/MANIFEST.json",
        }
        (SAMPLES / architecture / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        print(f"{architecture}: {manifest['elf_sha256']}")


if __name__ == "__main__":
    build()
