#!/usr/bin/env python3
"""Build the two independent RV64 synthetic firmware variants."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess


CASE = Path(__file__).resolve().parent
ROOT = CASE.parents[3]
COMMON = CASE / "common"
TOOLCHAIN = ROOT / "tools/toolchains/install/riscv32-lowrisc/bin"
GCC = TOOLCHAIN / "riscv32-unknown-elf-gcc"
LD = TOOLCHAIN / "riscv32-unknown-elf-ld"
BUILD_ROOT = ROOT / "output/firmware-build/processorfuzz_real_case_001"
VARIANTS = {"positive": 1, "negative_trigger": 0}

ARCH_FLAGS = ["-march=rv64ima_zicsr", "-mabi=lp64", "-mcmodel=medany"]
COMPILE_FLAGS = [
    *ARCH_FLAGS,
    "-std=c11", "-O1", "-g0", "-ffreestanding", "-fno-builtin",
    "-fno-stack-protector", "-fno-pic", "-fno-pie", "-fno-common",
    "-fno-inline", "-fno-optimize-sibling-calls", "-fno-ipa-icf",
    "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
    "-msmall-data-limit=0", "-Wall", "-Wextra", "-Werror",
]
LINK_FLAGS = ["-m", "elf64lriscv", "--build-id=none", "--relax"]


def digest(path: Path) -> str:
    h = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def tool_version(path: Path) -> str:
    result = subprocess.run([str(path), "--version"], check=True, text=True,
                            capture_output=True)
    return result.stdout.splitlines()[0]


def verify_toolchain() -> dict:
    manifest = ROOT / "tools/toolchains/MANIFEST.json"
    pinned = json.loads(manifest.read_text())["riscv"]
    for path, key in ((GCC, "compiler_sha256"), (LD, "linker_sha256")):
        if not path.is_file() or digest(path) != pinned[key]:
            raise RuntimeError(f"project toolchain mismatch: {path}")
    return {
        "manifest": relative(manifest),
        "gcc": {"path": relative(GCC), "sha256": digest(GCC),
                "version": tool_version(GCC)},
        "ld": {"path": relative(LD), "sha256": digest(LD),
               "version": tool_version(LD)},
    }


def verify_elf(path: Path) -> list[dict]:
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01":
        raise RuntimeError("build output is not little-endian ELF64")
    (e_type, e_machine, _version, entry, phoff, _shoff, _flags,
     _ehsize, phentsize, phnum, _shentsize, _shnum, _shstrndx) = struct.unpack_from(
         "<HHIQQQIHHHHHH", data, 16)
    if (e_type, e_machine, entry) != (2, 243, 0x80000000):
        raise RuntimeError("build output is not an RV64 executable at 0x80000000")
    if phentsize != 56 or phoff + phnum * phentsize > len(data):
        raise RuntimeError("invalid ELF program-header table")

    segments = []
    executable_entry = 0
    for index in range(phnum):
        p_type, flags, offset, vaddr, paddr, filesz, memsz, align = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * phentsize)
        if p_type != 1:
            continue
        if offset + filesz > len(data) or not 0x80000000 <= vaddr <= vaddr + memsz <= 0x80040000:
            raise RuntimeError("ELF PT_LOAD is outside the 256 KiB RAM image")
        if flags & 1 and vaddr <= entry < vaddr + filesz:
            executable_entry += 1
        segments.append({"virtual_address": f"0x{vaddr:x}",
                         "physical_address": f"0x{paddr:x}",
                         "file_size": filesz, "memory_size": memsz,
                         "flags": flags, "alignment": align})
    if executable_entry != 1:
        raise RuntimeError("entry is not uniquely file-backed by an executable PT_LOAD")
    return segments


def config_value(path: Path) -> int:
    found = re.findall(r"(?m)^\s*#\s*define\s+BENCH_TLB_INVALIDATE\s+([01])\s*$",
                       path.read_text())
    if len(found) != 1:
        raise RuntimeError(f"expected one BENCH_TLB_INVALIDATE definition: {path}")
    return int(found[0])


def run(command: list[str], *, cwd: Path) -> None:
    subprocess.run(command, cwd=cwd, check=True)


def build(variant: str, toolchain: dict) -> None:
    variant_dir = CASE / variant
    config = variant_dir / "config.h"
    if config_value(config) != VARIANTS[variant]:
        raise RuntimeError(f"incorrect BENCH_TLB_INVALIDATE for {variant}")
    sources = sorted((COMMON / "src").rglob("*.c"))
    if not sources:
        raise RuntimeError("common/src contains no C source")

    build_dir = BUILD_ROOT / variant
    build_dir.mkdir(parents=True, exist_ok=True)
    include_flags = ["-I", relative(variant_dir), "-I", relative(COMMON / "include")]
    objects = []
    commands = []
    for source in [COMMON / "start.S", *sources]:
        if source.suffix == ".S":
            object_name = "start.o"
        else:
            object_name = source.relative_to(COMMON / "src").as_posix().replace("/", "__") + ".o"
        obj = build_dir / object_name
        command = [str(GCC), *COMPILE_FLAGS, *include_flags,
                   "-c", relative(source), "-o", relative(obj)]
        run(command, cwd=ROOT)
        commands.append([relative(GCC), *command[1:]])
        objects.append(obj)

    built_elf = build_dir / "firmware.elf"
    link_command = [str(LD), *LINK_FLAGS, "-T", str(COMMON / "linker.ld"),
                    "-o", built_elf.name, *(obj.name for obj in objects)]
    run(link_command, cwd=build_dir)
    segments = verify_elf(built_elf)
    commands.append([relative(LD), *LINK_FLAGS, "-T", relative(COMMON / "linker.ld"),
                     "-o", built_elf.name, *(obj.name for obj in objects)])

    inputs = [COMMON / "start.S", COMMON / "linker.ld", *sources,
              *(COMMON / "include").rglob("*.h"), *variant_dir.rglob("*.h"),
              CASE / "design-note.md", CASE / "benchmark-contract.json"]
    input_hashes = {relative(path): digest(path) for path in sorted(set(inputs))}
    contract = json.loads((CASE / "benchmark-contract.json").read_text())
    metadata = {
        "schema": "chipchain-synthetic-firmware-build/v1",
        "sample_kind": contract["sample_kind"],
        "hardware_reference_case": contract["hardware_reference_case"],
        "benchmark_contract_kind": contract["contract_kind"],
        "variant": variant,
        "BENCH_TLB_INVALIDATE": VARIANTS[variant],
        "architecture": "riscv64-little",
        "entry": "0x80000000",
        "ram_origin": "0x80000000",
        "ram_size_bytes": 256 * 1024,
        "elf_sha256": digest(built_elf),
        "load_segments": segments,
        "inputs": input_hashes,
        "toolchain": toolchain,
        "compile_flags": COMPILE_FLAGS,
        "link_flags": LINK_FLAGS,
        "compile_working_directory": ".",
        "link_working_directory": relative(build_dir),
        "commands": commands,
    }
    destination = variant_dir / "firmware.elf"
    shutil.copyfile(built_elf, destination)
    (variant_dir / "build-metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    print(f"{variant}: {relative(destination)} {metadata['elf_sha256']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=[*VARIANTS, "all"], default="all")
    args = parser.parse_args()
    toolchain = verify_toolchain()
    selected = VARIANTS if args.variant == "all" else {args.variant: VARIANTS[args.variant]}
    for variant in selected:
        build(variant, toolchain)


if __name__ == "__main__":
    main()
