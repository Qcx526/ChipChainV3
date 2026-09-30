"""Inspectable local trace-plugin build; does not rebuild the frozen QEMU bundle."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import subprocess

from chipchain.firmware.static_ir import content_id
from chipchain.runtime.qemu_profile import PINNED_QEMU_VERSION

PLUGIN_API_VERSION = 7
BUILD_FLAGS = ("-std=c11", "-O2", "-fPIC", "-shared", "-fvisibility=hidden",
               "-Wall", "-Wextra", "-Werror", "-Wl,--build-id=none")


def validate_header_provenance(root: Path) -> dict:
    directory = root / "tools/qemu/plugins"
    provenance = json.loads((directory / "header-provenance.json").read_text())
    source = dict(line.split("=", 1) for line in (root / "tools/qemu/SOURCE").read_text().splitlines())
    header = (directory / "qemu-plugin-v7.h").read_bytes()
    expected = {
        "schema_version": "qemu-plugin-header-provenance/v1", "upstream_project": "QEMU",
        "upstream_version": PINNED_QEMU_VERSION, "upstream_tag": source["official_tag"],
        "upstream_commit": source["official_tag_commit"], "api_version": PLUGIN_API_VERSION,
        "upstream_header": "include/plugins/qemu-plugin.h",
        "upstream_header_sha256": "335d4e472067e914add598b60d1f7cf0dc029cd48f62f66656d6a88c54d8d9f9",
        "subset_sha256": sha256(header).hexdigest(), "license": "GPL-2.0-or-later",
    }
    if (provenance != expected or source["official_version"] != PINNED_QEMU_VERSION
            or re.findall(rb"^#define QEMU_PLUGIN_VERSION (\d+)$", header, re.M) != [b"7"]
            or b"SPDX-License-Identifier: GPL-2.0-or-later" not in header):
        raise ValueError("Plugin header/API provenance is incompatible with pinned QEMU")
    return provenance


def build_plugin(*, repository_root: Path, output_directory: Path) -> dict:
    root = Path(repository_root).resolve(strict=True)
    validate_header_provenance(root)
    source = root / "tools/qemu/plugins/chipchain_trace.c"
    header = source.with_name("qemu-plugin-v7.h")
    metadata = source.with_name("header-provenance.json")
    inputs = {"plugin_source_sha256": sha256(source.read_bytes()).hexdigest(),
              "plugin_api_header_sha256": sha256(header.read_bytes()).hexdigest(),
              "plugin_header_provenance_sha256": sha256(metadata.read_bytes()).hexdigest()}
    output = Path(output_directory).absolute()
    if any(p.is_symlink() for p in (output, *output.parents)):
        raise ValueError("Plugin build directory must not contain a symlink")
    binary, record = output / "trace-plugin.so", output / "plugin-build.json"
    if any(p.exists() or p.is_symlink() for p in (binary, record)):
        raise ValueError("Plugin build artifacts already exist")
    compiler = shutil.which("cc")
    if compiler is None:
        raise ValueError("A C compiler (cc) is required to build the project trace plugin")
    version = subprocess.run([compiler, "-dumpfullversion", "-dumpversion"],
                             capture_output=True, text=True, timeout=5, check=False)
    compiler_version = version.stdout.strip()
    if version.returncode or not re.fullmatch(r"[0-9][0-9A-Za-z.+~_-]*", compiler_version):
        raise ValueError("Cannot identify compiler version without host-dependent text")
    compiler_sha = sha256(Path(compiler).read_bytes()).hexdigest()
    output.mkdir(parents=True, exist_ok=True)
    build = subprocess.run([compiler, *BUILD_FLAGS, str(source), "-o", str(binary)],
                           capture_output=True, timeout=30, check=False)
    if build.returncode:
        raise ValueError("Trace plugin compilation failed: " + build.stderr.decode("utf-8", "replace")[-2000:])
    if any(sha256(path.read_bytes()).hexdigest() != inputs[key] for path, key in (
        (source, "plugin_source_sha256"), (header, "plugin_api_header_sha256"),
        (metadata, "plugin_header_provenance_sha256"),
    )) or sha256(Path(compiler).read_bytes()).hexdigest() != compiler_sha:
        raise ValueError("Plugin build input changed during compilation")
    fields = {
        "schema_version": "qemu-plugin-build/v1", "artifact_role": "local_build_provenance",
        "compiler_name": "cc", "compiler_version": compiler_version,
        "compiler_binary_sha256": compiler_sha, "plugin_api_version": PLUGIN_API_VERSION,
        "argv_template": ["cc", *BUILD_FLAGS, "tools/qemu/plugins/chipchain_trace.c",
                          "-o", "<output>/trace-plugin.so"],
        **inputs, "plugin_sha256": sha256(binary.read_bytes()).hexdigest(),
    }
    result = {**fields, "build_id": content_id("qemu-plugin-build", fields)}
    with record.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(result, sort_keys=True, indent=2) + "\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = build_plugin(repository_root=Path(__file__).resolve().parents[3], output_directory=args.output)
    print(result["plugin_sha256"] + "  trace-plugin.so")


if __name__ == "__main__":
    main()
