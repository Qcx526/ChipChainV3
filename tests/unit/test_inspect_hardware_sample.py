"""Read-only hardware adaptation diagnostics, never scientific evidence."""

from __future__ import annotations

from hashlib import sha256
import importlib.util
import io
import json
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tarfile
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/inspect_hardware_sample.py"
LOCAL_POPEN = subprocess.Popen  # Capture before the suite-wide external-tool guard.


def run_tool(source: Path, output: Path, *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(SCRIPT), "--input", str(source), "--output", str(output)]
    with LOCAL_POPEN(command, cwd=cwd or ROOT, text=True,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        stdout, stderr = process.communicate()
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def read_inventory(output: Path) -> dict:
    return json.loads((output / "inventory.json").read_text())


def elf32_riscv() -> bytes:
    header = bytearray(52)
    header[:4] = b"\x7fELF"
    header[4] = 1  # 32-bit
    header[5] = 1  # little endian
    struct.pack_into("<H", header, 16, 2)  # ET_EXEC
    struct.pack_into("<H", header, 18, 243)  # RISC-V
    struct.pack_into("<I", header, 24, 0x80000000)
    return bytes(header)


def test_directory_inventory_facts_and_no_execution(tmp_path: Path) -> None:
    source = tmp_path / "hardware"
    (source / "tests").mkdir(parents=True)
    elf = elf32_riscv()
    (source / "tests" / "trigger.elf").write_bytes(elf)
    (source / "tests" / "trace.csv").write_text("pc,instr\n0x10,addi\n")
    (source / "tests" / "info.json").write_text('{"a": 1}\n')
    (source / "tests" / "binary.bin").write_bytes(b"\x00\xff\x01")
    marker = tmp_path / "executed"
    malicious = source / "run.sh"
    malicious.write_text(f"#!/bin/sh\ntouch {marker}\n")
    malicious.chmod(0o755)
    output = tmp_path / "inspection"
    result = run_tool(source, output, cwd=Path("/"))
    assert result.returncode == 0, result.stderr
    assert not marker.exists()
    inventory = read_inventory(output)
    assert inventory["purpose"] == "development_diagnostics_only_not_scientific_evidence"
    assert inventory["input"]["container_type"] == "directory"
    assert inventory["summary"]["file_count"] == 5
    paths = [row["relative_path"] for row in inventory["artifacts"]]
    assert paths == sorted(paths)
    facts = {row["relative_path"]: row["facts"] for row in inventory["artifacts"]}
    assert facts["tests/trigger.elf"]["sha256"] == sha256(elf).hexdigest()
    assert facts["tests/trigger.elf"]["elf_header"] == {
        "status": "header_read", "elf_type": "executable", "elf_type_number": 2,
        "machine": "riscv", "machine_number": 243,
        "bits": 32, "endian": "little", "entry_point": "0x80000000",
    }
    assert facts["tests/trace.csv"]["csv_header"] == ["pc", "instr"]
    assert facts["tests/trace.csv"]["lf_line_count"] == 2
    assert facts["tests/info.json"]["json_top_level_type"] == "object"
    assert facts["tests/binary.bin"]["text_status"] == "binary"
    brief = (output / "adaptation-brief.md").read_text()
    assert "does not make it customer firmware" in brief
    assert "not a build or execution provenance proof" in brief


def test_zip_inventory_deterministic_and_hashes(tmp_path: Path) -> None:
    archive = tmp_path / "delivery.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg/z.txt", "last\n")
        zf.writestr("pkg/é.si", "addi x1,x2,0\n")
        zf.writestr("pkg/a.bin", b"\x00\x01")
    first = tmp_path / "first"
    second = tmp_path / "second"
    assert run_tool(archive, first).returncode == 0
    assert run_tool(archive, second, cwd=Path("/")).returncode == 0
    assert (first / "inventory.json").read_bytes() == (second / "inventory.json").read_bytes()
    assert (first / "adaptation-brief.md").read_bytes() == (second / "adaptation-brief.md").read_bytes()
    inventory = read_inventory(first)
    assert inventory["input"]["package_sha256"] == sha256(archive.read_bytes()).hexdigest()
    assert inventory["input"]["container_type"] == "zip"
    assert all(row["facts"]["container_type"] == "zip_member" for row in inventory["artifacts"])
    assert [row["relative_path"] for row in inventory["artifacts"]] == sorted(
        row["relative_path"] for row in inventory["artifacts"]
    )


def test_tar_inventory_and_unsafe_link_rejection(tmp_path: Path) -> None:
    good = tmp_path / "delivery.tar.gz"
    with tarfile.open(good, "w:gz") as archive:
        root = tarfile.TarInfo("./")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        data = b"p-m\naddi x1,x2,0\n"
        member = tarfile.TarInfo("package/case.si")
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    output = tmp_path / "good-output"
    result = run_tool(good, output)
    assert result.returncode == 0, result.stderr
    assert read_inventory(output)["summary"]["file_count"] == 1
    bad = tmp_path / "bad.tar"
    with tarfile.open(bad, "w") as archive:
        link = tarfile.TarInfo("package/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../escape"
        archive.addfile(link)
    result = run_tool(bad, tmp_path / "bad-output")
    assert result.returncode != 0
    assert "unsafe link" in result.stderr
    assert not (tmp_path / "bad-output").exists()


def test_tar_unsafe_member_path_rejected(tmp_path: Path) -> None:
    archive_path = tmp_path / "traversal.tar"
    with tarfile.open(archive_path, "w") as archive:
        member = tarfile.TarInfo("../outside.txt")
        member.size = 4
        archive.addfile(member, io.BytesIO(b"data"))
    output = tmp_path / "inspection"
    result = run_tool(archive_path, output)
    assert result.returncode != 0
    assert "Unsafe archive member path" in result.stderr
    assert not output.exists()


@pytest.mark.parametrize("unsafe", ["../escape", "/absolute", "C:/drive", "sub\\windows"])
def test_zip_unsafe_member_paths_rejected(tmp_path: Path, unsafe: str) -> None:
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(unsafe, "payload")
    output = tmp_path / "inspection"
    result = run_tool(archive, output)
    assert result.returncode != 0
    assert "Unsafe archive member path" in result.stderr
    assert not output.exists()


def test_zip_symlink_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "link.zip"
    link = zipfile.ZipInfo("pkg/link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(link, "../outside")
    result = run_tool(archive, tmp_path / "inspection")
    assert result.returncode != 0
    assert "unsafe link" in result.stderr


def test_directory_symlink_and_nested_output_rejected(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    (source / "link").symlink_to(tmp_path)
    result = run_tool(source, tmp_path / "inspection")
    assert result.returncode != 0
    assert "unsafe link" in result.stderr
    (source / "link").unlink()
    result = run_tool(source, source / "inspection")
    assert result.returncode != 0
    assert "outside the inspected input" in result.stderr


def test_member_and_size_bounds_fail_before_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    spec = importlib.util.spec_from_file_location("inspector_under_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = tmp_path / "bounded"
    source.mkdir()
    for index in range(3):
        (source / f"file_{index}").write_bytes(b"abc")
    monkeypatch.setattr(module, "MAX_MEMBERS", 2)
    with pytest.raises(ValueError, match="members"):
        module.inspect(source)
    monkeypatch.setattr(module, "MAX_MEMBERS", 20_000)
    monkeypatch.setattr(module, "MAX_TOTAL_BYTES", 5)
    with pytest.raises(ValueError, match="size bound"):
        module.inspect(source)
    monkeypatch.setattr(module, "MAX_TOTAL_BYTES", 4 * 1024**3)
    monkeypatch.setattr(module, "MAX_FILE_BYTES", 2)
    with pytest.raises(ValueError, match="size bound"):
        module.inspect(source)


def test_large_preview_and_noisy_build_summary(tmp_path: Path) -> None:
    source = tmp_path / "noisy"
    build = source / "build"
    build.mkdir(parents=True)
    for index in range(300):
        (build / f"Vtop_{index}.o").write_bytes(b"\x00" + bytes([index % 256]))
    trace = source / "rtl_1.log"
    trace.write_bytes(b"secret-trace-record\n" * 10_000)
    output = tmp_path / "inspection"
    result = run_tool(source, output)
    assert result.returncode == 0, result.stderr
    inventory = read_inventory(output)
    assert inventory["summary"]["file_count"] == 301
    trace_facts = next(row["facts"] for row in inventory["artifacts"]
                       if row["relative_path"] == "rtl_1.log")
    assert trace_facts["inspection_prefix_bytes"] == 64 * 1024
    assert trace_facts["inspection_prefix_truncated"] is True
    assert trace_facts["lf_line_count"] == 10_000
    brief = (output / "adaptation-brief.md").read_text()
    assert "300 generated-build-like files" in brief
    assert "secret-trace-record" not in brief
    assert len(brief) < 12_000


def test_real_case_001_inspection_is_read_only(tmp_path: Path) -> None:
    raw = ROOT / "samples/processorfuzz/real_case_001/raw/testis.zip"
    if not raw.exists():
        pytest.skip("Local hardware-team ZIP unavailable")
    before = sha256(raw.read_bytes()).hexdigest()
    result = run_tool(raw, tmp_path / "inspection")
    assert result.returncode == 0, result.stderr
    inventory = read_inventory(tmp_path / "inspection")
    assert inventory["input"]["package_sha256"] == before
    assert inventory["summary"]["file_count"] > 0
    assert any(row["facts"].get("elf_header", {}).get("machine") == "riscv"
               for row in inventory["artifacts"])
    assert sha256(raw.read_bytes()).hexdigest() == before
    assert before == "c0fe4e328be70238cfd7383fe3cc9b58267eeafc0795d1dbb8b4b074ad69df34"
