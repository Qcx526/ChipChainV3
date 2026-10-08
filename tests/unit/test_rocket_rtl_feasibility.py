"""Small synthetic archive diagnostics; no network, simulator or third-party tools."""

from __future__ import annotations

from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import stat
import sys
import zipfile

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/rtl/inspect_rocket_benchmark.py"
SPEC = importlib.util.spec_from_file_location("rocket_benchmark_inspection", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
inspection = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = inspection
SPEC.loader.exec_module(inspection)

RTL = b"""module RocketTile(
  input clock,
  input [31:0] auto_reset_vector_in,
  output [63:0] auto_tl_master_xing_out_a_bits_data,
  output [39:0] cmt_instr
);
// module NotReallyDefined;
wire reg_satp;
initial $fwrite(1, "trace");
endmodule
"""


def archive(tmp_path: Path, members: list[tuple[str | zipfile.ZipInfo, bytes]]) -> Path:
    path = tmp_path / "source.zip"
    with zipfile.ZipFile(path, "w") as container:
        for name, data in members:
            container.writestr(name, data)
    return path


def test_zip_exact_bytes_inventory_and_input_immutable(tmp_path: Path) -> None:
    path = archive(tmp_path, [("Benchmarks/Verilog/chosen.v", RTL), ("payload.bin", b"\x00\xff\x10")])
    original = path.read_bytes()
    result, files = inspection.inventory(path, expected_zip_sha256=sha256(original).hexdigest(),
                                         rtl_member="Benchmarks/Verilog/chosen.v",
                                         expected_rtl_sha256=sha256(RTL).hexdigest(), top="RocketTile")
    output = tmp_path / "diagnostic"
    inspection.write_inventory(output, result, files, extract_members=["Benchmarks/Verilog/chosen.v"])
    assert path.read_bytes() == original
    assert (output / "Benchmarks/Verilog/chosen.v").read_bytes() == RTL
    assert result["execution_observed"] is False
    assert result["purpose"] == "feasibility_diagnostics_only_not_hardware_runtime_evidence"
    assert result["input"]["zip_sha256"] == sha256(original).hexdigest()
    member = next(row for row in result["members"] if row["member"] == "payload.bin")
    assert member["sha256"] == sha256(b"\x00\xff\x10").hexdigest()
    assert json.loads((output / "input-inventory.json").read_text()) == result


@pytest.mark.parametrize("name", ["../escape", "/absolute", "a/../escape", "a/./b", "a//b", "C:/drive", "a\\b", "a/../../outside"])
def test_unsafe_archive_paths_are_refused(tmp_path: Path, name: str) -> None:
    path = archive(tmp_path, [(name, b"payload")])
    with pytest.raises(inspection.InspectionError, match="Unsafe archive member path"):
        inspection.read_archive(path)


def test_archive_symlink_is_refused(tmp_path: Path) -> None:
    member = zipfile.ZipInfo("package/link")
    member.create_system = 3
    member.external_attr = (stat.S_IFLNK | 0o777) << 16
    path = archive(tmp_path, [(member, b"../../outside")])
    with pytest.raises(inspection.InspectionError, match="symlink"):
        inspection.read_archive(path)


def test_duplicate_member_is_refused(tmp_path: Path) -> None:
    with pytest.warns(UserWarning, match="Duplicate name"):
        path = archive(tmp_path, [("same.v", RTL), ("same.v", b"changed")])
    with pytest.raises(inspection.InspectionError, match="Duplicate archive member"):
        inspection.read_archive(path)


def test_file_directory_collision_is_refused(tmp_path: Path) -> None:
    path = archive(tmp_path, [("same", b"data"), ("same/child", b"data")])
    with pytest.raises(inspection.InspectionError, match="file as parent"):
        inspection.read_archive(path)


def test_multiple_rtl_members_require_explicit_selection() -> None:
    files = {"first.v": RTL, "second.v": RTL}
    with pytest.raises(inspection.InspectionError, match="ambiguous"):
        inspection.select_rtl(files, None)
    assert inspection.select_rtl(files, "second.v") == ("second.v", RTL)


def test_missing_selected_member_does_not_choose_by_basename() -> None:
    with pytest.raises(inspection.InspectionError, match="absent"):
        inspection.select_rtl({"other/selected.v": RTL}, "requested/selected.v")


def test_zip_and_rtl_hash_conflicts_fail_before_output(tmp_path: Path) -> None:
    path = archive(tmp_path, [("chosen.v", RTL)])
    with pytest.raises(inspection.InspectionError, match="SHA256 mismatch for input ZIP"):
        inspection.read_archive(path, expected_sha256="0" * 64)
    with pytest.raises(inspection.InspectionError, match="SHA256 mismatch for RTL"):
        inspection.select_rtl({"chosen.v": RTL}, "chosen.v", expected_sha256="0" * 64)


def test_top_ports_are_source_clues_not_execution_or_configuration() -> None:
    result = inspection.inspect_verilog(RTL, top="RocketTile")
    assert result["modules"] == ["RocketTile"]
    assert result["top_ports"][1] == {"direction": "input", "packed_range": "[31:0]", "name": "auto_reset_vector_in"}
    assert result["interface_clues"]["uart_port_names"] == []
    assert result["interface_clues"]["tilelink_port_names"] == ["auto_tl_master_xing_out_a_bits_data"]
    assert result["source_clues"]["mmu_tlb_ptw"]
    assert result["processor_configuration"].startswith("UNKNOWN")
    assert result["rtl_generation_provenance"].startswith("NOT_ESTABLISHED")
    assert "unelaborated" in result["conditional_top_ports"]


def test_missing_or_duplicate_top_is_refused() -> None:
    with pytest.raises(inspection.InspectionError, match="exactly one"):
        inspection.inspect_verilog(RTL, top="OtherTop")
    with pytest.raises(inspection.InspectionError, match="exactly one"):
        inspection.inspect_verilog(RTL + RTL, top="RocketTile")


def test_existing_output_never_overwritten(tmp_path: Path) -> None:
    output = tmp_path / "results"
    output.mkdir()
    with pytest.raises(inspection.InspectionError, match="never overwritten"):
        inspection.write_inventory(output, {}, {"chosen.v": RTL}, extract_members=["chosen.v"])


def test_archive_input_symlink_is_refused(tmp_path: Path) -> None:
    original = archive(tmp_path, [("chosen.v", RTL)])
    alias = tmp_path / "alias.zip"
    alias.symlink_to(original)
    with pytest.raises(inspection.InspectionError, match="not a symlink"):
        inspection.read_archive(alias)


def test_bounded_archive_read_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = archive(tmp_path, [("chosen.v", RTL)])
    monkeypatch.setattr(inspection, "MAX_MEMBER_BYTES", len(RTL) - 1)
    with pytest.raises(inspection.InspectionError, match="bounded"):
        inspection.read_archive(path)
