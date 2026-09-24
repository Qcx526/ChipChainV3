"""Read-only replay of the hardware-team ZIP against reviewed expected artifacts."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import pytest

from chipchain.firmware.elf import ElfImage
from chipchain.firmware.ghidra_models import GhidraExport
from chipchain.firmware.ghidra_normalize import normalize
from chipchain.firmware.processorfuzz_si import parse_si
from chipchain.workflow.processorfuzz import _disassembly_status, _package, _unique

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "samples/processorfuzz/real_case_001/raw/testis.zip"
EXPECTED = ROOT / "samples/processorfuzz/real_case_001/expected"


def test_real_zip_static_bytes_and_conflict():
    if not RAW.is_file():
        pytest.skip("Hardware-team raw ZIP is not available in this checkout")
    before = sha256(RAW.read_bytes()).hexdigest()
    assert before == "c0fe4e328be70238cfd7383fe3cc9b58267eeafc0795d1dbb8b4b074ad69df34"
    files, archive_sha = _package(RAW)
    manifest = json.loads((EXPECTED / "processorfuzz-case-manifest.json").read_text())
    assert archive_sha == manifest["archive_sha256"]
    assert manifest["schema_version"] == "processorfuzz-case-manifest/v2"
    assert {key: manifest[key] for key in (
        "package_role", "firmware_role", "firmware_origin", "customer_firmware", "role_basis"
    )} == {
        "package_role": "hardware_trigger_validation_package",
        "firmware_role": "hardware_supplied_trigger_test_firmware",
        "firmware_origin": "hardware_department",
        "customer_firmware": False,
        "role_basis": "hardware_team_delivery_intake",
    }
    si = parse_si(_unique(files, "si")[1])
    assert si.model_dump(mode="json") == json.loads((EXPECTED / "processorfuzz-si.json").read_text())
    image = ElfImage(_unique(files, "elf")[1])
    assert image.identity.sha256 == manifest["elf_sha256"]
    export = GhidraExport.model_validate_json((EXPECTED / "ghidra-export.json").read_bytes())
    analysis = normalize(image, export)
    assert analysis.model_dump(mode="json") == json.loads((EXPECTED / "firmware-analysis.json").read_text())
    assert _disassembly_status(_unique(files, "disassembly")[1], image)["status"] == "CONFLICT_WITH_ELF"
    assert any(x["role"] == "human_note" for x in manifest["unbound_artifacts"])
    report = (EXPECTED / "processorfuzz-report.md").read_text()
    assert "不是客户固件、生产固件或真实目标固件镜像" in report
    assert "不能证明客户固件包含该触发行为" in report
    assert "不是客户固件、生产固件或真实目标镜像" in (EXPECTED / "firmware-report.md").read_text()
    assert sha256(RAW.read_bytes()).hexdigest() == before


def test_review_copy_matches_canonical_expected():
    demo = ROOT / "artifacts/demo/processorfuzz/real_case_001"
    for path in EXPECTED.iterdir():
        assert (demo / path.name).read_bytes() == path.read_bytes()
    summary = json.loads((EXPECTED / "summary.json").read_text())
    assert summary["signature_different_word_count"] == 3
    assert summary["type2_verification_status"] == "NOT_ESTABLISHED"
    assert summary["architectural_differential_status"] == "UNKNOWN"
    differential = json.loads((EXPECTED / "architectural-differential.json").read_text())
    assert differential["status"] == "UNKNOWN"
    assert len(differential["different_fields"]) == 3
