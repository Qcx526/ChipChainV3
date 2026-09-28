"""Offline CLI replay of the signature-only delivery; no inferred run binding."""
from hashlib import sha256
import json
from pathlib import Path
from zipfile import ZipFile

import pytest

from chipchain.cli import main
from chipchain.firmware.ghidra_models import GhidraExport
from chipchain.firmware.static_ir import content_id
from chipchain.workflow import processorfuzz as workflow

ROOT = Path(__file__).resolve().parents[2]
CASE = ROOT / "samples/processorfuzz/real_case_002"
RAW = CASE / "raw/testis.zip"
EXPECTED = CASE / "expected"
SI = "testis/out/tests/.input_1.si"
ELF = "testis/out/tests/.input_1.elf"
RAW_SHA = "7384a5337a0811c16c52bdd0c82f54e8765623c201223d44570b9c5f0f6b8161"


@pytest.fixture
def replay(monkeypatch):
    assert RAW.is_file(), "The supported signature-only fixture must be present"
    export = GhidraExport.model_validate_json((EXPECTED / "ghidra-export.json").read_bytes())
    # Replace only the external exporter. Real ELF validation, normalization,
    # ingestion, rendering and CLI writing still run, under offline_only.
    monkeypatch.setattr(workflow, "analyze_headless", lambda *a, **kw: export)
    return workflow._package(RAW)[0]


def _run(package, output, *, si=SI, elf=ELF):
    return main(["processorfuzz", "analyze", "--package", str(package), "--output", str(output),
                 "--si-member", si, "--elf-member", elf])


def _json(folder, name):
    return json.loads((folder / name).read_text())


def test_real_signature_only_cli_replay_is_deterministic(tmp_path, replay):
    assert sha256(RAW.read_bytes()).hexdigest() == RAW_SHA
    renamed = tmp_path / "unrelated-name.zip"
    renamed.write_bytes(RAW.read_bytes())
    for index, package in enumerate((RAW, renamed)):
        output = tmp_path / f"result-{index}"
        assert _run(package, output) == 0
        assert {p.name for p in output.iterdir()} == {p.name for p in EXPECTED.iterdir()}
        for expected in EXPECTED.iterdir():
            assert (output / expected.name).read_bytes() == expected.read_bytes(), expected.name
    manifest = _json(output, "processorfuzz-case-manifest.json")
    assert len(manifest["inventory"]) == 105
    assert {x["path"]: x["sha256"] for x in manifest["inventory"]} == {
        path: sha256(data).hexdigest() for path, data in replay.items()}
    assert manifest["package_role"] == manifest["firmware_role"] == "unclassified"
    assert manifest["customer_firmware"] is None
    assert manifest["selection_basis"]["provenance_binding"] == "UNKNOWN"
    assert set(manifest["bindings"].values()) == {"UNKNOWN"}
    for key in ("rtl_trace_sha256", "isa_trace_sha256", "isa_log_sha256"):
        assert manifest[key] is None
    for key in ("rtl_trace", "isa_csv", "isa_log"):
        assert manifest["selected_paths"][key] is None
    unbound = {x["path"] for x in manifest["unbound_artifacts"]}
    assert {"testis/usebug/timer.elf", "testis/tests/.input_MPIEnotMIE.si",
            "testis/tests/.input_timer_normal.si", "testis/tests/.input_timer_with_bug.si",
            "testis/out/tests/.input_1.asm", "testis/note.log"} <= unbound
    summary = _json(output, "summary.json")
    assert summary["execution_trace_status"] == "MISSING"
    assert summary["runtime_source_binding"] == summary["architectural_differential_status"] == "UNKNOWN"
    assert summary["type2_verification_status"] == "NOT_ESTABLISHED"
    assert summary["type2_verification_readiness"] == "not verification-ready"
    assert summary["rtl_instruction_count"] is summary["isa_instruction_count"] is summary["isa_log_instruction_count"] is None
    for name in ("rtl-runtime-evidence.json", "isa-reference-evidence.json", "verification.json"):
        assert not (output / name).exists()
    for name in ("rtl-signature.json", "isa-signature.json"):
        signature = _json(output, name)
        assert signature["source"] is None
        assert len(signature["words"]) == 254
        assert "instruction_observations" not in signature
    diff = _json(output, "architectural-differential.json")
    assert diff["matching_fields"] == 254 and not diff["different_fields"]
    assert diff["raw_values_differ"] is False and diff["status"] == "UNKNOWN"
    fields = {k: v for k, v in diff.items() if k != "differential_id"}
    assert diff["differential_id"] == content_id("architectural-differential", fields)
    assert sha256(RAW.read_bytes()).hexdigest() == RAW_SHA


def test_ambiguous_or_wrong_selection_is_rejected(tmp_path, replay):
    with pytest.raises(SystemExit) as exc:
        main(["processorfuzz", "analyze", "--package", str(RAW), "--output", str(tmp_path / "ambiguous")])
    assert exc.value.code == 2
    with pytest.raises(ValueError, match="Ambiguous elf"):
        workflow.analyze_package(RAW, tmp_path / "ambiguous-elf", si_member=SI)
    with pytest.raises(ValueError, match="wrong artifact role"):
        workflow.analyze_package(RAW, tmp_path / "wrong", si_member=ELF, elf_member=ELF)
    with pytest.raises(ValueError, match="absent"):
        workflow.analyze_package(RAW, tmp_path / "missing", si_member="missing.si", elf_member=ELF)


def test_selecting_a_different_si_does_not_bind_it_to_elf(tmp_path, replay):
    output = tmp_path / "other-si"
    assert _run(RAW, output, si="testis/tests/.input_timer_with_bug.si") == 0
    manifest = _json(output, "processorfuzz-case-manifest.json")
    assert manifest["case_id"] != _json(EXPECTED, "processorfuzz-case-manifest.json")["case_id"]
    assert manifest["bindings"]["si_to_elf"] == "UNKNOWN"
    assert _json(output, "architectural-differential.json")["status"] == "UNKNOWN"


@pytest.mark.parametrize("mutation,error", [
    ("partial_trace", "Missing required isa_csv"),
    ("missing_signature", "Missing required rtl_signature"),
    ("ambiguous_signature", "Ambiguous rtl_signature"),
    ("malformed_signature", "Unsupported signature format"),
])
def test_incomplete_or_invalid_records_are_not_silently_discarded(tmp_path, replay, mutation, error):
    files = {name: replay[name] for name in (SI, ELF, "testis/out/.rtl_sig_0.txt", "testis/out/.isa_sig_0.txt")}
    if mutation == "partial_trace":
        files["traces/rtl_7.log"] = b"unparsed trace"
    elif mutation == "missing_signature":
        del files["testis/out/.rtl_sig_0.txt"]
    elif mutation == "ambiguous_signature":
        files["different/rtl_sig_9.txt"] = b"1" * 32 + b"\n"
    else:
        files["testis/out/.rtl_sig_0.txt"] = b"not a signature\n"
    package = tmp_path / "delivery.zip"
    with ZipFile(package, "w") as archive:
        for path, data in files.items():
            archive.writestr(path, data)
    with pytest.raises(ValueError, match=error):
        workflow.analyze_package(package, tmp_path / "result")
    assert not (tmp_path / "result/summary.json").exists()


def test_signature_only_output_cannot_retain_previous_runtime_evidence(tmp_path, replay):
    previous = tmp_path / "result"
    previous.mkdir()
    stale = previous / "rtl-runtime-evidence.json"
    stale.write_bytes(b"prior evidence")
    with pytest.raises(ValueError, match="new or empty"):
        workflow.analyze_package(RAW, previous, si_member=SI, elf_member=ELF)
    assert stale.read_bytes() == b"prior evidence"


def test_existing_trace_case_full_workflow_unchanged(tmp_path, monkeypatch):
    case = ROOT / "samples/processorfuzz/real_case_001"
    expected = case / "expected"
    export = GhidraExport.model_validate_json((expected / "ghidra-export.json").read_bytes())
    monkeypatch.setattr(workflow, "analyze_headless", lambda *a, **kw: export)
    output = tmp_path / "old-case"
    assert main(["processorfuzz", "analyze", "--package", str(case / "raw/testis.zip"),
                 "--output", str(output), "--hardware-trigger-validation"]) == 0
    assert {p.name for p in output.iterdir()} == {p.name for p in expected.iterdir()}
    for path in expected.iterdir():
        assert (output / path.name).read_bytes() == path.read_bytes(), path.name
