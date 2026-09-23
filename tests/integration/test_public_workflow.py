"""Portable public examples replay frozen scientific identities without local output."""
import json
from pathlib import Path

import pytest

from chipchain.cli import main
from chipchain.workflow.type2 import analyze_manifest, write_result

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {
    "type2_positive": ("verified_controlled_type2_chain",
        "type2-verification:9c7ef89582f89727fcacdb6b8bb7334ba79733c4182a6e7b341ba324e2fa6b82"),
    "type2_trigger_negative": ("trigger_contradicted",
        "type2-verification:7dc13746b7067f7ce4adf6cc11ba8eeeb01a3b2582b7a2456b005704772477e7"),
    "type2_unknown": ("unknown",
        "type2-verification:21db55b0e4ddb2f545e57ebb731f09bd7bd1b6b465dbe4c63f4c49bd07dd526a"),
}


@pytest.mark.parametrize("name", EXPECTED)
def test_portable_example_identity(name, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    analysis = analyze_manifest(ROOT / "examples" / name / "manifest.json")
    assert list(tmp_path.iterdir()) == []  # analysis is read-only
    status, identity = EXPECTED[name]
    assert (analysis.result.final_status, analysis.result.result_id) == (status, identity)
    output = write_result(analysis, tmp_path / "result")
    assert {p.name for p in output.iterdir()} == {"summary.json", "verification.json", "report.md"}
    assert json.loads((output / "summary.json").read_text())["result_id"] == identity
    assert type(analysis.result).model_validate_json((output / "verification.json").read_text()) == analysis.result
    with pytest.raises(FileExistsError):
        write_result(analysis, output)
    if name == "type2_positive":
        control = analysis.result.reference_control
        assert control.verification_id == (
            "type2-reference-control:2d1ae9b25f06e6009e54b2081253ad93da1b3f8c1d91e942fd4ef6ed7dea28ab")
        assert (control.trigger_status, control.expected_behavior_status, control.deviation_observed) == (
            "supported", "supported", False)


def test_cli_verbose_is_opt_in(tmp_path):
    result = tmp_path / "result"
    assert main(["analyze", "--manifest", str(ROOT / "examples/type2_positive/manifest.json"),
                 "--output", str(result), "--verbose-artifacts"]) == 0
    assert (result / "target-bridge.json").is_file()
    assert (result / "reference-static.json").is_file()
    assert (result / "target-capabilities.json").is_file()


def test_bad_artifact_fails_closed_without_output(tmp_path):
    manifest = json.loads((ROOT / "examples/type2_positive/manifest.json").read_text())
    manifest["contract"] = "missing-contract.json"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises(FileNotFoundError):
        analyze_manifest(path)
    with pytest.raises(SystemExit) as exc:
        main(["analyze", "--manifest", str(path), "--output", str(tmp_path / "result")])
    assert exc.value.code == 2
    assert not (tmp_path / "result").exists()
