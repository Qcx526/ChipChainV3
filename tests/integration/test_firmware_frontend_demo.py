"""Offline integration over tracked three-ISA exports and frozen Type-II fixtures."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from chipchain.cross_layer.matching import match_requirements, render_cross_layer_report
from chipchain.cross_layer.resource_binding import bind_capabilities, bind_resources
from chipchain.firmware.elf import ElfImage
from chipchain.firmware.ghidra_models import GhidraExport
from chipchain.firmware.ghidra_normalize import normalize
from chipchain.firmware.report import write_firmware_result
from chipchain.firmware.static_capability import materialize_synthetic_static_capabilities
from chipchain.hardware.resources import HardwareResourceCatalog
from chipchain.workflow.type2 import analyze_manifest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("arch", ["arm", "riscv", "powerpc"])
def test_tracked_elf_to_canonical_report(arch, tmp_path):
    sample = ROOT / "samples/firmware" / arch
    image = ElfImage.from_path(sample / "sample.elf")
    export = GhidraExport.model_validate_json((sample / "expected/ghidra-export.json").read_bytes())
    result = normalize(image, export)
    write_firmware_result(result, tmp_path / "result")
    for output, expected in (("firmware-analysis.json", "firmware-static-analysis.json"),
                             ("firmware-summary.json", "firmware-summary.json"),
                             ("firmware-report.md", "firmware-report.md")):
        assert (tmp_path / "result" / output).read_bytes() == (sample / "expected" / expected).read_bytes()


@pytest.mark.parametrize("name,manifest,status", [
    ("positive", "type2_positive", "SUPPORTED"),
    ("trigger-negative", "type2_trigger_negative", "CONTRADICTED"),
    ("unknown", "type2_unknown", "SUPPORTED")])
def test_type2_static_binding_candidate_and_runtime_separation(name, manifest, status):
    verified = analyze_manifest(ROOT / "examples" / manifest / "manifest.json")
    directory = ROOT / "artifacts/demo/type2" / name
    image = ElfImage(verified.target.elf_bytes)
    export = GhidraExport.model_validate_json((directory / "ghidra-export.json").read_bytes())
    static = normalize(image, export)
    catalog = HardwareResourceCatalog.model_validate_json(
        (ROOT / "artifacts/demo/type2/hardware-resource-catalog.json").read_bytes())
    static_bindings = bind_resources(static, catalog)
    assert sum(b.status == "SUPPORTED" for b in static_bindings.bindings) >= 3
    projected = materialize_synthetic_static_capabilities(
        static, synthetic_fixture=True, bindings=static_bindings, catalog=catalog)
    projected_kinds = [p.kind.value for c in projected for p in c.primitives]
    assert projected_kinds.count("MMIO_WRITE") == 2 and projected_kinds.count("MMIO_READ") == 1
    bindings = bind_capabilities(verified.target.capabilities, catalog)
    candidate = match_requirements(verified.target.capabilities, bindings, verified.contract)
    assert candidate.static_compatibility_status == status
    assert candidate.verification_required
    assert candidate.model_dump(mode="json") == json.loads((directory / "cross-layer-candidates.json").read_text())
    assert render_cross_layer_report(candidate, bindings, verified.contract,
                                     catalog=catalog, capabilities=verified.target.capabilities) in (
        directory / "cross-layer-report.md").read_text()
    assert verified.result.result_id == json.loads((directory / "summary.json").read_text())["verification"]["result_id"]


def test_no_evaluator_label_controls_static_match():
    positive = analyze_manifest(ROOT / "examples/type2_positive/manifest.json")
    unknown = analyze_manifest(ROOT / "examples/type2_unknown/manifest.json")
    catalog = HardwareResourceCatalog.model_validate_json(
        (ROOT / "artifacts/demo/type2/hardware-resource-catalog.json").read_bytes())
    p = match_requirements(positive.target.capabilities,
                           bind_capabilities(positive.target.capabilities, catalog), positive.contract)
    u = match_requirements(unknown.target.capabilities,
                           bind_capabilities(unknown.target.capabilities, catalog), unknown.contract)
    assert p.candidate_id == u.candidate_id
    assert positive.result.final_status != unknown.result.final_status
