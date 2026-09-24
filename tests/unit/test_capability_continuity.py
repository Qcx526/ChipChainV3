"""Exact static/runtime matching never uses scenario labels or ordering."""
from __future__ import annotations

from pathlib import Path

from chipchain.cross_layer.capability_continuity import bind_static_runtime_capabilities
from chipchain.cross_layer.resource_binding import bind_resources
from chipchain.firmware.capability import NumericConstraint, NumericDomain
from chipchain.firmware.elf import ElfImage
from chipchain.firmware.ghidra_models import GhidraExport
from chipchain.firmware.ghidra_normalize import normalize
from chipchain.firmware.static_capability import materialize_synthetic_static_capabilities
from chipchain.hardware.resources import HardwareResourceCatalog
from chipchain.workflow.type2 import analyze_manifest

ROOT = Path(__file__).resolve().parents[2]


def _pair():
    run = analyze_manifest(ROOT / "examples/type2_positive/manifest.json")
    export = GhidraExport.model_validate_json((ROOT / "artifacts/demo/type2/positive/ghidra-export.json").read_bytes())
    analysis = normalize(ElfImage(run.target.elf_bytes), export)
    catalog = HardwareResourceCatalog.model_validate_json(
        (ROOT / "artifacts/demo/type2/hardware-resource-catalog.json").read_bytes())
    static = materialize_synthetic_static_capabilities(
        analysis, synthetic_fixture=True, bindings=bind_resources(analysis, catalog), catalog=catalog)
    for source in static:
        bound = bind_static_runtime_capabilities((source,), run.target.capabilities).bindings[0]
        if bound.status == "BOUND" and source.primitives[0].kind.value == "MMIO_WRITE":
            runtime = next(x for x in run.target.capabilities if x.capability_id == bound.runtime_capability_ids[0])
            return source, runtime
    raise AssertionError("No exact write pair")


def test_bound_unknown_ambiguous_and_contradicted():
    source, runtime = _pair()
    binding = lambda candidates: bind_static_runtime_capabilities((source,), tuple(candidates)).bindings[0]
    assert binding((runtime,)).status == "BOUND"
    assert binding(()).status == "UNKNOWN"
    duplicate = runtime.model_copy(update={"capability_id": "counterfactual:duplicate"})
    assert binding((runtime, duplicate)).status == "AMBIGUOUS"
    changed = []
    for constraint in runtime.constraints:
        if isinstance(constraint, NumericConstraint) and constraint.kind == "value":
            constraint = constraint.model_copy(update={"domain": NumericDomain(exact=999, bit_width=32)})
        changed.append(constraint)
    conflicting = runtime.model_copy(update={"constraints": changed})
    assert binding((conflicting,)).status == "CONTRADICTED"
