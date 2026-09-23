"""Regenerate reviewable, path-independent demo artifacts from tracked inputs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from chipchain.cross_layer.matching import match_requirements, render_cross_layer_report
from chipchain.cross_layer.resource_binding import bind_capabilities, bind_resources
from chipchain.firmware.elf import ElfImage
from chipchain.firmware.ghidra import analyze_headless
from chipchain.firmware.ghidra_models import GhidraExport
from chipchain.firmware.ghidra_normalize import normalize
from chipchain.firmware.report import firmware_summary, render_firmware_report, write_firmware_result
from chipchain.firmware.static_capability import materialize_synthetic_static_capabilities
from chipchain.firmware.static_ir import serialize_analysis
from chipchain.hardware.resources import build_catalog, build_resource
from chipchain.workflow.type2 import analyze_manifest, report as verification_report, summary as verification_summary
from chipchain.firmware.mmio_grounding import canonical as frozen_canonical

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "positive": "type2-verification:9c7ef89582f89727fcacdb6b8bb7334ba79733c4182a6e7b341ba324e2fa6b82",
    "trigger-negative": "type2-verification:7dc13746b7067f7ce4adf6cc11ba8eeeb01a3b2582b7a2456b005704772477e7",
    "unknown": "type2-verification:21db55b0e4ddb2f545e57ebb731f09bd7bd1b6b465dbe4c63f4c49bd07dd526a",
}


def dump(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value.model_dump(mode="json") if hasattr(value, "model_dump") else value,
                               sort_keys=True, indent=2, ensure_ascii=False) + "\n")


def export_for(elf_path: Path | None, image: ElfImage, path: Path, *, refresh: bool) -> GhidraExport:
    if refresh:
        if elf_path is None:
            raise ValueError("Refresh requires an explicit tracked ELF path")
        result = analyze_headless(elf_path, image)
        dump(path, result.model_dump(mode="json", by_alias=True))
        return result
    return GhidraExport.model_validate_json(path.read_bytes())


def build_firmware(*, refresh: bool) -> None:
    for arch in ("arm", "riscv", "powerpc"):
        source = ROOT / "samples/firmware" / arch
        image = ElfImage.from_path(source / "sample.elf")
        manifest = json.loads((source / "manifest.json").read_text())
        if image.identity.architecture != manifest["architecture"] or image.identity.sha256 != manifest["elf_sha256"]:
            raise ValueError(f"ELF/manifest architecture or hash mismatch for {arch}")
        if manifest.get("sample_kind") != "synthetic_fixture":
            raise ValueError("Synthetic capability projection requires explicit fixture provenance")
        export_path = source / "expected/ghidra-export.json"
        exported = export_for(source / "sample.elf", image, export_path, refresh=refresh)
        analysis = normalize(image, exported)
        expected = source / "expected"
        (expected / "firmware-static-analysis.json").write_text(serialize_analysis(analysis))
        dump(expected / "firmware-summary.json", firmware_summary(analysis))
        (expected / "firmware-report.md").write_text(render_firmware_report(analysis))
        write_firmware_result(analysis, ROOT / "artifacts/demo/firmware" / arch,
                              export=exported.model_dump(mode="json", by_alias=True))
        capabilities = materialize_synthetic_static_capabilities(analysis, synthetic_fixture=True)
        dump(ROOT / "artifacts/demo/firmware" / arch / "static-capabilities.json",
             [c.model_dump(mode="json") for c in capabilities])


def catalog_for(contract):
    rows = (("ENABLE", 0x40000, ("read", "write")),
            ("COMMAND", 0x40004, ("read", "write")),
            ("STATUS", 0x40008, ("read",)))
    resources = tuple(build_resource(
        kind="MMIO_REGISTER", architecture="riscv", name=name,
        address_start=address, address_end=address, width_bits=32, access=access,
        source_id=contract.contract_id, scope="manually_curated_controlled_synthetic_fixture")
        for name, address, access in rows)
    return build_catalog(architecture="riscv", source_id=contract.contract_id,
                         scope="manually_curated_controlled_synthetic_fixture", resources=resources)


def build_type2(*, refresh: bool) -> None:
    catalog_id = None
    for name, manifest_name in (("positive", "type2_positive"),
                                ("trigger-negative", "type2_trigger_negative"),
                                ("unknown", "type2_unknown")):
        manifest = ROOT / "examples" / manifest_name / "manifest.json"
        verified = analyze_manifest(manifest)
        if verified.contract.scope.source_authority != "synthetic_fixture":
            raise ValueError("Type-II demo requires synthetic contract provenance")
        if verified.result.result_id != EXPECTED[name]:
            raise ValueError(f"Frozen Type-II regression changed for {name}")
        target = ROOT / "artifacts/demo/type2" / name
        image = ElfImage(verified.target.elf_bytes)
        if refresh:
            index = json.loads(manifest.read_text())
            run_path = (manifest.parent / index["target_run"]).resolve()
            elf_path = (run_path.parent / json.loads(run_path.read_text())["elf"]).resolve()
        else:
            elf_path = None
        exported = export_for(elf_path, image, target / "ghidra-export.json", refresh=refresh)
        static = normalize(image, exported)
        write_firmware_result(static, target)
        catalog = catalog_for(verified.contract)
        if catalog_id is not None and catalog_id != catalog.catalog_id:
            raise ValueError("Type-II demo catalog identity differs by scenario")
        catalog_id = catalog.catalog_id
        dump(ROOT / "artifacts/demo/type2/hardware-resource-catalog.json", catalog)
        dump(target / "hardware-contract.json", verified.contract)
        static_bindings = bind_resources(static, catalog)
        dump(target / "static-resource-bindings.json", static_bindings)
        projected = materialize_synthetic_static_capabilities(
            static, synthetic_fixture=True, bindings=static_bindings, catalog=catalog)
        dump(target / "static-capabilities.json", [c.model_dump(mode="json") for c in projected])
        bindings = bind_capabilities(verified.target.capabilities, catalog)
        candidate = match_requirements(verified.target.capabilities, bindings, verified.contract)
        dump(target / "resource-bindings.json", bindings)
        dump(target / "cross-layer-candidates.json", candidate)
        (target / "cross-layer-report.md").write_text(
            render_cross_layer_report(candidate, bindings, verified.contract,
                                      catalog=catalog, capabilities=verified.target.capabilities) +
            "\nGeneral Ghidra static facts and frozen CAP0 MMIO facts are distinct evidence streams. "
            "This candidate uses frozen CAP0 constraints; the accompanying static-resource-bindings "
            "and static-capabilities show which generic memory facts independently resolved to the catalog. "
            "Newly projected static capabilities are not substituted into the frozen runtime verifier.\n")
        (target / "verification.json").write_text(frozen_canonical(verified.result) + "\n")
        (target / "verification-report.md").write_text(verification_report(verified))
        dump(target / "summary.json", {
            "firmware_analysis_id": static.analysis_id,
            "resource_catalog_id": catalog.catalog_id,
            "resource_binding_set_id": bindings.binding_set_id,
            "candidate_id": candidate.candidate_id,
            "static_compatibility_status": candidate.static_compatibility_status,
            "verification": verification_summary(verified),
        })


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--refresh-ghidra", action="store_true",
                        help="run project Ghidra on every tracked sample before regenerating artifacts")
    args = parser.parse_args()
    build_firmware(refresh=args.refresh_ghidra)
    build_type2(refresh=args.refresh_ghidra)


if __name__ == "__main__":
    main()
