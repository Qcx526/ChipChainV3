"""Portable tests of ELF/Ghidra reconciliation and conservative ISA semantics."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.firmware.elf import ElfImage, ghidra_language
from chipchain.firmware.ghidra_models import ExportInstruction, GhidraExport
from chipchain.firmware.ghidra_normalize import normalize
from chipchain.firmware.report import firmware_summary, render_firmware_report
from chipchain.firmware.semantics import classify
from chipchain.firmware.static_capability import materialize_synthetic_static_capabilities
from chipchain.firmware.static_ir import FirmwareStaticAnalysis, StaticBehaviorKind as K
from chipchain.hardware.resources import build_catalog, build_resource
from chipchain.cross_layer.resource_binding import bind_resources, ExplicitManualBinding
from chipchain.cross_layer.resource_binding import bind_capabilities
from chipchain.cross_layer.matching import match_requirements
from chipchain.hardware.behavior_contract import (
    HardwareBehaviorContractInput, build_hardware_behavior_contract,
)
from chipchain.workflow.type2 import analyze_manifest

ROOT = Path(__file__).resolve().parents[2]


def fixture(arch):
    base = ROOT / "samples/firmware" / arch
    return ElfImage.from_path(base / "sample.elf"), GhidraExport.model_validate_json(
        (base / "expected/ghidra-export.json").read_bytes())


@pytest.mark.parametrize("arch,language", [
    ("arm", "ARM:LE:32:Cortex"), ("riscv", "RISCV:LE:32:default"),
    ("powerpc", "PowerPC:BE:32:default")])
def test_elf_identity_bytes_and_language(arch, language):
    image, exported = fixture(arch)
    assert image.identity.architecture == arch
    assert ghidra_language(image.identity) == exported.language == language
    if arch == "arm":
        assert image.identity.arm_profile == "M"
        with pytest.raises(ValueError, match="No Ghidra language"):
            ghidra_language(image.identity.model_copy(update={"arm_profile": "A"}))
    instruction = exported.instructions[0]
    assert image.mapped_bytes(instruction.pc, len(instruction.bytes) // 2, executable=True).hex() == instruction.bytes
    with pytest.raises(ValueError, match="not uniquely file-backed"):
        image.mapped_bytes(0xffffffff, 4, executable=True)


@pytest.mark.parametrize("arch", ["arm", "riscv", "powerpc"])
def test_normalized_structure_identity_and_semantics(arch):
    image, exported = fixture(arch)
    first = normalize(image, exported)
    second = normalize(image, exported)
    expected = json.loads((ROOT / f"samples/firmware/{arch}/expected/firmware-static-analysis.json").read_text())
    assert first.model_dump(mode="json") == second.model_dump(mode="json") == expected
    assert len(first.functions) >= 3 and len({x.fact_id for x in first.functions}) == len(first.functions)
    assert len(first.blocks) >= 3 and len(first.edges) >= 3
    assert all(e.source_block_id in {b.fact_id for b in first.blocks} for e in first.edges)
    assert len(first.calls) >= 1 and all(c.direct and c.target is not None for c in first.calls)
    kinds = {b.kind for b in first.behaviors}
    assert {K.MEMORY_LOAD, K.MEMORY_STORE, K.SYSTEM_REGISTER_READ, K.MEMORY_BARRIER} <= kinds
    assert K.MMIO_READ not in kinds and K.MMIO_WRITE not in kinds
    assert firmware_summary(first)["unsupported_count"] == 0


def test_ghidra_schema_and_byte_conflicts_fail_closed():
    image, exported = fixture("arm")
    payload = exported.model_dump(mode="json", by_alias=True)
    payload["instructions"][0]["bytes"] = "ffffffff"
    with pytest.raises(ValueError, match="byte mismatch"):
        normalize(image, GhidraExport.model_validate(payload))
    payload = exported.model_dump(mode="json", by_alias=True)
    payload["instructions"][0]["function_entry"] = 0xdeadbeef
    payload["instructions"][0]["function_id"] = "function:0xdeadbeef"
    with pytest.raises(ValueError, match="ownership conflict"):
        normalize(image, GhidraExport.model_validate(payload))
    payload = exported.model_dump(mode="json", by_alias=True)
    payload["instructions"].append(payload["instructions"][0])
    with pytest.raises(ValidationError, match="Duplicate Ghidra"):
        GhidraExport.model_validate(payload)


@pytest.mark.parametrize("arch", ["arm", "riscv", "powerpc"])
def test_unsupported_instruction_preserved_without_analysis_failure(arch):
    image, exported = fixture(arch)
    payload = exported.model_dump(mode="json", by_alias=True)
    payload["instructions"][0]["mnemonic"] = "unsupported_xyz"
    payload["instructions"][0]["text"] = "unsupported_xyz"
    analysis = normalize(image, GhidraExport.model_validate(payload))
    behavior = analysis.behaviors[0]
    assert behavior.kind == K.UNKNOWN and behavior.semantic_status == "unsupported"
    assert analysis.instructions[0].raw_bytes == exported.instructions[0].bytes
    assert behavior.pc == exported.instructions[0].pc


def test_unknown_address_does_not_turn_into_mmio():
    i = ExportInstruction(pc=4, bytes="0000", mnemonic="str", operands=["r1", "[r0,#0x0]"],
                          text="str r1,[r0,#0x0]", function_entry=None, block_start=None)
    result = classify(i, "arm", {})[0]
    assert result["kind"] == K.MEMORY_STORE
    assert result["address_status"] == "unknown"


def test_report_determinism_and_unknown_disclosure():
    image, exported = fixture("riscv")
    analysis = normalize(image, exported)
    text = render_firmware_report(analysis)
    assert text == render_firmware_report(analysis)
    for section in ("Analysis Summary", "Functions", "Basic Blocks and CFG", "Call Analysis",
                    "Memory Access Analysis", "Hardware-facing Behaviors", "Unresolved / Unsupported Facts",
                    "Provenance and Toolchain", "Scientific Limitations"):
        assert section in text
    assert "Unresolved ≠ nonexistent" in text
    assert analysis.analysis_id in text


def test_resource_binding_unique_ambiguous_and_unbound():
    image, exported = fixture("riscv")
    analysis = normalize(image, exported)
    one = build_resource(kind="MMIO_REGISTER", architecture="riscv", name="R0",
                         address_start=0x40000000, address_end=0x40000000,
                         width_bits=32, access=("read", "write"), source_id="test:source", scope="synthetic")
    other = build_resource(kind="MEMORY_REGION", architecture="riscv", name="R1",
                           address_start=0x40000000, address_end=0x400000ff,
                           width_bits=32, access=("read", "write"), source_id="test:source", scope="synthetic")
    catalog = build_catalog(architecture="riscv", source_id="test:source", scope="synthetic", resources=(one,))
    bindings = bind_resources(analysis, catalog)
    memory = {b.fact_id for b in analysis.behaviors if b.kind in {K.MEMORY_LOAD, K.MEMORY_STORE}}
    assert {b.status for b in bindings.bindings if b.firmware_behavior_id in memory} == {"SUPPORTED"}
    assert {b.status for b in bindings.bindings if b.firmware_behavior_id not in memory} == {"NOT_APPLICABLE", "UNKNOWN"}
    overlap = build_catalog(architecture="riscv", source_id="test:source", scope="synthetic",
                            resources=(one, other))
    ambiguous = bind_resources(analysis, overlap)
    assert {b.status for b in ambiguous.bindings if b.firmware_behavior_id in memory} == {"AMBIGUOUS"}
    assert bindings.binding_set_id == bind_resources(analysis, catalog).binding_set_id
    site = next(b for b in analysis.behaviors if b.kind == K.MEMORY_STORE)
    declared = ExplicitManualBinding(firmware_behavior_id=site.fact_id,
                                     hardware_resource_id=one.resource_id,
                                     source_id="manual:research-record", reason="authored mapping")
    manual = bind_resources(analysis, overlap, manual_bindings=(declared,))
    selected = next(b for b in manual.bindings if b.firmware_behavior_id == site.fact_id)
    assert selected.binding_kind == "explicit_manual_binding" and selected.status == "UNKNOWN"
    assert "manual:research-record" in selected.evidence_ids


def test_mutated_analysis_identity_rejected():
    image, exported = fixture("arm")
    payload = normalize(image, exported).model_dump(mode="json")
    payload["analysis_id"] = "firmware-static:" + "0" * 64
    with pytest.raises(ValidationError, match="identity mismatch"):
        FirmwareStaticAnalysis.model_validate(payload)


@pytest.mark.parametrize("arch", ["arm", "riscv", "powerpc"])
def test_synthetic_cap0_projection_is_static_and_source_bound(arch):
    image, exported = fixture(arch)
    analysis = normalize(image, exported)
    with pytest.raises(ValueError, match="lacks a general"):
        materialize_synthetic_static_capabilities(analysis, synthetic_fixture=False)
    capabilities = materialize_synthetic_static_capabilities(analysis, synthetic_fixture=True)
    assert capabilities
    assert all(c.origin.kind == "synthetic_fixture" and c.entry.execution_status == "static_only"
               for c in capabilities)
    assert all(p.control.status == "not_established" for c in capabilities for p in c.primitives)
    assert all(analysis.analysis_id in c.source_artifact_ids for c in capabilities)
    kinds = {p.kind.value for c in capabilities for p in c.primitives}
    assert {"MEMORY_READ", "MEMORY_WRITE", "DIRECT_CONTROL_TRANSFER"} <= kinds
    assert "MMIO_READ" not in kinds and "MMIO_WRITE" not in kinds
    assert "CSR_READ" in kinds if arch == "riscv" else "CSR_READ" not in kinds
    assert {c.capability_id for c in capabilities} == {
        c.capability_id for c in materialize_synthetic_static_capabilities(analysis, synthetic_fixture=True)}


@pytest.mark.parametrize("kind,resource_kind,address,identity", [
    ("CSR_access", "CSR", None, "0x0300"),
    ("memory_operation", "MEMORY_REGION", 0x40000000, None),
])
def test_typed_csr_and_memory_requirement_match(kind, resource_kind, address, identity):
    image, exported = fixture("riscv")
    analysis = normalize(image, exported)
    capabilities = materialize_synthetic_static_capabilities(analysis, synthetic_fixture=True)
    resource = build_resource(kind=resource_kind, architecture="riscv", name="typed-resource",
                              address_start=address, address_end=address,
                              register_identity=identity, width_bits=32 if address is not None else None,
                              access=("read", "write"), source_id="test:typed", scope="synthetic")
    catalog = build_catalog(architecture="riscv", source_id="test:typed", scope="synthetic", resources=(resource,))
    bindings = bind_capabilities(capabilities, catalog)
    original = analyze_manifest(ROOT / "examples/type2_positive/manifest.json").contract
    payload = original.model_dump(mode="json", exclude={"contract_id", "contract_sha256", "schema_version"})
    requirement = original.trigger[0].model_dump(mode="json")
    requirement.update(condition_id="test:typed-requirement", condition_kind=kind,
                       instructions=[], ordering=None,
                       access={"kind": "csr_access", "atom_id": "test:csr-atom", "csr_identity": identity,
                               "access": "read", "purpose": "required", "value_constraint": None,
                               "csr_address": None} if kind == "CSR_access" else None,
                       required_relation={"subject": "address", "operator": "eq", "operands": [address],
                                          "unit": None} if kind == "memory_operation" else None)
    payload["trigger"] = [requirement]
    contract = build_hardware_behavior_contract(HardwareBehaviorContractInput.model_validate(payload))
    candidate = match_requirements(capabilities, bindings, contract)
    assert candidate.static_compatibility_status == "SUPPORTED"
    assert next(x for x in candidate.requirements if x.requirement_id == "test:typed-requirement").static_compatibility_status == "SUPPORTED"
    assert next(x for x in candidate.requirements if x.requirement_id == "hbc:platform-and-scope").static_compatibility_status == "UNKNOWN"
