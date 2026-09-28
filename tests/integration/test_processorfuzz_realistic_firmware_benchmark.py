"""Replay the tracked synthetic firmware pair without GCC or Ghidra."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import pytest

from chipchain.firmware.elf import ElfImage
from chipchain.firmware.ghidra_models import GhidraExport
from chipchain.firmware.ghidra_normalize import normalize
from chipchain.firmware.report import firmware_summary
from chipchain.firmware.static_ir import StaticBehaviorKind


ROOT = Path(__file__).resolve().parents[2]
BENCHMARK = ROOT / "samples/firmware/riscv/processorfuzz_real_case_001"
TARGET_PC = 0x80000064
FROZEN = {
    "positive": {
        "elf_sha256": "35f9fff9c00e6a93bb9e6884b8604cd3d36dd35f7fdea408412633c5b7ae9fe4",
        "mnemonic": "sfence.vma",
        "raw_bytes": "73000012",
        "behavior": StaticBehaviorKind.TLB_INVALIDATE,
        "tlb_invalidate_count": 1,
        "barrier_count": 1,
    },
    "negative_trigger": {
        "elf_sha256": "2b6275ffb203f5ffc5411bb9200f5eafaab61fe6615a403697ecabace469e7cd",
        "mnemonic": "fence",
        "raw_bytes": "0f003003",
        "behavior": StaticBehaviorKind.MEMORY_BARRIER,
        "tlb_invalidate_count": 0,
        "barrier_count": 2,
    },
}


@pytest.mark.parametrize("variant", FROZEN)
def test_tracked_elf_replays_frozen_static_analysis(variant: str) -> None:
    frozen = FROZEN[variant]
    elf_path = BENCHMARK / variant / "firmware.elf"
    expected = BENCHMARK / "expected" / variant
    elf_bytes = elf_path.read_bytes()
    assert sha256(elf_bytes).hexdigest() == frozen["elf_sha256"]

    image = ElfImage(elf_bytes)
    assert (image.identity.architecture, image.identity.bit_width,
            image.identity.endianness, image.identity.entry) == (
                "riscv", 64, "little", 0x80000000)
    export = GhidraExport.model_validate_json((expected / "ghidra-export.json").read_bytes())
    analysis = normalize(image, export)
    assert analysis.model_dump(mode="json") == json.loads(
        (expected / "firmware-analysis.json").read_text())
    summary = json.loads((expected / "firmware-summary.json").read_text())
    assert firmware_summary(analysis) == summary
    assert (summary["elf_sha256"], summary["architecture"], summary["bit_width"],
            summary["endianness"], summary["entry_address"]) == (
                frozen["elf_sha256"], "riscv", 64, "little", "0x80000000")
    assert (summary["function_count"], summary["basic_block_count"],
            summary["instruction_count"]) == (33, 164, 858)
    assert (summary["tlb_invalidate_count"], summary["barrier_count"]) == (
        frozen["tlb_invalidate_count"], frozen["barrier_count"])

    target = [instruction for instruction in analysis.instructions
              if instruction.pc == TARGET_PC]
    assert len(target) == 1
    instruction = target[0]
    assert (instruction.mnemonic, instruction.raw_bytes) == (
        frozen["mnemonic"], frozen["raw_bytes"])
    assert image.mapped_bytes(TARGET_PC, 4, executable=True) == bytes.fromhex(
        frozen["raw_bytes"])
    functions = {function.fact_id: function.name for function in analysis.functions}
    assert {functions[identifier] for identifier in instruction.function_ids} == {
        "arch_translation_sync"}
    behaviors = [behavior for behavior in analysis.behaviors
                 if behavior.instruction_id == instruction.fact_id]
    assert [(behavior.kind, behavior.semantic_status) for behavior in behaviors] == [
        (frozen["behavior"], "supported")]


def test_pair_differs_only_at_the_selected_instruction() -> None:
    streams = {}
    for variant in FROZEN:
        analysis = json.loads((BENCHMARK / "expected" / variant /
                               "firmware-analysis.json").read_text())
        streams[variant] = {
            instruction["pc"]: (instruction["mnemonic"], instruction["raw_bytes"])
            for instruction in analysis["instructions"]
        }
    positive = streams["positive"]
    negative = streams["negative_trigger"]
    assert positive.keys() == negative.keys()
    assert {pc for pc in positive if positive[pc] != negative[pc]} == {TARGET_PC}


def test_contract_preserves_synthetic_scope_and_unknown_runtime() -> None:
    contract = json.loads((BENCHMARK / "benchmark-contract.json").read_text())
    assert contract["sample_kind"] == "realistic_synthetic_firmware"
    assert contract["contract_kind"] == "SyntheticBenchmarkContract"
    assert contract["positive_variant"] == "positive"
    assert contract["negative_variant"] == "negative_trigger"
    assert contract["positive_expectation"] == "SATISFIES_SYNTHETIC_BENCHMARK_CONTRACT"
    assert contract["negative_expectation"] == "CONTRADICTS_SYNTHETIC_BENCHMARK_CONTRACT"
    for field in ("runtime_execution_status", "real_hardware_trigger_status",
                  "hardware_deviation_status", "type2_verification_status",
                  "physical_silicon_applicability"):
        assert contract[field] == "NOT_ESTABLISHED"
