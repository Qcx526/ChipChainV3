"""Explicitly synthetic callback streams for offline evidence-contract tests.

These short streams use known ELF byte locations but assert no actual run.
Real acceptance artifacts are acquired separately through the public CLI.
"""
from hashlib import sha256
import json
from pathlib import Path

from chipchain.firmware.static_ir import FirmwareStaticAnalysis
from chipchain.runtime.acquisition import ACQUISITION_ARGS
from chipchain.runtime.artifacts import _qemu_metadata, write_runtime_evidence
from chipchain.runtime.binding import materialize_runtime
from chipchain.runtime.qemu_evidence import (
    AcquisitionPolicy, QemuRuntimeRunDescriptor, RuntimeProfile, identified,
)
from chipchain.runtime.qemu_profile import RISCV64_FW_FEASIBILITY
from chipchain.runtime.image_mapping import declared_identity_mapping

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / "samples/firmware/riscv/processorfuzz_real_case_001"
SYNTHETIC_PLUGIN = b"synthetic test instrumentation; never executed"


def synthetic_runtime(variant="positive", pcs=None):
    elf_bytes = (BENCHMARK / variant / "firmware.elf").read_bytes()
    analysis = FirmwareStaticAnalysis.model_validate_json(
        (BENCHMARK / "expected" / variant / "firmware-analysis.json").read_text())
    by_pc = {item.pc: item for item in analysis.instructions}
    if pcs is None:
        pcs = (analysis.artifact.entry, 0x8000005c, 0x80000064, 0x80000068)
    policy = AcquisitionPolicy(kind="event_prefix", target_pc=None,
                               successor_events=0, max_events=len(pcs))
    bundle, checksums = _qemu_metadata(ROOT)
    run = identified(
        QemuRuntimeRunDescriptor, firmware=analysis.artifact,
        image_mapping=declared_identity_mapping(analysis.artifact),
        profile=RuntimeProfile.from_profile(RISCV64_FW_FEASIBILITY),
        qemu_version="11.1.1", qemu_executable_sha256=checksums["bin/qemu-system-riscv64"],
        qemu_bundle_sha256=bundle, plugin_sha256=sha256(SYNTHETIC_PLUGIN).hexdigest(),
        plugin_source_sha256=sha256((ROOT / "tools/qemu/plugins/chipchain_trace.c").read_bytes()).hexdigest(),
        plugin_api_header_sha256=sha256((ROOT / "tools/qemu/plugins/qemu-plugin-v7.h").read_bytes()).hexdigest(),
        plugin_header_provenance_sha256=sha256((ROOT / "tools/qemu/plugins/header-provenance.json").read_bytes()).hexdigest(),
        acquisition_args=ACQUISITION_ARGS, policy=policy,
    )
    records = [{"record": "header", "schema": "chipchain-qemu-trace/v1", "run_id": run.run_id, "target": "riscv64",
                "vcpu_count": 1, "api_version": 7, "policy": policy.model_dump(mode="json")}]
    records += [{"record": "event", "sequence": n, "vcpu": 0, "pc": pc,
                 "instruction_bytes": by_pc[pc].raw_bytes,
                 "instruction_size": len(by_pc[pc].raw_bytes) // 2} for n, pc in enumerate(pcs)]
    records.append({"record": "end", "event_count": len(pcs), "target_sequence": None,
                    "stop_reason": "event_bound"})
    raw = b"".join(json.dumps(row, sort_keys=True).encode() + b"\n" for row in records)
    return run, raw, analysis, elf_bytes


def write_synthetic_runtime(directory, variant="positive", pcs=None):
    run, raw, analysis, elf_bytes = synthetic_runtime(variant, pcs)
    evidence = materialize_runtime(run, raw, analysis=analysis, elf_bytes=elf_bytes)
    directory.mkdir(parents=True)
    (directory / "raw-events.jsonl").write_bytes(raw)
    (directory / "firmware.elf").write_bytes(elf_bytes)
    (directory / "trace-plugin.so").write_bytes(SYNTHETIC_PLUGIN)
    write_runtime_evidence(evidence, directory)
    return evidence, analysis
