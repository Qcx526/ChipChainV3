"""Scientific source binding and deterministic projection, using synthetic streams."""
from __future__ import annotations

import inspect
import json

import pytest

from chipchain.firmware.static_ir import FirmwareStaticAnalysis, StaticBehaviorKind as K, content_id
from chipchain.runtime import binding
from chipchain.runtime.artifacts import ARTIFACTS, load_runtime_evidence, serialize
from chipchain.runtime.binding import materialize_runtime, observed_before
from chipchain.runtime.decoders import DECODERS, RiscVRuntimeDecoder, decoder_for
from chipchain.runtime.qemu_evidence import (
    QemuRuntimeRunDescriptor, RuntimeEvent, RuntimeProfile, identified,
)
from chipchain.runtime.qemu_profile import QemuRunProfile
from tests.runtime_fixtures import synthetic_runtime, write_synthetic_runtime


def replay(inputs):
    run, raw, analysis, elf_bytes = inputs
    return materialize_runtime(run, raw, analysis=analysis, elf_bytes=elf_bytes)


def change_records(raw, transform):
    records = [json.loads(line) for line in raw.splitlines()]
    transform(records)
    return b"".join(json.dumps(row, sort_keys=True).encode() + b"\n" for row in records)


@pytest.mark.parametrize("variant,kind,mnemonic,encoding", [
    ("positive", K.TLB_INVALIDATE, "sfence.vma", "73000012"),
    ("negative_trigger", K.MEMORY_BARRIER, "fence", "0f003003"),
])
def test_exact_runtime_semantics_and_binding(variant, kind, mnemonic, encoding):
    result = replay(synthetic_runtime(variant))
    event = next(row for row in result.events.events if row.pc == 0x80000064)
    fact = next(row for row in result.semantics.facts if row.source_event_id == event.event_id)
    bound = next(row for row in result.bindings.bindings if row.pc == event.pc)
    capability = next(row for row in result.capabilities.capabilities if row.pc == event.pc)
    assert event.instruction_bytes == encoding
    assert event.observation_kind == "QEMU_INSTRUCTION_EXECUTION_OBSERVED"
    assert fact.mnemonic == mnemonic and fact.kind == kind
    assert bound.status == capability.status == "SUPPORTED"
    assert bound.kind == capability.kind == kind
    assert bound.source_event_ids == (event.event_id,)
    assert bound.semantic_fact_ids == (fact.fact_id,)
    assert capability.binding_id == bound.binding_id
    assert capability.hardware_trigger == capability.hardware_deviation == "NOT_ESTABLISHED"
    assert capability.control_authority == "NOT_ESTABLISHED"
    if variant == "negative_trigger":
        assert K.TLB_INVALIDATE not in {row.kind for row in result.semantics.facts}


def test_run_and_all_artifact_identity_and_bytes_deterministic():
    first, second = replay(synthetic_runtime()), replay(synthetic_runtime())
    for attribute, _ in ARTIFACTS.values():
        assert serialize(getattr(first, attribute)) == serialize(getattr(second, attribute))
    for event in first.events.events:
        assert event.event_id == content_id("qemu-event", event.model_dump(mode="json", exclude={"event_id"}))
    serialized = "\n".join(serialize(getattr(first, key)) for key, _ in ARTIFACTS.values())
    for forbidden in ("/tmp/", "/home/", "timestamp", "uuid", '"pid"', '"retired"'):
        assert forbidden not in serialized


@pytest.mark.parametrize("field,value", [("timestamp", 42), ("host_path", "/tmp/trace"),
                                         ("pid", 123), ("uuid", "run")])
def test_run_identity_rejects_transient_fields(field, value):
    run, *_ = synthetic_runtime()
    with pytest.raises(ValueError):
        identified(QemuRuntimeRunDescriptor, **run.model_dump(exclude={"run_id"}), **{field: value})


def test_source_sha_mismatch_and_same_mnemonic_different_elf_rejected():
    run, raw, analysis, elf = synthetic_runtime()
    other = synthetic_runtime("negative_trigger")[2]
    # The two programs share FENCE at 0x8000005c, but never share ELF identity.
    with pytest.raises(ValueError, match="exact supplied firmware ELF"):
        materialize_runtime(run, raw, analysis=other, elf_bytes=elf)
    with pytest.raises(ValueError, match="exact supplied firmware ELF"):
        materialize_runtime(run, raw, analysis=analysis, elf_bytes=elf + b"\0")


@pytest.mark.parametrize("change", [
    lambda rows: rows[3].update(instruction_bytes="0f003003"),
    lambda rows: rows[3].update(pc=0x12345678),
    lambda rows: rows[0].update(target="riscv32"),
    lambda rows: rows[0]["policy"].update(max_events=5),
])
def test_bad_event_bytes_mapping_target_or_policy_rejected(change):
    run, raw, analysis, elf = synthetic_runtime()
    with pytest.raises(ValueError):
        materialize_runtime(run, change_records(raw, change), analysis=analysis, elf_bytes=elf)


@pytest.mark.parametrize("architecture,width,executable", [
    ("arm", 32, "qemu-system-arm"), ("arm", 64, "qemu-system-aarch64"),
    ("riscv", 32, "qemu-system-riscv32"), ("riscv", 64, "qemu-system-riscv64"),
    ("powerpc", 32, "qemu-system-ppc"), ("powerpc", 64, "qemu-system-ppc64"),
])
def test_shared_schema_architecture_extensibility_only(architecture, width, executable):
    # Schema validation only: no ARM/PowerPC execution is represented or claimed.
    run, *_ = synthetic_runtime()
    identity = run.firmware.model_copy(update={"architecture": architecture, "bit_width": width})
    profile = RuntimeProfile.from_profile(QemuRunProfile(
        architecture=architecture, bit_width=width, executable=executable,
        machine="explicit-test-platform", cpu=None, boot_strategy="generic_loader", bios="none"))
    candidate = identified(QemuRuntimeRunDescriptor, **{
        **run.model_dump(exclude={"run_id", "firmware", "profile"}), "firmware": identity,
        "profile": profile})
    assert candidate.profile.executable == executable
    assert architecture in DECODERS
    if architecture != "riscv":
        assert decoder_for(identity) is None


@pytest.mark.parametrize("changes", [{"architecture": "arm"}, {"bit_width": 32}])
def test_profile_firmware_mismatch_rejected(changes):
    run, *_ = synthetic_runtime()
    firmware = run.firmware.model_copy(update=changes)
    with pytest.raises(ValueError, match="architecture/width"):
        identified(QemuRuntimeRunDescriptor, **{
            **run.model_dump(exclude={"run_id", "firmware"}), "firmware": firmware})


def test_raw_stream_rejects_different_machine_profile_with_same_isa():
    run, raw, analysis, elf = synthetic_runtime()
    profile = RuntimeProfile.model_validate({**run.profile.model_dump(), "machine": "other-board"})
    changed = identified(QemuRuntimeRunDescriptor, **{
        **run.model_dump(exclude={"run_id", "profile"}), "profile": profile})
    with pytest.raises(ValueError, match="run descriptor binding"):
        materialize_runtime(changed, raw, analysis=analysis, elf_bytes=elf)


def test_same_kind_different_pc_cannot_establish_target_execution():
    result = replay(synthetic_runtime("negative_trigger", pcs=(0x80000000, 0x8000005c)))
    by_pc = {row.pc: row for row in result.bindings.bindings}
    assert by_pc[0x8000005c].status == "SUPPORTED"
    assert by_pc[0x80000064].kind == K.MEMORY_BARRIER
    assert by_pc[0x80000064].status == "UNKNOWN"
    assert by_pc[0x80000064].reason == "NOT_OBSERVED_IN_THIS_RUN"
    assert not by_pc[0x80000064].source_event_ids


def test_runtime_order_is_event_order_only():
    result = replay(synthetic_runtime())
    a, b = result.events.events[1:3]
    assert observed_before(result.events, a.event_id, b.event_id)
    assert not observed_before(result.events, b.event_id, a.event_id)
    other = replay(synthetic_runtime("negative_trigger"))
    with pytest.raises(ValueError, match="same canonical prefix"):
        observed_before(result.events, a.event_id, other.events.events[1].event_id)


def test_unsupported_bytes_have_no_semantic_projection():
    run, _, analysis, _ = synthetic_runtime()
    decoder = RiscVRuntimeDecoder()
    for raw in ("13000000", "73000000", "0f003083", "0f000001", "0100"):
        assert decoder.decode(0x80000000, bytes.fromhex(raw), run.firmware) is None
    result = replay(synthetic_runtime(pcs=(analysis.artifact.entry,)))
    assert result.semantics.unsupported_event_ids
    assert not result.semantics.facts


def test_static_decode_mismatch_rejected_even_with_recomputed_content_identity():
    run, raw, analysis, elf = synthetic_runtime()
    data = analysis.model_dump(mode="json", exclude={"analysis_id"})
    next(row for row in data["instructions"] if row["pc"] == 0x80000064)["mnemonic"] = "fence"
    altered = FirmwareStaticAnalysis.model_validate({**data, "analysis_id": content_id("firmware-static", data)})
    with pytest.raises(ValueError, match="static instruction decode disagree"):
        materialize_runtime(run, raw, analysis=altered, elf_bytes=elf)


def test_shared_binding_has_no_isa_mnemonic_matcher():
    source = inspect.getsource(binding)
    for forbidden in ("sfence", "tlbi", "riscv", "powerpc"):
        assert forbidden not in source.lower()


def test_persisted_evidence_replays_from_exact_sources_and_is_path_independent(tmp_path):
    first, analysis = write_synthetic_runtime(tmp_path / "a")
    second, _ = write_synthetic_runtime(tmp_path / "different-name")
    assert load_runtime_evidence(tmp_path / "a", analysis=analysis) == first == second
    for name in ARTIFACTS:
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "different-name" / name).read_bytes()


@pytest.mark.parametrize("filename", [*ARTIFACTS, "raw-events.jsonl", "firmware.elf", "trace-plugin.so"])
def test_artifact_corruption_rejected(tmp_path, filename):
    _, analysis = write_synthetic_runtime(tmp_path / "runtime")
    path = tmp_path / "runtime" / filename
    path.write_bytes(path.read_bytes() + b"corrupt")
    with pytest.raises(ValueError):
        load_runtime_evidence(path.parent, analysis=analysis)


def test_recomputed_derived_identity_cannot_bypass_source_replay(tmp_path):
    _, analysis = write_synthetic_runtime(tmp_path / "runtime")
    path = tmp_path / "runtime/runtime-semantics.json"
    data = json.loads(path.read_text())
    data["unsupported_event_ids"] = []
    data["artifact_id"] = content_id("runtime-semantics", {k: v for k, v in data.items() if k != "artifact_id"})
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="source replay"):
        load_runtime_evidence(path.parent, analysis=analysis)


def test_event_id_integrity_enforced():
    event = replay(synthetic_runtime()).events.events[0]
    with pytest.raises(ValueError, match="content identity"):
        RuntimeEvent.model_validate({**event.model_dump(), "pc": event.pc + 4})
