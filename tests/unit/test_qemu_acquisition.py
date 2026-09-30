"""Offline protocol and source-boundary tests; no compiler/emulator launch."""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path

import pytest

from chipchain.firmware.elf import ElfImage
from chipchain.runtime.image_mapping import declared_identity_mapping
from chipchain.runtime import acquisition
from chipchain.runtime.acquisition import (
    AcquisitionError, acquire_raw, parse_raw_stream, validate_policy, verify_event_source,
)
from chipchain.runtime.qemu_profile import ArchitectureFamily, RISCV64_FW_FEASIBILITY

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "samples/firmware/riscv/processorfuzz_real_case_001/positive/firmware.elf"
POLICY = {"kind": "target_then_successors", "target_pc": 16,
          "successor_events": 2, "max_events": 4}


def records(policy=None, pcs=(16, 20, 24)):
    policy = dict(policy or POLICY)
    events = [{"record": "event", "sequence": n, "vcpu": 0, "pc": pc,
               "instruction_bytes": "13000000", "instruction_size": 4}
              for n, pc in enumerate(pcs)]
    target = next((e["sequence"] for e in events if e["pc"] == policy["target_pc"]), None)
    complete = target is not None and len(events) == target + policy["successor_events"] + 1
    return [{"record": "header", "schema": "chipchain-qemu-trace/v1", "target": "riscv64",
             "run_id": "qemu-runtime-run:" + "a" * 64,
             "vcpu_count": 1, "api_version": 7, "policy": policy}, *events,
            {"record": "end", "stop_reason": "target_window_complete" if complete else "event_bound",
             "event_count": len(events), "target_sequence": target}]


def stream(items):
    return b"".join(json.dumps(item, separators=(",", ":")).encode() + b"\n" for item in items)


def test_raw_order_is_contiguous_single_vcpu_and_target_window_exact():
    parsed = parse_raw_stream(stream(records()), POLICY)
    assert parsed["event_count"] == 3
    assert parsed["target_sequence"] == 0
    assert parsed["stop_reason"] == "target_window_complete"
    assert [e["sequence"] for e in parsed["events"]] == [0, 1, 2]
    assert parsed["events"][0]["pc"] == 16


def test_absent_target_at_deterministic_bound_remains_absent():
    parsed = parse_raw_stream(stream(records(pcs=(0, 4, 8, 12))), POLICY)
    assert parsed["target_sequence"] is None
    assert parsed["stop_reason"] == "event_bound"
    assert "contradicted" not in str(parsed).lower()


def test_partial_target_window_can_end_at_event_bound():
    parsed = parse_raw_stream(stream(records(pcs=(0, 4, 8, 16))), POLICY)
    assert parsed["target_sequence"] == 3
    assert parsed["stop_reason"] == "event_bound"


@pytest.mark.parametrize("target", ["arm", "aarch64", "riscv32", "riscv64", "ppc", "ppc64"])
def test_raw_protocol_is_architecture_neutral(target):
    items = records()
    items[0]["target"] = target
    assert parse_raw_stream(stream(items), POLICY)["target"] == target


@pytest.mark.parametrize("mutation", [
    lambda r: r.pop(),
    lambda r: r.append(r[-1]),
    lambda r: r[0].update(schema="other"),
    lambda r: r[0].update(vcpu_count=2),
    lambda r: r[0].update(api_version=True),
    lambda r: r[0].update(target="unknown"),
    lambda r: r[0]["policy"].update(max_events=6),
    lambda r: r[1].update(sequence=1),
    lambda r: r[1].update(sequence=False),
    lambda r: r[1].update(vcpu=1),
    lambda r: r[1].update(instruction_bytes="ff"),
    lambda r: r[1].update(instruction_bytes="FF000000"),
    lambda r: r[1].update(instruction_size=0),
    lambda r: r[1].update(pc=-1),
    lambda r: r[1].update(extra="untrusted"),
    lambda r: r[-1].update(event_count=99),
    lambda r: r[-1].update(target_sequence=1),
    lambda r: r[-1].update(stop_reason="event_bound"),
])
def test_malformed_or_incomplete_raw_protocol_rejected(mutation):
    items = records()
    mutation(items)
    with pytest.raises(AcquisitionError):
        parse_raw_stream(stream(items), POLICY)


@pytest.mark.parametrize("bad", [b"{}", b"\xff\n", b"{}\n\n{}\n", b"null\n{}\n{}\n"])
def test_non_protocol_bytes_rejected(bad):
    with pytest.raises(AcquisitionError):
        parse_raw_stream(bad, POLICY)


def test_duplicate_json_keys_and_missing_final_newline_rejected():
    raw = stream(records())
    with pytest.raises(AcquisitionError, match="Duplicate"):
        parse_raw_stream(raw.replace(b'"vcpu":0', b'"vcpu":0,"vcpu":0', 1), POLICY)
    with pytest.raises(AcquisitionError, match="Truncated"):
        parse_raw_stream(raw[:-1], POLICY)


@pytest.mark.parametrize("changes", [
    {"max_events": 0}, {"max_events": True}, {"max_events": 1000001},
    {"successor_events": 4}, {"target_pc": -1}, {"kind": "timeout"},
    {"host_path": "/tmp/run"}, {"target_pc": None},
])
def test_invalid_or_contaminated_policies_rejected(changes):
    with pytest.raises(AcquisitionError):
        validate_policy({**POLICY, **changes})


def source_events():
    image = ElfImage.from_path(ELF)
    event = {"sequence": 0, "vcpu": 0, "pc": image.identity.entry,
             "instruction_bytes": image.mapped_bytes(image.identity.entry, 4, executable=True).hex(),
             "instruction_size": 4}
    return image, {"events": [event], "target": "riscv64"}


def test_exact_entry_and_instruction_source_accepted():
    image, parsed = source_events()
    verify_event_source(parsed, image, RISCV64_FW_FEASIBILITY, declared_identity_mapping(image.identity))


@pytest.mark.parametrize("case", ["wrong_target", "wrong_bytes", "outside", "not_entry"])
def test_source_incompatibility_rejected(case):
    image, parsed = source_events()
    event = parsed["events"][0]
    if case == "wrong_target":
        parsed["target"] = "aarch64"
    elif case == "wrong_bytes":
        event["instruction_bytes"] = "00000000"
    elif case == "outside":
        parsed["events"].append({**event, "sequence": 1, "pc": 0xdeadbeef})
    else:
        event["pc"] += 4
    with pytest.raises(AcquisitionError):
        verify_event_source(parsed, image, RISCV64_FW_FEASIBILITY, declared_identity_mapping(image.identity))


def test_architecture_mismatch_rejects_before_launch(tmp_path):
    arm = replace(RISCV64_FW_FEASIBILITY, architecture=ArchitectureFamily.ARM,
                  executable="qemu-system-aarch64")
    with pytest.raises(AcquisitionError, match="architecture/bit-width"):
        acquire_raw(elf=ELF, image_mapping=declared_identity_mapping(ElfImage.from_path(ELF).identity), profile=arm, output=tmp_path / "run", repository_root=ROOT)
    assert not (tmp_path / "run").exists()


@pytest.mark.parametrize("changes", [{"vcpus": 2}, {"extra_args": ("-drive", "file=unbound")},
                                     {"bios": "unbound.bin"}])
def test_unbound_machine_inputs_rejected_before_launch(changes, tmp_path):
    profile = replace(RISCV64_FW_FEASIBILITY, **changes)
    with pytest.raises(AcquisitionError, match="V1 acquisition requires"):
        acquire_raw(elf=ELF, image_mapping=declared_identity_mapping(ElfImage.from_path(ELF).identity), profile=profile, output=tmp_path / "run", repository_root=ROOT)


def test_executable_must_match_pinned_bytes_before_version_process(tmp_path):
    binary = tmp_path / "tools/qemu/install/bin/qemu-system-riscv64"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"not the pinned emulator")
    binary.chmod(0o755)
    manifest = tmp_path / "tools/qemu/SHA256SUMS"
    manifest.write_text(sha256(b"expected").hexdigest() + "  bin/qemu-system-riscv64\n")
    with pytest.raises(AcquisitionError, match="checksum mismatch"):
        acquisition._pinned_executable(tmp_path, RISCV64_FW_FEASIBILITY)


def test_generic_event_prefix_requires_exact_count():
    policy = {"kind": "event_prefix", "target_pc": None, "successor_events": 0, "max_events": 3}
    assert parse_raw_stream(stream(records(policy, pcs=(0, 4, 8))), policy)["stop_reason"] == "event_bound"
    with pytest.raises(AcquisitionError, match="stopping policy"):
        parse_raw_stream(stream(records(policy, pcs=(0, 4))), policy)
