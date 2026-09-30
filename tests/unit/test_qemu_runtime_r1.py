"""R1 scientific-boundary tests; relocation/other ISA tuples are synthetic only."""
from __future__ import annotations

from hashlib import sha256
import inspect
import json
from pathlib import Path
import shutil

import pytest

from chipchain.runtime import binding, acquisition, artifacts
from chipchain.runtime.binding import materialize_runtime, runtime_order
from chipchain.runtime.decoders import RiscVRuntimeDecoder, decoder_for
from chipchain.runtime.image_mapping import RuntimeImageMapping, RuntimeImageRegion
from chipchain.runtime.plugin_build import validate_header_provenance, PLUGIN_API_VERSION
from chipchain.runtime.qemu_evidence import (
    QemuRuntimeRunDescriptor, RuntimeEvent, RuntimeProfile, StaticRuntimeBinding,
    RuntimeSupportedCapability, SUPPORTED_DEFINITION, identified,
)
from tests.runtime_fixtures import ROOT, synthetic_runtime, write_synthetic_runtime


def replace_run(run, **fields):
    return identified(QemuRuntimeRunDescriptor, **{
        **run.model_dump(exclude={"run_id"}), **fields})


def relocate_fixture(delta=0x10000):
    run, raw, analysis, elf = synthetic_runtime()
    mapping = RuntimeImageMapping(
        firmware_sha256=run.firmware.sha256, mapping_kind="relocated",
        regions=tuple(RuntimeImageRegion(runtime_base=r.runtime_base + delta,
                                        elf_virtual_base=r.elf_virtual_base, size=r.size)
                      for r in run.image_mapping.regions))
    shifted = replace_run(run, image_mapping=mapping)
    rows = [json.loads(line) for line in raw.splitlines()]
    rows[0]["run_id"] = shifted.run_id
    for row in rows[1:-1]:
        row["pc"] += delta
    raw = b"".join(json.dumps(row, sort_keys=True).encode() + b"\n" for row in rows)
    return shifted, raw, analysis, elf


@pytest.mark.parametrize("architecture,width,executable", [
    ("arm", 32, "qemu-system-arm"), ("powerpc", 32, "qemu-system-ppc"),
    ("powerpc", 64, "qemu-system-ppc64"),
])
def test_big_endian_shared_source_tuple_preserves_raw_byte_sequence(architecture, width, executable):
    run, *_ = synthetic_runtime()
    identity = run.firmware.model_copy(update={"architecture": architecture, "bit_width": width,
                                             "endianness": "big"})
    profile = RuntimeProfile.model_validate({**run.profile.model_dump(), "architecture": architecture,
                                            "bit_width": width, "executable": executable})
    changed = replace_run(run, firmware=identity, profile=profile)
    assert changed.firmware.endianness == "big"
    assert decoder_for(identity) is None
    # A schema value, not an asserted ARM/PPC execution artifact.
    event = identified(RuntimeEvent, run_id=changed.run_id, sequence=0, vcpu=0,
                       pc=identity.entry, instruction_bytes="01234567", instruction_size=4)
    assert event.instruction_bytes == "01234567"


def test_endianness_is_bound_not_inferred_or_silently_reinterpreted():
    run, raw, analysis, elf = synthetic_runtime()
    decoder = RiscVRuntimeDecoder()
    assert decoder.decode(0x80000064, bytes.fromhex("73000012"), run.firmware).kind == "TLB_INVALIDATE"
    big = run.firmware.model_copy(update={"endianness": "big"})
    assert decoder.decode(0x80000064, bytes.fromhex("73000012"), big) is None
    with pytest.raises(ValueError, match="exact firmware ELF identity"):
        materialize_runtime(replace_run(run, firmware=big), raw, analysis=analysis, elf_bytes=elf)
    for module in (binding, acquisition, artifacts):
        assert "int.from_bytes" not in inspect.getsource(module)
    assert 'int.from_bytes(instruction_bytes, identity.endianness)' in inspect.getsource(RiscVRuntimeDecoder)
    for value in (None, "unknown"):
        with pytest.raises(ValueError):
            replace_run(run, firmware={**run.firmware.model_dump(), "endianness": value})


@pytest.mark.parametrize("relocated", [False, True])
def test_explicit_mapping_exact_binding_preserves_both_addresses(relocated):
    run, raw, analysis, elf = relocate_fixture() if relocated else synthetic_runtime()
    evidence = materialize_runtime(run, raw, analysis=analysis, elf_bytes=elf)
    bound = next(row for row in evidence.bindings.bindings if row.pc == 0x80000064)
    assert bound.status == "SUPPORTED"
    semantic = next(row for row in evidence.semantics.facts if row.fact_id in bound.semantic_fact_ids)
    assert semantic.elf_virtual_address == 0x80000064
    assert semantic.pc == 0x80000064 + (0x10000 if relocated else 0)
    assert run.image_mapping.elf_address(semantic.pc, 4) == semantic.elf_virtual_address


def test_no_mapping_or_wrong_firmware_mapping_cannot_exact_bind():
    run, *_ = synthetic_runtime()
    fields = run.model_dump(exclude={"run_id", "image_mapping"})
    with pytest.raises(ValueError, match="Missing canonical field"):
        identified(QemuRuntimeRunDescriptor, **fields)
    with pytest.raises(ValueError):
        replace_run(run, image_mapping=None)
    with pytest.raises(ValueError, match="mapping firmware identity"):
        replace_run(run, image_mapping={**run.image_mapping.model_dump(), "firmware_sha256": "a" * 64})


def test_same_numeric_pc_does_not_bypass_declared_mapping():
    run, raw, analysis, elf = relocate_fixture()
    rows = [json.loads(line) for line in raw.splitlines()]
    for row in rows[1:-1]:
        row["pc"] -= 0x10000
    raw = b"".join(json.dumps(row).encode() + b"\n" for row in rows)
    with pytest.raises(ValueError, match="no unambiguous declared image mapping"):
        materialize_runtime(run, raw, analysis=analysis, elf_bytes=elf)


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(regions=[]),
    lambda d: d.update(mapping_kind="auto"),
    lambda d: d["regions"].append(d["regions"][0].copy()),
    lambda d: d["regions"][0].update(size=0),
    lambda d: d["regions"][0].update(runtime_base=d["regions"][0]["runtime_base"] + 4),
    lambda d: d["regions"][0].update(elf_virtual_base=0),
])
def test_missing_ambiguous_unsupported_or_invalid_mapping_rejected(mutation):
    run, *_ = synthetic_runtime()
    data = run.image_mapping.model_dump(mode="json")
    mutation(data)
    with pytest.raises(ValueError):
        replace_run(run, image_mapping=data)


def test_runtime_instruction_must_fit_entire_mapping_range():
    run, *_ = synthetic_runtime()
    region = run.image_mapping.regions[0]
    with pytest.raises(ValueError, match="unambiguous"):
        run.image_mapping.elf_address(region.runtime_base + region.size - 1, 4)


def test_acquirer_does_not_claim_to_implement_relocated_loading(tmp_path):
    run, _, _, _ = relocate_fixture()
    elf = ROOT / "samples/firmware/riscv/processorfuzz_real_case_001/positive/firmware.elf"
    with pytest.raises(ValueError, match="only implements declared identity"):
        acquisition.acquire_raw(elf=elf, profile=run.profile.to_profile(), output=tmp_path / "unused",
                                image_mapping=run.image_mapping, repository_root=ROOT)
    assert not (tmp_path / "unused").exists()


def test_order_same_run_same_vcpu_only_and_no_timestamp_channel():
    run, *_ = synthetic_runtime()
    fields = dict(run_id=run.run_id, pc=0x80000064, instruction_bytes="73000012", instruction_size=4)
    a = identified(RuntimeEvent, **fields, vcpu=0, sequence=10)
    b = identified(RuntimeEvent, **fields, vcpu=0, sequence=11)
    assert runtime_order(a, b) == "OBSERVED_BEFORE"
    assert runtime_order(b, a) == "OBSERVED_AFTER"
    assert runtime_order(a, a) == "SAME_EVENT"
    other_cpu = identified(RuntimeEvent, **fields, vcpu=1, sequence=11)
    assert runtime_order(a, other_cpu) == "UNKNOWN"
    other_run = identified(RuntimeEvent, **{**fields, "run_id": "qemu-runtime-run:" + "a" * 64},
                           vcpu=0, sequence=11)
    assert runtime_order(a, other_run) == "UNKNOWN"
    for timestamp in (0, 999999):
        with pytest.raises(ValueError):
            identified(RuntimeEvent, **fields, vcpu=0, sequence=11, timestamp=timestamp)
    # Incidental host annotations cannot participate in the comparison API.
    wrapped = [(999999, a), (0, b)]
    assert runtime_order(wrapped[0][1], wrapped[1][1]) == "OBSERVED_BEFORE"


def test_header_api_provenance_is_pinned_and_license_preserved():
    provenance = validate_header_provenance(ROOT)
    assert provenance["api_version"] == PLUGIN_API_VERSION == 7
    assert provenance["upstream_tag"] == "v11.1.1"
    assert provenance["upstream_commit"] == "c3d48b7d1e89604920e5b81b91140c2ad39a1943"
    assert provenance["subset_sha256"] == "b097fe65bcfdb50949a824c65be796a5d5925c0f72033c06e086b8addacb4678"
    assert provenance["license"] == "GPL-2.0-or-later"
    run, *_ = synthetic_runtime()
    assert run.plugin_api_version == 7
    assert run.plugin_header_provenance_sha256 == sha256(
        (ROOT / "tools/qemu/plugins/header-provenance.json").read_bytes()).hexdigest()


@pytest.mark.parametrize("target", ["header", "provenance", "qemu_version"])
def test_incompatible_api_header_or_environment_rejected(target, tmp_path):
    plugins = tmp_path / "tools/qemu/plugins"
    plugins.mkdir(parents=True)
    for name in ("qemu-plugin-v7.h", "header-provenance.json"):
        shutil.copyfile(ROOT / "tools/qemu/plugins" / name, plugins / name)
    source = tmp_path / "tools/qemu/SOURCE"
    shutil.copyfile(ROOT / "tools/qemu/SOURCE", source)
    if target == "header":
        path = plugins / "qemu-plugin-v7.h"
        path.write_text(path.read_text().replace("#define QEMU_PLUGIN_VERSION 7", "#define QEMU_PLUGIN_VERSION 8"))
    elif target == "provenance":
        path = plugins / "header-provenance.json"
        data = json.loads(path.read_text()); data["api_version"] = 8
        path.write_text(json.dumps(data))
    else:
        source.write_text(source.read_text().replace("official_version=11.1.1", "official_version=11.1.2"))
    with pytest.raises(ValueError, match="provenance is incompatible"):
        validate_header_provenance(tmp_path)


def test_plugin_binary_identity_differs_and_wrong_retained_plugin_is_rejected(tmp_path):
    evidence, analysis = write_synthetic_runtime(tmp_path / "runtime")
    run = evidence.run
    changed = replace_run(run, plugin_sha256="b" * 64)
    assert changed.run_id != run.run_id
    event = evidence.events.events[0]
    assert identified(RuntimeEvent, **{**event.model_dump(exclude={"event_id"}),
                                       "run_id": changed.run_id}).event_id != event.event_id
    with pytest.raises(ValueError, match="plugin identity mismatch"):
        artifacts.validate_tool_provenance(changed, tmp_path / "runtime", ROOT)
    (tmp_path / "runtime/trace-plugin.so").write_bytes(b"different instrumentation")
    with pytest.raises(ValueError, match="plugin identity mismatch"):
        artifacts.load_runtime_evidence(tmp_path / "runtime", analysis=analysis)


def test_supported_definition_is_normative_and_never_completion_or_hardware():
    for cls in (StaticRuntimeBinding, RuntimeSupportedCapability):
        assert cls.model_fields["status"].description == SUPPORTED_DEFINITION
    run, raw, analysis, elf = synthetic_runtime()
    evidence = materialize_runtime(run, raw, analysis=analysis, elf_bytes=elf)
    capability = next(c for c in evidence.capabilities.capabilities if c.pc == 0x80000064)
    assert capability.status == "SUPPORTED"
    assert capability.hardware_trigger == capability.hardware_deviation == "NOT_ESTABLISHED"
    for attribute in ("run", "events", "semantics", "bindings", "capabilities"):
        data = getattr(evidence, attribute).model_dump_json()
        for forbidden in ('"retired":', '"completed":', '"hardware_effect":'):
            assert forbidden not in data
