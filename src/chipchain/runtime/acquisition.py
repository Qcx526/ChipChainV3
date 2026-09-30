"""Bounded QEMU callbacks, with no instruction semantic interpretation.

The plugin observes the pre-instruction execution callback. Neither this layer
nor its raw protocol asserts completion, retirement, or target-hardware behavior.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from io import BytesIO
import math
from pathlib import Path
import re
import subprocess

from elftools.elf.elffile import ELFFile

from chipchain.firmware.elf import ElfImage
from chipchain.runtime.qemu_evidence import (
    AcquisitionPolicy, QemuRuntimeRunDescriptor, RuntimeProfile, identified,
)
from chipchain.runtime.image_mapping import RuntimeImageMapping
from chipchain.runtime.plugin_build import PLUGIN_API_VERSION, build_plugin
from chipchain.runtime.qemu_profile import (
    BootStrategy, PINNED_QEMU_VERSION, QemuRunProfile, QemuRuntimeBackend,
)

RAW_SCHEMA = "chipchain-qemu-trace/v1"
ACQUISITION_ARGS = ("-monitor", "none", "-serial", "none", "-nic", "none", "-no-reboot",
                    "-no-user-config")
_TARGETS = {"arm", "aarch64", "riscv32", "riscv64", "ppc", "ppc64"}
_HEX = re.compile(r"(?:[0-9a-f]{2})+\Z")


class AcquisitionError(ValueError):
    """Unusable profile, incomplete run, or non-source-bound observation."""


@dataclass(frozen=True, slots=True)
class RawAcquisition:
    elf_bytes: bytes
    profile: QemuRunProfile
    qemu_version: str
    executable_sha256: str
    plugin_sha256: str
    plugin_source_sha256: str
    plugin_api_header_sha256: str
    raw_stream: bytes
    policy: dict
    run: QemuRuntimeRunDescriptor


def _integer(value: object, *, minimum: int = 0, maximum: int = (1 << 64) - 1) -> bool:
    return type(value) is int and minimum <= value <= maximum


def validate_policy(policy: dict) -> None:
    if not isinstance(policy, dict) or set(policy) != {
        "kind", "target_pc", "successor_events", "max_events",
    }:
        raise AcquisitionError("Malformed acquisition policy")
    maximum, successors, target = (policy[name] for name in
                                   ("max_events", "successor_events", "target_pc"))
    if not _integer(maximum, minimum=1, maximum=1000000) or not _integer(
        successors, maximum=maximum - 1,
    ):
        raise AcquisitionError("Invalid deterministic event bound")
    if target is None:
        if policy["kind"] != "event_prefix" or successors != 0:
            raise AcquisitionError("Event prefix cannot declare target successors")
    elif not _integer(target) or policy["kind"] != "target_then_successors":
        raise AcquisitionError("Invalid target observation policy")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise AcquisitionError("Duplicate JSON field in raw stream")
        result[key] = value
    return result


def parse_raw_stream(raw: bytes, policy: dict, *, expected_run_id: str | None = None) -> dict:
    """Strictly parse a complete plugin stream; sequence is the raw event order.

    A missing terminator (including watchdog termination) cannot become valid
    evidence. No executable mapping/source assertion is made by parsing alone.
    """
    validate_policy(policy)
    if not isinstance(raw, bytes) or not raw.endswith(b"\n") or len(raw) > 300000000:
        raise AcquisitionError("Truncated or oversized raw stream")
    try:
        lines = raw.decode("utf-8").splitlines()
        if len(lines) < 3 or len(lines) > policy["max_events"] + 2:
            raise AcquisitionError("Invalid raw record count")
        records = [json.loads(line, object_pairs_hook=_unique_object,
                              parse_constant=lambda _: (_ for _ in ()).throw(
                                  AcquisitionError("Non-finite JSON value"))) for line in lines]
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AcquisitionError("Malformed raw JSON stream") from exc
    if any(type(record) is not dict for record in records):
        raise AcquisitionError("Raw record is not an object")
    header, *raw_events, end = records
    if set(header) != {"record", "schema", "run_id", "target", "vcpu_count", "api_version", "policy"}:
        raise AcquisitionError("Malformed raw header")
    if (type(header["run_id"]) is not str
            or not re.fullmatch(r"qemu-runtime-run:[0-9a-f]{64}", header["run_id"])
            or expected_run_id is not None and header["run_id"] != expected_run_id):
        raise AcquisitionError("Raw stream run descriptor binding mismatch")
    if (header["record"] != "header" or header["schema"] != RAW_SCHEMA
            or type(header["target"]) is not str or header["target"] not in _TARGETS
            or not _integer(header["vcpu_count"], minimum=1, maximum=1)
            or not _integer(header["api_version"], minimum=PLUGIN_API_VERSION,
                            maximum=PLUGIN_API_VERSION)):
        raise AcquisitionError("Unsupported raw header")
    validate_policy(header["policy"])
    if header["policy"] != policy:
        raise AcquisitionError("Raw stream policy mismatch")
    events = []
    target_sequence = None
    for sequence, record in enumerate(raw_events):
        if set(record) != {"record", "sequence", "vcpu", "pc", "instruction_bytes",
                           "instruction_size"} or record["record"] != "event":
            raise AcquisitionError("Malformed raw event")
        if (not _integer(record["sequence"], minimum=sequence, maximum=sequence)
                or not _integer(record["vcpu"], maximum=0)
                or not _integer(record["pc"])
                or not _integer(record["instruction_size"], minimum=1, maximum=64)
                or type(record["instruction_bytes"]) is not str
                or not _HEX.fullmatch(record["instruction_bytes"])
                or len(record["instruction_bytes"]) != record["instruction_size"] * 2):
            raise AcquisitionError("Invalid raw event fields or noncontiguous sequence")
        events.append({key: value for key, value in record.items() if key != "record"})
        if record["pc"] == policy["target_pc"] and target_sequence is None:
            target_sequence = sequence
    if set(end) != {"record", "stop_reason", "event_count", "target_sequence"}:
        raise AcquisitionError("Malformed raw terminator")
    if (end["record"] != "end" or not _integer(end["event_count"],
            minimum=len(events), maximum=len(events)) or end["target_sequence"] != target_sequence
            or (target_sequence is not None and type(end["target_sequence"]) is not int)):
        raise AcquisitionError("Raw terminator does not match events")
    target_count = (target_sequence + policy["successor_events"] + 1
                    if target_sequence is not None else None)
    complete_target = target_count is not None and target_count <= policy["max_events"]
    expected_count = target_count if complete_target else policy["max_events"]
    expected_reason = "target_window_complete" if complete_target else "event_bound"
    if len(events) != expected_count or end["stop_reason"] != expected_reason:
        raise AcquisitionError("Trace does not implement the declared stopping policy")
    return {"events": events, "stop_reason": expected_reason, "target_sequence": target_sequence,
            "event_count": len(events), "target": header["target"], "run_id": header["run_id"]}


def verify_event_source(parsed: dict, image: ElfImage, profile: QemuRunProfile,
                        mapping: RuntimeImageMapping) -> None:
    """Bind every callback byte to one exact executable ELF mapping."""
    identity = image.identity
    mapping.validate_source(identity)
    if identity.architecture != profile.architecture.value or identity.bit_width != profile.bit_width:
        raise AcquisitionError("ELF architecture/bit-width and runtime profile disagree")
    if parsed["target"] != profile.executable.removeprefix("qemu-system-"):
        raise AcquisitionError("QEMU target and runtime profile disagree")
    if not parsed["events"] or mapping.elf_address(
        parsed["events"][0]["pc"], parsed["events"][0]["instruction_size"]
    ) != identity.entry:
        raise AcquisitionError("Runtime prefix does not begin at exact ELF entry")
    for event in parsed["events"]:
        try:
            address = mapping.elf_address(event["pc"], event["instruction_size"])
            expected = image.mapped_bytes(address, event["instruction_size"], executable=True)
        except ValueError as exc:
            raise AcquisitionError("Runtime PC is outside unique executable ELF mapping") from exc
        if expected.hex() != event["instruction_bytes"]:
            raise AcquisitionError("Runtime instruction bytes disagree with exact ELF")


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _pinned_executable(repository_root: Path, profile: QemuRunProfile) -> tuple[Path, str]:
    backend = QemuRuntimeBackend.for_project(repository_root)
    binary = backend.executable_path(profile)
    manifest = repository_root / "tools/qemu/SHA256SUMS"
    matches = []
    for line in manifest.read_text().splitlines():
        fields = line.split("  ")
        if len(fields) != 2 or not re.fullmatch(r"[0-9a-f]{64}", fields[0]):
            raise AcquisitionError("Malformed pinned QEMU checksum manifest")
        if fields[1] == "bin/" + profile.executable:
            matches.append(fields[0])
    digest = _digest(binary)
    if len(matches) != 1 or digest != matches[0]:
        raise AcquisitionError("Project QEMU executable checksum mismatch")
    # Execute only after its exact bytes pass the frozen manifest check.
    backend.verified_executable(profile)
    return binary, digest


def acquire_raw(*, elf: Path, profile: QemuRunProfile, output: Path,
                image_mapping: RuntimeImageMapping,
                target_pc: int | None = None, successor_events: int = 8,
                max_events: int = 20000, watchdog_seconds: float = 20,
                repository_root: Path) -> RawAcquisition:
    """Acquire actual callbacks from the frozen project-managed QEMU executable.

    Outputs retain exact executed ELF bytes, the compiled instrumentation, and
    the raw protocol for later source checking. The watchdog is only a failure
    guard and never determines a successful scientific observation window.
    """
    if not isinstance(profile, QemuRunProfile):
        raise AcquisitionError("An explicit QemuRunProfile is required")
    if (profile.vcpus != 1 or profile.boot_strategy is not BootStrategy.GENERIC_LOADER
            or profile.bios != "none" or profile.extra_args):
        raise AcquisitionError("V1 acquisition requires one vCPU, generic loader, no BIOS or extra media/options")
    policy = {"kind": "target_then_successors" if target_pc is not None else "event_prefix",
              "target_pc": target_pc, "successor_events": successor_events if target_pc is not None else 0,
              "max_events": max_events}
    validate_policy(policy)
    canonical_policy = AcquisitionPolicy.model_validate(policy)
    canonical_profile = RuntimeProfile.from_profile(profile)
    if (type(watchdog_seconds) not in (int, float) or not math.isfinite(watchdog_seconds)
            or not 0 < watchdog_seconds <= 300):
        raise AcquisitionError("Watchdog must be finite and at most 300 seconds")
    data = Path(elf).read_bytes()
    image = ElfImage(data)
    image_mapping = RuntimeImageMapping.model_validate(image_mapping.model_dump(mode="json"))
    image_mapping.validate_source(image.identity)
    # This acquirer has no relocation/MMU setup. The mapping abstraction can
    # represent relocation, but this concrete generic-loader launch cannot.
    if image_mapping.mapping_kind != "identity":
        raise AcquisitionError("This acquisition backend only implements declared identity loading")
    for segment in ELFFile(BytesIO(data)).iter_segments():
        if segment["p_type"] == "PT_LOAD" and segment["p_paddr"] != segment["p_vaddr"]:
            raise AcquisitionError("Identity generic-loader profile requires ELF load PA = VA")
    if image.identity.architecture != profile.architecture.value or image.identity.bit_width != profile.bit_width:
        raise AcquisitionError("ELF architecture/bit-width and runtime profile disagree")
    image.mapped_bytes(image.identity.entry, 1, executable=True)
    if target_pc is not None:
        image.mapped_bytes(target_pc, 1, executable=True)
    root = Path(repository_root).resolve(strict=True)
    binary, executable_sha = _pinned_executable(root, profile)
    output = Path(output).absolute()
    if any(part.is_symlink() for part in (output, *output.parents)):
        raise AcquisitionError("Acquisition output path contains a symlink")
    if any(char in str(output) for char in (",", "\n", "\r")):
        raise AcquisitionError("Acquisition output path cannot contain QEMU option delimiters")
    output.mkdir(parents=True, exist_ok=True)
    paths = {name: output / name for name in
             ("firmware.elf", "trace-plugin.so", "plugin-build.json", "raw-events.jsonl", "qemu-stdout.log", "qemu-stderr.log")}
    if any(path.exists() or path.is_symlink() for path in paths.values()):
        raise AcquisitionError("Acquisition output files already exist; choose a new output directory")
    with paths["firmware.elf"].open("xb") as handle:
        handle.write(data)
    build = build_plugin(repository_root=root, output_directory=output)
    source_sha, header_sha = build["plugin_source_sha256"], build["plugin_api_header_sha256"]
    plugin_sha = build["plugin_sha256"]
    source_metadata = dict(line.split("=", 1) for line in
                           (root / "tools/qemu/SOURCE").read_text().splitlines())
    run = identified(
        QemuRuntimeRunDescriptor, firmware=image.identity, profile=canonical_profile,
        image_mapping=image_mapping,
        qemu_version=PINNED_QEMU_VERSION, qemu_executable_sha256=executable_sha,
        qemu_bundle_sha256=source_metadata["chipchain_bundle_sha256"],
        plugin_sha256=plugin_sha, plugin_source_sha256=source_sha,
        plugin_api_header_sha256=header_sha, acquisition_args=ACQUISITION_ARGS,
        plugin_header_provenance_sha256=build["plugin_header_provenance_sha256"],
        policy=canonical_policy,
    )
    argv = list(QemuRuntimeBackend.for_project(root).command(profile, paths["firmware.elf"]))
    argv.extend(ACQUISITION_ARGS)
    target = str(target_pc) if target_pc is not None else "none"
    argv.extend(("-plugin", f"{paths['trace-plugin.so']},trace={paths['raw-events.jsonl']},target={target},"
                 f"successors={policy['successor_events']},maximum={max_events},run_id={run.run_id}"))
    try:
        with paths["qemu-stdout.log"].open("xb") as stdout, paths["qemu-stderr.log"].open("xb") as stderr:
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                    timeout=watchdog_seconds, check=False)
    except subprocess.TimeoutExpired as exc:
        raise AcquisitionError("QEMU watchdog expired; incomplete trace is rejected") from exc
    if result.returncode:
        raise AcquisitionError(f"QEMU acquisition failed with exit code {result.returncode}; inspect qemu-stderr.log")
    if (_digest(binary) != executable_sha or _digest(paths["trace-plugin.so"]) != plugin_sha
            or paths["firmware.elf"].read_bytes() != data):
        raise AcquisitionError("Acquisition input changed during execution")
    try:
        raw = paths["raw-events.jsonl"].read_bytes()
    except FileNotFoundError as exc:
        raise AcquisitionError("QEMU produced no raw execution stream") from exc
    parsed = parse_raw_stream(raw, policy, expected_run_id=run.run_id)
    verify_event_source(parsed, image, profile, image_mapping)
    return RawAcquisition(data, profile, PINNED_QEMU_VERSION, executable_sha, plugin_sha,
                          source_sha, header_sha, raw, policy, run)
