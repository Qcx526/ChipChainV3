"""Pure source validation, semantic projection and exact static/runtime binding."""
from __future__ import annotations

from hashlib import sha256

from chipchain.firmware.elf import ElfImage
from chipchain.firmware.static_ir import FirmwareStaticAnalysis, StaticBehaviorKind
from chipchain.runtime.decoders import decoder_for
from chipchain.runtime.qemu_evidence import (
    QemuRuntimeRunDescriptor, RuntimeCapabilities, RuntimeEvent, RuntimeEvents,
    RuntimeEvidence, RuntimeSemanticFact, RuntimeSemantics, RuntimeSupportedCapability,
    StaticRuntimeBinding, StaticRuntimeBindings, identified,
)


def validate_static_source(analysis: FirmwareStaticAnalysis, image: ElfImage) -> FirmwareStaticAnalysis:
    analysis = FirmwareStaticAnalysis.model_validate(analysis.model_dump(mode="json"))
    if analysis.artifact != image.identity:
        raise ValueError("Static analysis does not identify the exact supplied firmware ELF")
    instructions = {item.fact_id: item for item in analysis.instructions}
    if len({item.pc for item in analysis.instructions}) != len(analysis.instructions):
        raise ValueError("Ambiguous static instruction PC")
    for item in analysis.instructions:
        if image.mapped_bytes(item.pc, len(item.raw_bytes) // 2, executable=True).hex() != item.raw_bytes:
            raise ValueError("Static instruction and exact ELF bytes disagree")
    for fact in analysis.behaviors:
        instruction = instructions.get(fact.instruction_id)
        if instruction is None or instruction.pc != fact.pc:
            raise ValueError("Static behavior has no exact source instruction")
    return analysis


def materialize_runtime(
    run: QemuRuntimeRunDescriptor, raw_stream: bytes, *,
    analysis: FirmwareStaticAnalysis, elf_bytes: bytes,
) -> RuntimeEvidence:
    """Replay raw evidence; mismatches reject, bounded absence stays UNKNOWN.

    Actual acquisition/tool-file validation is an IO boundary in artifacts.py.
    No scientific object contains a caller's filesystem path or process details.
    """
    from chipchain.runtime.acquisition import parse_raw_stream

    run = QemuRuntimeRunDescriptor.model_validate(run.model_dump(mode="json"))
    image = ElfImage(elf_bytes)
    analysis = validate_static_source(analysis, image)
    if run.firmware != image.identity:
        raise ValueError("Runtime run and exact firmware ELF identity mismatch")
    parsed = parse_raw_stream(raw_stream, run.policy.model_dump(mode="json"), expected_run_id=run.run_id)
    if parsed["target"] != run.profile.executable.removeprefix("qemu-system-"):
        raise ValueError("Raw QEMU target and declared runtime profile mismatch")
    rows = parsed["events"]
    mapping = run.image_mapping
    if not rows or mapping.elf_address(rows[0]["pc"], rows[0]["instruction_size"]) != image.identity.entry:
        raise ValueError("Runtime prefix does not start at the supplied ELF entry")
    events = []
    mapped_addresses = {}
    for row in rows:
        event = identified(RuntimeEvent, run_id=run.run_id, **row)
        elf_va = mapping.elf_address(event.pc, event.instruction_size)
        if image.mapped_bytes(elf_va, event.instruction_size, executable=True).hex() != event.instruction_bytes:
            raise ValueError(f"Runtime/ELF instruction-byte mismatch at 0x{event.pc:x}")
        events.append(event)
        mapped_addresses[event.event_id] = elf_va
    event_set = identified(
        RuntimeEvents, run_id=run.run_id, firmware_sha256=image.identity.sha256,
        raw_stream_sha256=sha256(raw_stream).hexdigest(), events=tuple(events),
        stop_reason=parsed["stop_reason"], target_sequence=parsed["target_sequence"],
    )
    decoder = decoder_for(image.identity)
    facts = []
    unsupported = []
    decoded_by_event = {}
    for event in events:
        decoded = decoder.decode(event.pc, bytes.fromhex(event.instruction_bytes), image.identity) if decoder else None
        if decoded is None:
            unsupported.append(event.event_id)
            continue
        decoded_by_event[event.event_id] = decoded
        facts.append(identified(
            RuntimeSemanticFact, run_id=run.run_id, source_event_id=event.event_id,
            pc=event.pc, instruction_bytes=event.instruction_bytes, decoder_id=decoder.decoder_id,
            elf_virtual_address=mapped_addresses[event.event_id],
            mnemonic=decoded.mnemonic, operands=decoded.operands, kind=decoded.kind,
        ))
    semantics = identified(
        RuntimeSemantics, run_id=run.run_id, events_id=event_set.artifact_id,
        decoder_id=decoder.decoder_id if decoder else None, facts=tuple(facts),
        unsupported_event_ids=tuple(unsupported),
    )
    facts_by_event = {item.source_event_id: item for item in facts}
    events_by_pc: dict[int, list[RuntimeEvent]] = {}
    for event in events:
        events_by_pc.setdefault(mapped_addresses[event.event_id], []).append(event)
    instructions = {item.fact_id: item for item in analysis.instructions}
    bindings = []
    for fact in sorted(analysis.behaviors, key=lambda item: (item.pc, item.fact_id)):
        instruction = instructions[fact.instruction_id]
        matching = events_by_pc.get(fact.pc, [])
        # Verify decode compatibility independently of whether the static fact
        # is a candidate kind. Never bind same-kind facts at a different PC.
        for event in matching:
            if event.instruction_bytes != instruction.raw_bytes:
                raise ValueError("Runtime/static instruction size or bytes disagree")
            decoded = decoded_by_event.get(event.event_id)
            if decoded is not None and not decoder.compatible_static(decoded, instruction):
                raise ValueError("Runtime byte decode and static instruction decode disagree")
            if decoded is not None and fact.semantic_status == "supported" and decoded.kind != fact.kind:
                raise ValueError("Runtime and static semantic kind disagree for the exact instruction")
        supported = [event for event in matching if event.event_id in facts_by_event
                     and facts_by_event[event.event_id].kind == fact.kind
                     and fact.semantic_status == "supported"]
        reason = ("EXACT_SOURCE_INSTRUCTION_AND_SEMANTIC" if supported else
                  "NOT_OBSERVED_IN_THIS_RUN" if not matching else
                  "STATIC_SEMANTIC_NOT_SUPPORTED" if fact.semantic_status != "supported" else
                  "UNSUPPORTED_RUNTIME_SEMANTICS")
        bindings.append(identified(
            StaticRuntimeBinding, analysis_id=analysis.analysis_id, run_id=run.run_id,
            static_behavior_id=fact.fact_id, static_instruction_id=instruction.fact_id,
            pc=fact.pc, kind=fact.kind, status="SUPPORTED" if supported else "UNKNOWN", reason=reason,
            source_event_ids=tuple(item.event_id for item in (supported or matching)),
            semantic_fact_ids=tuple(facts_by_event[item.event_id].fact_id for item in supported),
        ))
    binding_set = identified(
        StaticRuntimeBindings, analysis_id=analysis.analysis_id, run_id=run.run_id,
        events_id=event_set.artifact_id, semantics_id=semantics.artifact_id, bindings=tuple(bindings),
    )
    capabilities = tuple(identified(
        RuntimeSupportedCapability, static_behavior_id=item.static_behavior_id,
        static_instruction_id=item.static_instruction_id, binding_id=item.binding_id,
        run_id=run.run_id, pc=item.pc, kind=item.kind, status=item.status,
        source_event_ids=item.source_event_ids, semantic_fact_ids=item.semantic_fact_ids,
    ) for item in bindings if item.kind not in {
        StaticBehaviorKind.INSTRUCTION, StaticBehaviorKind.OTHER, StaticBehaviorKind.UNKNOWN,
    })
    capability_set = identified(
        RuntimeCapabilities, analysis_id=analysis.analysis_id, run_id=run.run_id,
        bindings_id=binding_set.artifact_id, capabilities=capabilities,
    )
    return RuntimeEvidence(run, event_set, semantics, binding_set, capability_set)


def observed_before(events: RuntimeEvents, first_event_id: str, second_event_id: str) -> bool:
    """Order only within this canonical single-vCPU prefix, with no timing claim."""
    events = RuntimeEvents.model_validate(events.model_dump(mode="json"))
    by_id = {item.event_id: item for item in events.events}
    if first_event_id not in by_id or second_event_id not in by_id:
        raise ValueError("Order evidence requires two events from the same canonical prefix")
    relation = runtime_order(by_id[first_event_id], by_id[second_event_id])
    if relation == "UNKNOWN":
        raise ValueError("Runtime order requires the same run and vCPU")
    return relation == "OBSERVED_BEFORE"


def runtime_order(first: RuntimeEvent, second: RuntimeEvent) -> str:
    """Compare validated event values only within one run and one vCPU.

    Callers obtain these values from source-replayed artifacts. This helper
    does not establish stream authenticity or infer order between vCPUs/runs.
    """
    first = RuntimeEvent.model_validate(first.model_dump(mode="json"))
    second = RuntimeEvent.model_validate(second.model_dump(mode="json"))
    if first.run_id != second.run_id or first.vcpu != second.vcpu:
        return "UNKNOWN"
    if first.event_id == second.event_id:
        return "SAME_EVENT"
    if first.sequence == second.sequence:
        return "UNKNOWN"
    return "OBSERVED_BEFORE" if first.sequence < second.sequence else "OBSERVED_AFTER"
