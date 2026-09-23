"""Reconcile exported structure with authoritative ELF bytes and create static IR."""
from __future__ import annotations

from chipchain.firmware.elf import ElfImage, ghidra_language
from chipchain.firmware.ghidra import GHIDRA_VERSION
from chipchain.firmware.ghidra_models import GhidraExport
from chipchain.firmware.semantics import classify
from chipchain.firmware.static_ir import (
    BasicBlockFact, CallSiteFact, ControlFlowEdgeFact, FirmwareFunctionFact,
    InstructionFact, Range, ReferenceFact, StaticBehaviorFact, build_analysis, content_id,
)


def _ranges(items) -> tuple[Range, ...]:
    return tuple(Range(start=x.start, end=x.end) for x in items)


def normalize(image: ElfImage, exported: GhidraExport):
    if exported.language != ghidra_language(image.identity):
        raise ValueError("Ghidra language and ELF architecture disagree")
    sha = image.identity.sha256
    functions = []
    for raw in exported.functions:
        fields = dict(entry=raw.entry, name=raw.name, ranges=_ranges(raw.ranges),
                      thunk=raw.thunk, external=raw.external)
        functions.append(FirmwareFunctionFact(fact_id=content_id("fwfunction", {"elf": sha, **raw.model_dump(exclude={"local_id"})}),
                                              **fields))
    functions.sort(key=lambda x: (x.entry, x.fact_id))

    def owners(pc: int) -> tuple[str, ...]:
        return tuple(f.fact_id for f in functions if any(r.start <= pc <= r.end for r in f.ranges))

    blocks = []
    for raw in exported.blocks:
        fields = dict(start=raw.start, end=raw.end, ranges=_ranges(raw.ranges),
                      function_ids=owners(raw.start))
        blocks.append(BasicBlockFact(fact_id=content_id("fwblock", {"elf": sha, **raw.model_dump(exclude={"local_id"})}),
                                     **fields))
    blocks.sort(key=lambda x: (x.start, x.fact_id))
    block_by_start = {b.start: b for b in blocks}
    function_by_entry = {f.entry: f for f in functions}

    instructions = []
    behaviors = []
    registers: dict[str, int] = {}
    previous_function = None
    previous_block = None
    for raw in sorted(exported.instructions, key=lambda x: x.pc):
        pc = raw.pc
        actual = image.mapped_bytes(pc, len(raw.bytes) // 2, executable=True)
        if actual.hex() != raw.bytes:
            raise ValueError(f"Ghidra/ELF byte mismatch at 0x{pc:x}")
        actual_owners = owners(pc)
        if raw.function_entry is not None:
            declared = function_by_entry.get(raw.function_entry)
            if declared is None or declared.fact_id not in actual_owners:
                raise ValueError(f"Ghidra function ownership conflict at 0x{pc:x}")
        block = block_by_start.get(raw.block_start) if raw.block_start is not None else None
        if block is not None and not any(r.start <= pc <= r.end for r in block.ranges):
            raise ValueError(f"Ghidra block ownership conflict at 0x{pc:x}")
        iid = content_id("fwinstruction", {"elf": sha, "pc": pc, "bytes": raw.bytes})
        instructions.append(InstructionFact(fact_id=iid, pc=pc, raw_bytes=raw.bytes,
                                            mnemonic=raw.mnemonic, operands=tuple(raw.operands),
                                            text=raw.text, function_ids=actual_owners,
                                            block_id=block.fact_id if block else None))
        current_function = actual_owners[0] if len(actual_owners) == 1 else None
        incoming = [e for e in exported.edges if e.target == raw.block_start]
        outgoing = [e for e in exported.edges if e.source == previous_block]
        straight_fallthrough = (raw.block_start != previous_block and current_function == previous_function
                                and len(incoming) == len(outgoing) == 1
                                and incoming[0].source == previous_block
                                and outgoing[0].target == raw.block_start
                                and incoming[0].type == "FALL_THROUGH")
        if current_function != previous_function or raw.block_start != previous_block and not straight_fallthrough:
            registers.clear()
        previous_function = current_function
        previous_block = raw.block_start
        semantic = classify(raw, image.identity.architecture, registers)
        semantic_payload = StaticBehaviorFact.model_construct(
            fact_id="", instruction_id=iid, pc=pc, **semantic).model_dump(
                mode="json", exclude={"fact_id", "instruction_id", "pc"},
                exclude_none=True, exclude_defaults=True)
        behaviors.append(StaticBehaviorFact(
            fact_id=content_id("fwbehavior", {"instruction": iid, "semantic": semantic_payload}),
            instruction_id=iid, pc=pc, **semantic))

    edges = []
    for raw in exported.edges:
        block = block_by_start.get(raw.source)
        if block is None:
            raise ValueError("CFG edge source block missing")
        dest = next((b for b in blocks if any(r.start <= raw.target <= r.end for r in b.ranges)), None)
        fields = dict(source_block_id=block.fact_id, target_block_id=dest.fact_id if dest else None,
                      target_address=raw.target, edge_type=raw.type)
        edges.append(ControlFlowEdgeFact(fact_id=content_id("fwedge", fields), **fields))
    edges = sorted({e.fact_id: e for e in edges}.values(), key=lambda e: (e.source_block_id, e.target_address, e.edge_type))

    calls = []
    instruction_by_pc = {i.pc: i for i in instructions}
    for raw in exported.calls:
        instruction = instruction_by_pc.get(raw.pc)
        if instruction is None:
            raise ValueError("Call site lacks instruction")
        if raw.direct and raw.target is None:
            raise ValueError("Direct call lacks objective target")
        if raw.caller is not None:
            declared = function_by_entry.get(raw.caller)
            if declared is None or declared.fact_id not in instruction.function_ids:
                raise ValueError("Call caller ownership conflict")
        fields = dict(pc=raw.pc, caller_function_ids=instruction.function_ids,
                      direct=raw.direct, target=raw.target if raw.direct else None,
                      target_function_id=function_by_entry[raw.target].fact_id
                      if raw.direct and raw.target in function_by_entry else None)
        calls.append(CallSiteFact(fact_id=content_id("fwcall", {"elf": sha, **fields}), **fields))

    refs = []
    for raw in exported.references:
        if raw.source not in instruction_by_pc:
            raise ValueError("Reference source lacks instruction")
        fields = dict(source_pc=raw.source, target=raw.target, reference_type=raw.type,
                      operand_index=raw.operand)
        refs.append(ReferenceFact(fact_id=content_id("fwref", {"elf": sha, **fields}), **fields))
    refs = sorted({x.fact_id: x for x in refs}.values(), key=lambda x: (x.source_pc, x.operand_index, x.fact_id))

    return build_analysis(artifact=image.identity, ghidra_language=exported.language,
                          ghidra_version=GHIDRA_VERSION, functions=tuple(functions), blocks=tuple(blocks),
                          instructions=tuple(instructions), edges=tuple(edges), calls=tuple(calls),
                          references=tuple(refs), behaviors=tuple(behaviors))
