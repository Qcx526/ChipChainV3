"""Bounded RISC-V static interpretation."""
from __future__ import annotations

from chipchain.firmware.ghidra_models import ExportInstruction
from chipchain.firmware.static_ir import StaticBehaviorKind as K
from chipchain.firmware.semantics import memory_offset, memory_result, number, target, unsupported


def classify_riscv(i: ExportInstruction, r: dict[str, int]) -> dict:
    m, o = i.mnemonic.lower(), [x.lower() for x in i.operands]
    if m in {"lui", "li", "addi"} and len(o) >= 2:
        if m == "lui":
            value = number(o[1])
            value = value << 12 if value is not None else None
        elif m == "li":
            value = number(o[1])
        else:
            base, offset = r.get(o[1]), number(o[2]) if len(o) > 2 else None
            value = base + offset if base is not None and offset is not None else None
        if value is None: r.pop(o[0], None)
        else: r[o[0]] = value
        return {"kind": K.INSTRUCTION, "semantic_status": "supported"}
    if m == "mv" and len(o) == 2:
        if o[1] in r: r[o[0]] = r[o[1]]
        else: r.pop(o[0], None)
        return {"kind": K.INSTRUCTION, "semantic_status": "supported"}
    if m in {"lw", "lh", "lb", "lhu", "lbu", "ld"} and len(o) in {2, 3}:
        address = memory_offset(o[1], r) if len(o) == 2 else (
            r[o[2]] + number(o[1]) if o[2] in r and number(o[1]) is not None else None)
        r.pop(o[0], None)
        return memory_result(K.MEMORY_LOAD, address,
                             width_bits=8 if m in {"lb", "lbu"} else 16 if m in {"lh", "lhu"} else 64 if m == "ld" else 32)
    if m in {"sw", "sh", "sb", "sd"} and len(o) in {2, 3}:
        address = memory_offset(o[1], r) if len(o) == 2 else (
            r[o[2]] + number(o[1]) if o[2] in r and number(o[1]) is not None else None)
        return memory_result(K.MEMORY_STORE, address, r.get(o[0]),
                             8 if m == "sb" else 16 if m == "sh" else 64 if m == "sd" else 32)
    if m.startswith("csr"):
        register = o[1] if len(o) >= 2 else None
        if o: r.pop(o[0], None)
        return {"kind": K.SYSTEM_REGISTER_READ if m in {"csrr", "csrrs", "csrrc"}
                else K.SYSTEM_REGISTER_WRITE, "semantic_status": "supported", "system_register": register}
    if m == "fence": return {"kind": K.MEMORY_BARRIER, "semantic_status": "supported"}
    if m == "fence.i": return {"kind": K.INSTRUCTION_BARRIER, "semantic_status": "supported"}
    if m in {"lr.w", "lr.d"}: return memory_result(K.ATOMIC_LOAD, memory_offset(o[-1], r))
    if m in {"sc.w", "sc.d"}: return memory_result(K.ATOMIC_STORE, memory_offset(o[-1], r))
    if m in {"mret", "sret", "uret"}: return {"kind": K.EXCEPTION_RETURN, "semantic_status": "supported"}
    if m == "ret": return {"kind": K.RETURN, "semantic_status": "supported"}
    if m in {"jal", "call", "jalr"}:
        value = target(o)
        return {"kind": K.DIRECT_CALL if value is not None else K.INDIRECT_CALL,
                "semantic_status": "supported" if value is not None else "partial", "target": value}
    if m in {"j", "jr"}:
        value = target(o)
        return {"kind": K.DIRECT_BRANCH if value is not None else K.INDIRECT_BRANCH,
                "semantic_status": "supported" if value is not None else "partial", "target": value}
    if m in {"beq", "bne", "blt", "bge", "bltu", "bgeu"}:
        value = target(o)
        return {"kind": K.CONDITIONAL_BRANCH, "semantic_status": "supported" if value is not None else "partial",
                "target": value}
    if m in {"add", "sub", "and", "or", "xor", "sll", "srl", "sra", "auipc", "nop"}:
        return {"kind": K.INSTRUCTION, "semantic_status": "supported"}
    return unsupported(i)
