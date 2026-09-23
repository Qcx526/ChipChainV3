"""Bounded PowerPC static interpretation."""
from __future__ import annotations

from chipchain.firmware.ghidra_models import ExportInstruction
from chipchain.firmware.static_ir import StaticBehaviorKind as K
from chipchain.firmware.semantics import memory_offset, memory_result, number, target, unsupported


def classify_powerpc(i: ExportInstruction, r: dict[str, int]) -> dict:
    m, o = i.mnemonic.lower(), [x.lower() for x in i.operands]
    if m in {"lis", "li", "addi", "addis"} and len(o) >= 2:
        if m in {"lis", "li"}:
            value = number(o[1])
            if value is not None and m == "lis": value <<= 16
        else:
            base, offset = r.get(o[1]), number(o[2]) if len(o) > 2 else None
            value = base + offset * (65536 if m == "addis" else 1) if base is not None and offset is not None else None
        if value is None: r.pop(o[0], None)
        else: r[o[0]] = value
        return {"kind": K.INSTRUCTION, "semantic_status": "supported"}
    if m in {"lwz", "lbz", "lhz", "ld"} and len(o) == 2:
        address = memory_offset(o[1], r)
        r.pop(o[0], None)
        return memory_result(K.MEMORY_LOAD, address,
                             width_bits=8 if m == "lbz" else 16 if m == "lhz" else 64 if m == "ld" else 32)
    if m in {"stw", "stb", "sth", "std"} and len(o) == 2:
        return memory_result(K.MEMORY_STORE, memory_offset(o[1], r), r.get(o[0]),
                             8 if m == "stb" else 16 if m == "sth" else 64 if m == "std" else 32)
    if m == "mfspr" and len(o) == 2:
        r.pop(o[0], None)
        return {"kind": K.SYSTEM_REGISTER_READ, "semantic_status": "supported", "system_register": o[1]}
    if m == "mtspr" and len(o) == 2:
        return {"kind": K.SYSTEM_REGISTER_WRITE, "semantic_status": "supported", "system_register": o[0]}
    if m in {"sync", "lwsync", "eieio"}:
        return {"kind": K.MEMORY_BARRIER, "semantic_status": "supported"}
    if m == "isync": return {"kind": K.INSTRUCTION_BARRIER, "semantic_status": "supported"}
    if m == "lwarx": return memory_result(K.ATOMIC_LOAD, None)
    if m == "stwcx.": return memory_result(K.ATOMIC_STORE, None)
    if m in {"rfi", "rfid"}: return {"kind": K.EXCEPTION_RETURN, "semantic_status": "supported"}
    if m in {"blr", "bclr"}: return {"kind": K.RETURN, "semantic_status": "supported"}
    if m in {"bl", "bctrl"}:
        value = target(o)
        return {"kind": K.DIRECT_CALL if value is not None else K.INDIRECT_CALL,
                "semantic_status": "supported" if value is not None else "partial", "target": value}
    if m in {"b", "ba", "bctr"} or m.startswith("b") and m not in {"blr", "bclr", "bctrl", "bl"}:
        value = target(o)
        kind = K.DIRECT_BRANCH if m in {"b", "ba"} else K.CONDITIONAL_BRANCH
        return {"kind": kind if value is not None else K.INDIRECT_BRANCH,
                "semantic_status": "supported" if value is not None else "partial", "target": value}
    if m in {"cmpwi", "cmplwi", "or", "ori", "nop", "add", "subf"}:
        return {"kind": K.INSTRUCTION, "semantic_status": "supported"}
    return unsupported(i)
