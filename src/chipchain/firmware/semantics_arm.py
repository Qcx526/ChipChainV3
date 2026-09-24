"""Bounded ARM/Thumb static interpretation; never infers run-time execution."""
from __future__ import annotations

from chipchain.firmware.ghidra_models import ExportInstruction
from chipchain.firmware.static_ir import StaticBehaviorKind as K
from chipchain.firmware.semantics import memory_arm, memory_result, number, target, unsupported


def classify_arm(i: ExportInstruction, r: dict[str, int]) -> tuple[dict, ...]:
    m, o = i.mnemonic.lower(), [x.lower() for x in i.operands]
    if m in {"mov", "movs", "movw", "movt"} and len(o) == 2:
        immediate = number(o[1])
        if immediate is not None:
            if m == "movt":
                if o[0] in r:
                    r[o[0]] = (r[o[0]] & 0xffff) | immediate << 16
                else:
                    r.pop(o[0], None)
            else:
                r[o[0]] = immediate
        else:
            r.pop(o[0], None)
        return ({"kind": K.INSTRUCTION, "semantic_status": "supported"},)
    if m.startswith("ldr") and len(o) >= 2:
        address = memory_arm(o[1], r)
        r.pop(o[0], None)
        return (memory_result(K.MEMORY_LOAD, address,
                              width_bits=8 if m.endswith("b") else 16 if m.endswith("h") else 32),)
    if m.startswith("str") and len(o) >= 2:
        return (memory_result(K.MEMORY_STORE, memory_arm(o[1], r), r.get(o[0]),
                              8 if m.endswith("b") else 16 if m.endswith("h") else 32),)
    if m == "mrs" and len(o) >= 2:
        r.pop(o[0], None)
        return ({"kind": K.SYSTEM_REGISTER_READ, "semantic_status": "supported", "system_register": o[1]},)
    if m == "msr" and len(o) >= 2:
        return ({"kind": K.SYSTEM_REGISTER_WRITE, "semantic_status": "supported", "system_register": o[0]},)
    if m == "dmb" or m == "dsb":
        return ({"kind": K.MEMORY_BARRIER, "semantic_status": "supported"},)
    if m == "isb":
        return ({"kind": K.INSTRUCTION_BARRIER, "semantic_status": "supported"},)
    if m.startswith("ldrex"):
        address = memory_arm(o[-1], r)
        if o: r.pop(o[0], None)
        return (memory_result(K.ATOMIC_LOAD, address),)
    if m.startswith("strex"):
        address = memory_arm(o[-1], r)
        if o: r.pop(o[0], None)
        return (memory_result(K.ATOMIC_STORE, address),)
    if m in {"bl", "blx"}:
        value = target(o)
        r.clear()
        return ({"kind": K.DIRECT_CALL if value is not None else K.INDIRECT_CALL,
                 "semantic_status": "supported" if value is not None else "partial", "target": value},)
    if m == "bx" and o == ["lr"] or m == "pop" and "pc" in ",".join(o):
        r.clear()
        return ({"kind": K.RETURN, "semantic_status": "supported"},)
    if m == "b" or m.startswith("b") and m not in {"bic", "bfi", "bfc"}:
        value = target(o)
        kind = K.DIRECT_BRANCH if m == "b" else K.CONDITIONAL_BRANCH
        r.clear()
        return ({"kind": kind if value is not None else K.INDIRECT_BRANCH,
                 "semantic_status": "supported" if value is not None else "partial", "target": value},)
    if m in {"push", "cmp", "cmn", "tst", "nop", "add", "adds", "sub", "subs", "and", "orr", "eor"}:
        if m == "push":
            r.pop("sp", None)
            r.pop("r13", None)
        if m in {"add", "adds", "sub", "subs", "and", "orr", "eor"} and o:
            r.pop(o[0], None)
        return ({"kind": K.INSTRUCTION, "semantic_status": "supported"},)
    r.clear()
    return (unsupported(i),)
