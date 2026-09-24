"""Conservative RISC-V instruction facts from Ghidra operands."""
from __future__ import annotations

import re

from chipchain.firmware.ghidra_models import ExportInstruction
from chipchain.firmware.static_ir import StaticBehaviorKind as K
from chipchain.firmware.semantics import kill, memory_offset, memory_result, number, register_value, target, unsupported


def _address(parts: list[str], r: dict[str, int]) -> int | None:
    if not parts:
        return None
    if len(parts) >= 2 and number(parts[-2]) is not None:
        base = register_value(r, parts[-1])
        return base + number(parts[-2]) if base is not None else None
    bare_base = re.fullmatch(r"\(([a-z0-9]+)\)", parts[-1])
    if bare_base:
        return register_value(r, bare_base.group(1))
    return memory_offset(parts[-1], r) if "(" in parts[-1] else register_value(r, parts[-1])


def _csr(m: str, o: list[str], r: dict[str, int]) -> tuple[dict, ...] | None:
    pseudo_read = {"csrr"}
    pseudo_write = {"csrw", "csrwi", "csrs", "csrc", "csrsi", "csrci"}
    direct = {"csrrw", "csrrwi", "csrrs", "csrrsi", "csrrc", "csrrci"}
    if m not in pseudo_read | pseudo_write | direct:
        return None
    if len(o) != (3 if m in direct else 2):
        r.clear()
        return ({"kind": K.UNKNOWN, "semantic_status": "partial", "detail": "Malformed CSR operands"},)
    if m in pseudo_read:
        dest, csr, source = o[0], o[1], None
    elif m in pseudo_write:
        dest, csr, source = None, o[0], o[1]
    else:
        dest, csr, source = o
    if dest is not None:
        kill(r, dest)
    zero_source = source in {"zero", "x0"}
    if m.endswith("i") and source is not None:
        zero_source = number(source) == 0
    reads = (m in pseudo_read or m in {"csrs", "csrc", "csrsi", "csrci", "csrrs", "csrrsi", "csrrc", "csrrci"}
             or m in {"csrrw", "csrrwi"} and dest not in {"zero", "x0"})
    writes = (m in {"csrw", "csrwi", "csrrw", "csrrwi"}
              or m in {"csrs", "csrc", "csrsi", "csrci", "csrrs", "csrrsi", "csrrc", "csrrci"}
              and not zero_source)
    facts = []
    if reads:
        facts.append({"kind": K.SYSTEM_REGISTER_READ, "semantic_status": "supported", "system_register": csr})
    if writes:
        facts.append({"kind": K.SYSTEM_REGISTER_WRITE, "semantic_status": "supported", "system_register": csr})
    return tuple(facts)


def classify_riscv(i: ExportInstruction, r: dict[str, int]) -> tuple[dict, ...]:
    m, o = i.mnemonic.lower(), [x.lower().strip() for x in i.operands]
    csr = _csr(m, o, r)
    if csr is not None:
        return csr
    if m in {"lui", "li", "addi"} and len(o) >= 2:
        if m in {"lui", "li"}:
            value = number(o[1])
            if m == "lui" and value is not None:
                value <<= 12
        else:
            base, offset = register_value(r, o[1]), number(o[2]) if len(o) > 2 else None
            value = base + offset if base is not None and offset is not None else None
        kill(r, o[0])
        if value is not None and o[0] not in {"zero", "x0"}:
            r[o[0]] = value
        return ({"kind": K.INSTRUCTION, "semantic_status": "supported"},)
    if m == "mv" and len(o) == 2:
        value = register_value(r, o[1])
        kill(r, o[0])
        if value is not None and o[0] not in {"zero", "x0"}:
            r[o[0]] = value
        return ({"kind": K.INSTRUCTION, "semantic_status": "supported"},)
    load_width = {"lb": 8, "lbu": 8, "lh": 16, "lhu": 16, "lw": 32, "lwu": 32, "ld": 64}
    store_width = {"sb": 8, "sh": 16, "sw": 32, "sd": 64}
    if m in load_width and len(o) >= 2:
        address = _address(o[1:], r)
        kill(r, o[0])
        return (memory_result(K.MEMORY_LOAD, address, width_bits=load_width[m]),)
    if m in store_width and len(o) >= 2:
        return (memory_result(K.MEMORY_STORE, _address(o[1:], r), register_value(r, o[0]), store_width[m]),)
    if m in {"fence", "fence.tso"}:
        return ({"kind": K.MEMORY_BARRIER, "semantic_status": "supported"},)
    if m == "fence.i":
        return ({"kind": K.INSTRUCTION_BARRIER, "semantic_status": "supported"},)
    if m == "sfence.vma":
        return ({"kind": K.TLB_INVALIDATE, "semantic_status": "supported"},)
    atomic = re.fullmatch(r"(lr|sc|amo(?:add|xor|or|and|min|max|minu|maxu|swap))\.(w|d)(?:\.(?:aq|rl|aqrl))?", m)
    if atomic:
        op, width = atomic.group(1), 32 if atomic.group(2) == "w" else 64
        address = _address(o[-1:], r)
        value = register_value(r, o[-2]) if op != "lr" and len(o) >= 3 else None
        if o:
            kill(r, o[0])
        if op == "lr":
            return (memory_result(K.ATOMIC_LOAD, address, width_bits=width),)
        if op == "sc":
            return (memory_result(K.ATOMIC_STORE, address, value, width),)
        return (memory_result(K.ATOMIC_LOAD, address, width_bits=width),
                memory_result(K.ATOMIC_STORE, address, value, width))
    if m in {"mret", "sret", "uret", "ret"}:
        r.clear()
        return ({"kind": K.RETURN if m == "ret" else K.EXCEPTION_RETURN, "semantic_status": "supported"},)
    if m in {"jal", "call", "jalr", "j", "jr", "beq", "bne", "blt", "bge", "bltu", "bgeu"}:
        value = target(o)
        r.clear()
        call = m in {"jal", "call", "jalr"} and (not o or o[0] not in {"zero", "x0"})
        kind = (K.CONDITIONAL_BRANCH if m in {"beq", "bne", "blt", "bge", "bltu", "bgeu"} else
                K.DIRECT_CALL if call and value is not None else
                K.INDIRECT_CALL if call else
                K.DIRECT_BRANCH if value is not None else K.INDIRECT_BRANCH)
        return ({"kind": kind, "semantic_status": "supported" if value is not None else "partial", "target": value},)
    if m in {"add", "sub", "and", "or", "xor", "sll", "srl", "sra", "slt", "sltu",
             "addw", "subw", "sllw", "srlw", "sraw", "auipc", "xori", "ori", "andi",
             "slti", "sltiu", "slli", "srli", "srai", "addiw", "slliw", "srliw", "sraiw"}:
        if o:
            kill(r, o[0])
        return ({"kind": K.INSTRUCTION, "semantic_status": "supported"},)
    if m == "nop":
        return ({"kind": K.INSTRUCTION, "semantic_status": "supported"},)
    r.clear()
    return (unsupported(i),)
