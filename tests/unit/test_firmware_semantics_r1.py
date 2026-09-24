"""Safety properties of conservative multi-effect static semantics."""
from __future__ import annotations

import pytest

from chipchain.firmware.ghidra_models import ExportInstruction
from chipchain.firmware.semantics import classify
from chipchain.firmware.static_ir import StaticBehaviorKind as K


def instruction(mnemonic, *operands):
    return ExportInstruction(pc=0, bytes="00000000", mnemonic=mnemonic,
                             operands=list(operands), text=mnemonic + " " + ",".join(operands),
                             function_entry=None, block_start=None)


@pytest.mark.parametrize("arch,overwrite,register,store", [
    ("arm", "adds", "r1", ("str", "r2", "[r1,#0x0]")),
    ("arm", "eor", "r1", ("str", "r2", "[r1,#0x0]")),
    ("riscv", "add", "t0", ("sw", "t1", "0(t0)")),
    ("riscv", "auipc", "t0", ("sw", "t1", "0(t0)")),
    ("powerpc", "or", "r3", ("stw", "r4", "0(r3)")),
    ("powerpc", "subf", "r3", ("stw", "r4", "0(r3)")),
])
def test_supported_overwrite_kills_old_address(arch, overwrite, register, store):
    registers = {register: 0x40000}
    classify(instruction(overwrite, register, register, register), arch, registers)
    assert register not in registers
    assert classify(instruction(*store), arch, registers)[0]["address_status"] == "unknown"


@pytest.mark.parametrize("arch,register,store", [
    ("arm", "r1", ("str", "r2", "[r1,#0x0]")),
    ("riscv", "t0", ("sw", "t1", "0(t0)")),
    ("powerpc", "r3", ("stw", "r4", "0(r3)")),
])
def test_unsupported_instruction_invalidates_unknown_side_effects(arch, register, store):
    registers = {register: 0x40000}
    assert classify(instruction("future_unknown", register), arch, registers)[0]["kind"] == K.UNKNOWN
    assert classify(instruction(*store), arch, registers)[0]["address"] is None


@pytest.mark.parametrize("mnemonic,operands,kinds,csr", [
    ("csrr", ("a0", "mstatus"), (K.SYSTEM_REGISTER_READ,), "mstatus"),
    ("csrw", ("mtvec", "a0"), (K.SYSTEM_REGISTER_WRITE,), "mtvec"),
    ("csrwi", ("mtvec", "0"), (K.SYSTEM_REGISTER_WRITE,), "mtvec"),
    ("csrrw", ("a0", "mstatus", "a1"), (K.SYSTEM_REGISTER_READ, K.SYSTEM_REGISTER_WRITE), "mstatus"),
    ("csrrw", ("x0", "mstatus", "a1"), (K.SYSTEM_REGISTER_WRITE,), "mstatus"),
    ("csrrwi", ("a0", "mstatus", "0"), (K.SYSTEM_REGISTER_READ, K.SYSTEM_REGISTER_WRITE), "mstatus"),
    ("csrrs", ("a0", "mstatus", "x0"), (K.SYSTEM_REGISTER_READ,), "mstatus"),
    ("csrrs", ("a0", "mstatus", "a1"), (K.SYSTEM_REGISTER_READ, K.SYSTEM_REGISTER_WRITE), "mstatus"),
    ("csrrsi", ("a0", "mstatus", "0"), (K.SYSTEM_REGISTER_READ,), "mstatus"),
    ("csrrc", ("a0", "mstatus", "x0"), (K.SYSTEM_REGISTER_READ,), "mstatus"),
    ("csrrci", ("a0", "mstatus", "1"), (K.SYSTEM_REGISTER_READ, K.SYSTEM_REGISTER_WRITE), "mstatus"),
    ("csrs", ("mstatus", "x0"), (K.SYSTEM_REGISTER_READ,), "mstatus"),
    ("csrc", ("mstatus", "a0"), (K.SYSTEM_REGISTER_READ, K.SYSTEM_REGISTER_WRITE), "mstatus"),
    ("csrsi", ("mstatus", "0"), (K.SYSTEM_REGISTER_READ,), "mstatus"),
])
def test_riscv_csr_operand_identity_and_side_effects(mnemonic, operands, kinds, csr):
    result = classify(instruction(mnemonic, *operands), "riscv", {})
    assert tuple(x["kind"] for x in result) == kinds
    assert all(x["system_register"] == csr for x in result)


def test_riscv_fence_atomic_and_privilege_return():
    assert classify(instruction("sfence.vma", "a0", "a1"), "riscv", {})[0]["kind"] == K.TLB_INVALIDATE
    assert classify(instruction("mret"), "riscv", {})[0]["kind"] == K.EXCEPTION_RETURN
    registers = {"a0": 0x40000, "a1": 3}
    assert tuple(x["kind"] for x in classify(instruction("amoadd.w", "a2", "a1", "a0"), "riscv", registers)) == (K.ATOMIC_LOAD, K.ATOMIC_STORE)
    assert classify(instruction("lr.d", "a2", "a0"), "riscv", registers)[0]["access_width_bits"] == 64
    assert classify(instruction("sc.w", "a2", "a1", "a0"), "riscv", registers)[0]["kind"] == K.ATOMIC_STORE
