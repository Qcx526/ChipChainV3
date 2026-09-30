"""Explicit ISA decoder registry; shared evidence has no mnemonic rules.

RISC-V encoding fields follow riscv/riscv-opcodes extensions/rv_s and rv_i.
Only the two required, conservatively selected instruction forms are decoded.
Their semantic classification uses the frozen static classifier directly.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from chipchain.firmware.ghidra_models import ExportInstruction
from chipchain.firmware.semantics_riscv import classify_riscv
from chipchain.firmware.static_ir import FirmwareArtifactIdentity, InstructionFact, StaticBehaviorKind


@dataclass(frozen=True)
class RuntimeDecode:
    mnemonic: str
    operands: tuple[str, ...]
    kind: StaticBehaviorKind


class RuntimeSemanticDecoder(Protocol):
    decoder_id: str

    def decode(self, pc: int, instruction_bytes: bytes, identity: FirmwareArtifactIdentity) -> RuntimeDecode | None: ...

    def compatible_static(self, decoded: RuntimeDecode, instruction: InstructionFact) -> bool: ...


_REGISTERS = ("zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
              "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4",
              "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6")


def _fence_set(value: int) -> str:
    return "".join(name for bit, name in ((8, "i"), (4, "o"), (2, "r"), (1, "w")) if value & bit)


class RiscVRuntimeDecoder:
    decoder_id = "riscv-runtime-sfence-fence/v1"

    def decode(self, pc, instruction_bytes, identity):
        if identity.architecture != "riscv" or identity.endianness != "little":
            return None
        if len(instruction_bytes) != 4 or pc % 2:
            return None
        # This backend currently supports only the explicit LE source tuple.
        # Shared events stay raw bytes; no architecture-wide byte-order default.
        word = int.from_bytes(instruction_bytes, identity.endianness)
        if word & 0xFE007FFF == 0x12000073:
            mnemonic = "sfence.vma"
            operands = (_REGISTERS[(word >> 15) & 31], _REGISTERS[(word >> 20) & 31])
        elif word & 0xF00FFFFF == 0x0000000F:
            # Ordinary FENCE with fm=0, rd=rs1=0. Reserved forms and PAUSE
            # (zero successor) are intentionally unsupported in this V1.
            pred, succ = (word >> 24) & 15, (word >> 20) & 15
            if not pred or not succ:
                return None
            mnemonic, operands = "fence", (_fence_set(pred), _fence_set(succ))
        else:
            return None
        exported = ExportInstruction(pc=pc, bytes=instruction_bytes.hex(), mnemonic=mnemonic,
                                     operands=list(operands), text=mnemonic + " " + ",".join(operands),
                                     function_entry=None, block_start=None)
        semantic, = classify_riscv(exported, {})
        if semantic["semantic_status"] != "supported":
            return None
        return RuntimeDecode(mnemonic, operands, StaticBehaviorKind(semantic["kind"]))

    def compatible_static(self, decoded, instruction):
        if instruction.mnemonic.lower().strip() != decoded.mnemonic:
            return False
        actual = tuple(part.lower().strip() for part in instruction.operands)
        if decoded.mnemonic == "sfence.vma":
            aliases = {f"x{i}": name for i, name in enumerate(_REGISTERS)}
            aliases["fp"] = "s0"
            actual = tuple(aliases.get(part, part) for part in actual)
        elif decoded.mnemonic == "fence":
            values = []
            for part in actual:
                try:
                    number = int(part, 0)
                except ValueError:
                    values.append(part)
                else:
                    if not 0 <= number <= 15:
                        return False
                    values.append(_fence_set(number))
            actual = tuple(values)
        return actual == decoded.operands


# None is an explicit unsupported backend, not a placeholder semantic decoder.
DECODERS: dict[str, RuntimeSemanticDecoder | None] = {
    "arm": None, "riscv": RiscVRuntimeDecoder(), "powerpc": None,
}


def decoder_for(identity: FirmwareArtifactIdentity) -> RuntimeSemanticDecoder | None:
    return DECODERS.get(identity.architecture)
