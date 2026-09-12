"""Bounded sequential Thumb decode, not execution analysis or a semantic lifter."""

from importlib.metadata import version
import re

import capstone
from capstone import arm_const as arm

from chipchain.domain.common import Architecture
from chipchain.domain.evidence import EvidenceRef
from chipchain.domain.instruction import DecodedInstruction, DecodedOperand, DecodeStatus, EncodingRepresentation
from chipchain.domain.provenance import ToolDescriptor

MODE = "thumb-m-little"
MAX_FUNCTION_BYTES = 4096


class ArmThumbInstructionDecoder:
    def __init__(self) -> None:
        resolved = version("capstone")
        match = re.fullmatch(r"5\.(\d+)\.(\d+)", resolved)
        if not match or tuple(map(int, match.groups())) < (0, 9):
            raise ValueError("ARM adapter requires Capstone >=5.0.9,<6")
        self.descriptor = ToolDescriptor(tool_name="capstone", tool_version=resolved,
            tool_role="instruction_decoder")
        # decoder_mode carries the complete configuration directly on each result.
        self._engine = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS | capstone.CS_MODE_LITTLE_ENDIAN)
        self._engine.detail = True
        self._registers = {getattr(arm, f"ARM_REG_R{i}"): f"r{i}" for i in range(13)}
        self._registers.update({arm.ARM_REG_SP: "r13", arm.ARM_REG_LR: "r14", arm.ARM_REG_PC: "r15"})

    def canonical_register(self, register_id: int) -> str:
        return self._registers[register_id]

    def _operands(self, insn) -> list[DecodedOperand]:
        # Preserve display text but do not pretend lists/shifts/writeback fit a base+disp AST.
        if insn.writeback or "{" in insn.op_str or insn.mnemonic.startswith(("ldm", "stm", "vld", "vst")):
            return []
        result = []
        try:
            for op in insn.operands:
                if op.shift.type != arm.ARM_SFT_INVALID or op.subtracted:
                    return []
                if op.type == arm.ARM_OP_REG:
                    result.append(DecodedOperand(kind="register", register=self.canonical_register(op.reg)))
                elif op.type == arm.ARM_OP_IMM:
                    result.append(DecodedOperand(kind="immediate", immediate=op.imm))
                elif op.type == arm.ARM_OP_MEM and not op.mem.index:
                    result.append(DecodedOperand(kind="memory", base=self.canonical_register(op.mem.base), displacement=op.mem.disp))
                else:
                    return []
        except KeyError:
            return []
        return result

    def decode_site(self, *, function_bytes: bytes, function_address: int, pc: int,
                    observation_id: str, evidence: list[EvidenceRef]) -> DecodedInstruction:
        """Only return a site reached sequentially from the containing function start.

        raw_encoding is lowercase hex in increasing memory-address order, with no
        numeric-word conversion. Full function bounds must be supplied by the caller.
        Invalid/unsupported streams retain their config fact in the ingestion layer.
        """
        if not 0 < len(function_bytes) <= MAX_FUNCTION_BYTES or function_address % 2 or pc % 2:
            raise ValueError("Function bound or Thumb address unsupported")
        if not function_address <= pc < function_address + len(function_bytes):
            raise ValueError("PC outside function")
        cursor = function_address
        try:
            for insn in self._engine.disasm(function_bytes, function_address):
                if insn.address != cursor or insn.size not in (2, 4):
                    break
                if insn.address == pc:
                    return DecodedInstruction(observation_id=observation_id, architecture=Architecture.ARM,
                        raw_encoding=bytes(insn.bytes).hex(), instruction_width_bits=insn.size * 8,
                        representation=EncodingRepresentation.MEMORY_BYTES, source_stage="static",
                        status=DecodeStatus.DECODED, mnemonic=insn.mnemonic, operand_text=insn.op_str,
                        backend_operand_text=insn.op_str, operands=self._operands(insn),
                        decoder=self.descriptor, decoder_mode=MODE, evidence=evidence)
                cursor += insn.size
                if cursor > pc:
                    raise ValueError("PC lies inside a Thumb instruction")
        except capstone.CsError as exc:
            raise ValueError("Capstone could not decode function prefix") from exc
        raise ValueError("Function prefix could not establish instruction boundary")


def memory_direction(decoded: DecodedInstruction | None, size: int) -> str:
    """Only simple decoded loads/stores with matching width establish direction."""
    if decoded is None or not any(o.kind == "memory" for o in decoded.operands):
        return "unknown"
    widths = {"ldr": 4, "ldrb": 1, "ldrh": 2, "ldrsb": 1, "ldrsh": 2,
              "str": 4, "strb": 1, "strh": 2}
    mnemonic = (decoded.mnemonic or "").removesuffix(".w").removesuffix(".n")
    if widths.get(mnemonic) != size:
        return "unknown"
    return "read" if mnemonic.startswith("ldr") else "write"
