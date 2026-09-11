"""Capstone 5 RV32 word decoding after ingestion has identified an observation."""

import hashlib
import re
from importlib.metadata import version

import capstone
from capstone import riscv_const

from chipchain.domain.behavior import BehaviorKind
from chipchain.domain.common import Architecture
from chipchain.domain.instruction import (
    DecodedInstruction, DecodedOperand, DecodeStatus, EncodingRepresentation, InstructionEncoding,
)
from chipchain.domain.provenance import ToolDescriptor
from chipchain.tools.contracts import HardwareObservation, HardwareObservationKind, HardwareObservations

MODE = "RV32; 32-bit instruction words; C disabled; instruction bytes little-endian"


def instruction_bytes(encoding: InstructionEncoding) -> bytes:
    """Serialize the numeric instruction word into low-address-first ISA bytes.

    VCD is an MSB-first bit-vector, not memory bytes. RISC-V instruction parcels
    place low-order bits first in the instruction stream; data endianness is a
    separate target property. This adapter supports one 32-bit word, C disabled.
    """
    if encoding.width_bits != 32 or any(c in encoding.bits for c in "xz"):
        raise ValueError("Byte conversion requires one known 32-bit instruction word")
    return int(encoding.bits, 2).to_bytes(4, byteorder="little", signed=False)


def from_observation(observation: HardwareObservation) -> InstructionEncoding:
    if observation.kind != HardwareObservationKind.INSTRUCTION_ENCODING_OBSERVED:
        raise ValueError("Decoder accepts identified instruction observations only")
    # Ingestion owns validity, stage selection, and representation. Never infer
    # them from a signal's spelling, reference waveform, or an opcode pattern.
    return InstructionEncoding(
        observation_id=observation.observation_id, architecture=Architecture.RISCV,
        bits=observation.details.host.value, width_bits=observation.details.host.width,
        representation=observation.details.encoding_representation,
        source_stage=observation.details.observation_stage,
        evidence=[e.model_copy(deep=True) for e in observation.evidence],
    )


class RiscVInstructionDecoder:
    """Decode what a presented word represents; never infer execution/retirement."""

    def __init__(self) -> None:
        resolved = version("capstone")
        release = re.fullmatch(r"5\.(\d+)\.(\d+)", resolved)
        if release is None or tuple(map(int, release.groups())) < (0, 9):
            raise ValueError("This adapter requires stable Capstone 5 (project dependency: >=5.0.9,<6)")
        self.descriptor = ToolDescriptor(
            tool_name="capstone", tool_version=resolved, tool_role="instruction_decoder",
            configuration_sha256=hashlib.sha256(MODE.encode()).hexdigest(),
        )
        self._engine = capstone.Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV32)
        self._engine.detail = True
        # Use public enum names rather than assuming register IDs are contiguous.
        self._registers = {getattr(riscv_const, f"RISCV_REG_X{i}"): f"x{i}" for i in range(32)}

    def canonical_register(self, register_id: int) -> str:
        try:
            return self._registers[register_id]
        except KeyError as exc:
            raise ValueError("Only integer x0–x31 operand normalization is supported") from exc

    def decode(self, encoding: InstructionEncoding) -> DecodedInstruction:
        raw = (f"0x{int(encoding.bits, 2):0{(encoding.width_bits + 3) // 4}x}"
               if not any(c in encoding.bits for c in "xz") else "0b" + encoding.bits)
        common = dict(
            observation_id=encoding.observation_id, architecture=encoding.architecture,
            raw_encoding=raw, instruction_width_bits=encoding.width_bits,
            representation=encoding.representation, source_stage=encoding.source_stage,
            decoder=self.descriptor.model_copy(deep=True), decoder_mode=MODE,
            evidence=[e.model_copy(deep=True) for e in encoding.evidence],
        )

        def failure(status: DecodeStatus, reason: str) -> DecodedInstruction:
            return DecodedInstruction(**common, status=status, reason=reason)

        if encoding.architecture != Architecture.RISCV:
            return failure(DecodeStatus.UNSUPPORTED, "This adapter decodes only RISC-V")
        if encoding.representation == EncodingRepresentation.UNKNOWN:
            return failure(DecodeStatus.UNKNOWN, "Instruction representation is not established by the producer")
        if any(c in encoding.bits for c in "xz"):
            return failure(DecodeStatus.UNKNOWN, "Observed instruction bits contain x/z")
        if encoding.width_bits != 32:
            return failure(DecodeStatus.UNSUPPORTED, "Only 32-bit words are enabled; compressed decoding is disabled")
        word = int(encoding.bits, 2)
        if word == 0:
            return failure(DecodeStatus.INVALID, "All-zero instruction encoding is reserved as illegal by RISC-V")
        if word & 3 != 3:
            status = (DecodeStatus.INVALID if encoding.representation == EncodingRepresentation.DECOMPRESSED_WORD
                      else DecodeStatus.UNSUPPORTED)
            return failure(status, "Word is not a 32-bit instruction; no implicit compressed interpretation")
        if word & 0x1f == 0x1f:
            return failure(DecodeStatus.UNSUPPORTED, "Encoding denotes a longer instruction parcel, outside this mode")
        try:
            # PC-independent decode: immediate operands retain backend offset
            # meaning. We do not calculate branch targets or infer control flow.
            instructions = list(self._engine.disasm(instruction_bytes(encoding), 0, count=1))
            if not instructions or instructions[0].size != 4:
                return failure(DecodeStatus.UNSUPPORTED, "Configured Capstone backend did not decode this word; ISA illegality is not inferred")
            insn = instructions[0]
            operands, text = [], []
            for operand in insn.operands:
                if operand.type == riscv_const.RISCV_OP_REG:
                    name = self.canonical_register(operand.reg)
                    operands.append(DecodedOperand(kind="register", register=name))
                    text.append(name)
                elif operand.type == riscv_const.RISCV_OP_IMM:
                    operands.append(DecodedOperand(kind="immediate", immediate=operand.imm))
                    text.append(str(operand.imm))
                elif operand.type == riscv_const.RISCV_OP_MEM:
                    base = self.canonical_register(operand.mem.base)
                    displacement = operand.mem.disp
                    operands.append(DecodedOperand(kind="memory", base=base, displacement=displacement))
                    text.append(f"{displacement}({base})")
                else:
                    return failure(DecodeStatus.UNSUPPORTED, "Unsupported backend operand detail; raw evidence retained")
        except (capstone.CsError, ValueError) as exc:
            return failure(DecodeStatus.UNSUPPORTED, f"Backend/operand limitation: {exc}")
        return DecodedInstruction(**common, status=DecodeStatus.DECODED,
                                  mnemonic=insn.mnemonic, operand_text=", ".join(text),
                                  backend_operand_text=insn.op_str, operands=operands)

    def enrich(self, observations: HardwareObservations) -> HardwareObservations:
        """Return an independent enriched batch; preserve identity, evidence, roles.

        Existing instruction behaviors receive a typed result even on failure.
        No new behaviors or hypotheses are manufactured. Caller may aggregate
        the returned behaviors into the existing ProcessorBehaviorIR.
        """
        result = observations.model_copy(deep=True)
        for observation in result.observations:
            if not isinstance(observation, HardwareObservation) or observation.kind != HardwareObservationKind.INSTRUCTION_ENCODING_OBSERVED:
                continue
            instructions = [b for b in observation.behaviors if b.kind == BehaviorKind.INSTRUCTION]
            if len(instructions) != 1:
                raise ValueError("Instruction observation must have exactly one existing instruction behavior")
            behavior = instructions[0]
            if behavior.architecture != Architecture.RISCV:
                raise ValueError("Instruction behavior architecture is not RISC-V")
            decoded = self.decode(from_observation(observation))
            if behavior.attributes.get("encoding", decoded.raw_encoding) != decoded.raw_encoding:
                raise ValueError("Existing behavior encoding disagrees with observation")
            behavior.decoded_instruction = decoded
        return result
