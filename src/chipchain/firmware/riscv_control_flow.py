"""RV32 I+C target semantics from instruction bits; Capstone supplies display text.

J/B/CJ/CB offsets are sign-extended before adding the instruction PC, modulo 2**32.
JALR remains indirect even with x0 base: runtime-target reasoning is out of scope.
"""
from importlib.metadata import version
import capstone
from chipchain.domain.common import Architecture
from chipchain.firmware.control_flow_grounding import ControlTransferFact, FactProvenance, identity


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def resolve_transfer(*, case_id, pc, encoding, architecture, artifact_id, evidence_ids,
                     source_sha256, word_size_bits=32, runtime_selection_sha256=None, byteorder="little"):
    architecture = Architecture(architecture)
    common = dict(case_id=case_id, architecture=architecture, source_artifact_ids=[artifact_id],
        resolution_method="encoding-sign-extended-pc-relative-rv32-ic/v1",
        decoder_mode=f"{architecture.value}:{word_size_bits}:{byteorder}:RV32IC-adapter", instruction_pc=pc, instruction_encoding=encoding.hex(),
        instruction_width_bits=len(encoding)*8, source_artifact_id=artifact_id, evidence_ids=evidence_ids,
        mnemonic='', operands='', transfer_kind='other_control_transfer', resolution_status='unsupported',
        resolved_target_pc=None, fallthrough_pc=None, decoder_backend='capstone+chipchain-rv32-ic',
        decoder_version=version('capstone'), provenance=FactProvenance(scope='static_instruction',
            method='encoding-sign-extended-pc-relative-rv32-ic/v1', input_sha256=source_sha256,
            architecture=architecture, word_size_bits=word_size_bits,
            runtime_selection_sha256=runtime_selection_sha256), reason='instruction_class_not_supported')

    def result(**updates):
        data = {**common, **updates}
        # Identity depends on deterministic content, not iteration order or run IDs.
        data['fact_id'] = identity('a6-transfer', {**data, 'provenance': data['provenance'].model_dump(mode='json')})
        return ControlTransferFact(**data)

    if architecture != Architecture.RISCV or word_size_bits != 32 or byteorder != "little":
        return result(reason='architecture_or_word_size_not_implemented')
    if len(encoding) not in (2, 4) or pc % 2 or pc > 0xffffffff:
        return result(resolution_status='invalid', reason='invalid_width_or_alignment')
    word = int.from_bytes(encoding, 'little')
    if word == 0 or ((word & 3 == 3) != (len(encoding) == 4)):
        return result(resolution_status='invalid', reason='invalid_encoding_or_length')
    if word & 0x1f == 0x1f:
        return result(reason='long_instruction_not_supported')
    if len(encoding) == 4 and ((word & 127 == 0x63 and (word >> 12) & 7 not in (0,1,4,5,6,7))
            or (word & 127 == 0x67 and (word >> 12) & 7 != 0)):
        return result(resolution_status='invalid', reason='reserved_transfer_funct3')
    engine = capstone.Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV32 | capstone.CS_MODE_RISCVC)
    insns = list(engine.disasm(encoding, pc, count=1))
    if insns and insns[0].size == len(encoding):
        common.update(mnemonic=insns[0].mnemonic, operands=insns[0].op_str)
    else:
        return result(reason='decoder_did_not_recognize_instruction')
    offset, kind, fallthrough = None, None, None
    if len(encoding) == 4:
        opcode, rd, funct3, rs1 = word & 127, (word >> 7) & 31, (word >> 12) & 7, (word >> 15) & 31
        if opcode == 0x6f:
            offset = signed(((word >> 31) << 20) | (((word >> 12) & 255) << 12) |
                            (((word >> 20) & 1) << 11) | (((word >> 21) & 1023) << 1), 21)
            kind = 'direct_call' if rd in (1, 5) else 'direct_jump'
            common.update(destination_register=f'x{rd}')
            fallthrough = (pc + 4) & 0xffffffff
        elif opcode == 0x63:
            if funct3 not in (0, 1, 4, 5, 6, 7):
                return result(resolution_status='invalid', reason='reserved_branch_funct3')
            offset = signed(((word >> 31) << 12) | (((word >> 7) & 1) << 11) |
                            (((word >> 25) & 63) << 5) | (((word >> 8) & 15) << 1), 13)
            kind, fallthrough = 'conditional_branch', (pc + 4) & 0xffffffff
        elif opcode == 0x67:
            if funct3 != 0:
                return result(resolution_status='invalid', reason='reserved_jalr_funct3')
            kind = ('return' if rd == 0 and rs1 in (1, 5) and word >> 20 == 0 else
                    'indirect_call' if rd in (1, 5) else 'indirect_jump')
            return result(transfer_kind=kind, resolution_status='indirect', reason='runtime_register_target')
        elif word in (0x30200073, 0x10200073, 0x00200073):
            return result(transfer_kind='return', resolution_status='indirect', reason='runtime_privilege_state_target')
    else:
        quadrant, funct3 = word & 3, word >> 13
        if quadrant == 1 and funct3 in (1, 5):
            offset = signed((((word >> 12) & 1) << 11) | (((word >> 11) & 1) << 4) |
                (((word >> 9) & 3) << 8) | (((word >> 8) & 1) << 10) | (((word >> 7) & 1) << 6) |
                (((word >> 6) & 1) << 7) | (((word >> 3) & 7) << 1) | (((word >> 2) & 1) << 5), 12)
            kind = 'direct_call' if funct3 == 1 else 'direct_jump'
            common.update(destination_register='x1' if funct3 == 1 else 'x0')
            fallthrough = (pc + 2) & 0xffffffff
        elif quadrant == 1 and funct3 in (6, 7):
            offset = signed((((word >> 12) & 1) << 8) | (((word >> 10) & 3) << 3) |
                (((word >> 5) & 3) << 6) | (((word >> 3) & 3) << 1) | (((word >> 2) & 1) << 5), 9)
            kind, fallthrough = 'conditional_branch', (pc + 2) & 0xffffffff
        elif quadrant == 2 and funct3 == 4 and (word >> 2) & 31 == 0:
            rs1 = (word >> 7) & 31
            if rs1 == 0:
                return result(reason='breakpoint_or_reserved_not_a_direct_transfer')
            kind = ('indirect_call' if word & 0x1000 else 'return' if rs1 in (1, 5) else 'indirect_jump')
            return result(transfer_kind=kind, resolution_status='indirect', reason='runtime_register_target')
    if offset is None:
        return result()
    return result(transfer_kind=kind, resolution_status='resolved_direct',
                  resolved_target_pc=(pc + offset) & 0xffffffff, fallthrough_pc=fallthrough, decoded_immediate=offset,
                  fallthrough_semantics='conditional_not_taken' if kind=='conditional_branch' else 'sequential_address_not_branch_alternative',
                  reason='signed_encoding_offset_added_to_instruction_pc')
