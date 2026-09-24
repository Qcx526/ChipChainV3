"""Conservative instruction semantics shared by the three ISA decoders."""
from __future__ import annotations

import re

from chipchain.firmware.ghidra_models import ExportInstruction
from chipchain.firmware.static_ir import StaticBehaviorKind as K


def number(text: str) -> int | None:
    match = re.fullmatch(r"#?(-?0x[0-9a-fA-F]+|-?[0-9]+)", text.strip())
    return int(match.group(1), 0) if match else None


def target(operands: list[str]) -> int | None:
    return number(operands[-1]) if operands else None


def memory_arm(operand: str, registers: dict[str, int]) -> int | None:
    match = re.fullmatch(r"\[([a-z0-9]+)(?:,#?(-?0x[0-9a-fA-F]+|-?[0-9]+))?\]", operand.lower())
    if not match or match.group(1) not in registers:
        return None
    return registers[match.group(1)] + (int(match.group(2), 0) if match.group(2) else 0)


def memory_offset(operand: str, registers: dict[str, int]) -> int | None:
    match = re.fullmatch(r"(-?0x[0-9a-fA-F]+|-?[0-9]+)\(([a-z0-9]+)\)", operand.lower())
    if not match:
        return None
    base = register_value(registers, match.group(2))
    return base + int(match.group(1), 0) if base is not None else None


def memory_result(kind: K, address: int | None, value: int | None = None,
                  width_bits: int | None = None) -> dict:
    return {"kind": kind, "semantic_status": "supported" if address is not None else "partial",
            "address": address, "address_status": "exact" if address is not None else "unknown",
            "known_value": value, "access_width_bits": width_bits}


def classify(instruction: ExportInstruction, architecture: str,
             registers: dict[str, int]) -> tuple[dict, ...]:
    if architecture == "arm":
        from chipchain.firmware.semantics_arm import classify_arm
        return classify_arm(instruction, registers)
    if architecture == "riscv":
        from chipchain.firmware.semantics_riscv import classify_riscv
        return classify_riscv(instruction, registers)
    if architecture == "powerpc":
        from chipchain.firmware.semantics_powerpc import classify_powerpc
        return classify_powerpc(instruction, registers)
    raise ValueError(f"Unsupported architecture {architecture}")


def unsupported(instruction: ExportInstruction) -> dict:
    return {"kind": K.UNKNOWN, "semantic_status": "unsupported",
            "detail": f"Unsupported mnemonic {instruction.mnemonic}"}


def register_value(registers: dict[str, int], name: str) -> int | None:
    return 0 if name.lower() in {"zero", "x0"} else registers.get(name.lower())


def kill(registers: dict[str, int], name: str) -> None:
    if name.lower() not in {"zero", "x0"}:
        registers.pop(name.lower(), None)
