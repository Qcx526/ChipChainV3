"""Deterministic architecture adapters; domain contracts contain no backend objects."""

from chipchain.tools.architecture.riscv import RiscVInstructionDecoder
from chipchain.tools.architecture.arm import ArmThumbInstructionDecoder

__all__ = ["RiscVInstructionDecoder", "ArmThumbInstructionDecoder"]
