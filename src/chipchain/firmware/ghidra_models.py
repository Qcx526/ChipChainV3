"""Strict schema for the committed Ghidra headless exporter."""
from __future__ import annotations

from pydantic import Field, model_validator

from chipchain.domain.common import Contract


class ExportRange(Contract):
    start: int = Field(ge=0)
    end: int = Field(ge=0)


class ExportFunction(Contract):
    local_id: str = Field(alias="id")
    entry: int = Field(ge=0)
    name: str
    ranges: list[ExportRange]
    thunk: bool
    external: bool


class ExportBlock(Contract):
    local_id: str = Field(alias="id")
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    ranges: list[ExportRange]


class ExportInstruction(Contract):
    pc: int = Field(ge=0)
    bytes: str = Field(pattern=r"^(?:[0-9a-f]{2})+$")
    mnemonic: str
    operands: list[str]
    text: str
    function_entry: int | None
    function_local_id: str | None = Field(default=None, alias="function_id")
    block_start: int | None
    block_local_id: str | None = Field(default=None, alias="block_id")


class ExportEdge(Contract):
    source: int = Field(ge=0)
    target: int = Field(ge=0)
    type: str


class ExportCall(Contract):
    pc: int = Field(ge=0)
    caller: int | None
    direct: bool
    target: int | None


class ExportReference(Contract):
    source: int = Field(ge=0)
    target: int | None
    type: str
    operand: int


class GhidraExport(Contract):
    schema_version: str = Field(alias="schema", pattern=r"^ghidra-firmware-facts/v1$")
    language: str
    compiler: str
    image_base: int = Field(ge=0)
    functions: list[ExportFunction]
    blocks: list[ExportBlock]
    instructions: list[ExportInstruction]
    edges: list[ExportEdge]
    calls: list[ExportCall]
    references: list[ExportReference]

    @model_validator(mode="after")
    def unique(self):
        for collection, key in ((self.functions, "entry"), (self.blocks, "start"),
                                (self.instructions, "pc"), (self.calls, "pc")):
            values = [getattr(item, key) for item in collection]
            if len(values) != len(set(values)):
                raise ValueError(f"Duplicate Ghidra {key}")
        for f in self.functions:
            if f.local_id != f"function:0x{f.entry:x}":
                raise ValueError("Ghidra function local ID mismatch")
        for b in self.blocks:
            if b.local_id != f"block:0x{b.start:x}":
                raise ValueError("Ghidra block local ID mismatch")
        for i in self.instructions:
            if i.function_local_id != (f"function:0x{i.function_entry:x}" if i.function_entry is not None else None):
                raise ValueError("Ghidra instruction function local ID mismatch")
            if i.block_local_id != (f"block:0x{i.block_start:x}" if i.block_start is not None else None):
                raise ValueError("Ghidra instruction block local ID mismatch")
        return self
