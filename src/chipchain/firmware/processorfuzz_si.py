"""Content-addressed ProcessorFuzz testcase specification parser (not execution proof)."""
from __future__ import annotations

from hashlib import sha256
import re

from pydantic import Field, model_validator

from chipchain.domain.common import Contract
from chipchain.firmware.static_ir import content_id


class SiInstruction(Contract):
    line: int = Field(gt=0)
    label: str | None
    section: str | None
    raw_text: str
    mnemonic: str
    operands: tuple[str, ...]
    parse_status: str


class ProcessorFuzzSiTestcase(Contract):
    schema_version: str = "processorfuzz-si/v1"
    case_id: str
    raw_sha256: str
    header: str | None
    execution_mode: str | None
    labels: tuple[str, ...]
    sections: tuple[str, ...]
    instructions: tuple[SiInstruction, ...]
    unparsed_lines: tuple[int, ...]

    @model_validator(mode="after")
    def identity(self):
        if self.case_id != content_id("processorfuzz-si", self.model_dump(mode="json", exclude={"case_id"})):
            raise ValueError("SI identity mismatch")
        return self


_LABEL = re.compile(r"^([A-Za-z_.$][\w.$]*):\s*(.*)$")
_INSTRUCTION = re.compile(r"^([A-Za-z][\w.]*)\s*(.*?)\s*$")


def parse_si(data: bytes) -> ProcessorFuzzSiTestcase:
    if not data or len(data) > 5_000_000 or b"\0" in data:
        raise ValueError("SI file is empty, oversized or binary")
    lines = data.decode("utf-8", errors="strict").splitlines()
    first_line = next((i for i, x in enumerate(lines, 1) if x.strip()), None)
    first = lines[first_line - 1].strip() if first_line is not None else None
    header = first if first and re.fullmatch(r"[pn]-[msu]", first.lower()) else None
    section = None
    labels: list[str] = []
    sections: list[str] = []
    instructions: list[SiInstruction] = []
    unparsed: list[int] = []
    for line_number, raw in enumerate(lines, 1):
        text = raw.strip()
        if not text or header is not None and line_number == first_line:
            continue
        if text.startswith(("#", "//", ";")):
            continue
        label = None
        match = _LABEL.match(text)
        if match:
            label, text = match.groups()
            labels.append(label)
            section = label
            sections.append(label)
        if not text:
            continue
        # Data words and directives are preserved as unparsed source lines.
        parsed = _INSTRUCTION.match(text)
        if not parsed or text.startswith(".") or re.fullmatch(r"[0-9a-fA-F]+", text):
            unparsed.append(line_number)
            continue
        mnemonic, tail = parsed.groups()
        # ProcessorFuzz may append generator annotations after wide spacing.
        operands = tuple(x.strip() for x in re.split(r",\s*", tail.split("    ")[0]) if x.strip())
        instructions.append(SiInstruction(line=line_number, label=label, section=section,
                                          raw_text=raw, mnemonic=mnemonic.lower(),
                                          operands=operands, parse_status="parsed"))
    if not instructions:
        raise ValueError("SI contains no parseable instructions")
    fields = dict(schema_version="processorfuzz-si/v1", raw_sha256=sha256(data).hexdigest(),
                  header=header, execution_mode=header, labels=tuple(labels),
                  sections=tuple(dict.fromkeys(sections)), instructions=tuple(instructions),
                  unparsed_lines=tuple(unparsed))
    return ProcessorFuzzSiTestcase(case_id=content_id("processorfuzz-si", fields), **fields)
