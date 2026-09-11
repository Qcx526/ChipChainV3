"""Bounded text subsets observed in EnCorpus Ibex driver exports, not full parsers."""

import re
from dataclasses import dataclass
from typing import Callable

from chipchain.domain.evidence import BitRange
from chipchain.tools.hardware.encorpus.models import IngestionError

MAX_BYTES = 16 * 1024 * 1024
MAX_LINE = 64 * 1024
MAX_SIGNALS = 20_000
MAX_WIDTH = 65_536
MAX_FRAMES = 10_000
MAX_SNAPSHOT_VALUES = 1_000_000


def checked_lines(text: str) -> list[str]:
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise IngestionError("Artifact exceeds 16 MiB reader limit")
    lines = text.splitlines()
    if any(len(line) > MAX_LINE for line in lines):
        raise IngestionError("Artifact line exceeds 64 KiB reader limit")
    return lines


@dataclass(frozen=True)
class Mutation:
    module: str
    signal: str
    reference: str
    host: str
    reference_line: int
    host_line: int
    source: str | None


def _rtl_lines(text: str):
    normalized = []
    module = None
    in_cell = False
    markers = []
    source = None
    cell_source = None
    module_count = 0
    for number, raw in enumerate(checked_lines(text), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0]
        if line == 'attribute \\buggy "buggy"':
            if module is None or in_cell:
                raise IngestionError("Unsupported buggy marker location")
            markers.append((module, len(normalized)))
            continue
        if token == "module":
            if module is not None or len(line.split()) != 2:
                raise IngestionError("Malformed RTLIL module")
            module = line.split()[1]
            module_count += 1
        elif token == "cell":
            if module is None or in_cell or len(line.split()) != 3:
                raise IngestionError("Malformed RTLIL cell")
            in_cell = True
        elif token == "end":
            if line != "end" or module is None:
                raise IngestionError("Unbalanced RTLIL end")
            if in_cell:
                in_cell = False
            else:
                module = None
        elif token not in {"autoidx", "attribute", "parameter", "wire", "connect", "memory"}:
            raise IngestionError(f"Unsupported RTLIL construct: {token}")
        if token not in {"autoidx", "attribute", "module", "end"} and module is None:
            raise IngestionError("RTLIL declaration outside a module")
        row_source = None
        if line.startswith('attribute \\src '):
            if not line.startswith('attribute \\src "') or not line.endswith('"'):
                raise IngestionError("Malformed RTLIL source attribute")
            source = line[len('attribute \\src "'):-1]
            row_source = source
        elif token == "cell":
            cell_source, source = source, None
            row_source = cell_source
        elif token in {"wire", "memory", "module", "autoidx"}:
            row_source, source = source, None
        elif token in {"connect", "parameter"}:
            row_source = cell_source if in_cell else None
            source = None
        elif token == "end":
            cell_source = source = None
        normalized.append((line, number, module, in_cell, row_source))
    if module is not None or in_cell or not module_count:
        raise IngestionError("Incomplete RTLIL module")
    return normalized, markers


_CONNECTION = re.compile(r"connect (\S+) (.+)")
# Single signal with optional bit selection, or a constant. No concat/RHS expression.
_DRIVER = re.compile(r"(?:[\\$][^\s{}]+(?: \[\d+(?::\d+)?\])?|\d+'[01xz]+|\d+)")


def parse_driver_mutation(host_text: str, reference_text: str) -> Mutation | None:
    host, markers = _rtl_lines(host_text)
    reference, reference_markers = _rtl_lines(reference_text)
    if reference_markers or len(host) != len(reference):
        raise IngestionError("Unsupported RTLIL layout: expected matched host/reference exports")
    changes = [(h, r) for h, r in zip(host, reference) if h[0] != r[0]]
    if not changes:
        if markers:
            raise IngestionError("Buggy marker without a changed connection")
        return None
    if len(changes) != 1 or len(markers) != 1:
        raise IngestionError("Expected exactly one driver connect mutation and one buggy marker")
    h, r = changes[0]
    hm, rm = _CONNECTION.fullmatch(h[0]), _CONNECTION.fullmatch(r[0])
    if (not hm or not rm or h[2] != r[2] or h[3] or r[3]
            or hm[1] != rm[1] or not _DRIVER.fullmatch(hm[2]) or not _DRIVER.fullmatch(rm[2])):
        raise IngestionError("Unsupported driver mutation: expected one module-level connection RHS")
    module, next_index = markers[0]
    marked = host[next_index][0] if next_index < len(host) else ""
    if module != h[2] or not marked.startswith("wire ") or marked.split()[-1] != hm[1]:
        raise IngestionError("Buggy marker does not identify the changed driver signal")
    # src is intentionally the declaration's annotation, not the nearest unrelated
    # connect. Generated nodes often have no own source span.
    source = host[next_index][4]
    if source is None:
        sources = sorted({row[4] for row in host if row[2] == module and row[3]
                          and row[0].startswith("connect ") and row[0].split()[2:] == [hm[1]]
                          and row[4] is not None})
        source = " | ".join(sources) or None
    return Mutation(h[2], hm[1], rm[2], hm[2], r[1], h[1], source)


_COVER = re.compile(
    r'.*The cover property "(?P<property>[^"]+)" was covered in '
    r'(?P<cycles>\d+) cycles in \d+(?:\.\d+)? s\.'
)
_ERROR = re.compile(r"ERROR \((EVS053)\): (.+)")


def parse_formal_log(text: str) -> list[dict]:
    results = []
    for number, line in enumerate(checked_lines(text), 1):
        if 'The cover property "' in line and "was covered" in line:
            m = _COVER.fullmatch(line)
            if not m:
                raise IngestionError(f"Malformed cover result at line {number}")
            if m["property"] != "miter.i_miter.c_propagated":
                continue
            results.append(dict(line=number, category="cover_hit", raw_result=line,
                                property_name=m["property"], cycles=int(m["cycles"])))
        elif "EVS053" in line:
            m = _ERROR.fullmatch(line)
            if not m:
                raise IngestionError(f"Malformed EVS053 result at line {number}")
            results.append(dict(line=number, category="trace_error", raw_result=line, error_code=m[1]))
        elif line.startswith("ERROR "):
            raise IngestionError(f"Unsupported formal error at line {number}: {line}")
    if not results:
        raise IngestionError("No supported formal result found")
    return results


@dataclass(frozen=True)
class Signal:
    name: str
    code: str
    width: int
    bit_range: BitRange | None
    line: int


@dataclass(frozen=True)
class Value:
    bits: str
    line: int


@dataclass
class Waveform:
    signals: dict[str, Signal]
    frames: list[tuple[int, dict[str, Value]]]
    unit: str
    scale: int


def parse_vcd(text: str, select: Callable[[str], bool] = lambda _: True) -> Waveform:
    """wire/reg, module scopes, descending ranges, four-state values, dumpvars/all.

    Validate all declarations/changes; retain only selected values at the end of
    each timestamp. Unsupported directives/value types and resource excess fail.
    """
    lines = checked_lines(text)
    scope, signals, codes = [], {}, {}
    unit = None
    scale = 1
    index = 0
    ended = False
    while index < len(lines):
        number = index + 1
        parts = lines[index].split()
        index += 1
        if not parts:
            continue
        while "$end" not in parts:
            if index >= len(lines):
                raise IngestionError("Unterminated VCD header directive")
            parts.extend(lines[index].split())
            index += 1
        if parts[-1] != "$end" or parts.count("$end") != 1:
            raise IngestionError("Unsupported VCD header directive layout")
        tag = parts[0]
        if tag in {"$date", "$version", "$comment"}:
            continue
        if tag == "$scope" and len(parts) == 4 and parts[1] == "module":
            scope.append(parts[2])
        elif tag == "$upscope" and len(parts) == 2 and scope:
            scope.pop()
        elif tag == "$timescale" and unit is None:
            m = re.fullmatch(r"(1|10|100)\s*(s|ms|us|ns|ps|fs)", " ".join(parts[1:-1]))
            if not m:
                raise IngestionError("Unsupported VCD timescale")
            scale, unit = int(m[1]), m[2]
        elif tag == "$var" and len(parts) in {6, 7} and parts[1] in {"wire", "reg"} and scope:
            if not parts[2].isdigit() or not 0 < int(parts[2]) <= MAX_WIDTH:
                raise IngestionError("Unsupported VCD signal width")
            width, code, name = int(parts[2]), parts[3], ".".join([*scope, parts[4]])
            bit_range = None
            if len(parts) == 7:
                m = re.fullmatch(r"\[(\d+)(?::(\d+))?\]", parts[5])
                if not m or int(m[1]) - int(m[2] or m[1]) + 1 != width:
                    raise IngestionError("Unsupported VCD bit range")
                bit_range = BitRange(msb=int(m[1]), lsb=int(m[2] or m[1]))
            if name in signals or (code in codes and codes[code] != width):
                raise IngestionError("Conflicting VCD signal identity")
            signals[name] = Signal(name, code, width, bit_range, number)
            codes[code] = width
            if len(signals) > MAX_SIGNALS:
                raise IngestionError("VCD signal limit exceeded")
        elif tag == "$enddefinitions" and len(parts) == 2 and not scope:
            ended = True
            break
        else:
            raise IngestionError(f"Unsupported VCD header at line {number}: {tag}")
    if not ended or not signals or unit is None:
        raise IngestionError("Incomplete VCD header")
    signals = {name: signal for name, signal in signals.items() if select(name)}
    selected = {s.code for s in signals.values()}
    current, frames = {}, []
    time = None
    dumping = False
    entries = 0

    def save():
        nonlocal entries
        entries += len(current)
        if len(frames) >= MAX_FRAMES or entries > MAX_SNAPSHOT_VALUES:
            raise IngestionError("VCD snapshot limit exceeded")
        frames.append((time, current.copy()))

    while index < len(lines):
        number = index + 1
        line = lines[index].strip()
        index += 1
        if not line:
            continue
        if line.split()[0] == "$comment":
            while "$end" not in line:
                if index >= len(lines):
                    raise IngestionError("Unterminated VCD comment")
                line += " " + lines[index].strip()
                index += 1
            if not line.endswith("$end"):
                raise IngestionError("Unsupported VCD comment layout")
            continue
        if line in {"$dumpvars", "$dumpall"} and not dumping:
            dumping = True
            continue
        if line == "$end" and dumping:
            dumping = False
            continue
        if line.startswith("#") and line[1:].isdigit():
            new_time = int(line[1:])
            if time is not None and new_time < time:
                raise IngestionError("VCD time moved backwards")
            if time is not None and new_time != time:
                save()
            time = new_time
            continue
        if line[0] in "01xXzZ":
            bits, code = line[0].lower(), line[1:]
            if codes.get(code) != 1:
                raise IngestionError(f"Invalid scalar VCD change at line {number}")
        elif line[0] in "bB":
            m = re.fullmatch(r"[bB]([01xXzZ]+)\s+(\S+)", line)
            if not m or m[2] not in codes or len(m[1]) > codes[m[2]]:
                raise IngestionError(f"Invalid vector VCD change at line {number}")
            bits, code = m[1].lower(), m[2]
            bits = bits.rjust(codes[code], bits[0] if bits[0] in "xz" else "0")
        else:
            raise IngestionError(f"Unsupported VCD body construct at line {number}")
        if time is None:
            if not dumping:
                raise IngestionError("VCD value precedes timestamp/dumpvars")
            time = 0
        if code in selected:
            current[code] = Value(bits, number)
    if dumping or time is None:
        raise IngestionError("Incomplete VCD body")
    save()
    return Waveform(signals, frames, unit, scale)
