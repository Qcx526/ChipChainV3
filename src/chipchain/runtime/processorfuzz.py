"""Strict bounded parsers for documented ProcessorFuzz trace/signature columns."""
from __future__ import annotations

import csv
from hashlib import sha256
from io import StringIO
import re

from chipchain.firmware.static_ir import content_id
from chipchain.runtime.evidence import InstructionExecutionObservation, RuntimeSource


def _observation(source: RuntimeSource, stream: str, index: int, pc: int,
                 encoding: str, mode: str | None, raw: str) -> InstructionExecutionObservation:
    fields = dict(source=source, stream=stream, record_index=index, pc=pc,
                  encoding=encoding.lower(), privilege_mode=mode,
                  raw_record_sha256=sha256(raw.encode()).hexdigest())
    return InstructionExecutionObservation(observation_id=content_id("runtime-insn", fields), **fields)


def _require_source(data: bytes, source: RuntimeSource) -> None:
    if sha256(data).hexdigest() != source.trace_sha256:
        raise ValueError("Runtime source trace SHA mismatch")


_RTL = re.compile(r"^(\d+)\s+(\d+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+([0-9a-fA-F]+)(?:\s+.*)?$")
_ISA_LOG = re.compile(r"^core\s+\d+:\s+0x([0-9a-fA-F]+)\s+\(0x([0-9a-fA-F]+)\)\s+\[([^]]+)\]")


def parse_rtl_trace(data: bytes, source: RuntimeSource) -> dict:
    _require_source(data, source)
    text = data.decode("utf-8", errors="strict")
    lines = text.splitlines()
    if not lines or lines[0].strip() != "HartID mode PC INSTR WDATA COV":
        raise ValueError("Unsupported RTL trace header")
    observations = []
    sideband = 0
    for line_no, raw in enumerate(lines[1:], 2):
        match = _RTL.fullmatch(raw)
        if match:
            hart, mode, pc, encoding, _wdata, _cov = match.groups()
            if hart != "0":
                raise ValueError("Multi-hart RTL trace requires explicit hart binding")
            observations.append(_observation(source, "rtl", len(observations), int(pc, 16),
                                             encoding, mode, raw))
        elif raw.startswith(("DELAYED ", "RTL ", "TRACE ")) or not raw.strip():
            sideband += 1
        else:
            # Unknown rows may contain architectural events; record rather than discard.
            sideband += 1
    if not observations:
        raise ValueError("RTL trace has no supported instruction rows")
    return {"schema_version": "processorfuzz-rtl-evidence/v1", "source": source.model_dump(mode="json"),
            "parse_scope": "header and first six columns only; remaining columns opaque",
            "instruction_observations": [x.model_dump(mode="json") for x in observations],
            "unparsed_sideband_rows": sideband}


_CSV_COLUMNS = {"pc", "instr", "gpr", "csr", "binary", "mode", "instr_str", "operand",
                "pad", "mstatus", "frm", "fflags", "mcause", "scause", "medeleg",
                "mcounteren", "scounteren"}


def parse_isa_csv(data: bytes, source: RuntimeSource) -> dict:
    _require_source(data, source)
    text = data.decode("utf-8", errors="strict")
    reader = csv.DictReader(StringIO(text))
    if set(reader.fieldnames or ()) != _CSV_COLUMNS:
        raise ValueError("Unsupported ISA CSV header")
    observations = []
    for row in reader:
        if None in row or any(value is None for value in row.values()):
            raise ValueError("Malformed ISA CSV row")
        try:
            pc = int(row["pc"], 16)
            int(row["binary"], 16)
        except ValueError as exc:
            raise ValueError("Malformed ISA CSV PC/encoding") from exc
        raw = ",".join(row[key] for key in reader.fieldnames)
        observations.append(_observation(source, "isa_reference", len(observations), pc,
                                         row["binary"], row["mode"], raw))
    if not observations:
        raise ValueError("ISA CSV has no instruction observations")
    return {"schema_version": "processorfuzz-isa-evidence/v1", "source": source.model_dump(mode="json"),
            "parse_scope": "ISA reference CSV instruction columns; CSR/state columns preserved in source",
            "instruction_observations": [x.model_dump(mode="json") for x in observations]}


def parse_isa_log(data: bytes, source: RuntimeSource) -> dict:
    _require_source(data, source)
    lines = data.decode("utf-8", errors="strict").splitlines()
    observations = []
    for raw in lines:
        match = _ISA_LOG.match(raw)
        if match:
            pc, encoding, state = match.groups()
            mode = state.split(",", 1)[0]
            observations.append(_observation(source, "isa_reference", len(observations),
                                             int(pc, 16), encoding, mode, raw))
    if not observations:
        raise ValueError("ISA log has no supported instruction observations")
    return {"schema_version": "processorfuzz-isa-log-evidence/v1", "source": source.model_dump(mode="json"),
            "parse_scope": "instruction records only; register-write sideband remains unparsed",
            "instruction_observations": [x.model_dump(mode="json") for x in observations],
            "unparsed_rows": len(lines) - len(observations)}


def parse_signature(data: bytes, source: RuntimeSource, stream: str) -> dict:
    _require_source(data, source)
    lines = data.decode("ascii", errors="strict").splitlines()
    if not lines or any(not re.fullmatch(r"[0-9a-fA-F]{32}", line) for line in lines):
        raise ValueError("Unsupported signature format")
    return {"schema_version": "architectural-signature/v1", "stream": stream,
            "source": source.model_dump(mode="json"), "sha256": sha256(data).hexdigest(),
            "word_width_bits": 128, "words": [line.lower() for line in lines]}


def differential(rtl: dict, isa: dict, *, testcase_binding: str,
                 firmware_binding: str, execution_context_binding: str) -> dict:
    a, b = rtl["words"], isa["words"]
    mismatches = [{"index": i, "rtl_raw": x, "isa_raw": y}
                  for i, (x, y) in enumerate(zip(a, b)) if x != y]
    a_source, b_source = rtl["source"], isa["source"]
    source_conflict = any(a_source[key] != b_source[key] for key in
                          ("case_id", "elf_sha256", "si_sha256", "rtl_trace_sha256",
                           "isa_trace_sha256", "simulator_sha256", "build_metadata_sha256"))
    fields = {"reference_artifact_id": "sha256:" + isa["sha256"],
              "rtl_artifact_id": "sha256:" + rtl["sha256"],
              "same_testcase_binding": testcase_binding,
              "same_firmware_binding": firmware_binding,
              "same_execution_context_binding": execution_context_binding,
              "comparison_scope": "raw 128-bit signature words by exact index; register attribution unknown",
              "matching_fields": min(len(a), len(b)) - len(mismatches),
              "different_fields": mismatches,
              "status": ("CONFLICT" if len(a) != len(b) or source_conflict else
                         "UNKNOWN" if "BOUND" not in {testcase_binding, firmware_binding, execution_context_binding}
                         or not all(x == "BOUND" for x in (testcase_binding, firmware_binding, execution_context_binding))
                         else "SUPPORTED_DIFFERENTIAL" if mismatches else "NO_DIFFERENTIAL"),
              "raw_values_differ": bool(mismatches)}
    return {"differential_id": content_id("architectural-differential", fields), **fields}


def align_traces(rtl: dict, isa: dict) -> dict:
    # Unique PC+encoding equality, never positional zip or nearest-PC matching.
    from collections import Counter
    left = rtl["instruction_observations"]
    right = isa["instruction_observations"]
    if any(rtl["source"][key] != isa["source"][key] for key in
           ("case_id", "elf_sha256", "si_sha256", "rtl_trace_sha256", "isa_trace_sha256")):
        return {"status": "UNKNOWN", "unique_pairs": [], "ambiguous_keys": [],
                "missing_keys": [], "reason": "Source case/ELF/SI identities disagree"}
    lk = Counter((x["pc"], x["encoding"]) for x in left)
    rk = Counter((x["pc"], x["encoding"]) for x in right)
    pairs = []
    positions = []
    ambiguous = []
    missing = []
    for key in sorted(lk):
        if lk[key] == rk[key] == 1:
            a = next(x for x in left if (x["pc"], x["encoding"]) == key)
            b = next(x for x in right if (x["pc"], x["encoding"]) == key)
            pairs.append({"rtl_observation_id": a["observation_id"],
                          "isa_observation_id": b["observation_id"], "pc": key[0], "encoding": key[1]})
            positions.append((a["record_index"], b["record_index"]))
        elif rk[key] == 0:
            missing.append({"pc": key[0], "encoding": key[1]})
        else:
            ambiguous.append({"pc": key[0], "encoding": key[1]})
    ordered = [b for _, b in sorted(positions)]
    monotonic = ordered == sorted(ordered)
    extra_reference = [key for key in rk if key not in lk]
    return {"status": "AMBIGUOUS" if ambiguous else
            "UNKNOWN" if missing or extra_reference or not monotonic else "BOUND",
            "unique_pairs": pairs, "ambiguous_keys": ambiguous, "missing_keys": missing,
            "extra_reference_keys": [{"pc": pc, "encoding": enc} for pc, enc in sorted(extra_reference)],
            "order_consistent": monotonic}
