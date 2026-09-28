"""Portable ProcessorFuzz parser and provenance boundary tests."""
from __future__ import annotations

from pathlib import Path
from hashlib import sha256
from zipfile import ZipInfo
from zipfile import ZipFile

import pytest

from chipchain.firmware.processorfuzz_si import parse_si
from chipchain.runtime.evidence import RuntimeSource
from chipchain.runtime.processorfuzz import (
    align_traces, differential, parse_isa_csv, parse_rtl_trace, parse_signature,
)
from chipchain.workflow.processorfuzz import (
    _package, _select, ProcessorFuzzRoleDeclaration, HARDWARE_TRIGGER_VALIDATION, UNCLASSIFIED_ROLE,
)


def test_si_identity_content_only_and_not_execution():
    data = b"p-m\n_p0: csrrw x1, mstatus, x2\n    sfence.vma x0, x0\n"
    parsed = parse_si(data)
    assert parsed == parse_si(data)
    assert parsed.header == "p-m"
    assert [x.mnemonic for x in parsed.instructions] == ["csrrw", "sfence.vma"]
    assert not hasattr(parsed.instructions[0], "executed")
    with pytest.raises((ValueError, UnicodeDecodeError)):
        parse_si(b"\xff\0")


def test_trigger_test_role_is_explicit_and_coherent():
    assert HARDWARE_TRIGGER_VALIDATION.customer_firmware is False
    assert UNCLASSIFIED_ROLE.customer_firmware is None
    with pytest.raises(ValueError, match="inconsistent"):
        ProcessorFuzzRoleDeclaration(
            package_role="hardware_trigger_validation_package",
            firmware_role="hardware_supplied_trigger_test_firmware",
            firmware_origin="hardware_department", customer_firmware=True,
            role_basis="hardware_team_delivery_intake")


@pytest.mark.parametrize("entry", ["../escape.si", "/absolute.si", "C:/drive.si", "dir\\escape.si"])
def test_zip_rejects_unsafe_paths(tmp_path: Path, entry: str):
    package = tmp_path / "bad.zip"
    with ZipFile(package, "w") as archive:
        archive.writestr(entry, "p-m\nli x1,1\n")
    with pytest.raises(ValueError, match="Unsafe ZIP"):
        _package(package)


def test_zip_rejects_symlink(tmp_path: Path):
    package = tmp_path / "link.zip"
    link = ZipInfo("inside.si")
    link.create_system = 3
    link.external_attr = 0o120777 << 16
    with ZipFile(package, "w") as archive:
        archive.writestr(link, "../outside")
    with pytest.raises(ValueError, match="Unsafe ZIP"):
        _package(package)


def test_runtime_parsers_and_ambiguous_alignment():
    def source(data):
        return RuntimeSource(case_id="case", elf_sha256="0" * 64, si_sha256="1" * 64,
                             trace_sha256=sha256(data).hexdigest(),
                             rtl_trace_sha256="2" * 64, isa_trace_sha256="3" * 64)
    rtl_data = b"HartID mode PC INSTR WDATA COV\n0 3 0x1000 0x13 0x0 0000\n0 3 0x1000 0x13 0x0 0000\n"
    rtl = parse_rtl_trace(rtl_data, source(rtl_data))
    header = b"pc,instr,gpr,csr,binary,mode,instr_str,operand,pad,mstatus,frm,fflags,mcause,scause,medeleg,mcounteren,scounteren\n"
    rows = b"1000,addi,,,13,3,addi,,,,,,,,,,\n"
    isa = parse_isa_csv(header + rows, source(header + rows))
    assert len(rtl["instruction_observations"]) == 2
    assert len(isa["instruction_observations"]) == 1
    assert align_traces(rtl, isa)["status"] == "AMBIGUOUS"
    assert rtl["source"]["rtl_source_revision"] == "not_established"
    with pytest.raises(ValueError, match="Unsupported RTL"):
        parse_rtl_trace(b"unknown\n", source(b"unknown\n"))
    with pytest.raises(ValueError, match="SHA mismatch"):
        parse_rtl_trace(rtl_data, source(b"different"))


def test_alignment_checks_order_and_extra_reference_records():
    source = {"case_id": "c", "elf_sha256": "0" * 64, "si_sha256": "1" * 64,
              "rtl_trace_sha256": "2" * 64, "isa_trace_sha256": "3" * 64}
    rows = [{"pc": 1, "encoding": "aa", "record_index": 0, "observation_id": "r0"},
            {"pc": 2, "encoding": "bb", "record_index": 1, "observation_id": "r1"}]
    rtl = {"source": source, "instruction_observations": rows}
    isa = {"source": source, "instruction_observations": [
        {**rows[0], "record_index": 1, "observation_id": "i1"},
        {**rows[1], "record_index": 0, "observation_id": "i0"}]}
    assert align_traces(rtl, isa)["status"] == "UNKNOWN"
    isa["instruction_observations"] = [{**rows[0], "observation_id": "i0"},
                                       {**rows[1], "observation_id": "i1"},
                                       {"pc": 3, "encoding": "cc", "record_index": 2, "observation_id": "i2"}]
    assert align_traces(rtl, isa)["status"] == "UNKNOWN"


def test_signature_difference_requires_context_binding():
    def source(data):
        return RuntimeSource(case_id="case", elf_sha256="0" * 64, si_sha256="1" * 64,
                             trace_sha256=sha256(data).hexdigest(),
                             rtl_trace_sha256="2" * 64, isa_trace_sha256="3" * 64)
    rtl_data = ("0" * 32 + "\n" + "1" * 32 + "\n").encode()
    isa_data = ("0" * 32 + "\n" + "2" * 32 + "\n").encode()
    rtl = parse_signature(rtl_data, source(rtl_data), "rtl")
    isa = parse_signature(isa_data, source(isa_data), "isa_reference")
    result = differential(rtl, isa, testcase_binding="UNKNOWN", firmware_binding="BOUND",
                          execution_context_binding="UNKNOWN")
    assert result["raw_values_differ"]
    assert result["status"] == "UNKNOWN"


@pytest.mark.parametrize("different", [False, True])
def test_signatures_without_traces_never_establish_differential(different):
    rtl_bytes = ("0" * 32 + "\n").encode()
    isa_bytes = (("1" if different else "0") * 32 + "\n").encode()
    rtl = parse_signature(rtl_bytes, None, "rtl")
    isa = parse_signature(isa_bytes, None, "isa_reference")
    assert rtl["source"] is isa["source"] is None
    assert rtl["sha256"] == sha256(rtl_bytes).hexdigest()
    result = differential(rtl, isa, testcase_binding="BOUND", firmware_binding="BOUND",
                          execution_context_binding="BOUND")
    assert result["raw_values_differ"] is different
    assert len(result["different_fields"]) == int(different)
    assert result["status"] == "UNKNOWN"
    assert all(result[key] == "UNKNOWN" for key in (
        "same_testcase_binding", "same_firmware_binding", "same_execution_context_binding"))


@pytest.mark.parametrize("data", [b"", b"0\n", b"g" * 32, b"\xff" * 32])
def test_unbound_signature_still_rejects_invalid_words(data):
    with pytest.raises(ValueError):
        parse_signature(data, None, "rtl")


def test_signature_missing_source_and_length_conflict():
    data = b"0" * 32 + b"\n"
    source = RuntimeSource(case_id="case", elf_sha256="0" * 64, si_sha256="1" * 64,
                           trace_sha256=sha256(data).hexdigest(),
                           rtl_trace_sha256="2" * 64, isa_trace_sha256="3" * 64)
    rtl = parse_signature(data, source, "rtl")
    isa = parse_signature(data, None, "isa_reference")
    assert differential(rtl, isa, testcase_binding="BOUND", firmware_binding="BOUND",
                        execution_context_binding="BOUND")["status"] == "UNKNOWN"
    isa = parse_signature(data * 2, None, "isa_reference")
    assert differential(rtl, isa, testcase_binding="BOUND", firmware_binding="BOUND",
                        execution_context_binding="BOUND")["status"] == "CONFLICT"


def test_member_selection_never_resolves_ambiguity_implicitly():
    files = {"arbitrary/one.si": b"p-m\nli x1, 1", "elsewhere/two.si": b"p-m\nli x1, 2",
             "arbitrary/one.elf": b"elf bytes"}
    with pytest.raises(ValueError, match="Ambiguous si"):
        _select(files, "si", None)
    assert _select(files, "si", "elsewhere/two.si") == ("elsewhere/two.si", files["elsewhere/two.si"])
    for member in ("missing.si", "arbitrary/one.elf", "../arbitrary/one.si"):
        with pytest.raises(ValueError, match="absent or has the wrong"):
            _select(files, "si", member)
