"""Portable source joins with tiny synthetic ELF and explicit line intervals."""
import json
from pathlib import Path
import struct
from types import SimpleNamespace

import pytest

from chipchain.firmware.elf import ElfImage
from chipchain.firmware.static_ir import StaticBehaviorFact, build_analysis, content_id
from experiments.firmware import source_grounding as api

COMMIT = "a" * 40
BASE = 0x1000


def fixture(*, architecture="riscv", overlap=False):
    machine, endian, width = {"riscv": (243, "<", 64), "arm": (40, "<", 32),
                              "powerpc": (20, ">", 32)}[architecture]
    data = bytearray(0x140)
    identity = b"\x7fELF" + bytes((2 if width == 64 else 1, 1 if endian == "<" else 2, 1)) + b"\0" * 9
    if width == 64:
        data[:64] = struct.pack(endian + "16sHHIQQQIHHHHHH", identity, 2, machine, 1,
                               BASE, 64, 0, 0, 64, 56, 1, 64, 0, 0)
        data[64:120] = struct.pack(endian + "IIQQQQQQ", 1, 5, 0x100, BASE, BASE, 0x40, 0x40, 4)
    else:
        data[:52] = struct.pack(endian + "16sHHIIIIIHHHHHH", identity, 2, machine, 1,
                               BASE, 52, 0, 0, 52, 32, 1, 40, 0, 0)
        data[52:84] = struct.pack(endian + "IIIIIIII", 1, 0x100, BASE, BASE, 0x40, 0x40, 5, 4)
    data[0x100:0x10c] = bytes.fromhex("0102030405060708090a0b0c")
    elf = bytes(data)
    image = ElfImage(elf)
    funcs = []
    for name, start, end in [("entry", BASE, BASE + 3), ("service", BASE + 4, BASE + 7),
                             *(([("alias", BASE, BASE + 3)]) if overlap else [])]:
        fields = dict(entry=start, name=name, ranges=[{"start": start, "end": end}], thunk=False, external=False)
        funcs.append({**fields, "fact_id": content_id("fwfunction", {"elf": image.identity.sha256, **fields})})
    instructions, behaviors = [], []
    for index in range(3):
        pc, raw = BASE + index * 4, data[0x100 + index * 4:0x104 + index * 4].hex()
        iid = content_id("fwinstruction", {"elf": image.identity.sha256, "pc": pc, "bytes": raw})
        owners = [f["fact_id"] for f in funcs if f["ranges"][0]["start"] <= pc <= f["ranges"][0]["end"]]
        instructions.append(dict(fact_id=iid, pc=pc, raw_bytes=raw, mnemonic="synthetic", operands=[],
                                 text="synthetic instruction", function_ids=owners, block_id=None))
        semantic = {"kind": "INSTRUCTION", "semantic_status": "supported"}
        behaviors.append({**semantic, "fact_id": content_id("fwbehavior", {"instruction": iid, "semantic": semantic}),
                          "instruction_id": iid, "pc": pc})
    call = dict(pc=BASE, caller_function_ids=instructions[0]["function_ids"], direct=True,
                target=BASE + 4, target_function_id=funcs[1]["fact_id"])
    call["fact_id"] = content_id("fwcall", {"elf": image.identity.sha256, **call})
    analysis = build_analysis(artifact=image.identity, ghidra_language="synthetic", ghidra_version="synthetic",
                              producer={"role": "synthetic"}, functions=funcs, blocks=[],
                              instructions=instructions, behaviors=[StaticBehaviorFact.model_validate(b) for b in behaviors],
                              calls=[call], edges=[], references=[])
    return elf, analysis


def ground(*, intervals=None, sources=None, functions=(), architecture="riscv", overlap=False):
    elf, analysis = fixture(architecture=architecture, overlap=overlap)
    return api.ground_source(elf, analysis, tuple(intervals if intervals is not None else [
        api.LineInterval(BASE, BASE + 4, "src/service.c", 2)]),
        sources if sources is not None else {"src/service.c": b"header\nnormal operation\n"},
        source_commit=COMMIT, functions=functions)


@pytest.mark.parametrize("architecture", ["arm", "riscv", "powerpc"])
def test_source_mapping_is_architecture_neutral_and_exact(architecture):
    result = ground(architecture=architecture, functions=("entry",))
    record, = result["instructions"]
    assert record["source_status"] == "BOUND_COMPILE_METADATA"
    assert record["source_candidates"][0]["line_text"] == "normal operation"
    assert record["source_candidates"][0]["line_bytes_hex"] == b"normal operation".hex()
    assert result["direct_calls"][0]["status"] == "CONFIRMED_STATIC"
    assert result["limits"]["runtime_execution"] == "NOT_ESTABLISHED"
    assert result["limits"]["triggerability"] == "UNKNOWN"


@pytest.mark.parametrize("problem", ["no_intervals", "no_source", "line_missing", "past_file", "crosses_interval"])
def test_missing_source_information_remains_unknown(problem):
    intervals = [api.LineInterval(BASE, BASE + (2 if problem == "crosses_interval" else 4),
                                  "src/service.c", None if problem == "line_missing" else
                                  9 if problem == "past_file" else 2)]
    result = ground(intervals=[] if problem == "no_intervals" else intervals,
                    sources={} if problem == "no_source" else None, functions=("entry",))
    assert result["instructions"][0]["source_status"] == "UNKNOWN"


def test_overlapping_dwarf_or_function_owners_are_ambiguous():
    record = ground(intervals=[api.LineInterval(BASE, BASE + 4, "src/service.c", 1),
                              api.LineInterval(BASE, BASE + 4, "src/service.c", 2)])["instructions"][0]
    assert record["source_status"] == "AMBIGUOUS"
    assert len(record["source_candidates"]) == 2
    result = ground(overlap=True)
    assert result["instructions"][0]["ownership_status"] == "AMBIGUOUS"
    assert result["instructions"][0]["grounding_status"] == "AMBIGUOUS"
    assert result["direct_calls"][0]["status"] == "UNKNOWN"
    assert result["instructions"][2]["ownership_status"] == "UNKNOWN"


@pytest.mark.parametrize("name", ["../file.c", "/file.c", "x\\file.c", ""])
def test_unsafe_source_names_are_rejected(name):
    with pytest.raises(ValueError, match="safe relative"):
        ground(sources={name: b"content"})


@pytest.mark.parametrize("problem", ["wrong_elf", "wrong_analysis_id", "hidden_byte_conflict", "false_owner", "false_behavior"])
def test_identity_and_all_instruction_bytes_fail_closed_even_when_selected_elsewhere(problem):
    elf, model = fixture()
    value = model.model_dump(mode="json")
    if problem == "wrong_elf":
        changed = bytearray(elf)
        changed[0x100] ^= 1
        elf = bytes(changed)
    elif problem == "wrong_analysis_id":
        value["analysis_id"] = "firmware-static:" + "f" * 64
    else:
        instruction = value["instructions"][2]
        if problem == "hidden_byte_conflict":
            instruction["raw_bytes"] = "ffffffff"
            instruction["fact_id"] = content_id("fwinstruction", {"elf": value["artifact"]["sha256"],
                                                "pc": instruction["pc"], "bytes": instruction["raw_bytes"]})
        elif problem == "false_owner":
            instruction["function_ids"] = [value["functions"][0]["fact_id"]]
        else:
            behavior = value["behaviors"][2]
            behavior["pc"] += 4
        value["analysis_id"] = content_id("firmware-static", {k: v for k, v in value.items() if k != "analysis_id"})
    with pytest.raises(ValueError):
        api.ground_source(elf, json.dumps(value).encode(), (), {}, source_commit=COMMIT, functions=("entry",))


def test_absent_function_and_nonexact_commit_are_rejected():
    with pytest.raises(ValueError, match="absent"):
        ground(functions=("invented",))
    elf, analysis = fixture()
    with pytest.raises(ValueError, match="exact source commit"):
        api.ground_source(elf, analysis, (), {}, source_commit="main")


def test_actual_elf_without_dwarf_is_not_invented(tmp_path):
    elf, _ = fixture()
    assert api.dwarf_intervals(elf, tmp_path) == ()


@pytest.mark.parametrize("version,outside", [(4, False), (5, False), (5, True)])
def test_dwarf_half_open_intervals_file_index_and_outside_source_scope(tmp_path, monkeypatch, version, outside):
    root = tmp_path / "checkout"
    root.mkdir()
    file = SimpleNamespace(name=b"service.c", dir_index=0 if version == 5 else 1)
    directory = tmp_path / "external" if outside else root / "src"
    row = SimpleNamespace(address=BASE, file=0 if version == 5 else 1, line=2, column=1, end_sequence=False)
    end = SimpleNamespace(address=BASE + 4, end_sequence=True)
    program = SimpleNamespace(header=SimpleNamespace(version=version, file_entry=[file],
                                                     include_directory=[str(directory).encode()]),
                              get_entries=lambda: [SimpleNamespace(state=row), SimpleNamespace(state=end)])
    cu = SimpleNamespace(get_top_DIE=lambda: SimpleNamespace(attributes={
        "DW_AT_comp_dir": SimpleNamespace(value=str(root).encode())}))
    dwarf = SimpleNamespace(iter_CUs=lambda: [cu], line_program_for_CU=lambda value: program)
    monkeypatch.setattr(api, "ELFFile", lambda stream: SimpleNamespace(
        get_section_by_name=lambda name: object(), get_dwarf_info=lambda: dwarf))
    interval, = api.dwarf_intervals(b"synthetic line program", root)
    assert (interval.start, interval.end, interval.line) == (BASE, BASE + 4, 2)
    assert interval.file == (None if outside else "src/service.c")


def test_interval_order_does_not_choose_an_ambiguous_source():
    intervals = [api.LineInterval(BASE, BASE + 8, "src/service.c", 1),
                 api.LineInterval(BASE, BASE + 4, "src/service.c", 2)]
    assert ground(intervals=intervals) == ground(intervals=list(reversed(intervals)))
    assert ground(intervals=intervals)["instructions"][0]["grounding_status"] == "AMBIGUOUS"


def test_reproducible_build_paths_require_explicit_reverse_map(tmp_path):
    root = tmp_path.resolve()
    assert api.source_path(Path("/src/service.c"), root, ()) is None
    mapping = api.validated_path_maps((("/", "."),))
    assert api.source_path(Path("/src/service.c"), root, mapping) == "src/service.c"
    # Virtual /lib from prefix-stripped DWARF must not follow the host /lib symlink.
    assert api.source_path(Path("/lib/service.c"), root, mapping) == "lib/service.c"
    elf, analysis = fixture()
    result = api.ground_source(elf, analysis, (), {}, source_commit=COMMIT, path_maps=mapping)
    assert result["explicit_dwarf_path_maps"] == [{"prefix": "/", "checkout_relative": "."}]
    assert result["limits"]["source_commit_build_binding"] == "REQUIRES_EXTERNAL_BUILD_PROVENANCE"


@pytest.mark.parametrize("mapping", [(("relative", "."),), (("/", "../external"),),
                                   (("/", "/external"),), (("/", "."), ("/src", "src"))])
def test_unsafe_or_overlapping_reverse_maps_are_rejected(mapping):
    with pytest.raises(ValueError):
        api.validated_path_maps(mapping)


def test_reverse_map_cannot_escape_checkout_through_symlink(tmp_path):
    root, outside = tmp_path / "root", tmp_path / "external"
    root.mkdir()
    outside.mkdir()
    (root / "src").symlink_to(outside, target_is_directory=True)
    assert api.source_path(Path("/src/file.c"), root, (("/", "."),)) is None


def test_deterministic_identity_includes_exact_source_bytes_and_static_limits():
    first, second = ground(), ground()
    assert first == second
    assert ground(sources={"src/service.c": b"header\nchanged operation\n"})["diagnostic_id"] != first["diagnostic_id"]
    assert first["limits"]["source_commit_build_binding"] == "REQUIRES_EXTERNAL_BUILD_PROVENANCE"
    report = api.render_report(first)
    assert "行号是编译元数据" in report and "仅为静态关系" in report
    assert "0x1000" in report and "src/service.c:2" in report


def test_cli_refuses_existing_output_without_external_processes(tmp_path):
    source, output = tmp_path / "source", tmp_path / "output"
    source.mkdir()
    output.mkdir()
    sentinel = output / "keep"
    sentinel.write_bytes(b"unchanged")
    with pytest.raises(SystemExit):
        api.main(["--elf", "absent", "--analysis", "absent", "--source-root", str(source),
                  "--source-commit", COMMIT, "--output", str(output)])
    assert sentinel.read_bytes() == b"unchanged"


def test_cli_records_checkout_failure_without_network_or_tools(tmp_path, monkeypatch):
    source, output = tmp_path / "source", tmp_path / "output"
    source.mkdir()
    def invalid(*args):
        raise ValueError("Source checkout commit or tracked cleanliness mismatch")
    monkeypatch.setattr(api, "verify_checkout", invalid)
    assert api.main(["--elf", "absent", "--analysis", "absent", "--source-root", str(source),
                     "--source-commit", COMMIT, "--output", str(output)]) == 2
    assert json.loads((output / "failure.json").read_text())["status"] == "BLOCKED"
    assert "未建立运行" in (output / "source-grounding.md").read_text()


def test_cli_records_malformed_elf_without_external_tools(tmp_path, monkeypatch):
    source, output, elf = tmp_path / "source", tmp_path / "output", tmp_path / "bad.elf"
    source.mkdir()
    elf.write_bytes(b"not an ELF")
    monkeypatch.setattr(api, "verify_checkout", lambda *args: set())
    assert api.main(["--elf", str(elf), "--analysis", "absent", "--source-root", str(source),
                     "--source-commit", COMMIT, "--output", str(output)]) == 2
    assert json.loads((output / "failure.json").read_text())["status"] == "BLOCKED"
