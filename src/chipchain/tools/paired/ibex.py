"""Bounded baseline facts from Ibex RVFI text and an ELF32 RISC-V image.

This adapter does not inspect RTL semantics, prove reachability, or implement
A3/B2 relation support. All trace rows are checked; model selection is explicit.
"""

from collections import Counter
from dataclasses import dataclass
import hashlib
from io import BytesIO
from pathlib import Path
import re

import capstone
from elftools.elf.elffile import ELFFile

from chipchain.domain.behavior import ProcessorBehavior
from chipchain.domain.case import ArtifactRef, CaseBundle
from chipchain.domain.evidence import EvidenceLocation, EvidenceRef
from chipchain.tools.contracts import DeterministicObservation, HardwareObservations, FirmwareObservations

VERSION = "ibex-paired-baseline-v1"


@dataclass(frozen=True)
class TraceRow:
    line: int
    cycle: int
    pc: int
    encoding: bytes
    mnemonic: str
    text: str


def parse_trace(text: str) -> list[TraceRow]:
    lines = text.splitlines()
    if not lines or not lines[0].startswith("Time\tCycle\tPC\tInsn\t"):
        raise ValueError("Unsupported Ibex trace header")
    rows = []
    for line, value in enumerate(lines[1:], 2):
        fields = value.split()
        if len(fields) < 5 or not re.fullmatch(r"(?:[0-9a-fA-F]{4}|[0-9a-fA-F]{8})", fields[3]):
            raise ValueError("Malformed Ibex trace row")
        int(fields[0]); cycle = int(fields[1]); pc = int(fields[2], 16)
        width = len(fields[3]) // 2
        word = int(fields[3], 16)
        if ((word & 3 == 3) != (width == 4) or word & 0x1f == 0x1f
                or pc % 2 or cycle < 0):
            raise ValueError("Trace encoding width or alignment mismatch")
        if rows and cycle < rows[-1].cycle:
            raise ValueError("Trace cycles are not monotonic")
        rows.append(TraceRow(line, cycle, pc, word.to_bytes(width, 'little'), fields[4], value.strip()))
    if not rows:
        raise ValueError("Empty trace")
    return rows


def file_ref(path: Path, identifier: str, kind: str, format: str) -> ArtifactRef:
    data = path.read_bytes()
    return ArtifactRef(artifact_id=identifier, artifact_type=kind, path=str(path.resolve()),
                       format=format, sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data))


def prepare_inputs(template: CaseBundle, *, elf_path: Path, trace_path: Path,
                   stdout_path: Path, ascii_path: Path):
    """Read explicit artifacts, bind every trace instruction to file-backed ELF bytes.

    Return a new case view with neutral firmware IDs. The historical case is intact.
    Firmware facts are static, even where selection was informed by runtime PCs.
    """
    if (template.target.architecture != 'riscv' or template.target.word_size_bits != 32
            or template.target.endianness != 'little'):
        raise ValueError("This adapter requires a little-endian RV32 target")
    elf_ref = file_ref(elf_path, 'elf', 'firmware_binary', 'elf')
    trace_ref = file_ref(trace_path, 'hw-trace', 'hardware_trace', 'ibex-rvfi-text')
    stdout_ref = file_ref(stdout_path, 'hw-stdout', 'other', 'text')
    ascii_ref = file_ref(ascii_path, 'hw-ascii', 'other', 'text')
    case = CaseBundle(case_id=template.case_id, name=template.name, target=template.target,
                      hardware_artifacts=[trace_ref, stdout_ref, ascii_ref],
                      firmware_artifacts=[elf_ref], metadata=dict(template.metadata))
    rows = parse_trace(trace_path.read_text())
    elf = ELFFile(BytesIO(elf_path.read_bytes()))
    if elf.elfclass != 32 or not elf.little_endian or elf['e_machine'] != 'EM_RISCV':
        raise ValueError("Expected ELF32 little-endian RISC-V")
    segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD' and s['p_flags'] & 1]

    def image_bytes(address, size):
        matches = [s for s in segments if s['p_vaddr'] <= address and
                   address + size <= s['p_vaddr'] + s['p_filesz']]
        if len(matches) != 1:
            raise ValueError("Trace PC not in a unique file-backed executable ELF segment")
        s = matches[0]; offset = address - s['p_vaddr']
        return s.data()[offset:offset + size]

    for row in rows:
        if image_bytes(row.pc, len(row.encoding)) != row.encoding:
            raise ValueError("Trace instruction bytes differ from ELF")
    hw, fw = [], []

    def observation(side, ident, summary, ref, *, kind=None, line=None, address=None, function=None):
        evidence = EvidenceRef(evidence_id=f'{side}-ev-{ident}', source_type='deterministic_analyzer',
            artifact_id=ref.artifact_id, analyzer=VERSION, summary=summary, epistemic_status='derived',
            location=EvidenceLocation(line=line, address=address, function=function))
        behaviors = [] if kind is None else [ProcessorBehavior(behavior_id=f'{side}-b-{ident}',
            kind=kind, architecture='riscv', origin='hardware' if side == 'hw' else 'firmware',
            summary=summary, evidence=[evidence], epistemic_status='derived')]
        item = DeterministicObservation(observation_id=f'{side}-o-{ident}', summary=summary,
                                       evidence=[evidence], behaviors=behaviors, epistemic_status='derived')
        (hw if side == 'hw' else fw).append(item)

    counts = Counter(r.mnemonic for r in rows)
    observation('hw', 'trace', f'Trace contains {len(rows)} records and {len({r.pc for r in rows})} unique PCs. '
                f'First cycle {rows[0].cycle}, last cycle {rows[-1].cycle}. '
                f'Trace mnemonic counts: {dict(sorted(counts.items()))}. '
                'Trace labels are producer text, not an independent decode or formal correctness proof.', trace_ref)
    stdout = stdout_path.read_text()
    cycles = re.search(r'Executed cycles:\s*(\d+)', stdout)
    if not cycles or 'Terminating simulation by software request.' not in stdout:
        raise ValueError('Simulation did not record a normal software halt')
    observation('hw', 'completion', f'Simulator reports software-requested termination and {cycles[1]} executed cycles. '
                'This is a successful baseline run, not a proof of hardware correctness.', stdout_ref)
    observation('hw', 'output', 'Simulation console text: ' + repr(ascii_path.read_text()), ascii_ref)
    # First/last row plus first occurrence of each memory address below RAM.
    # The address threshold is a selection rule, not inferred peripheral semantics.
    selected = {rows[0].line: rows[0], rows[-1].line: rows[-1]}
    seen = set()
    for row in rows:
        match = re.search(r'PA:0x([0-9a-fA-F]+)', row.text)
        if match and int(match[1], 16) < 0x100000 and match[1] not in seen:
            seen.add(match[1]); selected[row.line] = row
    if len(selected) > 24:
        raise ValueError('Selected runtime records exceed this baseline adapter budget')
    for line, row in sorted(selected.items()):
        observation('hw', f'row-{line}', 'Observed RVFI text row: ' + row.text,
                    trace_ref, kind='instruction', line=line, address=row.pc)
    observation('fw', 'header', f'ELF32 little-endian RISC-V; entry address {elf["e_entry"]:#x}. '
                'This is static image metadata. No firmware runtime path is inferred.', elf_ref,
                address=elf['e_entry'])
    symbols = elf.get_section_by_name('.symtab')
    functions = [] if symbols is None else sorted(
        [(s.name, int(s['st_value']), int(s['st_size'])) for s in symbols.iter_symbols()
         if s['st_info']['type'] == 'STT_FUNC' and s['st_size']], key=lambda s: (s[1], s[0]))
    if len(functions) > 32:
        raise ValueError('ELF function inventory exceeds this baseline adapter budget')
    for index, (name, address, size) in enumerate(functions):
        observation('fw', f'function-{index}', f'ELF function symbol {name}: start {address:#x}, size {size} bytes. '
                    'A symbol name is not proof of function semantics or reachability.', elf_ref,
                    address=address, function=name)
    engine = capstone.Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV32 | capstone.CS_MODE_RISCVC)
    unique = {r.pc: r for r in sorted(selected.values(), key=lambda r: r.line)}
    for pc, row in sorted(unique.items()):
        data = image_bytes(pc, len(row.encoding)); insns = list(engine.disasm(data, pc, count=1))
        decoded = (f'{insns[0].mnemonic} {insns[0].op_str}' if len(insns) == 1 and insns[0].size == len(data)
                   else 'unsupported by configured decoder')
        observation('fw', f'site-{pc:x}', f'Static ELF site {pc:#x}: little-endian bytes {data.hex()}; '
                    f'Capstone RV32+C decode: {decoded}. Selection used observed trace PCs; '
                    'ELF bytes and this decode alone do not prove runtime reachability.', elf_ref,
                    kind='instruction', address=pc)
    limits = ['Only one unmodified baseline is observed; no reference ISA comparison or mutant execution.',
              'No externally controlled input path, abnormal hardware state, or verified trigger was established.',
              'No RTL semantic scan, CFG, solver, Ghidra or angr analysis was performed.']
    audit = dict(adapter=VERSION, trace_records=len(rows), byte_matched_records=len(rows),
                 selected_trace_lines=sorted(selected), selected_unique_elf_sites=len(unique),
                 omitted_trace_records=len(rows) - len(selected), elf_function_symbols=len(functions),
                 selection_policy='first and last record plus first access per address below 0x100000',
                 limits=limits)
    return (case, HardwareObservations(case_id=case.case_id, observations=hw, unresolved_questions=limits),
            FirmwareObservations(case_id=case.case_id, observations=fw, unresolved_questions=[
                'Firmware observations here are static ELF facts; no CFG paths or external input consumption established.',
                *limits]), audit)
