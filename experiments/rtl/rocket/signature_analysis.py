"""Bounded, byte-validated signature origins; diagnostic research only.

Memory layout and word comparison do not depend on an ISA. The small RV64
adapter follows CSR reads and exact stores within one straight-line basic block.
It reuses ChipChain's ELF mapping and canonical static IR; it is not an emulator.
"""
from __future__ import annotations

from hashlib import sha256
from io import BytesIO
import re

from elftools.elf.elffile import ELFFile
from chipchain.firmware.elf import ElfImage
from chipchain.firmware.static_ir import FirmwareStaticAnalysis


CSR_NAMES = {0x001: 'fflags', 0x002: 'frm', 0x003: 'fcsr', 0x100: 'sstatus',
             0x104: 'sie', 0x105: 'stvec', 0x140: 'sscratch', 0x141: 'sepc',
             0x142: 'scause', 0x143: 'stval', 0x144: 'sip', 0x180: 'satp',
             0x300: 'mstatus', 0x301: 'misa', 0x302: 'medeleg', 0x303: 'mideleg',
             0x304: 'mie', 0x305: 'mtvec', 0x340: 'mscratch', 0x341: 'mepc',
             0x342: 'mcause', 0x343: 'mtval', 0x344: 'mip'}


def symbols_from_elf(elf_bytes: bytes) -> dict[str, int]:
    table = ELFFile(BytesIO(elf_bytes)).get_section_by_name('.symtab')
    if table is None:
        raise ValueError('Signature layout requires an explicit ELF symbol table')
    symbols = {}
    for symbol in table.iter_symbols():
        if symbol.name:
            value = int(symbol['st_value'])
            if symbol.name in symbols and symbols[symbol.name] != value:
                raise ValueError('Ambiguous ELF symbol: ' + symbol.name)
            symbols[symbol.name] = value
    return symbols


def make_layout(elf_bytes: bytes, *, expected_elf_sha256: str,
                range_symbols: list[tuple[str, str]]) -> dict:
    """Caller supplies the ordered ranges established from its signature writer."""
    image = ElfImage(elf_bytes)
    if image.identity.sha256 != expected_elf_sha256:
        raise ValueError('Signature ELF identity mismatch')
    symbols = symbols_from_elf(elf_bytes)
    ranges = []
    for start_name, end_name in range_symbols:
        if start_name not in symbols or end_name not in symbols:
            raise ValueError('Missing signature range symbols')
        start, end = symbols[start_name], symbols[end_name]
        if start % 16 or end <= start or (end-start) % 16:
            raise ValueError('Signature range must contain aligned 128-bit words')
        image.mapped_bytes(start, end-start)
        if any(start < r['end'] and r['start'] < end for r in ranges):
            raise ValueError('Signature ranges overlap')
        ranges.append({'start': start, 'end': end, 'start_symbol': start_name,
                       'end_symbol': end_name})
    if not ranges:
        raise ValueError('Missing signature layout')
    return {'elf_sha256': expected_elf_sha256, 'ranges': ranges,
            'word_bytes': 16, 'textual_order': 'high64_then_low64',
            'memory_byte_order': 'little', 'word_count': sum((r['end']-r['start'])//16 for r in ranges)}


def map_signature(data: bytes, layout: dict, *, expected_elf_sha256: str) -> dict:
    """Pure architecture-neutral calculation; missing words never mean zero."""
    if layout['elf_sha256'] != expected_elf_sha256:
        raise ValueError('Signature layout identity mismatch')
    if (layout['word_bytes'], layout['textual_order'], layout['memory_byte_order']) != (
            16, 'high64_then_low64', 'little'):
        raise ValueError('Unsupported signature framing')
    lines = data.decode('ascii').splitlines()
    if len(lines) != layout['word_count'] or any(not re.fullmatch('[0-9a-fA-F]{32}', line) for line in lines):
        raise ValueError('Signature length or word framing disagrees with layout')
    words = []
    for r in layout['ranges']:
        for address in range(r['start'], r['end'], 16):
            index = len(words); text = lines[index].lower()
            words.append({'index': index, 'range': r['start_symbol'], 'address': address,
                          'raw': text, 'halves': {
                              'low': {'address': address, 'value': int(text[16:], 16),
                                      'memory_bytes': int(text[16:], 16).to_bytes(8, 'little').hex()},
                              'high': {'address': address+8, 'value': int(text[:16], 16),
                                       'memory_bytes': int(text[:16], 16).to_bytes(8, 'little').hex()}}})
    return {'elf_sha256': expected_elf_sha256, 'signature_sha256': sha256(data).hexdigest(),
            'layout': layout, 'words': words}


def compare_mapped(left: dict, right: dict) -> dict:
    if left['layout'] != right['layout'] or left['elf_sha256'] != right['elf_sha256']:
        raise ValueError('Different firmware or signature layout')
    differences = []
    for a, b in zip(left['words'], right['words'], strict=True):
        halves = [{'half': name, 'address': a['halves'][name]['address'],
                   'rtl_value': a['halves'][name]['value'], 'reference_value': b['halves'][name]['value']}
                  for name in ('low', 'high') if a['halves'][name]['value'] != b['halves'][name]['value']]
        if halves:
            differences.append({'index': a['index'], 'rtl_raw': a['raw'], 'reference_raw': b['raw'],
                                'different_halves': halves})
    return {'different_words': differences, 'architectural_differential': 'UNKNOWN',
            'verified_deviation': False,
            'reason': 'Byte differences alone do not establish configuration equivalence or specification violation'}


def _signed(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits-1)) else value


def store_origins(elf_bytes: bytes, static_bytes: bytes) -> dict:
    """Find all statically justified SD sources; ambiguous writers stay explicit."""
    image = ElfImage(elf_bytes)
    analysis = FirmwareStaticAnalysis.model_validate_json(static_bytes)
    if analysis.artifact != image.identity:
        raise ValueError('Static analysis ELF binding mismatch')
    for instruction in analysis.instructions:
        if image.mapped_bytes(instruction.pc, len(bytes.fromhex(instruction.raw_bytes)), executable=True) != bytes.fromhex(instruction.raw_bytes):
            raise ValueError('Static instruction bytes disagree with ELF')
    if (image.identity.architecture, image.identity.bit_width, image.identity.endianness) != ('riscv', 64, 'little'):
        raise ValueError('This source adapter requires RV64 little-endian')
    states = {0: {'constant': 0, 'source_pcs': []}}
    previous = None; stores = []
    for instruction in sorted(analysis.instructions, key=lambda i: i.pc):
        raw = bytes.fromhex(instruction.raw_bytes)
        if (previous is None or instruction.block_id != previous.block_id
                or instruction.pc != previous.pc + len(bytes.fromhex(previous.raw_bytes))):
            states = {0: {'constant': 0, 'source_pcs': []}}
        previous = instruction
        if len(raw) != 4:
            states = {0: {'constant': 0, 'source_pcs': []}}; continue
        w = int.from_bytes(raw, 'little'); opcode = w & 127
        rd, rs1, rs2, f3 = (w >> 7) & 31, (w >> 15) & 31, (w >> 20) & 31, (w >> 12) & 7
        result = None
        if opcode in (0x17, 0x37):
            result = {'constant': ((_signed(w & 0xfffff000, 32) + (instruction.pc if opcode == 0x17 else 0)) & ((1<<64)-1)),
                      'source_pcs': [instruction.pc]}
        elif opcode == 0x13 and f3 == 0 and 'constant' in states.get(rs1, {}):
            result = {'constant': (states[rs1]['constant'] + _signed(w>>20, 12)) & ((1<<64)-1),
                      'source_pcs': states[rs1]['source_pcs']+[instruction.pc]}
        elif opcode == 0x73 and f3 in (1, 2, 3, 5, 6, 7) and rd:
            csr = w>>20
            result = {'csr': csr, 'csr_name': CSR_NAMES.get(csr, f'csr_0x{csr:x}'),
                      'read_pc': instruction.pc, 'read_bytes': raw.hex()}
        elif opcode == 0x23:
            immediate = _signed(((w>>25)<<5) | ((w>>7)&31), 12)
            if f3 == 3 and 'constant' in states.get(rs1, {}):
                source = states.get(rs2)
                stores.append({'address': (states[rs1]['constant']+immediate) & ((1<<64)-1),
                               'width_bits': 64, 'store_pc': instruction.pc, 'store_bytes': raw.hex(),
                               'source_register': rs2, 'address_source_pcs': states[rs1]['source_pcs'],
                               'value_source': source,
                               'basis': 'byte_validated_single_basic_block_static_relation'})
            continue
        elif opcode in (0x63, 0x6f, 0x67) or opcode == 0x73 and f3 == 0:
            states = {0: {'constant': 0, 'source_pcs': []}}; continue
        elif opcode not in (0x03, 0x07, 0x0f, 0x13, 0x1b, 0x2f, 0x33, 0x3b, 0x53):
            states = {0: {'constant': 0, 'source_pcs': []}}; continue
        if rd:
            states.pop(rd, None)
            if result is not None:
                states[rd] = result
    symbols = symbols_from_elf(elf_bytes)
    return {'elf_sha256': image.identity.sha256, 'static_analysis_sha256': sha256(static_bytes).hexdigest(),
            'stores': stores, 'symbols': symbols,
            'scope': 'static relation only; execution, last writer and memory effects require separate trace evidence'}


def annotate_origins(mapping: dict, origins: dict) -> dict:
    if mapping['elf_sha256'] != origins['elf_sha256']:
        raise ValueError('Signature/store origin ELF identity mismatch')
    results = []
    for word in mapping['words']:
        for name, half in word['halves'].items():
            matches = [s for s in origins['stores'] if s['address'] == half['address']]
            results.append({'index': word['index'], 'half': name, **half,
                            'symbols': sorted(n for n, a in origins['symbols'].items() if a == half['address']),
                            'store_candidates': matches,
                            'static_source_status': 'UNIQUE_BOUNDED_CANDIDATE' if len(matches) == 1 else 'AMBIGUOUS' if matches else 'UNKNOWN',
                            'all_possible_writers_established': False})
    return {'elf_sha256': mapping['elf_sha256'], 'halves': results}


def render_signature_analysis(comparison: dict, origins: dict) -> str:
    lines = ['# 签名数据来源分析', '',
             '签名中的每行是一个 128 位数据单元。文本左半部保存较高地址的 64 位值，',
             '右半部保存较低地址的 64 位值；地址由 ELF 符号范围和真实签名写出规则计算。',
             '以下静态关系需要与真实运行记录进一步核对，不能单凭签名差异认定硬件漏洞。', '']
    for word in comparison['different_words']:
        lines += [f"## 第 {word['index']} 个数据单元", '',
                  f"RTL 为 `{word['rtl_raw']}`，参考模型为 `{word['reference_raw']}`。", '']
        for half in word['different_halves']:
            candidates = [r for r in origins['halves'] if r['address'] == half['address']]
            entry = candidates[0] if len(candidates) == 1 else None
            lines += [f"差异位于地址 `0x{half['address']:x}`：RTL 值 `0x{half['rtl_value']:x}`，"
                      f"参考值 `0x{half['reference_value']:x}`。"]
            stores = entry['store_candidates'] if entry else []
            if len(stores) == 1 and stores[0]['value_source'] and 'csr' in stores[0]['value_source']:
                store = stores[0]; source = store['value_source']
                names = ', '.join(entry['symbols']) or '无对应变量名'
                lines += [f"ELF 符号为 `{names}`。字节核对后的静态指令显示："
                          f"在 `0x{source['read_pc']:x}` 读取 `{source['csr_name']}` 到 x{store['source_register']}，"
                          f"在 `0x{store['store_pc']:x}` 将该寄存器写入这个地址。",
                          '这是当前识别出的单个有依据的写入候选；其实际执行、是否为最终写入以及差异根因，仍需轨迹和控制实验。', '']
            else:
                lines += ['写入数据的唯一来源尚未确定；需要补充可解析的指令路径、寄存器来源及同次运行的写内存记录。', '']
    if not comparison['different_words']:
        lines += ['本次原始签名相同。这不自动证明两个模型配置等价，也不证明不存在硬件问题。', '']
    lines += ['架构偏差仍为 UNKNOWN；正式的预期行为、配置等价和跨层验证条件尚未建立。', '']
    return '\n'.join(lines)
