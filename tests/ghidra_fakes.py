"""Generated tiny ELF and export schema, no corpus or Ghidra required."""
import hashlib
import json
import struct
from tests.firmware_fakes import BASE, synthetic_elf


def function(start=BASE, size=8, name='entry'):
    return dict(function_id=f'f{start:x}', entry_address=start, name=name,
                ranges=[dict(start=start,end=start+size)],size_bytes=size,
                source_type='IMPORTED', symbols=[dict(name=name,source_type='IMPORTED')],
                is_thunk=False,is_external=False)


def exported(elf=None):
    # BL +4; BL +0; BX LR: two direct call sites targeting the same callee.
    if elf is None:
        elf,_=synthetic_elf(bytes.fromhex('00f002f800f000f87047'),symbol_size=8)
    from chipchain.tools.firmware.ghidra.elf import parse_elf
    meta=parse_elf(elf)
    memory=[]
    for s in meta.image.segments:
        if s.filesz:
            memory.append(dict(name='load', start=s.vaddr,end=s.vaddr+s.filesz,initialized=True,execute=bool(s.flags&1)))
        if s.memsz>s.filesz:
            memory.append(dict(name='bss',start=s.vaddr+s.filesz,end=s.vaddr+s.memsz,initialized=False,execute=False))
    value=dict(schema_version='ghidra-export/v1',ghidra_version='synthetic-1',java_runtime_version='test-java',
        java_vendor='test',language_id='ARM:LE:32:Cortex',compiler_spec_id='default',processor='ARM',
        word_size_bits=32,endianness='little',image_base=BASE,executable_sha256=hashlib.sha256(elf).hexdigest(),
        entry_points=[BASE],analysis_options={'Decompiler Parameter ID':'false'},memory=memory,
        functions=[function(),function(BASE+8,2,'callee')],call_sites=[])
    for pc in (BASE,BASE+4):
        value['call_sites'].append(dict(call_site_address=pc,caller_function_id=f'f{BASE:x}',
            callee_function_id=f'f{BASE+8:x}',target_address=BASE+8,computed=False,target_count=1,
            raw_encoding=meta.read_code(pc,4).hex(),instruction_size=4))
    return elf,value


def normalize(elf,value):
    from chipchain.tools.firmware.ghidra.normalize import normalize_export
    return normalize_export(json.dumps(value).encode(),elf,case_id='synthetic-firmware',
                            expected_version='synthetic-1',script_sha256='a'*64)


def vector_elf(words=None):
    # Real section metadata establishes exactly five words, separate from code.
    words=words or [0x20001000,BASE+21,BASE+23,0x40000001,0]
    code=struct.pack('<5I',*words)+bytes.fromhex('00bf7047')
    elf,_=synthetic_elf(code,symbol_value=BASE+21,symbol_size=4)
    data=bytearray(elf)
    struct.pack_into('<I',data,24,BASE+21)
    names=b'\x00.vectors\x00.symtab\x00.strtab\x00.shstrtab\x00'
    data[0x240:0x240+len(names)]=names
    struct.pack_into('<I',data,0x300+40+20,20)  # vector section size
    for index,offset in [(2,10),(3,18),(4,26)]:
        struct.pack_into('<I',data,0x300+index*40,offset)
    struct.pack_into('<I',data,0x300+4*40+20,len(names))
    return bytes(data)
