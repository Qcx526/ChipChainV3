"""Tiny generated ELF/BIN/YAML inputs; contains no real corpus bytes."""

import hashlib
from pathlib import Path
import struct

import yaml

from chipchain.domain.case import ArtifactRef, CaseBundle, TargetDescriptor

BASE = 0x80000


def synthetic_elf(code=bytes.fromhex("00bf996900bf"), *, symbol_value=BASE | 1, symbol_size=None):
    """ELF32 LE ARM, code LOAD + relocated data LOAD + unrelated BSS LOAD."""
    symbol_size = len(code) if symbol_size is None else symbol_size
    data = bytearray(0x400)
    ident = b'\x7fELF\x01\x01\x01' + bytes(9)
    struct.pack_into('<16sHHIIIIIHHHHHH', data, 0, ident, 2, 40, 1, BASE | 1,
                     52, 0x300, 0x5000000, 52, 32, 3, 40, 5, 4)
    for i, ph in enumerate([(1,0x100,BASE,BASE,len(code),len(code),5,2),
                           (1,0x180,0x20000000,BASE+len(code),4,8,6,2),
                           (1,0x190,0x20000100,0x20000100,0,16,6,2)]):
        struct.pack_into('<IIIIIIII',data,52+i*32,*ph)
    data[0x100:0x100+len(code)] = code
    data[0x180:0x184] = b'DATA'
    data[0x200:0x207] = b'\x00entry\x00'
    names = b'\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00'
    data[0x240:0x240+len(names)] = names
    struct.pack_into('<IIIBBH',data,0x1a0+16,1,symbol_value,symbol_size,0x12,0,1)
    headers=[(0,0,0,0,0,0,0,0,0,0),
             (1,1,6,BASE,0x100,len(code),0,0,2,0),
             (7,2,0,0,0x1a0,32,3,1,4,16),
             (15,3,0,0,0x200,7,0,0,1,0),
             (23,3,0,0,0x240,len(names),0,0,1,0)]
    for i,h in enumerate(headers):struct.pack_into('<IIIIIIIIII',data,0x300+40*i,*h)
    return bytes(data),code+b'DATA'


def synthetic_config(pc=BASE+2):
    return {
        'interrupt_triggers': {'trigger': {'every_nth_tick':1000,'fuzz_mode':'round_robin'}},
        'memory_map': {
            'text': {'base_addr':BASE,'size':0x1000,'permissions':'r-x','file':'image.bin'},
            'ram': {'base_addr':0x20000000,'size':0x10000,'permissions':'rw-'},
            'mmio': {'base_addr':0x40000000,'size':0x20000000,'permissions':'rw-'},
            'nvic': {'base_addr':0xe0000000,'size':0x10000000,'permissions':'rw-'},
            'irq_ret': {'base_addr':0xfffff000,'size':0x1000,'permissions':'--x'},
        },
        'mmio_models': {
            'constant': {'constant_site': {'pc':pc,'addr':0x40000018,'access_size':4,'val':123}},
            'bitextract': {'masked_site': {'pc':pc,'addr':0x40000028,'access_size':4,'mask':255,'left_shift':0,'size':1}},
            'passthrough': {'state_site': {'pc':pc,'addr':0x40000038,'access_size':4,'init_val':0}},
            'set': {'set_site': {'pc':pc,'addr':0x40000048,'access_size':4,'vals':[0,1]}},
            'unmodeled': {'unmodeled_site': {'pc':pc,'addr':0x40000058,'access_size':4}},
        },
    }


def reference(path, kind, fmt):
    data=Path(path).read_bytes()
    return ArtifactRef(artifact_id=fmt, artifact_type=kind, format=fmt, path=str(path),
                       sha256=hashlib.sha256(data).hexdigest(),size_bytes=len(data))


def make_case(root, *, code=None, pc=BASE+2, symbol_size=None):
    root.mkdir(parents=True,exist_ok=True)
    elf, binary=synthetic_elf(**({'code':code} if code is not None else {}),symbol_size=symbol_size)
    content=[('image.elf','firmware_binary','elf',elf),('image.bin','firmware_binary','bin',binary),
             ('config.yml','firmware_config','yaml',yaml.safe_dump(synthetic_config(pc)).encode()),
             ('input','firmware_input','opaque',b'OPAQUE_INPUT_MUST_NOT_ENTER_CONTEXT\x00\xff')]
    refs=[]
    for filename,kind,fmt,data in content:
        path=root/filename;path.write_bytes(data);refs.append(reference(path,kind,fmt))
    return CaseBundle(case_id='synthetic-firmware',name='Synthetic firmware',firmware_artifacts=refs,
                      target=TargetDescriptor(processor_id='synthetic-arm',architecture='arm',
                                              word_size_bits=32,endianness='little',isa_variant='Thumb M-profile'))
