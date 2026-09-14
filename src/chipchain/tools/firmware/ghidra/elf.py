"""ELF-only metadata view using the existing pyelftools backend and A1 range types."""
from dataclasses import dataclass
from io import BytesIO
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from chipchain.tools.firmware.fuzzware.readers import LoadSegment, Function, Image, IMAGE_CAP
from .process import GhidraError


@dataclass(frozen=True)
class ElfMetadata:
    image: Image
    elf: ELFFile
    data: bytes

    def read_code(self, address: int, size: int) -> bytes:
        s=self.image.locate(address,size)
        offset=s.offset+address-s.vaddr
        return self.data[offset:offset+size]


def parse_elf(data: bytes) -> ElfMetadata:
    """A2's Cortex-M input boundary. Does not open BIN, configuration or source files."""
    try:
        if len(data)>IMAGE_CAP: raise ValueError('size')
        elf=ELFFile(BytesIO(data))
        if elf.elfclass!=32 or not elf.little_endian or elf['e_machine']!='EM_ARM' or elf['e_type']!='ET_EXEC':
            raise ValueError('target')
        if not 0<elf['e_phnum']<=32 or not 0<elf['e_shnum']<=256: raise ValueError('headers')
        segments=[]
        for p in elf.iter_segments():
            if p['p_type']=='PT_LOAD':
                s=LoadSegment(*(p[k] for k in ('p_offset','p_vaddr','p_paddr','p_filesz','p_memsz','p_flags')))
                if s.offset+s.filesz>len(data) or s.filesz>s.memsz or s.vaddr+s.memsz>2**32: raise ValueError('load')
                segments.append(s)
        ranges=sorted(segments,key=lambda s:s.vaddr)
        if not ranges or any(a.vaddr+a.memsz>b.vaddr for a,b in zip(ranges,ranges[1:])): raise ValueError('overlap')
        functions=[]
        for section in elf.iter_sections():
            if section['sh_type']!='SHT_NOBITS' and section['sh_offset']+section['sh_size']>len(data): raise ValueError('section')
            if isinstance(section,SymbolTableSection):
                if section.num_symbols()>10000: raise ValueError('symbols')
                for symbol in section.iter_symbols():
                    if symbol['st_info']['type']=='STT_FUNC' and isinstance(symbol['st_shndx'],int) and symbol['st_size']:
                        raw=symbol['st_value']
                        functions.append(Function(symbol.name,raw,raw & ~1,symbol['st_size']))
        image=Image(elf['e_entry'],tuple(ranges),tuple(sorted(set(functions),key=lambda f:(f.address,f.size,f.name))))
        if not image.entry & 1: raise ValueError('Thumb entry')
        image.locate(image.entry & ~1,2)
        return ElfMetadata(image,elf,data)
    except Exception:
        raise GhidraError('Invalid or unsupported ELF metadata') from None
