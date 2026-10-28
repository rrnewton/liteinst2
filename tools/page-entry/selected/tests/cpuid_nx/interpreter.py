"""Literal actual ET_DYN custom interpreter; no runtime or event simulation."""
from pathlib import Path
import json,struct
import page_selected_images as elf

MAIN=0x200401000
SONAME=b'li2-provider-entry.so\0'

def emit(directory):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=False)
    dynamic,strings=0x400,0x480
    dyn=b''.join(struct.pack('<qQ',t,v)for t,v in ((5,strings),(10,len(SONAME)+1),(14,1),(0,0)))
    ph=[elf.segment(1,4,0,0,4096),elf.segment(1,5,4096,4096,4096),
        elf.segment(2,4,dynamic,dynamic,len(dyn),8),elf.segment(0x6474e551,6,0,0,0,16)]
    # The very first interpreter instruction is selected, with genuine inherited
    # inputs. Only after its configured completion does MOV/JMP enter main.
    code=bytes.fromhex('0fa2')+elf.mov64(0,MAIN)+bytes.fromhex('ffe0')
    p=directory/SONAME[:-1].decode()
    elf.emit(p,3,4096,ph,[(dynamic,dyn),(strings,b'\0'+SONAME),(4096,code)],8192)
    # Compile this actual string into PT_INTERP; do not ask the host linker to
    # consume the deliberately symbol-free custom interpreter as a DSO.
    text='.section .interp,"a",@progbits\n.asciz '+json.dumps(str(p))+'\n'
    text+='.section .dynstr.fixture,"a",@progbits\n.asciz '+json.dumps(SONAME[:-1].decode())+'\n'
    text+='.section .note.GNU-stack,"",@progbits\n'
    metadata=directory/'metadata.S';metadata.write_text(text)
    return p,metadata
