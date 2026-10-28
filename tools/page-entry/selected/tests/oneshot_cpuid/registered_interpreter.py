"""CPUID-first interpreter with literal bounded-purpose real AT_ENTRY handoff."""
import json,struct
from pathlib import Path
import page_selected_images as elf
SONAME=b'li2-registered-cpuid-entry.so\0'
# Entry CPUID/JMP; helper NOP forces the existing OLD_STEP fallback and a real NX admission opportunity.
# The unchanged clean helper body then executes CLD; RCX=argc; RSI=envp; skip envp; find AT_ENTRY;
# load its value into RAX and JMP RAX. No syscall/RDTSC or one-shot owner occurs.
CODE=bytes.fromhex('90fc488b0c24488d74cc1048833e00488d760875f6488b064883f80974064883c610ebf1488b4608ffe0')
def emit(directory):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=False)
    dynamic,strings=0x400,0x480
    dyn=b''.join(struct.pack('<qQ',t,v)for t,v in((5,strings),(10,len(SONAME)+1),(14,1),(0,0)))
    ph=[elf.segment(1,4,0,0,4096),elf.segment(1,5,4096,4096,8192),elf.segment(2,4,dynamic,dynamic,len(dyn),8),elf.segment(0x6474e551,6,0,0,0,16)]
    p=directory/SONAME[:-1].decode();elf.emit(p,3,4096,ph,[(dynamic,dyn),(strings,b'\0'+SONAME),(4096,bytes.fromhex('0fa2e9f90f0000')),(8192,CODE)],12288)
    # GCC/ld owns the sole PT_INTERP string through the exact link argument.
    text='.section .dynstr.fixture,"a",@progbits\n.asciz '+json.dumps(SONAME[:-1].decode())+'\n.section .note.GNU-stack,"",@progbits\n'
    metadata=directory/'metadata.S';metadata.write_text(text);return p,metadata
