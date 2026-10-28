/* ET_DYN main: readable ELF/PHDR header at offset zero, one immutable RX
   five-page segment, and separate RW data/dynamic metadata. Real ld.so owns
   normal startup; carrier.py replaces only the interpreter for gated runs. */
OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)
PHDRS {
    phdr PT_PHDR PHDRS FLAGS(4);
    headers PT_LOAD FILEHDR PHDRS FLAGS(4);
    interp PT_INTERP FLAGS(4);
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
    dynamic PT_DYNAMIC FLAGS(6);
    stack PT_GNU_STACK FLAGS(6);
}
SECTIONS {
    . = SIZEOF_HEADERS;
    .interp : { *(.interp) } :headers :interp
    .hash : { *(.hash) } :headers
    .gnu.hash : { *(.gnu.hash) } :headers
    .dynsym : { *(.dynsym) } :headers
    .dynstr : { *(.dynstr) } :headers
    .gnu.version : { *(.gnu.version) } :headers
    .gnu.version_d : { *(.gnu.version_d) } :headers
    .gnu.version_r : { *(.gnu.version_r) } :headers
    .rela.dyn : { *(.rela.dyn) *(.rela.plt) } :headers
    ASSERT(. <= 4096, "ELF metadata must fit the R header page")
    . = 4096;
    .text.call : { *(.text.call) } :text
    .text.return : { *(.text.return) } :text
    .text.callee : { *(.text.callee) } :text
    .text.straddle : { *(.text.straddle) } :text
    .text.tail : { *(.text.tail) } :text
    ASSERT(ADDR(.text.call) == 4096 && SIZEOF(.text.call) == 4096, "CALL page")
    ASSERT(ADDR(.text.return) == 8192 && SIZEOF(.text.return) == 4096, "return page")
    ASSERT(ADDR(.text.callee) == 12288 && SIZEOF(.text.callee) == 4096, "callee page")
    ASSERT(ADDR(.text.straddle) == 16384 && SIZEOF(.text.straddle) == 4096, "straddler first page")
    ASSERT(ADDR(.text.tail) == 20480 && SIZEOF(.text.tail) == 4096, "straddler tail page")
    ASSERT(li2_boundary_call == 8187 && li2_boundary_return == 8192, "original CALL return PC")
    ASSERT(li2_straddler == 20477 && li2_straddler_end == 20487, "actual 3+7 fetch split")
    . = ALIGN(4096);
    .data : { *(.data) *(.data.*) } :data
    .dynamic : { *(.dynamic) } :data :dynamic
    .got : { *(.got) *(.got.plt) } :data
    .bss : { *(.bss) *(.bss.*) *(COMMON) } :data
    /DISCARD/ : { *(.note.GNU-stack) *(.note.gnu.build-id) *(.comment) *(.eh_frame) *(.eh_frame_hdr) }
}
