/* Same carrier/header contract as linker.ld; three distinct executable pages. */
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
    .text.start : { *(.text.start) } :text
    .text.call : { *(.text.call) } :text
    .text.tail : { *(.text.tail) } :text
    ASSERT(ADDR(.text.start) == 4096 && SIZEOF(.text.start) == 4096, "marker page")
    ASSERT(ADDR(.text.call) == 8192 && SIZEOF(.text.call) == 4096, "native CALL page")
    ASSERT(ADDR(.text.tail) == 12288 && SIZEOF(.text.tail) == 4096, "output page")
    . = ALIGN(4096);
    .data : { *(.data) *(.data.*) } :data
    .dynamic : { *(.dynamic) } :data :dynamic
    .got : { *(.got) *(.got.plt) } :data
    .bss : { *(.bss) *(.bss.*) *(COMMON) } :data
    /DISCARD/ : { *(.note.GNU-stack) *(.note.gnu.build-id) *(.comment) *(.eh_frame) *(.eh_frame_hdr) }
}
