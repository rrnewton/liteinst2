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
    . = 0x200400000 + SIZEOF_HEADERS;
    .interp : { *(.interp) } :headers :interp
    .hash : { *(.hash) } :headers
    .gnu.hash : { *(.gnu.hash) } :headers
    .dynsym : { *(.dynsym) } :headers
    .dynstr : { BYTE(0); *(.dynstr.fixture) } :headers
    .gnu.version : { *(.gnu.version) } :headers
    .gnu.version_d : { *(.gnu.version_d) } :headers
    .gnu.version_r : { *(.gnu.version_r) } :headers
    .rela.dyn : { *(.rela.dyn) *(.rela.plt) } :headers
    ASSERT(. <= 0x200401000, "read-only metadata page")
    . = 0x200401000;
    .text.main : { *(.text.main) } :text
    ASSERT(_start == 0x200401000 && SIZEOF(.text.main) == 4096, "actual first-main source page")
    ASSERT(pl_exit + 5 <= 0x200402000, "eight same-page publication windows")
    .text.helper : { *(.text.helper) } :text
    ASSERT(ADDR(.text.helper) == 0x200402000 && SIZEOF(.text.helper) == 4096, "complete native helper page")
    . = 0x200403000;
    .data.fixture : { *(.data.fixture) } :data
    ASSERT(pl_data == 0x200403000 && pl_data_end - pl_data == 16384, "full observed data and stack extent")
    /* Literal DT_NEEDED/DT_STRTAB metadata, as in the existing emitted rseq
       custom-interpreter images. No unused libc or conventional ld.so exists. */
    .dynamic : {
        QUAD(1); QUAD(1);
        QUAD(5); QUAD(ADDR(.dynstr));
        QUAD(10); QUAD(SIZEOF(.dynstr));
        QUAD(0); QUAD(0);
    } :data :dynamic
    .got : { *(.got) *(.got.plt) } :data
    .bss : { *(.bss) *(.bss.*) *(COMMON) } :data
    /DISCARD/ : { *(.note.GNU-stack) *(.note.gnu.build-id) *(.comment) *(.eh_frame) *(.eh_frame_hdr) }
}
