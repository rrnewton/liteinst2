/* Genuine custom-interpreter ET_DYN; no libc startup or implicit rseq area. */
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
    .dynstr : { BYTE(0); *(.dynstr.fixture) } :headers
    .gnu.version : { *(.gnu.version) } :headers
    .gnu.version_d : { *(.gnu.version_d) } :headers
    .gnu.version_r : { *(.gnu.version_r) } :headers
    .rela.dyn : { *(.rela.dyn) *(.rela.plt) } :headers
    ASSERT(. <= 4096, "ELF metadata fits R header page")
    . = 4096;
    .text.registered : { *(.text.registered) } :text
    ASSERT(_start == 4096 && SIZEOF(.text.registered) == 8192, "two complete source pages")
    ASSERT(li2_registered_tail == 8190, "mmap and rseq use actual two-byte page tail")
    ASSERT(li2_registered_clock >= 8192 && li2_registered_exit + 5 <= 12288, "four registered five-byte windows")
    . = 12288;
    .data.registered : { *(.data.registered) } :data
    ASSERT(li2_registered_output == 12288 && li2_registered_iov == 12352 && SIZEOF(.data.registered) == 4096, "independent output and iov layout")
    .dynamic : { QUAD(1); QUAD(1); QUAD(5); QUAD(ADDR(.dynstr)); QUAD(10); QUAD(SIZEOF(.dynstr)); QUAD(0); QUAD(0); } :data :dynamic
    .got : { *(.got) *(.got.plt) } :data
    .bss : { *(.bss) *(.bss.*) *(COMMON) } :data
    /DISCARD/ : { *(.note.GNU-stack) *(.note.gnu.build-id) *(.comment) *(.eh_frame) *(.eh_frame_hdr) }
}
