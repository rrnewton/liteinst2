/* ET_DYN main: readable ELF/PHDR header at offset zero, one immutable RX
   two-page segment, and separate RW data/dynamic metadata. Real ld.so owns
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
    .text.oneshot : { *(.text.oneshot) } :text
    ASSERT(ADDR(.text.oneshot) == 4096 && SIZEOF(.text.oneshot) == 4096, "one full immutable source page")
    ASSERT(_start == 4096 && li2_oneshot_entry == _start, "first main instruction is RDTSC")
    ASSERT(li2_oneshot_record_end - li2_oneshot_record == 328, "exact retained application observations")
    ASSERT(li2_oneshot_exit + 5 <= 8192, "all selected five-byte windows stay on one source page")
    .text.capture : { *(.text.capture) } :text
    ASSERT(ADDR(.text.capture) == 8192 && SIZEOF(.text.capture) == 4096, "native flag capture page")
    . = ALIGN(4096);
    .data : { *(.data) *(.data.*) } :data
    .dynamic : { *(.dynamic) } :data :dynamic
    .got : { *(.got) *(.got.plt) } :data
    .bss : { *(.bss) *(.bss.*) *(COMMON) } :data
    /DISCARD/ : { *(.note.GNU-stack) *(.note.gnu.build-id) *(.comment) *(.eh_frame) *(.eh_frame_hdr) }
}
