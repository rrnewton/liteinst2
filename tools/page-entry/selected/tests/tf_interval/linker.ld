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
 .dynstr : { *(.dynstr) rn_dynamic_name = .; *(.dynstr.fixture) } :headers
 .gnu.version : { *(.gnu.version) } :headers
 .gnu.version_d : { *(.gnu.version_d) } :headers
 .gnu.version_r : { *(.gnu.version_r) } :headers
 .rela.dyn : { *(.rela.dyn) *(.rela.plt) } :headers
 ASSERT(. <= 0x200401000, "complete metadata page")
 . = 0x200401000;
 .text.setup : { *(.text.setup) } :text
 .text.helper : { *(.text.helper) } :text
 .text.body : { *(.text.body) } :text
 .text.tail : { *(.text.tail) } :text
 .text.guard : { *(.text.guard) } :text
 .text.reference : { *(.text.reference) *(.text .text.*) . = ALIGN(4096); } :text
 ASSERT(_start == 0x200401000 && SIZEOF(.text.setup) == 4096, "setup page")
 ASSERT(rn_seed == 0x200402000 && SIZEOF(.text.helper) == 4096, "complete seed and capture page")
 ASSERT(rn_body == 0x200403000 && SIZEOF(.text.body) == 4096, "complete WAIT page")
 ASSERT(rn_tail == 0x200404000 && SIZEOF(.text.tail) == 4096, "complete ADD page")
 ASSERT(tfi_wait_tail == 0x200403ffd && tfi_read == 0x200403ffe, "exact old NOP and final syscall")
 ASSERT(rn_program == 0x200404000 && (tfi_body_end - rn_program == 4 || tfi_body_end - rn_program == 1024), "fixed eligible body")
 ASSERT(rn_guard == 0x200405000 && SIZEOF(.text.guard) == 4096, "guarded continuation page")
 ASSERT(ADDR(.text.reference) == 0x200406000 && SIZEOF(.text.reference) == 4096, "bounded actual native observer")
 . = 0x200407000;
 .data.fixture : { *(.data.fixture) } :data
 ASSERT(rn_data == 0x200407000 && rn_data_end - rn_data == 16384, "observed data and stack")
 .dynamic : {
  QUAD(1); QUAD(rn_dynamic_name - ADDR(.dynstr));
  QUAD(5); QUAD(ADDR(.dynstr)); QUAD(10); QUAD(SIZEOF(.dynstr));
  QUAD(0); QUAD(0);
 } :data :dynamic
 .rodata : { *(.rodata .rodata.*) } :data
 .data : { *(.data .data.*) *(.got .got.*) } :data
 .bss : { *(.bss .bss.*) *(COMMON) } :data
 /DISCARD/ : { *(.note.GNU-stack) *(.note.gnu.build-id) *(.comment) *(.eh_frame) *(.eh_frame_hdr) }
}
