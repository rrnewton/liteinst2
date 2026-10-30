ENTRY(_start)
PHDRS {
 headers PT_PHDR PHDRS FLAGS(4);
 ro PT_LOAD FILEHDR PHDRS FLAGS(4);
 text PT_LOAD FLAGS(5);
 data PT_LOAD FLAGS(6);
 note PT_NOTE FLAGS(4);
 stack PT_GNU_STACK FLAGS(6);
}
SECTIONS {
 . = 0x400000 + SIZEOF_HEADERS;
 .note.fixture : { *(.note.fixture) } :ro :note
 .header_pad : { *(.li2.header_pad); . = ALIGN(4096); } :ro
 . = 0x401000;
 .text : { *(.text.start) . = 0x1000; *(.text.kernel) . = 0x2000; *(.text.hook) . = ALIGN(4096); } :text
 . = 0x404000;
 .data : { *(.data.buffers) } :data
 /DISCARD/ : { *(.comment) *(.note.GNU-stack) *(.eh_frame*) }
}
