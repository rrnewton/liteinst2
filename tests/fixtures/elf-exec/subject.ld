ENTRY(_start)
PHDRS
{
  headers PT_PHDR PHDRS FLAGS(4);
  ro PT_LOAD FILEHDR PHDRS FLAGS(4);
  text PT_LOAD FLAGS(5);
  data PT_LOAD FLAGS(6);
  journal PT_LOAD FLAGS(6);
  stack PT_LOAD FLAGS(6);
  stack_policy PT_GNU_STACK FLAGS(6);
}
SECTIONS
{
  . = 0x400000 + SIZEOF_HEADERS;
  .header_pad : { BYTE(0); . = ALIGN(4096); } :ro
  . = 0x401000;
  .text : { *(.text.fixture) . = ALIGN(4096); } :text
  . = 0x403000;
  .data : { *(.data.fixture) } :data
  . = 0x404000;
  .journal : { *(.journal.fixture) } :journal
  . = 0x406000;
  .stack : { *(.stack.fixture) } :stack
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
