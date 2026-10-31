ENTRY(_start)
PHDRS {
 phdr PT_PHDR PHDRS;
 interp PT_INTERP;
 ro PT_LOAD FILEHDR PHDRS FLAGS(4);
 text PT_LOAD FLAGS(5);
 data PT_LOAD FLAGS(6);
 dynamic PT_DYNAMIC FLAGS(6);
 pure PT_LOAD FLAGS(5);
 constants PT_LOAD FLAGS(4);
 machine PT_LOAD FLAGS(5);
 state PT_LOAD FLAGS(6);
 stack PT_GNU_STACK FLAGS(6);
}
SECTIONS {
 . = 0x400000 + SIZEOF_HEADERS;
 .interp : { KEEP(*(.interp)) } :ro :interp
 .rodata : { *(.rodata .rodata.*) } :ro
 . = ALIGN(4096);
 .text : { *(.text.startup) *(.text) *(.text.unlikely .text.unlikely.*) } :text
 ASSERT(. <= 0x410000,"bounded freestanding ordinary setup")
 .region 0x410000 : { KEEP(*(.text.ra_region)) } :text
 .return 0x412000 : { KEEP(*(.text.ra_return)) } :text
 .repeat 0x413000 : { KEEP(*(.text.ra_repeat)) } :text
 . = 0x420000;
 .dynamic : { KEEP(*(.data.subentry_dynamic)) } :data :dynamic
 .data : { *(.data .data.*) } :data
 .bss (NOLOAD) : { *(.bss .bss.* COMMON) } :data
 .ua_pure 0x200000000 : {
  FILL(0xcccccccc) BYTE(0xcc) . = ALIGN(4096);
  region_app_pure = .; KEEP(*(.li2_ua_pure))
  ASSERT(. - region_app_pure <= 4096,"bounded pure helpers");
  . = region_app_pure + 4096; region_app_pure_end = .;
  . = region_app_pure_end + 4096;
 } :pure
 .ua_machine_rodata 0x200010000 : {
  region_app_machine_rodata_begin = .; FILL(0) KEEP(*(.li2_ua_rodata))
  ASSERT(. - region_app_machine_rodata_begin <= 4096,"bounded constants");
  . = region_app_machine_rodata_begin + 4096;
 } :constants
 .ua_machine 0x200020000 : {
  region_app_machine_begin = .; FILL(0xcccccccc) BYTE(0xcc) . = ALIGN(4096);
  KEEP(*(.li2_ua_machine))
  ASSERT(region_app_helper == region_app_machine_begin + 4096,"exact assembly page");
  ASSERT(region_app_helper_end == region_app_helper + 4096,"whole assembly page");
  . = region_app_machine_begin + 3*4096;
 } :machine
 .ua_machine_state 0x200030000 (NOLOAD) : {
  region_app_machine_state_begin = .; KEEP(*(.li2_ua_state))
  ASSERT(. - region_app_machine_state_begin <= 8192,"bounded assembly state");
  . = region_app_machine_state_begin + 8192;
 } :state
 /DISCARD/ : { *(.comment) *(.note.GNU-stack) *(.eh_frame .eh_frame_hdr) }
}
