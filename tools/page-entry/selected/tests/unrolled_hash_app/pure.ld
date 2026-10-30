/* Only the bulk helpers move high. Low focal source and assembly retain
   direct rel32 reach to the controller's actual MAP_32BIT arena. */
SECTIONS {
  .ua_pure 0x200000000 : {
    FILL(0xcccccccc)
    BYTE(0xcc)
    . = ALIGN(4096);
    unrolled_app_pure = .;
    KEEP(*(.li2_ua_pure))
    ASSERT(. - unrolled_app_pure <= 4096, "bounded unrolled application helpers");
    . = unrolled_app_pure + 4096;
    unrolled_app_pure_end = .;
    . = unrolled_app_pure_end + 4096;
  }
}
INSERT AFTER .bss;
