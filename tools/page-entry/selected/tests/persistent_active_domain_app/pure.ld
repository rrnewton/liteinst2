/* Keep ordinary startup and the focal/return pages low. Native seed/capture
   runs high with nearby state; both cross-island jumps preserve all registers
   and flags. Distinct R/RX/RW loads preserve the original pure RX extent. */
SECTIONS {
  .ua_pure 0x200000000 : {
    FILL(0xcccccccc)
    BYTE(0xcc)
    . = ALIGN(4096);
    region_app_pure = .;
    KEEP(*(.li2_ua_pure))
    ASSERT(. - region_app_pure <= 4096, "bounded scalar region application helpers");
    . = region_app_pure + 4096;
    region_app_pure_end = .;
    . = region_app_pure_end + 4096;
  }
  .ua_machine_rodata 0x200010000 : {
    region_app_machine_rodata_begin = .;
    FILL(0)
    KEEP(*(.li2_ua_rodata))
    ASSERT(. - region_app_machine_rodata_begin <= 4096, "bounded assembly constants");
    . = region_app_machine_rodata_begin + 4096;
  }
  .ua_machine 0x200020000 : {
    region_app_machine_begin = .;
    FILL(0xcccccccc)
    BYTE(0xcc)
    . = ALIGN(4096);
    KEEP(*(.li2_ua_machine))
    ASSERT(region_app_helper == region_app_machine_begin + 4096, "exact high assembly entry page");
    ASSERT(region_app_helper_end == region_app_helper + 4096, "complete assembly page");
    . = region_app_machine_begin + 3 * 4096;
  }
  .ua_machine_state 0x200030000 (NOLOAD) : {
    region_app_machine_state_begin = .;
    KEEP(*(.li2_ua_state))
    ASSERT(. - region_app_machine_state_begin <= 8192, "bounded assembly state");
    . = region_app_machine_state_begin + 8192;
  }
}
INSERT AFTER .bss;
