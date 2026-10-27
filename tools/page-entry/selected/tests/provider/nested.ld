/* Applied only to the separate -fno-inline native-attempt fault binary. */
SECTIONS {
 .li2_native_random ALIGN(4096) : {
  __li2_native_random_page = .;
  KEEP(*provider-nested.o(.text.native_random))
  __li2_native_random_code_end = .;
  . = ALIGN(4096);
  __li2_native_random_page_end = .;
 }
}
INSERT AFTER .text;
ASSERT(__li2_native_random_code_end > __li2_native_random_page, "native_random section absent")
ASSERT(__li2_native_random_page_end - __li2_native_random_page == 4096, "native_random isolated page extent")
