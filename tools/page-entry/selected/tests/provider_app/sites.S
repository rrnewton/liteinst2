/* Both images have a real, separate RX page with the same fixed geometry.
   Five original bytes are read by module.c after every resumed effect. */
#if PA_DSO
#define P(x) pa_dso_##x
#else
#define P(x) pa_main_##x
#endif
.section .text.pa_sites,"ax",@progbits
.balign 4096
.globl P(page),P(page_end),P(cpuid),P(cpuid_next),P(getpid),P(getpid_next),P(rdtsc),P(rdtsc_next)
.hidden P(page),P(page_end),P(cpuid),P(cpuid_next),P(getpid),P(getpid_next),P(rdtsc),P(rdtsc_next)
P(page):
.org 128,0xcc
P(cpuid):
    .byte 0x0f,0xa2
P(cpuid_next):
    .byte 0x90,0x90,0x90
    .byte 0xe9
    .long P(capture_after) - . - 4
.org 160,0xcc
P(getpid):
    .byte 0x0f,0x05
P(getpid_next):
    .byte 0x90,0x90,0x90
    .byte 0xe9
    .long P(capture_after) - . - 4
.org 192,0xcc
P(rdtsc):
    .byte 0x0f,0x31
P(rdtsc_next):
    .byte 0x90,0x90,0x90
    .byte 0xe9
    .long P(capture_after) - . - 4
.org 4096,0xcc
P(page_end):
.section .note.GNU-stack,"",@progbits
