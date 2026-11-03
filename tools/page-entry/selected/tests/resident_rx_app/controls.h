/* Seven causal subjects in six risk categories. The unchanged positive application does not
   include this file. Addresses below are descriptive test inputs only. */
#ifndef LI2_RESIDENT_RX_APP_CONTROLS_H
#define LI2_RESIDENT_RX_APP_CONTROLS_H
#if !defined(LI2_RRX_CASE) || LI2_RRX_CASE < 1 || LI2_RRX_CASE > 7
#error "one exact resident RX causal subject"
#endif
#include <fcntl.h>
struct rrx_mailbox {
    uint64_t magic,case_id,armed,interior,metadata,source_offset,fd_plus_one;
    uint64_t result,returned,reserved;
};
const uint64_t rrx_case_id=LI2_RRX_CASE;
__attribute__((section(".li2_ua_state"),used))
volatile struct rrx_mailbox rrx_mailbox;
_Static_assert(sizeof(struct rrx_mailbox)==80,"whole descriptive guest mailbox");
static void rrx_prepare(const char *image) {
    rrx_mailbox.magic=UINT64_C(0x315852524d32494c);
    rrx_mailbox.case_id=LI2_RRX_CASE;
#if LI2_RRX_CASE == 4
    long fd=RAW(SYS_openat,AT_FDCWD,image,O_RDONLY|O_CLOEXEC,0,0,0);
    need(fd>=0 && fd<INT32_MAX,190);rrx_mailbox.fd_plus_one=(uint64_t)fd+1;
#else
    (void)image;
#endif
}
static void rrx_boundary(void) {
    need(rrx_mailbox.magic==UINT64_C(0x315852524d32494c) &&
         rrx_mailbox.case_id==LI2_RRX_CASE && rrx_mailbox.armed==1 &&
         rrx_mailbox.interior && rrx_mailbox.metadata &&
         !rrx_mailbox.result && !rrx_mailbox.returned && !rrx_mailbox.reserved,191);
#if LI2_RRX_CASE == 1
    /* Actual guest branch under TF, never an observer-written RIP. */
    __asm__ volatile(".global rrx_attack\n.type rrx_attack,@function\n"
                     "rrx_attack: jmp *%%rdi\n.size rrx_attack,.-rrx_attack"
                     ::"D"(rrx_mailbox.interior):"memory");
    die(192);
#elif LI2_RRX_CASE == 2
    __asm__ volatile(".global rrx_attack\n.type rrx_attack,@function\n"
                     "rrx_attack: movb $0x5a,(%%rdi)\n.size rrx_attack,.-rrx_attack"
                     ::"D"(rrx_mailbox.metadata):"memory");
    die(193);
#elif LI2_RRX_CASE == 3
    long result;
    __asm__ volatile(".global rrx_attack\n.type rrx_attack,@function\n"
                     "rrx_attack: syscall\n.size rrx_attack,.-rrx_attack"
                     :"=a"(result):"a"(SYS_clock_gettime),"D"(1L),
                     "S"(rrx_mailbox.metadata):"rcx","r11","memory");
    rrx_mailbox.result=(uint64_t)result;rrx_mailbox.returned=1;die(194);
#elif LI2_RRX_CASE == 4
    need(rrx_mailbox.fd_plus_one && !(rrx_mailbox.source_offset&4095),195);
    /* The original file bytes and offset are bound by the real ELF binder.
       The current source policy must refuse this guest replacement before RAW;
       trusted case7 separately exercises an actual equal-byte replacement. */
    register long r10 __asm__("r10")=MAP_PRIVATE|MAP_FIXED;
    register long r8 __asm__("r8")=(long)rrx_mailbox.fd_plus_one-1;
    register long r9 __asm__("r9")=(long)rrx_mailbox.source_offset;
    long result;
    __asm__ volatile(".global rrx_attack\n.type rrx_attack,@function\n"
                     "rrx_attack: syscall\n.size rrx_attack,.-rrx_attack\n"
                     ".global rrx_after_attack\nrrx_after_attack:"
                     :"=a"(result):"a"(SYS_mmap),"D"(region_app_page),
                     "S"((long)UA_SOURCE),"d"((long)(PROT_READ|PROT_EXEC)),
                     "r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
    rrx_mailbox.result=(uint64_t)result;rrx_mailbox.returned=1;
    need(result==(long)region_app_page,196);
#elif LI2_RRX_CASE == 5 || LI2_RRX_CASE == 7
    /* The observer changes only the saved content generation at the next
       genuine HELD bind. All intervening guest getters remain real. */
    need(RAW(SYS_getpid,0,0,0,0,0,0)==(long)prefix.h[6] &&
         RAW(SYS_gettid,0,0,0,0,0,0)==(long)prefix.h[7],197);
#else
    /* MOV SS would suppress a subsequent debug trap. The actual source
       classifier must refuse before executing it; no generated RIP edit. */
    __asm__ volatile("mov %%ss,%%ax\n.global rrx_attack\n.type rrx_attack,@function\n"
                     "rrx_attack: mov %%ax,%%ss\n.size rrx_attack,.-rrx_attack\nnop"
                     :::"rax","memory");
    die(198);
#endif
}
#endif
