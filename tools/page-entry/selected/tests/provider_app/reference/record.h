#ifndef PA_NATIVE_REFERENCE_RECORD_H
#define PA_NATIVE_REFERENCE_RECORD_H
#include <stdint.h>
#include <signal.h>
#include <sys/user.h>
#define PAN_MAGIC UINT64_C(0x3146455250504150)
#define PAN_FP 65536U
#define PAN_PAGE 4096U
#define PAN_STACK 16384U
#define PAN_ROWS 18U
/* Exact Linux/x86-64 raw records, not signal-frame substitutes. All unused
   capacity starts zero. h fields are documented in read.py beside the parser. */
struct pan_point {
    uint64_t h[8];
    struct user_regs_struct trap, state;
    siginfo_t si;
    unsigned char fp[PAN_FP], source[2][PAN_PAGE], stack[2][PAN_STACK];
};
struct pan_row {
    uint64_t h[8];
    struct user_regs_struct helper;
    siginfo_t helper_si;
    struct pan_point point[2];
};
struct pan_image { uint64_t h[16]; unsigned char source[PAN_PAGE]; };
struct pan_record {
    uint64_t h[32];
    struct pan_image image[2];
    unsigned char maps[65536];
    struct user_regs_struct main_regs;
    siginfo_t main_si;
    struct pan_row row[PAN_ROWS];
};
_Static_assert(sizeof(struct user_regs_struct)==216 && sizeof(siginfo_t)==128,"raw kernel ABI");
_Static_assert(sizeof(struct pan_point)==107120 && sizeof(struct pan_row)==214648,"whole point/row ABI");
_Static_assert(sizeof(struct pan_record)==3938248,"complete bounded native wire");
#endif
