#ifndef LI2_SELECTED_PROVIDER_BUILTIN_POLICY_H
#define LI2_SELECTED_PROVIDER_BUILTIN_POLICY_H
#include "provider.h"
/* Scalar policy ABI only. No callback receives a frame, source pointer, stack,
   permission hook or authority to change its original continuation. Callbacks
   are immutable linked policy, not application pointers: they must not allocate,
   use TLS, issue syscalls, reenter dispatch or mutate their const input. A fault
   is terminal and its entered/returned prefix remains distinct from commit. */
struct li2_selected_clock_input {
    uint32_t abi_version,kind;
    uint64_t pc,next_pc,logical_flags,ordinal;
};
struct li2_selected_clock_result { uint64_t value;uint32_t aux,reserved; };
typedef int (*li2_selected_clock_callback)(const struct li2_selected_clock_input *,
                                         struct li2_selected_clock_result *);
enum li2_selected_syscall_action { LI2_SYSCALL_NATIVE=0,LI2_SYSCALL_REPLACE=1 };
struct li2_selected_syscall_input {
    uint32_t abi_version,reserved;
    uint64_t pc,next_pc,logical_flags,number,args[6],input_rcx,input_r11;
};
struct li2_selected_syscall_result { uint32_t action,reserved;uint64_t value; };
typedef int (*li2_selected_syscall_callback)(const struct li2_selected_syscall_input *,
                                           struct li2_selected_syscall_result *);
#define LI2_POLICY_CLOCK_BASE UINT64_C(0x1122334400000000)
#define LI2_POLICY_CLOCK_LAST UINT64_C(0x00000000ffffffff)
#define LI2_POLICY_PID UINT64_C(0x4c320001)
#define LI2_POLICY_TID UINT64_C(0x4c320002)
static int li2_policy_clock_v1(const struct li2_selected_clock_input *in,
                              struct li2_selected_clock_result *out) {
    if(!in || !out || in->abi_version!=1 ||
       (in->kind!=LI2_RDTSC && in->kind!=LI2_RDTSCP) ||
       !in->ordinal || in->ordinal>LI2_POLICY_CLOCK_LAST)return LI2_SELECTED_ARGUMENT;
    *out=(struct li2_selected_clock_result){LI2_POLICY_CLOCK_BASE+(in->ordinal<<8),
        in->kind==LI2_RDTSCP?UINT32_C(0xc001c0de):0,0};
    return 0;
}
static int li2_policy_syscall_v1(const struct li2_selected_syscall_input *in,
                                struct li2_selected_syscall_result *out) {
    if(!in || !out || in->abi_version!=1 || in->reserved)return LI2_SELECTED_ARGUMENT;
    *out=(struct li2_selected_syscall_result){LI2_SYSCALL_NATIVE,0,0};
    /* x86-64 syscall numbers are part of this finite linked policy. */
    if(in->number==39)*out=(struct li2_selected_syscall_result){LI2_SYSCALL_REPLACE,0,LI2_POLICY_PID};
    if(in->number==186)*out=(struct li2_selected_syscall_result){LI2_SYSCALL_REPLACE,0,LI2_POLICY_TID};
    return 0;
}
_Static_assert(sizeof(struct li2_selected_clock_input)==40,"clock input scalar ABI");
_Static_assert(sizeof(struct li2_selected_clock_result)==16,"clock result scalar ABI");
_Static_assert(sizeof(struct li2_selected_syscall_input)==104,"syscall input scalar ABI");
_Static_assert(sizeof(struct li2_selected_syscall_result)==16,"syscall result scalar ABI");
#endif
