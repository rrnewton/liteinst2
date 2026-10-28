#ifndef LI2_SELECTED_PROVIDER_CALLBACK_H
#define LI2_SELECTED_PROVIDER_CALLBACK_H
#include "provider.h"
/* Additive callback contract. Existing provider structures and functions retain
   their ABI. The input is a runtime-owned scalar copy, not frame authority. */
struct li2_selected_callback_input {
    uint32_t abi_version,kind,width_bits,destination;
    uint64_t pc,next_pc,logical_flags,input_destination;
};
typedef int (*li2_selected_callback)(const struct li2_selected_callback_input *,
                                   struct li2_selected_script *);
struct li2_selected_callback_progress {
    uint32_t abi_version;
    volatile sig_atomic_t entered,returned,committed;
    int callback_status;
    uint32_t first_error;
    struct li2_selected_callback_input input;
    struct li2_selected_script script;
};
/* Same actual-frame, disjoint-allocation, sealed-decoder and exclusive-owner
   requirements as complete_scripted. callback/progress are also disjoint from
   frame/request/output. Callback is trusted, nonreentrant, allocation/TLS/syscall
   free; it may write only its script result. A callback exception is terminal:
   only entered is meaningful until returned, and no native retry is permitted.
   Full source/lifecycle authority remains with the caller. */
int li2_selected_complete_callback(ucontext_t *,const struct li2_selected_request *,
    li2_selected_callback,struct li2_selected_callback_progress *,
    struct li2_selected_completion *);
#endif
