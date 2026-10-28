#ifndef LI2_RSEQ_NATIVE_BOUNDARY_H
#define LI2_RSEQ_NATIVE_BOUNDARY_H
#if !defined(LI2_RSEQ_NATIVE) || !defined(LI2_RSEQ_NATIVE_BOUNDARY) || LI2_RSEQ_NATIVE_BOUNDARY != 1
#error "Registered boundary retries require the explicit registered-native profile"
#endif
#include "native_epoch.h"

enum li2_rseq_boundary_phase { LI2_RNB_IDLE,LI2_RNB_FIRST,LI2_RNB_WAIT_REFAULT,
    LI2_RNB_ENTERING,LI2_RNB_OBSERVED,LI2_RNB_FAILED };
/* A retry token grants no executable permission. Keep the actual one-page
   revocation distinct from the next event's zero-page observation. */
struct li2_rseq_native_boundary_state {
    volatile sig_atomic_t phase;
    unsigned first_error,entry_checked;
    long first_detail,pid,tid;
    uint64_t attempts,preentries,entries,observations,tls_refreshes,completed;
    uintptr_t pc,fault_address,admitted_page,address,page;
    uint64_t registration_epoch,native_admissions,native_closed;
    uint32_t length,signature;
    uint64_t word_first,word_entry,word_after;
    uint64_t fs_first,gs_first,fs_second,gs_second;
    uint16_t fs_selector_first,gs_selector_first,fs_selector_entry,gs_selector_entry;
    uint16_t fs_selector_after,gs_selector_after;
    struct li2_rseq_data first_data,second_data;
    struct li2_native_close first_close,second_close;
};
const struct li2_rseq_native_boundary_state *li2_rseq_native_boundary_snapshot(void);
/* Called only after the unchanged native owner authenticates the real NX
   frame. Completion is called only after its full first/second comparison. */
int li2_rseq_native_boundary_enter(int,siginfo_t *,const ucontext_t *,unsigned);
int li2_rseq_native_boundary_complete(void);
#endif
