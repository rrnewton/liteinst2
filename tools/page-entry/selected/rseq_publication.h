#ifndef LI2_RSEQ_PUBLICATION_H
#define LI2_RSEQ_PUBLICATION_H
#include "rseq_guard.h"
#include "oneshot.h"
enum li2_rseq_publication_phase { LI2_RP_IDLE,LI2_RP_PREPARING,LI2_RP_PREPARED,
    LI2_RP_BOUND,LI2_RP_PUBLISHED,LI2_RP_LANDED,LI2_RP_RESTORED,LI2_RP_FAILED };
struct li2_rseq_publication_state {
    volatile sig_atomic_t phase,checking;
    unsigned first_error,unsafe_terminal,registered,entry_checked;
    long first_detail,pid,tid;
    uint64_t attempts,retired,cancelled,last_closed_sequence,sequence;
    uintptr_t pc,landing,address,page;
    uint64_t registration_epoch,fs_before,gs_before,fs_after,gs_after;
    uint32_t length,signature;
    uint16_t fs_entry,gs_entry,fs_restored,gs_restored;
    uint64_t word_before,word_entry,word_restored;
    struct li2_rseq_data before,after;
};
const struct li2_rseq_publication_state *li2_rseq_publication_snapshot(void);
const struct li2_rseq_publication_state *li2_rseq_publication_last_complete(void);
const struct li2_rseq_publication_state *li2_rseq_publication_last_refused(void);
/* Old selected fetch must first be authenticated and released. Prepare makes
   a new real data-page/TLS observation; caller then freshly prepares the same
   original PC. bind joins its exact backend plan without a raw call. */
int li2_rseq_publication_prepare(uintptr_t original_pc);
int li2_rseq_publication_bind(const struct li2_oneshot_plan *);
int li2_rseq_publication_check(uint64_t sequence,uintptr_t original_pc);
int li2_rseq_publication_publish(const struct li2_oneshot_owner *);
/* First handler statement, before native_preentry or any returning raw call.
   Contradictory pin/nonzero word/reentry uses only nonreturning raw exit. */
void li2_rseq_publication_preentry(void);
/* Caller has first authenticated the actual signal-frame ranges. */
int li2_rseq_publication_landed(const struct li2_oneshot_owner *,int,
                               const siginfo_t *,const ucontext_t *);
/* After actual source restoration/release, before any fresh effect borrow. */
int li2_rseq_publication_restored(const struct li2_oneshot_owner *);
/* Only backend retirement calls this after the actual effect has committed.
   It deliberately does not compare pre-effect registration/mapping state:
   an authorized rseq/lifecycle syscall may have changed that state. */
int li2_rseq_publication_retire(const struct li2_oneshot_owner *);
int li2_rseq_publication_cancel_unbound(uintptr_t original_pc);
/* Backend-only: it has authenticated the genuine clean transfer refusal. */
int li2_rseq_publication_cancel_bound(uint64_t sequence,uintptr_t original_pc);
#endif
