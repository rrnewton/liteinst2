#ifndef LI2_TF_SPAN_TRANSFER_H
#define LI2_TF_SPAN_TRANSFER_H
#include "tf_chain.h"
#include "span_fetch.h"
#if !defined(LI2_SCALAR_SPAN_TRACE) || LI2_SCALAR_SPAN_TRACE != 1 || \
    !defined(LI2_SCALAR_SPAN) || LI2_SCALAR_SPAN != 1 || \
    !defined(LI2_RUN_CACHE_REUSE) || LI2_RUN_CACHE_REUSE != 1
#error "scalar-span TRACE needs its exact typed profile and old quiet interlock"
#endif
enum li2_span_transfer_phase {
    LI2_ST_IDLE,LI2_ST_CLOSING,LI2_ST_CLOSED,LI2_ST_CONSUMED,
    LI2_ST_RESUMING,LI2_ST_RESUMED
};
enum li2_span_transfer_error {
    LI2_ST_ARGUMENT=3000,LI2_ST_STATE,LI2_ST_ORIGIN,LI2_ST_FRAME,
    LI2_ST_FETCH,LI2_ST_OVERFLOW
};
struct li2_tf_span_transfer;
/* Fixed read-only history; neither this copy nor an opaque pointer alone is
   authority. The actual private valid bit is consumed once in this handler. */
struct li2_span_transfer_progress {
    unsigned phase,issued,consume_attempted,consumed,resume_attempted,resumed;
    unsigned previous,next,successor_installed,first_error;
    long first_detail;
    uint64_t serial,event,previous_generation,previous_borrow,fresh_borrow;
    uintptr_t pc;
    uint64_t flags;
    struct li2_span_fetch_observation released,fresh;
};
/* Chosen close: no descriptive fallback is returned once it starts. Old source
   cleanup and genuine TRACE validation remain the actual chain's operations. */
int li2_tf_chain_span_close(struct li2_tf_chain *,int,siginfo_t *,ucontext_t *,
                           const struct li2_tf_span_transfer **);
int li2_tf_chain_span_quiet(const struct li2_tf_span_transfer *);
/* Binds current actual held fetch to the exact real closed frame. Does not
   edit it, publish code, change permissions, or authorize an old plan cast. */
int li2_tf_chain_span_consume(const struct li2_tf_span_transfer *,
                            struct li2_step_session *,const struct li2_fetch_ref *,
                            uintptr_t,int,const siginfo_t *,const ucontext_t *);
/* The actual singleton must show a complete newer requested15 borrow at pc,
   now released. No caller release flag/ref is accepted. Before mutation an
   error returns to the new controller; after chain_next, actual old chain
   failure owns the installed successor. Result is written only on success. */
int li2_tf_chain_span_resume(const struct li2_tf_span_transfer *,int,siginfo_t *,
                           ucontext_t *,enum li2_chain_result *);
const struct li2_span_transfer_progress *li2_tf_chain_span_progress(void);
#endif
