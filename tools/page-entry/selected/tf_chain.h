#ifndef LI2_TF_CHAIN_H
#define LI2_TF_CHAIN_H
#include "tf_owner.h"
#include "tf_continuation.h"
#include "tf_entry_route.h"
#ifdef LI2_TF_SAME_PAGE_LEASE
#include "tf_same_page.h"
#endif
/* Opt-in singleton owner. Fixed storage survives until process exit. No API
   creates source authority: every query still consumes the real held ref. */
enum li2_chain_result { LI2_CHAIN_NX_FALLBACK=0, LI2_CHAIN_RUNNING=1
#ifdef LI2_TF_SAME_PAGE_LEASE
    , LI2_CHAIN_LEASE_RUNNING=2
#endif
};
enum li2_chain_phase { LI2_CHAIN_EMPTY, LI2_CHAIN_PREPARING, LI2_CHAIN_ARMING,
    LI2_CHAIN_EXECUTING, LI2_CHAIN_CLOSING, LI2_CHAIN_CLOSED,
    LI2_CHAIN_FALLBACK, LI2_CHAIN_FAILED };
enum li2_chain_fallback { LI2_CHAIN_NO_FALLBACK, LI2_CHAIN_DECODE_INVALID,
    LI2_CHAIN_DECODE_TRUNCATED, LI2_CHAIN_SELECTED, LI2_CHAIN_OLD_STEP,
    LI2_CHAIN_NOT_PLAIN, LI2_CHAIN_NOT_CLASSIFIED };
enum li2_chain_error { LI2_CHAIN_ARGUMENT=900, LI2_CHAIN_STATE,
    LI2_CHAIN_OVERFLOW, LI2_CHAIN_PREPARE, LI2_CHAIN_DECODE,
    LI2_CHAIN_RELEASE, LI2_CHAIN_ORIGIN, LI2_CHAIN_FRAME,
    LI2_CHAIN_ROUTE, LI2_CHAIN_STATS };
struct li2_tf_chain;
#if defined(LI2_EFFECT_PROVIDER) && defined(LI2_TF_HANDOFF) && defined(LI2_REGISTER_RUN)
struct li2_tf_run_entry;
/* Read-only actual handoff prefix. Copying it never creates an entry permit. */
struct li2_tf_run_origin {
    unsigned issued,consume_attempted,consumed,preflight_skipped,miss_released,previous,next;
    int result;
    uint64_t event_id,previous_generation,next_generation;
    uint64_t previous_borrow,next_borrow,run_borrow;
    uintptr_t pc;
    uint64_t flags;
};
/* Offered only by a completed OLD_STEP fallback in this real handler. */
const struct li2_tf_run_entry *li2_tf_chain_run_entry(struct li2_tf_chain *);
/* Descriptive planner SLOW grants no entry: consume the real proof and retain
   the unchanged closed TRACE frame, without any new borrow or permission. */
int li2_tf_chain_run_skip(const struct li2_tf_run_entry *,int,const siginfo_t *,const ucontext_t *);
/* Consumes exactly once, checks the real closed predecessor/full frame and
   the newly held source ref. Success does not publish code or change a frame. */
int li2_tf_chain_run_consume(const struct li2_tf_run_entry *,struct li2_step_session *,
                           const struct li2_fetch_ref *,uintptr_t,uint64_t,
                           int,const siginfo_t *,const ucontext_t *);
/* Planner/capacity miss only: observe the actual post-consume release and
   unchanged frame. This never issues a new permit or performs a release. */
int li2_tf_chain_run_released(const struct li2_tf_run_entry *,const struct li2_fetch_ref *,
                            int,const siginfo_t *,const ucontext_t *);
const struct li2_tf_run_origin *li2_tf_chain_run_snapshot(const struct li2_tf_chain *);
#endif
/* These copies contain no pointers into fetch's reusable singleton payload.
   ref.owner is the opaque identity used by the API, never dereferenced here. */
struct li2_chain_fetch {
    struct li2_fetch_ref ref;
    struct li2_fetch_progress progress;
    uintptr_t pc;
    size_t length,page_count;
    long pid,tid;
    unsigned identity_observed;
    unsigned char bytes[15];
    struct li2_fetch_page pages[2];
    struct li2_fetch_backing backing[2],last_backing;
};
struct li2_chain_release { unsigned started,complete; int result; };
struct li2_tf_chain_slot {
    struct li2_tf_chain *chain;
    volatile sig_atomic_t phase;
    unsigned index,origin,fallback,prepare_attempted,prepare_complete;
    unsigned decode_attempted,decode_complete,retry,unexpected_frame_observed;
    int unexpected_signal,unexpected_code,unexpected_errno;
    uintptr_t unexpected_address;
    uint64_t generation,event_id;
    struct li2_tf_owner owner;
    struct li2_decoded decoded,first_decoded;
    struct li2_tf_classification descriptive_classification;
    int prepare_result,decode_result,classify_result;
    struct li2_chain_fetch fetch,first_fetch;
    struct li2_chain_release release,first_release;
    struct li2_tf_continuation query;
    struct li2_step_frame unexpected;
};
/* Private entry capability is consumed in the same handler before any source
   opens. Caller must not mutate these fields; only the module produces it. */
struct li2_tf_trace_entry {
    volatile sig_atomic_t valid;
    unsigned previous,next;
    uint64_t event_id,sequence,previous_generation,next_generation;
    uintptr_t pc;
    uint64_t flags,previous_borrow_sequence;
};
struct li2_tf_chain {
    struct li2_step_session *session;
    void (*failure)(const struct li2_tf_chain *);
    unsigned initialized,first_error;
    volatile sig_atomic_t active,pending,in_handler;
    long first_detail;
    uint64_t event_id,sequence,attempts,steps,nx_entries,trace_entries;
    uint64_t fallbacks,prepare_attempts,releases,unexpected_events;
    struct li2_decoder_stats initial_stats;
    struct li2_tf_trace_entry entry;
    struct li2_tf_chain_slot slots[2];
#ifdef LI2_TF_SAME_PAGE_LEASE
    struct li2_tf_same_page lease;
#endif
};
/* Initialize before target entry. Existing session/selftest/signal/altstack,
   singleton, no-debug, source-generation and no-cross-modification contracts
   remain mandatory. One initialized chain exists in this translation unit. */
int li2_tf_chain_init(struct li2_tf_chain *,struct li2_step_session *,
                      void (*failure)(const struct li2_tf_chain *));
/* First action of the real reserved dispatcher (after maps invalidation).
   Invalidates any prior entry proof, including on nested/foreign delivery. */
void li2_tf_chain_event_boundary(struct li2_tf_chain *);
void li2_tf_chain_begin_nx(struct li2_tf_chain *,const struct li2_fetch_ref *,
                         const struct li2_decoded *,uint64_t,int,siginfo_t *,ucontext_t *);
/* Genuine TRACE only. RUNNING means a freshly authenticated ordinary successor
   now owns TF; FALLBACK means its real borrow was closed/released with no RX.
   Mandatory ownership/decoder API/cleanup errors never return as fallback. */
enum li2_chain_result li2_tf_chain_trace(struct li2_tf_chain *,int,siginfo_t *,ucontext_t *);
_Noreturn void li2_tf_chain_abort(struct li2_tf_chain *,unsigned,long);
_Noreturn void li2_tf_chain_unexpected(struct li2_tf_chain *,int,siginfo_t *,ucontext_t *);
/* Ends the handler scope; a capability never survives application execution. */
void li2_tf_chain_handler_end(struct li2_tf_chain *);
#endif
