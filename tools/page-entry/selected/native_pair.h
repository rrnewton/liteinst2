#ifndef LI2_NATIVE_PAIR_H
#define LI2_NATIVE_PAIR_H
/* Internal opt-in two-page execution owner. Public snapshots are descriptive;
   only the one fixed private owner and lifecycle's retained records authorize
   operations. No caller-created pointer, copied snapshot or phase grants X. */
#if !defined(LI2_NATIVE_PAIR) || LI2_NATIVE_PAIR != 1 || \
    !defined(LI2_RSEQ_NATIVE_BOUNDARY) || !defined(LI2_EFFECT_PROVIDER) || \
    !defined(LI2_REPEAT_RX_LEASE) || !defined(LI2_MAPS_PHASE_REUSE)
#error "native pair requires the complete explicit release profile"
#endif
#include "native_epoch.h"
#include "rseq_guard.h"
#define LI2_NATIVE_PAIR_SLOTS 2U
#define LI2_NATIVE_PAIR_WINDOW (LI2_STEP_PAGE+28U)
enum li2_native_pair_phase {
    LI2_NP_EMPTY,LI2_NP_INITIALIZING,LI2_NP_IDLE,LI2_NP_SEEDING,
    LI2_NP_EXECUTING_ONE,LI2_NP_ENTERING,LI2_NP_EXTENDING,
    LI2_NP_EXECUTING_TWO,LI2_NP_CLOSING,LI2_NP_WAIT_REFAULT,
    LI2_NP_REFAULTING,LI2_NP_FAILED
};
enum li2_native_pair_error {
    LI2_NP_ARGUMENT=1900,LI2_NP_STATE,LI2_NP_IDENTITY,LI2_NP_REENTRY,
    LI2_NP_FRAME,LI2_NP_FOREIGN,LI2_NP_FLAGS,LI2_NP_SOURCE,
    LI2_NP_MAPPING,LI2_NP_BACKING,LI2_NP_STALE,LI2_NP_OVERFLOW,
    LI2_NP_CLOSE,LI2_NP_RETRY_CHANGED,LI2_NP_RSEQ,LI2_NP_TLS
};
enum li2_native_pair_result { LI2_NP_FALLBACK=0,LI2_NP_RESUME=1,LI2_NP_REFAULT=2 };
enum li2_native_pair_reason { LI2_NP_POLICY=1,LI2_NP_CAPACITY,
    LI2_NP_STRADDLER,LI2_NP_EFFECT,LI2_NP_FAULT,LI2_NP_TERMINAL };
struct li2_native_pair_owner;
/* One retained record per actual page. Full backing/stat evidence is retained;
   historical identity compares only stable dev/ino/size/mode+FD/seals/extent. */
struct li2_native_pair_slot {
    unsigned prepared,published,slot,window_before,window_after,policy;
    uintptr_t pc;
    struct li2_fetch_page page;
    struct li2_fetch_backing backing;
    size_t window_bytes,window_initialized;
    unsigned char window[LI2_NATIVE_PAIR_WINDOW];
};
struct li2_native_pair_lifecycle {
    const struct li2_native_pair_owner *owner;
    unsigned initialized,busy,live,first_error,opening,post_verified;
    long first_detail,pid,tid;
    uint64_t sequence,allocation_epoch,generation_epoch,transactions_epoch;
    size_t records_epoch;
    uint64_t attempts,published,closed_pages,close_calls;
    uintptr_t candidate;
    unsigned candidate_policy,candidate_eligible;
    struct li2_fetch_map_progress before,after;
    struct li2_native_pair_slot slots[LI2_NATIVE_PAIR_SLOTS];
    struct li2_native_close close;
};
struct li2_rseq_pair_progress {
    const struct li2_native_pair_owner *owner;
    unsigned initialized,registered,active,checking,entry_checked,first_error,unsafe_terminal;
    long first_detail,pid,tid;
    uint64_t attempts,published,preentries,entries,refreshes,closed,registration_epoch;
    uintptr_t address,page;
    uint32_t length,signature;
    uint64_t word_before,word_entry,word_after;
    uint64_t fs_before,gs_before,fs_after,gs_after;
    uint16_t fs_selector_entry,gs_selector_entry,fs_selector_after,gs_selector_after;
    struct li2_rseq_data before,after;
};
struct li2_native_pair_progress {
    const struct li2_step_session *session;
    unsigned initialized,phase,in_handler,first_error,live,entry_pending;
    unsigned first_observed,second_observed,close_reason;
    long first_detail,pid,tid;
    uint64_t events,seeds,extensions,epochs_closed,one_page_closes,two_page_closes;
    uint64_t policy_closes,capacity_closes,refaults,refault_completed,logical_flags;
    int signal_number,signal_code,signal_errno;
    uintptr_t pc,signal_address;
    struct li2_step_frame first,second;
    struct li2_native_close first_close;
};
/* initialize is once-only after the genuine session self-test. preentry is the
   first native-owner handler statement, before returning raw/cleanup calls;
   a live registered word/pin contradiction exits without returning cleanup. */
int li2_native_pair_initialize(struct li2_step_session *);
void li2_native_pair_preentry(void);
/* Genuine nonnested NX only. RESUME/REFAULT preserve actual uc and FP bytes.
   FALLBACK requires fully closed custody. Known cold flags stay exact;
   only completed native closure imports next-instruction flags. flags_known
   must be one at IDLE and zero for actual active/refault states.
   A clean cold ineligible page returns FALLBACK without opening anything. */
int li2_native_pair_nx(int,siginfo_t *,ucontext_t *,unsigned flags_known,uint64_t *logical_flags);
int li2_native_pair_quiet(void);
/* Application effects may call only while quiet. This is a guard, not a
   caller-directed close permit. Fatal abort owns exact attempted cleanup. */
int li2_native_pair_effect_guard(void);
void li2_native_pair_abort(unsigned,long);
const struct li2_native_pair_progress *li2_native_pair_progress(void);
const struct li2_native_pair_lifecycle *li2_lifecycle_pair_progress(void);
const struct li2_rseq_pair_progress *li2_rseq_pair_progress(void);
#ifdef LI2_COST_PROFILE
#if LI2_COST_PROFILE != 1
#error "cost profile is an explicit diagnostic opt-in"
#endif
/* Diagnostic only. These fields are never read by an execution owner.
   count/sum/min/max cover only successful prepare-to-publication intervals
   already measured by native_clock, not ingress, native execution or close.
   valid is computed by the snapshot against actual publication counts. */
struct li2_native_pair_cost {
    uint64_t count,sum_ns,min_ns,max_ns;
    unsigned initialized,valid,busy,overflow;
};
void li2_lifecycle_pair_cost_snapshot(struct li2_native_pair_cost *);
#endif
/* Fixed linked cross-TU seams. Exact private owner pointer + current stage
   checked independently in each module; parameters are never authority. */
int li2_native_pair_owner_check(const struct li2_native_pair_owner *,unsigned phase);
int li2_lifecycle_pair_initialize(const struct li2_native_pair_owner *);
/* eligible=0 is clean policy/geometry refusal only; other errors are terminal.
   New source proof is occupied before I/O. Opening is a separate call. */
int li2_lifecycle_pair_prepare(const struct li2_native_pair_owner *,uintptr_t,int *eligible);
int li2_lifecycle_pair_publish(const struct li2_native_pair_owner *,uintptr_t);
int li2_lifecycle_pair_close(const struct li2_native_pair_owner *);
int li2_lifecycle_pair_quiet(const struct li2_native_pair_owner *);
int li2_rseq_pair_initialize(const struct li2_native_pair_owner *);
int li2_rseq_pair_seed(const struct li2_native_pair_owner *);
int li2_rseq_pair_published(const struct li2_native_pair_owner *);
void li2_rseq_pair_preentry(const struct li2_native_pair_owner *);
int li2_rseq_pair_enter(const struct li2_native_pair_owner *);
int li2_rseq_pair_refresh(const struct li2_native_pair_owner *,int closing);
int li2_rseq_pair_closed(const struct li2_native_pair_owner *,int wait_refault);
int li2_rseq_pair_refault(const struct li2_native_pair_owner *);
int li2_rseq_pair_quiet(const struct li2_native_pair_owner *);
#endif
