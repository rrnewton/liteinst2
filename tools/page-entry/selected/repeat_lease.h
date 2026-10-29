#ifndef LI2_REPEAT_LEASE_H
#define LI2_REPEAT_LEASE_H
#if LI2_REPEAT_RX_LEASE != 1 || !defined(LI2_EFFECT_PROVIDER) || \
    !defined(LI2_RSEQ_INACTIVE) || !defined(LI2_MAPS_PHASE_REUSE)
#error "REP RX lease requires the explicit effect/registered/maps profile"
#endif
#include "repeat_owner.h"
#include "rseq_guard.h"

enum li2_repeat_lease_error { LI2_REPEAT_LEASE_STATE=220,
    LI2_REPEAT_LEASE_CUSTODY, LI2_REPEAT_LEASE_REGISTRATION,
    LI2_REPEAT_LEASE_FRAME, LI2_REPEAT_LEASE_OVERFLOW, LI2_REPEAT_LEASE_WRITE };
/* Only identity/pin fields are invariant. Guard counters and last-footprint
   observations deliberately remain live in the original rseq owner. */
struct li2_repeat_lease_registration {
    unsigned initialized,registered,held,tls_attempted,tls_complete;
    int phase;
    long pid,tid,fs_result,gs_result;
    uintptr_t address,page;
    uint32_t length,signature;
    uint64_t epoch,fs_base,gs_base;
    struct li2_rseq_data data;
};
struct li2_repeat_lease_owner {
    struct li2_repeat_owner repeat;
    struct li2_fetch_ref borrow;
    /* Actual progress of this same sequence, retained across later borrows. */
    unsigned borrow_held;
    struct li2_repeat_lease_registration registration;
    /* Lifetime totals survive only a checked, actually released reset. */
    uint64_t attempts,completed,total_traces,total_retained,total_closes,total_releases;
    uint64_t retained_transfers,rseq_checks,write_checks;
    uintptr_t write_first;
    size_t write_bytes;
    unsigned write_query_attempted;
    int write_result;
    unsigned begin_checked,cold_seeded,return_pending,handler_returned;
    unsigned close_started,close_complete,release_started,release_complete;
    unsigned failure_started,unexpected_observed,nested_observed;
    unsigned unexpected_info_complete,nested_info_complete;
    unsigned unexpected_context_complete,nested_context_complete;
    int custody_result,rseq_result,release_result;
    uintptr_t entry_frame_address,trace_frame_address,return_frame_address;
    ucontext_t entry_context,trace_context,return_context;
    siginfo_t unexpected_info,nested_info;
    ucontext_t unexpected_context,nested_context;
    struct li2_step_frame unexpected_frame,nested_frame;
};
/* Fixed linked trusted runtime query, never an owner-carried callback. Return
   zero only when the complete nonempty interval misses EVERY protected range;
   full containment is not overlap. The runtime binds its actual registry. */
int li2_repeat_lease_private_intersects(uintptr_t first,size_t bytes);
/* Lifecycle custody initialize registers/protects the one real owner before
   these calls. Arm performs its authenticated idle/reset check; callers never
   zero a live owner or manufacture a completed/reset record. */
int li2_repeat_lease_arm(struct li2_repeat_lease_owner *,struct li2_step_session *,
    const struct li2_tf_hooks *,const struct li2_step_request *,const struct li2_fetch_ref *);
void li2_repeat_lease_begin(struct li2_repeat_lease_owner *,int,siginfo_t *,ucontext_t *);
/* Final TRACE owns actual revoke/sync/closed query/release. The controller
   must not release again. Intermediate returns preserve the same borrow/RX. */
void li2_repeat_lease_trace(struct li2_repeat_lease_owner *,int,siginfo_t *,ucontext_t *);
/* After every ordinary handler consumer, before maps_phase_end/sigreturn. */
void li2_repeat_lease_handler_end(struct li2_repeat_lease_owner *,const ucontext_t *);
/* Descriptive closure only; lifecycle reset_ready separately checks authority. */
int li2_repeat_lease_closed(const struct li2_repeat_lease_owner *);
_Noreturn void li2_repeat_lease_abort(struct li2_repeat_lease_owner *,unsigned,long);
_Noreturn void li2_repeat_lease_unexpected(struct li2_repeat_lease_owner *,int,siginfo_t *,ucontext_t *);
/* Internal step-owner abort dispatch, selected by the actual registered arm.
   No ownership/permission constructor is exposed through these helpers. */
int li2_repeat_lease_owns_step(const struct li2_step_owner *);
_Noreturn void li2_repeat_lease_abort_step(struct li2_step_owner *,unsigned,long);
#endif
