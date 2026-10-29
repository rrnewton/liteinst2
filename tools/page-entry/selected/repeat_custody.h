#ifndef LI2_REPEAT_CUSTODY_H
#define LI2_REPEAT_CUSTODY_H
#if LI2_REPEAT_RX_LEASE != 1 || !defined(LI2_EFFECT_PROVIDER) || \
    !defined(LI2_RSEQ_INACTIVE) || !defined(LI2_MAPS_PHASE_REUSE)
#error "REP custody requires the explicit effect/registered/maps profile"
#endif
#include "lifecycle_loader.h"
struct li2_repeat_lease_owner;
struct li2_step_session;
struct li2_step_request;
struct li2_run_protection;
enum li2_repeat_custody_phase {
    LI2_REP_CUSTODY_EMPTY, LI2_REP_CUSTODY_BOUND, LI2_REP_CUSTODY_SEEDING,
    LI2_REP_CUSTODY_VALIDATED, LI2_REP_CUSTODY_RETURN, LI2_REP_CUSTODY_READY,
    LI2_REP_CUSTODY_ENTRY, LI2_REP_CUSTODY_CLOSING, LI2_REP_CUSTODY_FAILED
};
enum li2_repeat_custody_reason {
    LI2_REP_CUSTODY_RAW=1, LI2_REP_CUSTODY_LIFECYCLE,
    LI2_REP_CUSTODY_RELEASE, LI2_REP_CUSTODY_ERROR
};
/* Descriptive actual observations. No scalar or copied snapshot can create a
   ticket, change its phase, or authorize a return to retained RX source. */
struct li2_repeat_custody_observation {
    unsigned initialized,phase,bound,reset_ready,ticket,first_error;
    long first_detail;
    uint64_t epoch,attempt,event,seeds,entries,validations,returns,closed;
    uint64_t invalidations,last_reason,borrow_sequence;
    struct li2_fetch_page page;
    struct li2_fetch_backing seed_backing,last_backing;
    struct li2_fetch_map_progress cold_maps;
};
/* Fixed real owner, session and custody storage are protected before use.
   Initialize after selected_selftest, before any application owner is armed. */
int li2_repeat_custody_initialize(struct li2_repeat_lease_owner *,
    struct li2_step_session *,const struct li2_run_protection *);
/* Status and eligibility are distinct: only a valid unsupported geometry or
   backing returns status zero with *eligible==0. Stale/invalid source is error.
   This function changes no permission and performs no borrow release. */
int li2_repeat_custody_eligible(const struct li2_fetch_ref *,
    const struct li2_step_request *,int *eligible);
/* Authenticate idle prior release BEFORE clearing/rearming the actual owner.
   bind consumes that checked reset once, after original li2_repeat_arm. */
int li2_repeat_custody_reset_ready(const struct li2_repeat_lease_owner *);
int li2_repeat_custody_quiet(const struct li2_repeat_lease_owner *);
int li2_repeat_custody_bind(struct li2_repeat_lease_owner *,const struct li2_fetch_ref *);
int li2_repeat_custody_before_begin(struct li2_repeat_lease_owner *,const struct li2_fetch_ref *);
/* seed sees actual RX, RUNNING/in_handler==1 after the real opening. */
int li2_repeat_custody_seed(struct li2_repeat_lease_owner *,const struct li2_fetch_ref *);
/* Call once at actual event boundary, before ordinary maps-phase invalidation.
   It consumes READY; nested/unexpected transitions poison instead of reseeding. */
void li2_repeat_custody_boundary(void);
/* validate follows original complete TRACE/progress proof and traces++.
   prepare_return follows the fresh remaining-span/registration guard.
   handler_end follows complete unchanged UC/FP proof and in_handler=0. */
int li2_repeat_custody_validate(struct li2_repeat_lease_owner *,const struct li2_fetch_ref *);
int li2_repeat_custody_prepare_return(struct li2_repeat_lease_owner *,const struct li2_fetch_ref *);
int li2_repeat_custody_handler_end(struct li2_repeat_lease_owner *,const struct li2_fetch_ref *);
/* Ticket destruction precedes actual revoke. released follows actual R/NX
   validation and successful release of the same original borrow. */
int li2_repeat_custody_close(struct li2_repeat_lease_owner *,const struct li2_fetch_ref *);
int li2_repeat_custody_released(struct li2_repeat_lease_owner *,const struct li2_fetch_ref *);
void li2_repeat_custody_invalidate(unsigned reason);
void li2_repeat_custody_fail(const struct li2_repeat_lease_owner *,unsigned,long);
const struct li2_repeat_custody_observation *li2_repeat_custody_progress(void);
#endif
