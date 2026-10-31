#ifndef LI2_LINKED_PREEDGE_SOURCE_H
#define LI2_LINKED_PREEDGE_SOURCE_H
#include "span_source.h"
#include "linked_preedge_plan.h"
#include "private_code_query.h"
/* A full-page span_source is reused only as a fresh descriptive snapshot.
   The distinct private lifecycle epoch below is the actual exclusion owner. */
struct li2_preedge_epoch;
/* Value capability: owner storage may be reused; this serial never is. */
struct li2_preedge_epoch_token {
    const struct li2_preedge_epoch *owner;
    uint64_t serial;
};
enum li2_preedge_epoch_phase { LI2_PREEDGE_IDLE,LI2_PREEDGE_HELD,LI2_PREEDGE_RX,LI2_PREEDGE_CLOSED,LI2_PREEDGE_RELEASED };
struct li2_preedge_epoch_progress {
    unsigned phase,first_error,release_started,release_complete;
    long first_detail;
    uint64_t serial,publication,borrow,allocation_epoch,generation_epoch,transactions_epoch;
    size_t records_epoch;
    uintptr_t source,generated;
    struct li2_private_code_query opened,closed;
};
int li2_lifecycle_preedge_initialize(void);
/* The old source fetch is already held. Caller has installed a pending route,
   validated the whole typed v2 graph and static NONE proof for every EMITTED
   head, and owns immutable protected storage. The cut instruction is decoded
   and source-bound, never executed or credited to that NONE proof. No old plan
   cast or caller-supplied frontier readiness is accepted. The old v1 owner and
   this owner share the direct-lifecycle interlock; neither may overlap. */
int li2_lifecycle_preedge_validate(const struct li2_fetch_ref *,const struct li2_span_source *,
                                const struct li2_preedge_plan *);
int li2_lifecycle_preedge_begin(const struct li2_fetch_ref *,const struct li2_span_source *,
                             const struct li2_preedge_plan *,uint64_t,struct li2_preedge_epoch_token *);
int li2_lifecycle_preedge_opened(const struct li2_preedge_epoch_token *,const struct li2_span_source *,
                              const struct li2_preedge_plan *);
/* Actual generated R/NX query and full live source proof precede the old
   fetch_release. No caller-supplied 'closed' or inactive bit is accepted. */
int li2_lifecycle_preedge_release(const struct li2_preedge_epoch_token *,const struct li2_span_source *,
                               const struct li2_preedge_plan *);
int li2_lifecycle_preedge_interlock(void);
const struct li2_preedge_epoch_progress *li2_lifecycle_preedge_progress(void);
#endif
