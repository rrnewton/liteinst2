#ifndef LI2_LINKED_SOURCE_H
#define LI2_LINKED_SOURCE_H
#include "span_source.h"
#include "linked_plan.h"
#include "private_code_query.h"
#ifdef LI2_LINKED_PREEDGE
#include "linked_preedge_source.h"
#endif
/* A full-page span_source is reused only as a fresh descriptive snapshot.
   The distinct private lifecycle epoch below is the actual exclusion owner. */
struct li2_link_epoch;
/* Value capability: owner storage may be reused; this serial never is. */
struct li2_link_epoch_token {
    const struct li2_link_epoch *owner;
    uint64_t serial;
};
enum li2_link_epoch_phase { LI2_LINK_IDLE,LI2_LINK_HELD,LI2_LINK_RX,LI2_LINK_CLOSED,LI2_LINK_RELEASED };
struct li2_link_epoch_progress {
    unsigned phase,first_error,release_started,release_complete;
    long first_detail;
    uint64_t serial,publication,borrow,allocation_epoch,generation_epoch,transactions_epoch;
    size_t records_epoch;
    uintptr_t source,generated;
    struct li2_private_code_query opened,closed;
};
int li2_lifecycle_link_initialize(void);
/* The old source fetch is already held. Caller has installed a pending route,
   validated the new whole graph and static NONE proof, and owns immutable
   protected storage. These functions never accept an old span-plan cast. */
int li2_lifecycle_link_validate(const struct li2_fetch_ref *,const struct li2_span_source *,
                                const struct li2_link_plan *);
int li2_lifecycle_link_begin(const struct li2_fetch_ref *,const struct li2_span_source *,
                             const struct li2_link_plan *,uint64_t,struct li2_link_epoch_token *);
int li2_lifecycle_link_opened(const struct li2_link_epoch_token *,const struct li2_span_source *,
                              const struct li2_link_plan *);
/* Actual generated R/NX query and full live source proof precede the old
   fetch_release. No caller-supplied 'closed' or inactive bit is accepted. */
int li2_lifecycle_link_release(const struct li2_link_epoch_token *,const struct li2_span_source *,
                               const struct li2_link_plan *);
int li2_lifecycle_link_interlock(void);
const struct li2_link_epoch_progress *li2_lifecycle_link_progress(void);
#endif
