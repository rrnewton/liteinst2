#ifndef LI2_ONESHOT_REUSABLE_H
#define LI2_ONESHOT_REUSABLE_H
#include "lifecycle_loader.h"
#include "selected_effect.h"
#include "rseq_publication.h"
/* Description of the actual sealed source allocation. A landing may exist
   for this object while bound==0 after a later allocation/range changed.
   Rebind that same protected landing only after a fresh source check; never
   free/reuse a landing or infer reachability from object identity alone. */
struct li2_oneshot_site {
    uint64_t object_id,allocation;
    uintptr_t first,end,pc,landing;
    unsigned bound,reserved;
};
struct li2_oneshot_reuse_stats {
    uint64_t prepared,completed,refused,last_fetch_sequence,last_completed_sequence;
    volatile unsigned reset_started,reset_complete;
};
int li2_lifecycle_oneshot_landing_query(const struct li2_fetch_ref *,struct li2_oneshot_site *);
int li2_lifecycle_oneshot_register_object_landing(const struct li2_oneshot_site *,uintptr_t landing);
/* Existing prepare/transfer/advance/observe/release signatures stay unchanged.
   The new profile has one reusable attempt, not a larger lifetime allowance. */
int li2_lifecycle_oneshot_interlock(void);
int li2_lifecycle_oneshot_retire(void *,const struct li2_oneshot_owner *,
                                const struct li2_effect_owner *);
int li2_lifecycle_oneshot_cancel(void *,const struct li2_oneshot_owner *,int refusal);
const struct li2_oneshot_reuse_stats *li2_lifecycle_oneshot_reuse_snapshot(void);
const struct li2_oneshot_lifecycle_progress *li2_lifecycle_oneshot_last_complete(void);
const struct li2_oneshot_lifecycle_progress *li2_lifecycle_oneshot_last_refused(void);
#endif
