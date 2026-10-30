#ifndef LI2_FETCH_CURRENT_CUSTODY_H
#define LI2_FETCH_CURRENT_CUSTODY_H
#include "maps_current_ticket.h"
#include "tf_same_page.h"
/* Distinct provenance, never an alternative accepted by physical FRESH APIs. */
enum { LI2_CUSTODY_CURRENT_SEED=3,LI2_CUSTODY_CURRENT_RETAINED=4,
       LI2_CUSTODY_CURRENT_MANAGED_SEALED=2 };
struct li2_current_custody_provenance {
    unsigned version,kind,consumed,complete;
    uint64_t epoch,origin_sequence,stage_serial;
    /* Historical query description only after consumption; table is never
       dereferenced through this retained copy. Physical baseline stays honest. */
    struct li2_maps_current_view origin;
};
struct li2_current_custody_stats {
    uint64_t attempts,current_stages,current_seeds,physical_fallbacks;
    uint64_t retained_stages,retained_checks,commits,cancels;
    unsigned first_error;
    long first_detail;
};
int li2_lifecycle_fetch_rx_stage_current_custody(const struct li2_fetch_ref *,uintptr_t,
    const struct li2_custody_owner *,const struct li2_fetch_rx_view **);
int li2_lifecycle_fetch_rx_commit_current_custody(const struct li2_fetch_ref *,
    const struct li2_fetch_rx_view *,const struct li2_custody_owner *,struct li2_fetch_ref *);
int li2_lifecycle_fetch_rx_publish_current_custody(const struct li2_fetch_ref *,
    const struct li2_fetch_rx_view *,const struct li2_custody_owner *);
int li2_lifecycle_fetch_rx_cancel_current_custody(const struct li2_fetch_ref *,
    const struct li2_fetch_rx_view *);
const struct li2_fetch_rx_view *li2_lifecycle_fetch_rx_current_progress(void);
const struct li2_current_custody_provenance *li2_current_custody_provenance(void);
int li2_current_custody_owned(void);
int li2_current_custody_return(const void *);
void li2_current_custody_snapshot(struct li2_current_custody_stats *);
#endif
