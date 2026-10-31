#ifndef LI2_RSEQ_CURRENT_DATA_H
#define LI2_RSEQ_CURRENT_DATA_H
#include "rseq_guard.h"
#include "maps_current_ticket.h"
#if !defined(LI2_RSEQ_CURRENT_DATA) || LI2_RSEQ_CURRENT_DATA != 1 || \
    !defined(LI2_RSEQ_INACTIVE) || LI2_RSEQ_INACTIVE != 1
#error "current rseq mapping requires the explicit maintained-data profile"
#endif
enum li2_rseq_current_kind {
    LI2_RSEQ_CURRENT_NONE=0, LI2_RSEQ_CURRENT_VIEW=1,
    LI2_RSEQ_CURRENT_PHYSICAL_UNAVAILABLE=2
};
/* Descriptive mapping evidence only. The ticket is consumed before return;
   it never proves an inactive rseq word, source custody or execution rights.
   data.maps is the actual query, not a relabelled physical origin. */
struct li2_rseq_current_data {
    uint32_t version,attempted,complete,kind;
    int result;
    long detail;
    unsigned phase_started,phase_ended,release_attempted,release_complete;
    int acquire_result,release_result;
    unsigned fallback_started,fallback_complete;
    struct li2_maps_current_ref ticket;
    struct li2_maps_current_view view;
    struct li2_rseq_data data;
};
/* Requires an ended maps phase. A successful current query is checked and
   consumed with no intervening RAW. Only CURRENT_UNAVAILABLE may invoke the
   unchanged physical API, after ending this helper's phase. All other errors
   are terminal to the caller and retain their actual partial observations. */
int li2_lifecycle_rseq_data_current(uintptr_t,struct li2_rseq_current_data *);
#endif
