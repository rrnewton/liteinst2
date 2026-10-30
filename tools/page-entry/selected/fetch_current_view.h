#ifndef LI2_FETCH_CURRENT_VIEW_H
#define LI2_FETCH_CURRENT_VIEW_H
#include "maps_current_ticket.h"
#include "tf_same_page.h"
/* Descriptive first half of a distinct cold-TF provenance path. It neither
   seeds old physical custody nor changes/commits a borrow or permission owner.
   Its embedded stage is not the old rx_view and old commit rejects its pointer.
   A future typed current-custody seed must consume this exact live reference. */
struct li2_fetch_rx_current_view {
    unsigned version,complete;
    int result;
    struct li2_fetch_ref borrow;
    struct li2_maps_current_ref ticket;
    const struct li2_maps_current_view *query;
    struct li2_fetch_rx_view stage;
};
int li2_lifecycle_fetch_rx_current_stage(const struct li2_fetch_ref *,uintptr_t,
                                        const struct li2_fetch_rx_current_view **);
int li2_lifecycle_fetch_rx_current_cancel(const struct li2_fetch_rx_current_view *);
#endif
