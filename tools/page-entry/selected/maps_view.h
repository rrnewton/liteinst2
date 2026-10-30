#ifndef LI2_MAPS_VIEW_H
#define LI2_MAPS_VIEW_H
#include <stdint.h>
#include <stddef.h>
#if defined(LI2_MAPS_MAINTAINED) && LI2_MAPS_MAINTAINED != 1
#error "maintained maps is an explicit enabled profile"
#endif
#if defined(LI2_MAPS_DIFFERENTIAL) && (!defined(LI2_MAPS_MAINTAINED) || LI2_MAPS_DIFFERENTIAL != 1)
#error "differential maps requires the maintained profile"
#endif
/* Experimental singleton address-space projection. This is not source,
   allocation, generation, entry or execution authority. The existing owners
   still check those facts on every query. No multithread/shared-mm contract. */
struct li2_maps_view_stats {
    uint64_t queries,hits,refreshes,updates,invalidations,comparisons,mismatches;
    uint64_t unexplained,stack_probes;
    uint32_t enabled,differential,poisoned,reserved;
};
void li2_maps_view_stack(uintptr_t);
int li2_maps_view_enable(void);
void li2_maps_view_unexplained(void);
/* Existing owners that require a new physical acquisition retain that demand. */
void li2_maps_view_require_fresh(void);
void li2_maps_view_snapshot(struct li2_maps_view_stats *);
#endif
