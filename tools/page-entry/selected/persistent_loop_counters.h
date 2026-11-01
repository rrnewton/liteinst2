#ifndef LI2_PERSISTENT_LOOP_COUNTERS_H
#define LI2_PERSISTENT_LOOP_COUNTERS_H
#include "persistent_group_counters.h"
#if !defined(LI2_PERSISTENT_LOOP_COUNTERS) || LI2_PERSISTENT_LOOP_COUNTERS != 1 || \
    !defined(LI2_PERSISTENT_LOOP_RUNTIME) || LI2_PERSISTENT_LOOP_RUNTIME != 1 || \
    !defined(LI2_PERSISTENT_RETAINED_TWO_COUNTERS) || LI2_PERSISTENT_RETAINED_TWO_COUNTERS != 1
#error "ABI3 requires the explicit mixed11/12 release counter selector"
#endif
#if defined(LI2_PERSISTENT_LOOP_CAPTURE) || defined(LI2_PERSISTENT_DIRECT_FRONTIER_CAPTURE) || \
    defined(LI2_PERSISTENT_FUSED_CAPTURE) || defined(LI2_PERSISTENT_BLOCK_CENSUS) || \
    defined(LI2_REUSE_CENSUS) || defined(LI2_MAPS_DIFFERENTIAL)
#error "ABI3 has no capture, census or differential-profile compatibility"
#endif
#define LI2_PLC_VERSION 3U
#define LI2_PLC_BYTES 824U
struct li2_plc_counts {
    uint64_t chooser_attempts,chooser_selected,chooser_no_envelope;
    uint64_t publications12,hits12,entries_with12,completed_with12;
    uint64_t historical_reconstructions,actual_entries12;
};
/* A distinct format. The old record type and every old member offset remain
   unchanged; ABI2 readers must reject version3 and its nonzero appended cells. */
struct li2_plc_record {
    struct li2_pgc_record base;
    struct li2_plc_counts loop;
};
_Static_assert(sizeof(struct li2_plc_counts)==72 &&
    offsetof(struct li2_plc_record,base)==0 && offsetof(struct li2_plc_record,loop)==752 &&
    sizeof(struct li2_plc_record)==LI2_PLC_BYTES && LI2_PLC_BYTES<=1024,
    "distinct bounded ABI3 appends exactly nine cells");
#define PLC_OFFSET(n,i) _Static_assert(offsetof(struct li2_plc_counts,n)==8U*(i),"exact ABI3 " #n)
PLC_OFFSET(chooser_attempts,0);PLC_OFFSET(chooser_selected,1);PLC_OFFSET(chooser_no_envelope,2);
PLC_OFFSET(publications12,3);PLC_OFFSET(hits12,4);PLC_OFFSET(entries_with12,5);
PLC_OFFSET(completed_with12,6);PLC_OFFSET(historical_reconstructions,7);PLC_OFFSET(actual_entries12,8);
#undef PLC_OFFSET
#endif
