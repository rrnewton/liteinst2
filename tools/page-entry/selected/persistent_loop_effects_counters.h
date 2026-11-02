#ifndef LI2_PERSISTENT_LOOP_EFFECTS_COUNTERS_H
#define LI2_PERSISTENT_LOOP_EFFECTS_COUNTERS_H
#include "persistent_loop_counters.h"
#if !defined(LI2_PERSISTENT_LOOP_EFFECTS_COUNTERS) || LI2_PERSISTENT_LOOP_EFFECTS_COUNTERS != 1 || \
    !defined(LI2_PERSISTENT_LOOP_EFFECTS) || LI2_PERSISTENT_LOOP_EFFECTS != 1
#error "ABI4 requires the explicit mixed11/12/13 release counter selector"
#endif
#define LI2_PLEC_VERSION 4U
#define LI2_PLEC_BYTES 896U
struct li2_plec_counts {
    uint64_t chooser_attempts,chooser_selected,chooser_no_envelope;
    uint64_t publications13,hits13,entries_with13,completed_with13;
    uint64_t historical_reconstructions,actual_entries13;
};
/* The complete ABI3 layout is a prefix; its header remains a distinct ABI4
   identity. Old ABI2/3 readers must reject this format, including a zero tail. */
struct li2_plec_record {
    struct li2_plc_record base;
    struct li2_plec_counts effects;
};
_Static_assert(sizeof(struct li2_plec_counts)==72 &&
    offsetof(struct li2_plec_record,base)==0 && offsetof(struct li2_plec_record,effects)==824 &&
    sizeof(struct li2_plec_record)==LI2_PLEC_BYTES && LI2_PLEC_BYTES<=1024,
    "distinct bounded ABI4 appends exactly nine effects cells");
#define PLEC_OFFSET(n,i) _Static_assert(offsetof(struct li2_plec_counts,n)==8U*(i),"exact ABI4 " #n)
PLEC_OFFSET(chooser_attempts,0);PLEC_OFFSET(chooser_selected,1);PLEC_OFFSET(chooser_no_envelope,2);
PLEC_OFFSET(publications13,3);PLEC_OFFSET(hits13,4);PLEC_OFFSET(entries_with13,5);
PLEC_OFFSET(completed_with13,6);PLEC_OFFSET(historical_reconstructions,7);PLEC_OFFSET(actual_entries13,8);
#undef PLEC_OFFSET
#endif
