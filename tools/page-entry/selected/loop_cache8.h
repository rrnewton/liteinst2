#ifndef LI2_LOOP_CACHE8_H
#define LI2_LOOP_CACHE8_H
#include "loop_cache8_profile.h"
/* Observations only. None is consulted by membership, source or execution. */
struct li2_loop_cache8_progress {
    uint64_t cold_calls,compact_build_calls,compact_validate_calls;
    uint64_t attach_attempts,accepted,source_declines;
    uint64_t bound_by_count[LI2_LOOP_CACHE8_MEMBERS+1U];
    uint64_t entered_by_count[LI2_LOOP_CACHE8_MEMBERS+1U];
    uint64_t completed_by_count[LI2_LOOP_CACHE8_MEMBERS+1U];
};
const struct li2_loop_cache8_progress *li2_loop_cache8_progress(void);
#ifdef LI2_LOOP_CACHE8_OBSERVE
#include "loop_cache8_observe.h"
#endif
#endif
