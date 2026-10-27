#ifndef LI2_REGISTER_RUN_TIMING_H
#define LI2_REGISTER_RUN_TIMING_H
#include "register_run_reset.h"
#include "maps_phase.h"
#define LI2_TIME_HITS 10U
#define LI2_TIME_SAMPLES (LI2_TIME_HITS+1U)
enum li2_time_mode { LI2_TIME_DISCOVERY=1, LI2_TIME_MEASURE=2 };
enum li2_time_error { LI2_TIME_ARGUMENT=800,LI2_TIME_REUSE,LI2_TIME_IDENTITY,
    LI2_TIME_CLOCK,LI2_TIME_ORDER,LI2_TIME_PUBLICATION,LI2_TIME_RESET,
    LI2_TIME_OVERFLOW,LI2_TIME_INTERRUPTED };
struct li2_time_key {
    uint64_t offset,source_length,run_length,instructions,guard_length,guard_code;
    unsigned char source[16]; /* byte 15 is always zero */
};
struct li2_time_config {
    unsigned mode;
    unsigned char image_hash[32];
    struct li2_time_key key; /* zero in discovery; fixed before measured exec */
};
struct li2_time_clock { int64_t sec,nsec; };
struct li2_time_sample {
    uint64_t ordinal,borrow,slot,hit;
    unsigned started,published,complete,clock_attempted,clock_complete;
    long clock_result,clock_id;
    uint64_t ns[3];
    struct li2_maps_stats maps_before[3],maps_after[3];
};
struct li2_time_site {
    unsigned installed;
    struct li2_time_key key;
    uintptr_t pc,stop;
    size_t page_count;
    struct li2_fetch_page pages[2];
    uint64_t publication_generation,completed,hits;
};
struct li2_time_pending {
    unsigned active,matched,sampled,published;
    struct li2_time_key key;
    uintptr_t pc,stop;
    size_t page_count;
    struct li2_fetch_page pages[2];
    uint64_t borrow,ordinal,slot,hit;
};
struct li2_run_timing {
    unsigned initialized,first_error,finalized,qualified;
    long first_detail,resolution_result;
    struct li2_time_config config;
    uintptr_t image_first,image_end,image_bias;
    struct li2_time_clock clock_buffer,resolution;
    uint64_t completed,publications,hits,full_misses,clock_calls,samples_complete;
    struct li2_time_pending pending;
    struct li2_time_sample sample;
    struct li2_time_sample samples[LI2_TIME_SAMPLES];
    struct li2_time_site sites[LI2_RUN_CACHE_PAGES];
};
/* Observations only: no function grants source/publication/continuation authority.
   The caller supplies actual owned image bounds/hash, and protects this fixed
   owner before registration. Same process/singleton lifetime as the real cache. */
int li2_run_timing_init(struct li2_run_timing *,const struct li2_time_config *,
    uintptr_t,uintptr_t,uintptr_t,const unsigned char[32],const struct li2_run_protection *);
int li2_run_timing_begin(struct li2_run_timing *,const struct li2_run_plan *,
    const struct li2_fetch_ref *,const struct li2_fetch_view *);
int li2_run_timing_published(struct li2_run_timing *,int,
    const struct li2_run_cache_diagnostic *,const struct li2_run_publication_progress *);
int li2_run_timing_complete(struct li2_run_timing *,const struct li2_run_completion_history *);
void li2_run_timing_fail(struct li2_run_timing *,unsigned,long);
void li2_run_timing_finish(struct li2_run_timing *,unsigned);
#ifdef LI2_RUN_TIMING_TEST
int li2_run_timing_test_bad_clock(struct li2_run_timing *);
#endif
#endif
