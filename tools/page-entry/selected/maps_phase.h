#ifndef LI2_MAPS_PHASE_H
#define LI2_MAPS_PHASE_H
#include <stdint.h>
/* Private singleton-handler optimization; not mapping or source authority.
   The shared key is ONLY (handler_id, mutation_epoch). Every query retains its
   own current allocation/generation/record/transaction and byte predicates. */
enum li2_maps_kind { LI2_MAPS_DIRECT=0, LI2_MAPS_FRESH=1, LI2_MAPS_REUSED=2 };
struct li2_maps_observation {
    uint64_t acquisition_id,handler_id,mutation_epoch;
    uint32_t kind,io_performed;
};
struct li2_maps_stats {
    uint64_t fresh_calls,acquisitions,reuses,invalidations,handler_id,mutation_epoch;
    uint32_t active,valid,poisoned,reserved;
};
void li2_maps_event_boundary(void);
int li2_maps_phase_begin(void);
void li2_maps_phase_end(void);
void li2_maps_phase_fail(void);
void li2_maps_before_raw(long,long,long,long,long,long,long);
void li2_maps_after_raw(long,long,long,long,long,long,long,long);
void li2_maps_stats_read(struct li2_maps_stats *);
#ifdef LI2_MAPS_PHASE_TEST
int li2_maps_test_saturate(unsigned);
#endif
/* Use at the actual gateway AND at adapters that can return without issuing a
   syscall. Hooks are intentionally idempotent for validity, not for counts. */
static inline long li2_maps_raw(long (*call)(long,long,long,long,long,long,long),
                               long n,long a,long b,long c,long d,long e,long f) {
    li2_maps_before_raw(n,a,b,c,d,e,f);
    long result=call(n,a,b,c,d,e,f);
    li2_maps_after_raw(n,a,b,c,d,e,f,result);
    return result;
}
#endif
