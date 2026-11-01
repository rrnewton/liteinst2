#ifndef LI2_RESIDENT_SOURCE_LEASE_H
#define LI2_RESIDENT_SOURCE_LEASE_H
#include "persistent_group_runtime.h"
#if !defined(LI2_RESIDENT_SOURCE_LEASE) || LI2_RESIDENT_SOURCE_LEASE != 1 || \
    !defined(LI2_INITIAL_CODE_PROTECTION) || LI2_INITIAL_CODE_PROTECTION != 1 || \
    !defined(LI2_PERSISTENT_ACTIVE_DOMAIN) || LI2_PERSISTENT_ACTIVE_DOMAIN != 1 || \
    !defined(LI2_RSEQ_INACTIVE) || LI2_RSEQ_INACTIVE != 1
#error "source lease requires explicit initial-code and actual active-domain owners"
#endif
#if defined(LI2_PERSISTENT_EPOCH_CAPTURE) || defined(LI2_PERSISTENT_DYNAMIC_CAPTURE) || \
    defined(LI2_PERSISTENT_GROUP_CAPTURE) || defined(LI2_PERSISTENT_RESIDENT_CAPTURE) || \
    defined(LI2_PERSISTENT_RETAINED_TWO_CAPTURE) || defined(LI2_PERSISTENT_ACTIVE_DOMAIN_CAPTURE) || \
    defined(LI2_PERSISTENT_STARTUP_CAPTURE) || defined(LI2_PERSISTENT_SUBENTRY_CAPTURE) || \
    defined(LI2_PERSISTENT_DIRECT_FRONTIER_CAPTURE) || defined(LI2_PERSISTENT_CALL_OWNER_CAPTURE) || \
    defined(LI2_PERSISTENT_RET_OWNER_CAPTURE) || defined(LI2_PERSISTENT_COLD_ADMISSION_CAPTURE) || \
    defined(LI2_PERSISTENT_CROSS_PAIR_CAPTURE)
#error "source-lease storage is not represented by the older capture schemas"
#endif
/* Initial main/interpreter pages only. This is source retention, never a
   directory, RX grant, or permission to increase LI2_PGD_MEMBERS. */
#define LI2_RSL_PAGES 64U
struct li2_rsl_owner;
/* Descriptive source-retention identity only. A copied reference never grants
   storage pinning, entry, RX, a new owner token, or additional active members. */
struct li2_rsl_ref { const struct li2_rsl_owner *owner; uint64_t epoch; };
struct li2_rsl_progress {
    uint64_t epoch,bindings,invalidations;
    unsigned initialized,valid,pages,reserved;
    struct li2_pg_token bound;
};
/* Protected zeroed output: before PID/TID, actual clear-TID setter result,
   after PID/TID, robust query result/head/bytes, complete. Observation only. */
int li2_rsl_initialize(uint64_t observed[9]);
int li2_rsl_bind(const struct li2_pg_token *);
int li2_rsl_current(const struct li2_pg_token *,struct li2_rsl_ref *);
int li2_rsl_ref_live(const struct li2_rsl_ref *);
/* Snapshot first authenticates the whole real union. Page copies and coverage
   are descriptive; only plan() binds an actual protected owner-view member. */
int li2_rsl_snapshot(const struct li2_pg_token *,struct li2_rsl_ref *,unsigned *);
int li2_rsl_page_at(const struct li2_rsl_ref *,unsigned,struct li2_pg_source_page *);
int li2_rsl_covers(const struct li2_rsl_ref *,const struct li2_mg_table *);
int li2_rsl_validate(const struct li2_pg_token *);
int li2_rsl_plan(const struct li2_pg_token *,const struct li2_pg_compact *);
/* Called only from the real ordinary syscall ingress. It authenticates the
   old owner's completed/NX state itself, before invalidation or guest RAW. */
int li2_rsl_before_effect(long,const long[6]);
const struct li2_rsl_progress *li2_rsl_progress(void);
/* Implemented by the actual controller, not supplied by callers. */
int li2_rsl_owner_quiet(void);
#ifdef LI2_RESIDENT_THREE
#include "resident_three_owner.h"
#ifdef LI2_RESIDENT_SOURCE_PROBE
#error "the resident owner needs its own observation, not the old two-slot probe schema"
#endif
/* The by-value seed is issued by the actual held resident owner. Neither this
   separate binding nor the descriptive reference widens the old pgd view. */
struct li2_rsl_resident_progress {
    struct li2_r3_token bound;
    struct li2_r3_seed seed;
    uint64_t epoch,last_serial,bindings,snapshots,plans,validations;
    uint64_t authentications,fresh_maps_passes,source_bytes,plan_source_bytes,guard_pages;
    uint64_t observation_seals;
};
/* Advisory membership only: no refresh, token, source permission or RX grant. */
int li2_rsl_resident_advisory(uintptr_t);
int li2_rsl_resident_bind(const struct li2_r3_token *);
int li2_rsl_resident_snapshot(const struct li2_r3_token *,struct li2_rsl_ref *,unsigned *);
int li2_rsl_resident_plan(const struct li2_r3_token *,unsigned);
int li2_rsl_resident_validate(const struct li2_r3_token *);
/* Counts describe completed operations only. A failed prefix may have done
   partial authentication and must not infer zero work from unchanged totals.
   fresh_maps_passes counts complete rsl_maps acquisitions, not read syscalls.
   Snapshot/plan/validate records add one trusted RW->R metadata interval;
   bind records use its existing interval. These observation_seals are separate
   from original/generated source permissions. */
const struct li2_rsl_resident_progress *li2_rsl_resident_progress(void);
#ifdef LI2_RESIDENT_STABLE_GENERATION
#include "resident_source_generation.h"
#endif
#endif
#endif
