#ifndef LI2_PERSISTENT_LOOP_FUSED_PLAN_H
#define LI2_PERSISTENT_LOOP_FUSED_PLAN_H
#include "persistent_fused_plan.h"
#include "linked_loop_direct.h"
#if !defined(LI2_PERSISTENT_LOOP_PLAN) || LI2_PERSISTENT_LOOP_PLAN != 1 || \
    !defined(LI2_PG_LOOP_ENCODING_VERSION) || LI2_PG_LOOP_ENCODING_VERSION != 2
#error "LOOP-bound PF encoding requires the explicit version-2 LOOP profile"
#endif
/* Policy11 remains the exact PF source graph. These separate entry points
   select canonical LD1 near or LD2 far miss transfers; the old PF/DD APIs
   retain their original signed32 refusal. Encoding authority belongs to the
   caller's authenticated LOOP profile, never to a retagged policy field.
   Whole plan/compact reconstruction still precedes boundary-only recovery. */
int li2_lpf_plan_pages(const uintptr_t[2],const unsigned char[2][LI2_REGION_PAGE],
    uintptr_t,const struct li2_pg_layout *,const struct li2_mg_table *,
    struct li2_pg_plan *,struct li2_pg_miss *);
int li2_lpf_plan_validate(const struct li2_pg_plan *,struct li2_pg_plan *);
int li2_lpf_miss_validate(const struct li2_pg_plan *,const struct li2_pg_miss *,int,struct li2_pg_plan *);
/* Exact unready guarded-RIP reach proof; source/NO_ENVELOPE authority stays with the LOOP owner. */
unsigned li2_lpf_guard_relocation_reason(const struct li2_pg_plan *,const struct li2_pg_miss *,int,
    struct li2_pg_plan *);
/* Saved-completion graph reconstruction only. The caller authenticates the
   saved source, layout and table address and proves complete NO_ENVELOPE.
   This performs the unchanged PF decoder/BFS/cut checks and binding geometry;
   it does not reconstruct an unavailable table, exclusion proof or emitted
   plan. Only table.address is populated; ready remains zero even on success.
   The result cannot pass any plan/compact admission validator. */
int li2_lpf_graph_history(const uintptr_t[2],const unsigned char[2][LI2_REGION_PAGE],
    uintptr_t,const struct li2_pg_layout *,uintptr_t,struct li2_pg_plan *);
int li2_lpf_compact_build(const struct li2_pg_plan *,struct li2_pg_plan *,struct li2_pg_compact *);
int li2_lpf_compact_validate(const struct li2_pg_compact *,struct li2_pg_plan *,struct li2_pg_compact *);
int li2_lpf_compact_direct(const struct li2_pg_compact *,unsigned,unsigned,struct li2_dd_plan *);
int li2_lpf_compact_guard(const struct li2_pg_compact *,unsigned,unsigned,struct li2_mg_plan *);
/* -1 absent/internal arm, -2 malformed; otherwise exact ordinary exit token. */
int li2_lpf_compact_exit(const struct li2_pg_compact *,uintptr_t,uint64_t);
/* Whole immutable validation precedes this boundary-only materialization.
   Unlike PB10 this needs the full MOV/DIRECT scratch union and distinguishes
   before-store, store, and committed-after-store recovery without replay.
   Actual faults, full FP/siginfo/stack, source leases and cancel/drain belong
   to the owner; these APIs do not synthesize them or claim owner completion. */
int li2_lpf_compact_recover(const struct li2_pg_compact *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],union li2_pg_guard *,struct li2_pg_recovered *);
#endif
