#ifndef LI2_PERSISTENT_LOOP_EFFECTS_PLAN_H
#define LI2_PERSISTENT_LOOP_EFFECTS_PLAN_H
#include "persistent_loop_plan.h"
#include "loop_effects_bridge.h"
#if !defined(LI2_PERSISTENT_LOOP_EFFECTS) || LI2_PERSISTENT_LOOP_EFFECTS != 1 || \
    !defined(LI2_LOOP_EFFECTS) || LI2_LOOP_EFFECTS != 1
#error "policy13 and its separate decoder/byte-guard APIs must be explicitly selected"
#endif
#if !defined(LI2_PG_LOOP_ENCODING_VERSION) || LI2_PG_LOOP_ENCODING_VERSION != 2
#error "policy13 requires the existing explicit LOOP direct encoding domain2"
#endif
#define LI2_LPE_VERSION 13U
_Static_assert(LI2_LPE_VERSION==LI2_LEE_VERSION && LI2_LPE_VERSION!=LI2_LP_VERSION &&
    LI2_LPE_VERSION!=LI2_PF_VERSION,"separate effects policy and witness");
/* Same full/compact/witness storage and all old geometry/host-alias limits.
   No automatic12 or11 fallback. Caller must independently authenticate each
   complete NO_ENVELOPE before choosing the next policy. Source versions1/2/3
   are canonical; MOV descriptor/guard versions1/2 select MG/BMG respectively.
   Whole source-bound reconstruction precedes decoder-free boundary recovery.
   Data faults, full signal/FP state, source lifetime and permission custody
   remain runtime obligations. This pure API grants none of those authorities. */
int li2_lpe_placement(uintptr_t,const struct li2_pg_layout *);
unsigned li2_lpe_relocation_reason(const struct li2_pg_plan *,const struct li2_pg_miss *,int,
    struct li2_pg_plan *,struct li2_le_witness *);
int li2_lpe_plan_pages(const uintptr_t[2],const unsigned char[2][LI2_REGION_PAGE],
    uintptr_t,const struct li2_pg_layout *,const struct li2_mg_table *,
    struct li2_pg_plan *,struct li2_pg_miss *,struct li2_le_witness *);
int li2_lpe_plan_validate(const struct li2_pg_plan *,struct li2_pg_plan *,struct li2_le_witness *);
int li2_lpe_miss_validate(const struct li2_pg_plan *,const struct li2_pg_miss *,int,
    struct li2_pg_plan *,struct li2_le_witness *);
int li2_lpe_compact_build(const struct li2_pg_plan *,struct li2_pg_plan *,
    struct li2_pg_compact *,struct li2_le_witness *);
int li2_lpe_compact_validate(const struct li2_pg_compact *,struct li2_pg_plan *,
    struct li2_pg_compact *,struct li2_le_witness *);
int li2_lpe_compact_direct(const struct li2_pg_compact *,unsigned,unsigned,struct li2_dd_plan *);
int li2_lpe_compact_guard(const struct li2_pg_compact *,unsigned,unsigned,struct li2_mg_plan *);
int li2_lpe_compact_exit(const struct li2_pg_compact *,uintptr_t,uint64_t);
int li2_lpe_compact_recover(const struct li2_pg_compact *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],union li2_pg_guard *,struct li2_pg_recovered *);
#endif
