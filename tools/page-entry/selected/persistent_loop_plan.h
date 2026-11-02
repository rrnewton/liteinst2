#ifndef LI2_PERSISTENT_LOOP_PLAN_H
#define LI2_PERSISTENT_LOOP_PLAN_H
#include "persistent_fused_plan.h"
#include "loop_read_bridge.h"
#include "linked_loop_direct.h"
#if !defined(LI2_PERSISTENT_LOOP_PLAN) || LI2_PERSISTENT_LOOP_PLAN != 1
#error "separate loop-envelope component must be explicitly selected"
#endif
#define LI2_LP_VERSION 12U
_Static_assert(LI2_LP_VERSION!=LI2_PF_VERSION && LI2_LP_VERSION!=LI2_PG_VERSION &&
    LI2_LP_VERSION!=LI2_PG_COMPACT_VERSION && LI2_LP_VERSION!=10U,"separate exact policy");
_Static_assert(LI2_LE_HEADS==LI2_PG_HEADS && LI2_LE_BOUNDARIES==LI2_PG_BOUNDARIES &&
    LI2_LE_MEMBER_HEADS==LI2_PE_HEADS && LI2_LE_PAGE==LI2_REGION_PAGE,"unchanged geometry");
/* Pure cold component only. No owner/cancel/source/entry permission and no
   automatic PF fallback. NO_ENVELOPE is returned only by complete discovery;
   other chooser errors remain distinct. A future owner may independently
   select the unchanged PF11 route only after exact NO_ENVELOPE.

   Full and compact plans have explicit version12, no repurposed reserved
   words or new storage capacity. The winning interval/BFS is reconstructed
   from the actual two source pages and genuine entry. Every external arm is
   an individual branch-before DIRECT exit. NONE branches have both arms
   internal. Original rows are canonical actual v1 old forms or v2 additions.

   All host buffers are valid owned, aligned and disjoint. Caller-owned chooser
   scratch is separate protected storage in any future owner, not a stack or
   source-authority object. Decoder calls require the existing sealed serialized
   arena. Entire plan/compact reconstruction precedes boundary-only recovery. */
/* Geometry-only offer predicate. A far source can attempt policy12; it still
   needs full held-source planning or an exactly reconstructed cancellation. */
int li2_lp_placement(uintptr_t,const struct li2_pg_layout *);
/* Return the exact existing reach category, or0. Neither function changes any
   input plan/miss or grants source/entry authority. The fallback classifier
   requires a separately authenticated complete NO_ENVELOPE at its caller. */
unsigned li2_lp_relocation_reason(const struct li2_pg_plan *,const struct li2_pg_miss *,int,
    struct li2_pg_plan *,struct li2_le_witness *);
unsigned li2_lp_fallback_relocation_reason(const struct li2_pg_plan *,const struct li2_pg_miss *,int,
    struct li2_pg_plan *);
int li2_lp_plan_pages(const uintptr_t[2],const unsigned char[2][LI2_REGION_PAGE],
    uintptr_t,const struct li2_pg_layout *,const struct li2_mg_table *,
    struct li2_pg_plan *,struct li2_pg_miss *,struct li2_le_witness *);
int li2_lp_plan_validate(const struct li2_pg_plan *,struct li2_pg_plan *,struct li2_le_witness *);
int li2_lp_miss_validate(const struct li2_pg_plan *,const struct li2_pg_miss *,int,
    struct li2_pg_plan *,struct li2_le_witness *);
int li2_lp_compact_build(const struct li2_pg_plan *,struct li2_pg_plan *,
    struct li2_pg_compact *,struct li2_le_witness *);
int li2_lp_compact_validate(const struct li2_pg_compact *,struct li2_pg_plan *,
    struct li2_pg_compact *,struct li2_le_witness *);
int li2_lp_compact_direct(const struct li2_pg_compact *,unsigned,unsigned,struct li2_dd_plan *);
int li2_lp_compact_guard(const struct li2_pg_compact *,unsigned,unsigned,struct li2_mg_plan *);
int li2_lp_compact_exit(const struct li2_pg_compact *,uintptr_t,uint64_t);
/* Decoder-free exact boundary materialization after complete validation.
   Actual data faults/FP/SI/UC/stack and closure/replay remain owner obligations. */
int li2_lp_compact_recover(const struct li2_pg_compact *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],union li2_pg_guard *,struct li2_pg_recovered *);
#endif
