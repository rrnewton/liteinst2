#ifndef LI2_PERSISTENT_FUSED_PLAN_H
#define LI2_PERSISTENT_FUSED_PLAN_H
#include "persistent_group_compact.h"
#if !defined(LI2_PERSISTENT_FUSED_PLAN) || LI2_PERSISTENT_FUSED_PLAN != 1 || \
    !defined(LI2_PERSISTENT_DIRECT_FRONTIER) || LI2_PERSISTENT_DIRECT_FRONTIER != 1 || \
    !defined(LI2_PERSISTENT_DISPATCH) || LI2_PERSISTENT_DISPATCH != 1 || \
    !defined(LI2_PERSISTENT_ACTIVE_DOMAIN) || LI2_PERSISTENT_ACTIVE_DOMAIN != 1 || \
    !defined(LI2_PERSISTENT_CROSS_PAIR) || LI2_PERSISTENT_CROSS_PAIR != 1 || \
    !defined(LI2_MOV_GUARD) || LI2_MOV_GUARD != 1
#error "fused policy requires its explicit direct-directory and MOV-guard profile"
#endif
#if defined(LI2_ADD_GUARD) || defined(LI2_PERSISTENT_CALL_DISPATCH) || \
    defined(LI2_PERSISTENT_RET_DISPATCH) || defined(LI2_PERSISTENT_CALL_RETURN_HEADS) || \
    defined(LI2_PERSISTENT_DIRECT_CALL)
#error "version 11 admits only existing NONE, guarded MOV, and direct branches"
#endif
#define LI2_PF_VERSION 11U
/* PF-only diagnosis namespace: the shared PG reasons and ABI2 stay at 18. */
#define LI2_PF_REFUSAL_VERSION 1U
enum li2_pf_reason { LI2_PFD_BACKWARD_UNSUPPORTED=0x100U };
_Static_assert((unsigned)LI2_PFD_BACKWARD_UNSUPPORTED>(unsigned)LI2_PGD_REASON_COUNT,"distinct PF refusal namespace");
_Static_assert(LI2_PF_VERSION!=LI2_PG_VERSION && LI2_PF_VERSION!=LI2_PG_COMPACT_VERSION &&
    LI2_PF_VERSION!=10U,"separate fused policy never aliases BFS or PB10");
/* Descriptive partition only; no source/execution or directory authority.
   Follow a forward Jcc's fallthrough; cut its taken arm. Close an in-pair
   backward Jcc onto an exact decoded head; cut its fallthrough. Backward
   in-pair JMP closes internally; other JMPs cut. An out-of-pair arm always
   cuts. Initial head is exactly entry: backward closure does not move entry.
   Every cut retains the original branch-before state and full typed arm.
   Unknown non-root instructions stop before effect; unknown roots refuse.
   A backward arm resolved to an exact unsupported frontier refuses GRAPH
   with a PF-only diagnosis; unresolved or malformed closure stays unclassified.
   A diagnosis alone grants no owner cancellation or publication capability.
   All 128-head/8-boundary/2-source-page limits remain refusal limits, never
   implicit truncation. MOV uses the unchanged decoder/table/guard primitive.
   CALL/RET/indirect JMP/other writers are never admitted as generated heads. */
static inline unsigned li2_pf_in_pair(const uintptr_t pages[2],uintptr_t pc) {
    return (pc>=pages[0] && pc-pages[0]<LI2_REGION_PAGE) ||
        (pc>=pages[1] && pc-pages[1]<LI2_REGION_PAGE);
}
static inline unsigned li2_pf_cut_mask(const uintptr_t pages[2],const struct li2_span_decoded *d) {
    const unsigned back=d->target<=d->decoded.pc && li2_pf_in_pair(pages,d->target);
    unsigned mask=back?0U:1U;
    if(d->flow==LI2_REGION_JCC && (back || !li2_pf_in_pair(pages,d->decoded.next_pc)))mask|=2U;
    return mask;
}
int li2_pf_plan_pages(const uintptr_t[2],const unsigned char[2][LI2_REGION_PAGE],
    uintptr_t,const struct li2_pg_layout *,const struct li2_mg_table *,
    struct li2_pg_plan *,struct li2_pg_miss *);
int li2_pf_plan_validate(const struct li2_pg_plan *,struct li2_pg_plan *);
int li2_pf_miss_validate(const struct li2_pg_plan *,const struct li2_pg_miss *,int,struct li2_pg_plan *);
int li2_pf_compact_build(const struct li2_pg_plan *,struct li2_pg_plan *,struct li2_pg_compact *);
int li2_pf_compact_validate(const struct li2_pg_compact *,struct li2_pg_plan *,struct li2_pg_compact *);
int li2_pf_compact_direct(const struct li2_pg_compact *,unsigned,unsigned,struct li2_dd_plan *);
int li2_pf_compact_guard(const struct li2_pg_compact *,unsigned,unsigned,struct li2_mg_plan *);
/* -1 absent/internal arm, -2 malformed; otherwise exact ordinary exit token. */
int li2_pf_compact_exit(const struct li2_pg_compact *,uintptr_t,uint64_t);
/* Whole immutable validation precedes this boundary-only materialization.
   Unlike PB10 this needs the full MOV/DIRECT scratch union and distinguishes
   before-store, store, and committed-after-store recovery without replay.
   Actual faults, full FP/siginfo/stack, source leases and cancel/drain belong
   to the owner; these APIs do not synthesize them or claim owner completion. */
int li2_pf_compact_recover(const struct li2_pg_compact *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],union li2_pg_guard *,struct li2_pg_recovered *);
#endif
