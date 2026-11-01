#ifndef LI2_PERSISTENT_FUSED_RUNTIME_H
#define LI2_PERSISTENT_FUSED_RUNTIME_H
#include "persistent_fused_plan.h"
#if LI2_PERSISTENT_FUSED_RUNTIME != 1 || !defined(LI2_PERSISTENT_ACTIVE_DOMAIN) || \
    LI2_PERSISTENT_ACTIVE_DOMAIN != 1 || !defined(LI2_PERSISTENT_RETAINED_TWO) || \
    LI2_PERSISTENT_RETAINED_TWO != 1 || !defined(LI2_PERSISTENT_SUBENTRY) || \
    LI2_PERSISTENT_SUBENTRY != 1 || !defined(LI2_PERSISTENT_CROSS_PAIR) || \
    LI2_PERSISTENT_CROSS_PAIR != 1 || !defined(LI2_PERSISTENT_UNREGISTERED) || \
    LI2_PERSISTENT_UNREGISTERED != 1
#error "PF runtime selects one exact version11 observed-root two-active owner"
#endif
#if defined(LI2_PERSISTENT_BLOCK_RUNTIME) || defined(LI2_PERSISTENT_BLOCK_CAPTURE) || \
    defined(LI2_PERSISTENT_BLOCK_CENSUS) || defined(LI2_REUSE_CENSUS) || \
    defined(LI2_PERSISTENT_CALL_DISPATCH) || defined(LI2_PERSISTENT_RET_DISPATCH) || \
    defined(LI2_ADD_GUARD) || defined(LI2_PERSISTENT_DIRECT_CALL) || \
    defined(LI2_PERSISTENT_CALL_RETURN_HEADS) || defined(LI2_RESIDENT_THREE) || \
    defined(LI2_PERSISTENT_RETAINED_EIGHT)
#error "PF NONE/MOV/direct runtime does not borrow another instruction or resident policy"
#endif
/* Exact reconstruction is necessary but does not classify every internal
   error as a recoverable miss. Only the PF policy's explicit source/placement
   refusals may reach the existing genuine HELD cancellation path. Decoder,
   argument, corruption and unclassified emission errors remain fatal. */
static inline int li2_pfr_miss_valid(const struct li2_pg_plan *plan,
    const struct li2_pg_miss *miss,int result,struct li2_pg_plan *scratch) {
    if(!plan || !miss || !scratch || !result || !miss->reason ||
       miss->reason>=LI2_PGD_REASON_COUNT || plan->decoder_result ||
       (miss->site!=LI2_PGD_SOURCE && miss->site!=LI2_PGD_EMIT))return 0;
    switch(miss->reason) {
    case LI2_PGD_ROOT_SELECTED:case LI2_PGD_ROOT_UNSUPPORTED:
        if(result!=LI2_PG_MISS || miss->site!=LI2_PGD_SOURCE)return 0;
        break;
    case LI2_PGD_SOURCE_INVALID:case LI2_PGD_SOURCE_TRUNCATED:
        if(result!=LI2_PG_BOUNDARY || miss->site!=LI2_PGD_SOURCE)return 0;
        break;
    case LI2_PGD_SOURCE_OVERLAP:case LI2_PGD_OUTSIDE_PAIR:
    case LI2_PGD_HEAD_LIMIT:case LI2_PGD_EXIT_LIMIT:case LI2_PGD_LINK_LIMIT:
        if(result!=LI2_PG_GRAPH || miss->site!=LI2_PGD_SOURCE)return 0;
        break;
    case LI2_PGD_RIP_REACH:case LI2_PGD_BRANCH_REACH:case LI2_PGD_FALLTHROUGH_REACH:
        if(result!=LI2_PG_RELOCATION || miss->site!=LI2_PGD_EMIT)return 0;
        break;
    default:return 0;
    }
    return li2_pf_miss_validate(plan,miss,result,scratch)==0;
}
#endif
