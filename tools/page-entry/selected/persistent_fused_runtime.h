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
       (miss->reason>=LI2_PGD_REASON_COUNT && miss->reason!=LI2_PFD_BACKWARD_UNSUPPORTED) || plan->decoder_result ||
       (miss->site!=LI2_PGD_SOURCE && miss->site!=LI2_PGD_EMIT))return 0;
    switch(miss->reason) {
    case LI2_PGD_ROOT_SELECTED:case LI2_PGD_ROOT_UNSUPPORTED:
        if(result!=LI2_PG_MISS || miss->site!=LI2_PGD_SOURCE)return 0;
        break;
    case LI2_PGD_SOURCE_INVALID:case LI2_PGD_SOURCE_TRUNCATED:
        if(result!=LI2_PG_BOUNDARY || miss->site!=LI2_PGD_SOURCE)return 0;
        break;
    case LI2_PFD_BACKWARD_UNSUPPORTED:
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
/* Pure route description, never an owner/source/entry permit. The caller
   must already authenticate the actual CLOSED completion cell. A fresh
   selected_prepare decoder row is compared whole, including its window.
   Only the recorded external arm may request original-PC generic TF. */
static inline int li2_pfr_direct_replay_valid(const struct li2_span_decoded *original,
    const struct li2_dd_descriptor *direct,const uintptr_t source[2],unsigned arm,uint64_t closed_flags,
    const struct li2_decoded *fresh,uint64_t logical_flags) {
    const uint64_t tf=UINT64_C(0x100),rf=UINT64_C(0x10000);
    if(!original || !direct || !source || !fresh || arm>1 || (logical_flags&(tf|rf)) ||
       closed_flags!=(logical_flags|rf))return 0;
    if(source[0]>=source[1] || (source[0]&4095) || (source[1]&4095) ||
       source[1]>(UINT64_C(1)<<47)-4096)return 0;
    struct li2_dd_descriptor expected;
    if(li2_dd_span(original,direct->external_mask,&expected))return 0;
    unsigned at=0,taken=0,fall=0;
    for(unsigned i=0;i<2;i++) {
        if(expected.decoded.pc>=source[i] && expected.decoded.pc-source[i]<4096)++at;
        if(expected.target[0]>=source[i] && expected.target[0]-source[i]<4096)++taken;
        if(expected.target[1]>=source[i] && expected.target[1]-source[i]<4096)++fall;
    }
    if(at!=1 || taken>1 || fall>1)return 0;
    const unsigned backward=taken && expected.target[0]<=expected.decoded.pc;
    const unsigned external=(!backward?1U:0U)|
        (expected.flow==LI2_REGION_JCC && (backward || !fall)?2U:0U);
    if(direct->external_mask!=external)return 0;
    const unsigned char *a=(const unsigned char *)&expected,*b=(const unsigned char *)direct;
    for(size_t i=0;i<sizeof expected;i++)if(a[i]!=b[i])return 0;
    a=(const unsigned char *)&original->decoded;b=(const unsigned char *)fresh;
    for(size_t i=0;i<sizeof *fresh;i++)if(a[i]!=b[i])return 0;
    return li2_dd_arm(direct,closed_flags)==(int)arm && (direct->external_mask&(1U<<arm));
}
#endif
