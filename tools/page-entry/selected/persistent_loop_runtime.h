#ifndef LI2_PERSISTENT_LOOP_RUNTIME_H
#define LI2_PERSISTENT_LOOP_RUNTIME_H
#include "persistent_fused_runtime.h"
#include "persistent_loop_plan.h"
#include "persistent_loop_fused_plan.h"
#if !defined(LI2_PERSISTENT_LOOP_RUNTIME) || LI2_PERSISTENT_LOOP_RUNTIME != 1 || \
    !defined(LI2_PERSISTENT_FUSED_RUNTIME) || LI2_PERSISTENT_FUSED_RUNTIME != 1
#error "loop runtime explicitly composes policy12 with exact policy11 fallback"
#endif
#if defined(LI2_PERSISTENT_FUSED_CAPTURE) || defined(LI2_SEALED_BYTE_CERTIFICATE) || \
    defined(LI2_RESIDENT_STABLE_GENERATION)
#error "loop runtime has a distinct capture and no implicit certificate/generation composition"
#endif
#if defined(LI2_PERSISTENT_DIRECT_FRONTIER_CAPTURE) != defined(LI2_PERSISTENT_LOOP_CAPTURE)
#error "loop capture requires both its own selector and the original callback lifecycle"
#endif
#ifdef LI2_PERSISTENT_LOOP_CAPTURE
#if LI2_PERSISTENT_LOOP_CAPTURE != 1 || LI2_PERSISTENT_DIRECT_FRONTIER_CAPTURE != 1
#error "exact separate policy14 capture selection"
#endif
#endif
#ifdef LI2_PERSISTENT_LOOP_EFFECTS
#if LI2_PERSISTENT_LOOP_EFFECTS != 1
#error "explicit byte-store/register-multiply LOOP composition"
#endif
#include "persistent_loop_effects_plan.h"
#endif
#define LI2_LPR_VERSION 1U
#define LI2_LPR_HEADER_VERSION 2U
#define LI2_LPR_CAPTURE_VERSION 14U
/* This is an exact descriptive dispatch, not proof of a stored certificate.
   Header/source/immutable bytes and owner lifetime must authenticate first. */
static inline int li2_lpr_policy(unsigned p) {
#ifdef LI2_PERSISTENT_LOOP_EFFECTS
    if(p==LI2_LPE_VERSION)return 1;
#endif
    return p==LI2_PF_VERSION || p==LI2_LP_VERSION;
}
static inline int li2_lpr_header(uint64_t version,uint64_t policy,unsigned plan) {
    return version==LI2_LPR_HEADER_VERSION && li2_lpr_policy(plan) && policy==plan;
}
static inline int li2_lpr_exit(const struct li2_pg_compact *p,uintptr_t pc,uint64_t flags) {
    if(!p)return -2;
#ifdef LI2_PERSISTENT_LOOP_EFFECTS
    if(p->version==LI2_LPE_VERSION)return li2_lpe_compact_exit(p,pc,flags);
#endif
    if(p->version==LI2_LP_VERSION)return li2_lp_compact_exit(p,pc,flags);
    if(p->version==LI2_PF_VERSION)return li2_lpf_compact_exit(p,pc,flags);
    return -2;
}
static inline int li2_lpr_recover(const struct li2_pg_compact *p,uintptr_t pc,
    const uint64_t r[16],uint64_t flags,const uint64_t spill[4],union li2_pg_guard *scratch,
    struct li2_pg_recovered *out) {
    if(!p)return LI2_PG_CORRUPT;
#ifdef LI2_PERSISTENT_LOOP_EFFECTS
    if(p->version==LI2_LPE_VERSION)return li2_lpe_compact_recover(p,pc,r,flags,spill,scratch,out);
#endif
    if(p->version==LI2_LP_VERSION)return li2_lp_compact_recover(p,pc,r,flags,spill,scratch,out);
    if(p->version==LI2_PF_VERSION)return li2_lpf_compact_recover(p,pc,r,flags,spill,scratch,out);
    return LI2_PG_CORRUPT;
}
/* Exact original PF recoverable classification, with whole reconstruction
   through the separately bound LOOP encoding API. Old PF remains unchanged. */
static inline int li2_lpr_fallback_miss_valid(const struct li2_pg_plan *plan,
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
    return li2_lpf_miss_validate(plan,miss,result,scratch)==0;
}
/* A request identifies the actual latest closed receipt. It contains no
   supplied interval/mask permission. The owner reauthenticates it after fresh
   fetch/decode and before generic TF; copying this value grants nothing. */
struct li2_lpr_replay { uint64_t id,serial,policy;unsigned member,reserved; };
int li2_pg_loop_replay_valid(const struct li2_lpr_replay *,const struct li2_span_decoded *,
    const struct li2_dd_descriptor *,const uintptr_t[2],unsigned,uint64_t,
    const struct li2_decoded *,uint64_t);
/* Exact fresh decoder identity after source-bound historical cut validation. */
static inline int li2_lpr_replay_value(const struct li2_span_decoded *original,
    const struct li2_dd_descriptor *direct,unsigned arm,uint64_t closed_flags,
    const struct li2_decoded *fresh,uint64_t logical_flags) {
    const uint64_t tf=UINT64_C(0x100),rf=UINT64_C(0x10000);
    if(!original || !direct || !fresh || arm>1 || (logical_flags&(tf|rf)) ||
       closed_flags!=(logical_flags|rf))return 0;
    struct li2_dd_descriptor expected;
    if(li2_dd_span(original,direct->external_mask,&expected))return 0;
    const unsigned char *a=(const unsigned char *)&expected,*b=(const unsigned char *)direct;
    for(size_t i=0;i<sizeof expected;i++)if(a[i]!=b[i])return 0;
    a=(const unsigned char *)&original->decoded;b=(const unsigned char *)fresh;
    for(size_t i=0;i<sizeof *fresh;i++)if(a[i]!=b[i])return 0;
    return li2_dd_arm(direct,closed_flags)==(int)arm && (direct->external_mask&(1U<<arm));
}
#endif
