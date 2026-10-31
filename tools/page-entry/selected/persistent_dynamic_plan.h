#ifndef LI2_PERSISTENT_DYNAMIC_PLAN_H
#define LI2_PERSISTENT_DYNAMIC_PLAN_H
#include "persistent_plan.h"
#if !defined(LI2_PERSISTENT_DYNAMIC) || LI2_PERSISTENT_DYNAMIC != 1
#error "explicit dynamic persistent profile required"
#endif
#define LI2_PE_DYNAMIC_MISS_VERSION 1U
enum li2_pe_dynamic_reason {
    LI2_PED_NONE=0, LI2_PED_ROOT_UNSUPPORTED, LI2_PED_SOURCE_INVALID,
    LI2_PED_SOURCE_TRUNCATED, LI2_PED_SOURCE_OVERLAP, LI2_PED_OUTSIDE_PAIR,
    LI2_PED_HEAD_LIMIT, LI2_PED_EXIT_LIMIT, LI2_PED_QUEUE_LIMIT, LI2_PED_NO_EXIT,
    LI2_PED_RIP_REACH, LI2_PED_BRANCH_REACH, LI2_PED_FALLTHROUGH_REACH,
    LI2_PED_GUARD_RIP_REACH, LI2_PED_GUARD_FOLLOW_REACH,
    LI2_PED_REASON_COUNT
};
enum li2_pe_dynamic_site { LI2_PED_NO_SITE=0, LI2_PED_SOURCE=1, LI2_PED_EMIT=2 };
struct li2_pe_dynamic_miss {
    uint32_t version,status,reason,site;
    uintptr_t pc;
    uint64_t detail;
};
/* Same pure plan and unchanged decoder/guard APIs. The additional aligned,
   disjoint output is a source-stage diagnosis, NOT cancellation authority.
   Every old result/partial plan byte is retained. Success and unclassified
   terminal errors have reason/site/pc/detail zero, version1/status=result.
   Only precisely marked source/placement refusals can pass miss_valid().
   Generated re-decode, malformed metadata, unresolved targets, arguments,
   static-NONE and guard-internal/spill errors remain terminal.
   Actual HELD source/rseq cancellation, complete release and unchanged
   genuine TRACE resume remain mandatory independent owner operations. */
int li2_pe_plan_pages_dynamic(const uintptr_t[LI2_PE_SOURCES],
    const unsigned char[LI2_PE_SOURCES][LI2_REGION_PAGE],uintptr_t,uintptr_t,uintptr_t,
    const struct li2_mg_table *,struct li2_pe_plan *,struct li2_pe_dynamic_miss *);
/* Pure strict consistency check on the immediate protected call outputs.
   No re-decode, mapped-source read, RAW, permission or execution credit.
   Returns1 only for a classified non-ready refusal, never for success. */
int li2_pe_dynamic_miss_valid(const struct li2_pe_plan *,const struct li2_pe_dynamic_miss *,int);
_Static_assert(sizeof(struct li2_pe_dynamic_miss)==32,"separate bounded diagnosis");
_Static_assert(LI2_PED_REASON_COUNT==15,"fixed reason0 plus14 refusal classes");
#endif
