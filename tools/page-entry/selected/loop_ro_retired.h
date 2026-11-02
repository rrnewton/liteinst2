#ifndef LI2_LOOP_RO_RETIRED_H
#define LI2_LOOP_RO_RETIRED_H
#include "loop_ro_reasons.h"
#if !defined(LI2_LOOP_RO_RETIRED) || LI2_LOOP_RO_RETIRED != 1
#error "retired-root observations require their distinct ABI6 release profile"
#endif
#define LI2_LRX_VERSION 6U
#define LI2_LRX_BYTES 2016U
#define LI2_LRX_SLOTS 16U
/* Each cell is an independent killed-prefix observation. Rank counts retired
   publications, including duplicates; it is not an LRU stack distance. */
struct li2_lrx_counts {
    uint64_t error,saves,overwrites,gate4,search_done,root_seen,source_seen,exact_seen;
    uint64_t no_root,source_changed,context_changed,bank_changed,registry_changed,lifetime_changed,reserved[2];
    uint64_t retirement_rank[16],offer_age[8];
};
struct li2_lrx_record { struct li2_lrr_record base;struct li2_lrx_counts retired; };
_Static_assert(sizeof(struct li2_lrx_counts)==320 &&
    offsetof(struct li2_lrx_record,retired)==1696 && sizeof(struct li2_lrx_record)==LI2_LRX_BYTES &&
    LI2_LRX_BYTES<LI2_PGC_PAGE,"ABI6 preserves the whole ABI5 structural prefix");
#endif
