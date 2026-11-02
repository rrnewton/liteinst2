#ifndef LI2_LOOP_RO_REASONS_H
#define LI2_LOOP_RO_REASONS_H
#include "persistent_loop_effects_counters.h"
#include "loop_ro_profile.h"
#if !defined(LI2_LOOP_RO_REASONS) || LI2_LOOP_RO_REASONS != 1 || \
    defined(LI2_REUSE_CENSUS) || defined(LI2_PERSISTENT_BLOCK_CENSUS) || \
    defined(LI2_LOOP_RO_TEST) || defined(LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL)
#error "RO reason prefixes require their separate release-only ABI5 profile"
#endif
#define LI2_LRR_VERSION 5U
#define LI2_LRR_BYTES 1696U
/* Selection kind: 0 no resident head, 1 exact root, 2 internal head.
   Outcomes: warm plan, refused cold plan, built cold plan, warm bind,
   empty-slot publication, replacement publication, cancellation, completion.
   Each cell is independent. A killed prefix is not a transaction snapshot. */
struct li2_lrr_counts {
    uint64_t error,attempts,finished,in_flight,root_hits,subentry_hits,reserved[2];
    uint64_t selection[3][3][2];
    uint64_t seen[10],passed[10],first_failure[3][10],outcome[3][8];
};
struct li2_lrr_record { struct li2_plec_record base;struct li2_lrr_counts reasons; };
_Static_assert(sizeof(struct li2_lrr_counts)==800 &&
    offsetof(struct li2_lrr_record,reasons)==896 && sizeof(struct li2_lrr_record)==LI2_LRR_BYTES &&
    LI2_LRR_BYTES<LI2_PGC_PAGE,"distinct ABI5 preserves the complete ABI4 structural prefix");
_Static_assert(offsetof(struct li2_lrr_counts,selection)==64 &&
    offsetof(struct li2_lrr_counts,seen)==208 && offsetof(struct li2_lrr_counts,passed)==288 &&
    offsetof(struct li2_lrr_counts,first_failure)==368 && offsetof(struct li2_lrr_counts,outcome)==608,
    "exact reason-bank offsets");
#endif
