#ifndef LI2_LINKED_NATIVE_HINT_H
#define LI2_LINKED_NATIVE_HINT_H
#if !defined(LI2_LINKED_NATIVE_HINT) || LI2_LINKED_NATIVE_HINT != 1 || \
    !defined(LI2_LINKED_EPOCH) || LI2_LINKED_EPOCH != 1 || \
    !defined(LI2_NATIVE_PAIR) || LI2_NATIVE_PAIR != 1
#error "native hint requires its distinct literal linked/native-pair profile"
#endif
#include "native_pair.h"
#include "span_source.h"
/* A descriptive identity, never permission or a retained borrow. Neighbor
   absence is additionally bound to the exact lifecycle generation epoch. */
struct li2_link_native_hint_identity {
    uintptr_t address;
    uint64_t allocation,generation,offset,initial_extent;
    unsigned backing,object,logical;
};
/* One positive receipt, deliberately evictable. Its whole policy window was
   actually checked by the unchanged native owner. Every hit consumes it;
   only another successful native publication can make it ready again. */
struct li2_link_native_hint_progress {
    unsigned ready,pending,outcome_complete;
    int outcome_result;
    uint64_t publications,evictions,lookups,hits,invalidations;
    uint64_t next_nx,admitted,refused,errors;
    uint64_t receipt_sequence,receipt_publication,allocation_epoch,generation_epoch;
    size_t records_epoch;
    struct li2_native_pair_slot receipt;
    struct li2_link_native_hint_identity identity[3]; /* page, left, right */
    unsigned neighbors[2];
    uint64_t selected_publication,selected_serial,selected_event,selected_seeds,selected_published;
    uintptr_t selected_pc;
};
/* Pure with respect to execution authority: no RAW, source read, decode,
   permission change, or native API call. The exact current released fetch
   and fresh immutable source snapshot are required. Updates only advisory
   counters/one-use bookkeeping. 0 means no selection; 1 selects real NX. */
int li2_lifecycle_link_native_hint_choose(const struct li2_span_source *,uint64_t,uint64_t *);
/* Called immediately after the ACTUAL native-pair NX API returns, before any
   successor. Its real result and actual owner/lifecycle deltas distinguish
   admission, clean refusal and fatal prefix; the hint cannot claim success. */
int li2_lifecycle_link_native_hint_outcome(int);
const struct li2_link_native_hint_progress *li2_lifecycle_link_native_hint_progress(void);
#if defined(LI2_LINKED_EPOCH_CAPTURE) && !defined(LI2_LINKED_EPOCH_REUSE_CAPTURE)
/* Deliberate actual advisory-receipt corruption, never a runtime selector.
   attempted0 leaves state untouched; attempted1 requires terminal caller. */
int li2_lifecycle_link_native_hint_probe(const struct li2_span_source *,uint64_t,unsigned,
    unsigned *,size_t *,uint64_t *,struct li2_link_native_hint_progress *,
    struct li2_link_native_hint_progress *,struct li2_link_native_hint_progress *);
#endif
#endif
