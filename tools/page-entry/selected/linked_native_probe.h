#ifndef LI2_LINKED_NATIVE_PROBE_H
#define LI2_LINKED_NATIVE_PROBE_H
#if !defined(LI2_LINKED_NATIVE_PROBE) || LI2_LINKED_NATIVE_PROBE != 1 || \
    !defined(LI2_LINKED_EPOCH) || LI2_LINKED_EPOCH != 1 || \
    !defined(LI2_NATIVE_PAIR) || LI2_NATIVE_PAIR != 1 || defined(LI2_LINKED_NATIVE_HINT)
#error "cold native probe requires its distinct linked/native-pair profile"
#endif
#include "native_pair.h"
#include "span_source.h"
/* Descriptive protected counters, not native publication or execution
   permission. The full page policy result only selects a genuine NX retry;
   that real native owner still checks the whole page, both executable halos,
   backing, aliases, rseq, identity and permissions independently. */
struct li2_link_native_probe_progress {
    unsigned pending,outcome_complete;
    int outcome_result;
    unsigned reserved;
    uint64_t lookups,current_declines,negative_hits,policy_checks,policy_blocked;
    uint64_t chosen,refaults,next_nx,admitted,refused,errors;
    uint64_t selected_record,selected_generation,selected_serial;
    uint64_t selected_event,selected_seeds,selected_published;
    uintptr_t selected_pc;
};
/* Pure with respect to permission/source/custody: no RAW, guest source read,
   decoder call or native API. The current, released full-page snapshot is
   mandatory. Only a prior actual clean native refusal suppresses a lifetime;
   successful native admission leaves a later probe eligible. */
int li2_lifecycle_link_native_probe_choose(const struct li2_span_source *,uint64_t);
/* Called only after the unchanged real TRACE refault operation and all its
   whole-frame/borrow/phase checks have succeeded. */
int li2_lifecycle_link_native_probe_refault(uint64_t);
/* Immediately follows the actual native-pair NX API. No supplied description
   can substitute for that owner's event/frame/publication observations. */
int li2_lifecycle_link_native_probe_outcome(int);
const struct li2_link_native_probe_progress *li2_lifecycle_link_native_probe_progress(void);
#endif
