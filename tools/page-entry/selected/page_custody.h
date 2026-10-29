#ifndef LI2_PAGE_CUSTODY_H
#define LI2_PAGE_CUSTODY_H
#include <stdint.h>
#if LI2_TF_SEALED_CUSTODY != 1 || !defined(LI2_TF_SAME_PAGE_LEASE) || \
    !defined(LI2_MAPS_PHASE_REUSE) || !defined(LI2_RSEQ_INACTIVE)
#error "sealed page custody requires the fixed same-page lease profile"
#endif
/* Separate from maps validity: normal event/return maps invalidation remains
   unconditional. No API here publishes rows or grants execution permission. */
enum li2_custody_phase { LI2_CUSTODY_EMPTY, LI2_CUSTODY_READY,
    LI2_CUSTODY_ENTRY, LI2_CUSTODY_BUILDING, LI2_CUSTODY_STAGED,
    LI2_CUSTODY_COMMITTED, LI2_CUSTODY_RETURN, LI2_CUSTODY_POISONED };
enum li2_custody_reason { LI2_CUSTODY_EFFECT=1, LI2_CUSTODY_ERROR,
    LI2_CUSTODY_EVENT, LI2_CUSTODY_SYSCALL, LI2_CUSTODY_SLOT,
    LI2_CUSTODY_RELEASE, LI2_CUSTODY_MISS };
struct li2_page_custody_stats {
    uint64_t epoch,seeds,retained_stages,retained_checks,commits,discards;
    unsigned phase,last_reason;
};
void li2_page_custody_discard(unsigned);
void li2_page_custody_boundary(void);
int li2_page_custody_return(const void *chain);
const struct li2_page_custody_stats *li2_page_custody_snapshot(void);
#endif
