#ifndef LI2_SPAN_FETCH_H
#define LI2_SPAN_FETCH_H
#include "lifecycle_loader.h"

/* Actual protected singleton observation, including its identity after release.
   Copying this object grants no source, release, TRACE or execution authority.
   No caller-supplied ref/held/released assertion is accepted by this getter. */
struct li2_span_fetch_observation {
    unsigned complete;
    struct li2_fetch_ref ref;
    struct li2_fetch_progress progress;
    uintptr_t pc;
    size_t length,page_count;
    long pid,tid;
    unsigned char bytes[15];
    struct li2_fetch_page pages[2];
    struct li2_fetch_backing backing[2],last_backing;
};
/* Caller supplies complete aligned disjoint zero output storage. Pure:
   authenticate the current complete error-free singleton and its actual
   lifecycle epochs, then copy bounded bytes. Works held or genuinely released;
   after release this is diagnostic state, never a live source ticket. */
int li2_lifecycle_span_fetch_snapshot(struct li2_span_fetch_observation *);
#endif
