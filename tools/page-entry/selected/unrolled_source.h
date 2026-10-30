#ifndef LI2_UNROLLED_SOURCE_H
#define LI2_UNROLLED_SOURCE_H
#include "lifecycle_loader.h"
#include "unrolled_hash.h"
/* Extension of the caller's actual held fetch15 borrow, restricted to the same
   authenticated SEALED source page. No new entry or execution permission. */
struct li2_unrolled_source {
    unsigned ready;
    struct li2_fetch_ref borrow;
    uintptr_t pc;
    struct li2_fetch_page page;
    struct li2_fetch_backing backing;
    unsigned char bytes[LI2_UNROLLED_HASH_SOURCE];
};
/* 0+ready0 is a pre-I/O geometry/backing miss; nonzero is a terminal failure.
   The genuine original fetch borrow remains held on every return. */
int li2_lifecycle_unrolled_source(const struct li2_fetch_ref *,struct li2_unrolled_source *);
int li2_lifecycle_unrolled_validate(const struct li2_fetch_ref *,const struct li2_unrolled_source *);
#endif
