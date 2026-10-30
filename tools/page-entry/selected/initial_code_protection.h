#ifndef LI2_INITIAL_CODE_PROTECTION_H
#define LI2_INITIAL_CODE_PROTECTION_H
#include "lifecycle_loader.h"
#include <sys/mman.h>
#if !defined(LI2_INITIAL_CODE_PROTECTION) || LI2_INITIAL_CODE_PROTECTION != 1
#error "initial code protection requires the explicit value 1"
#endif
/* Pure range decision only. The caller owns complete arrays of count entries;
   the runtime supplies its bounded, append-only private table. Zero/other kind
   is strict, exact 1 is initial code. No rseq, live-owner, source, permission
   transaction or execution authority is supplied by this predicate. */
static inline int li2_initial_code_protection_intersects(
    const struct li2_fork_range *ranges,const unsigned char *kinds,size_t count,
    uintptr_t first,size_t bytes,unsigned prot) {
    if (!bytes || first>UINTPTR_MAX-bytes) return 1;
    unsigned initial=0;
    for(size_t i=0;i<count;i++) {
        if(first>=ranges[i].end || ranges[i].first>=first+bytes) continue;
        if(kinds[i]!=1) return 1; /* Any strict overlap wins. */
        initial=1;
    }
    if(initial && prot!=PROT_READ && prot!=(PROT_READ|PROT_EXEC)) return 1;
    return 0;
}
#endif
