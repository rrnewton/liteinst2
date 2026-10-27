#ifndef LI2_PRIVATE_CODE_QUERY_H
#define LI2_PRIVATE_CODE_QUERY_H
#include "lifecycle_loader.h"
/* This inspects actual private anonymous VMAs, not application code ownership.
   It deliberately cannot infer anonymous alias identity from inode zero. The
   exclusive allocator plus the protected, closed mutation surface supplies
   that separate provenance. No admission, allocation or permission changes.
   Each call requires a distinct zero-initialized retained output. */
struct li2_private_code_query {
    uintptr_t first,end,first_vma,last_vma_end;
    size_t pages_checked;
    unsigned attempted,complete;
    int expected_prot,actual_prot,result;
    long detail;
    struct li2_fetch_map_progress maps;
};
int li2_lifecycle_private_code_query(uintptr_t,size_t,int,
                                     struct li2_private_code_query *);
#endif
