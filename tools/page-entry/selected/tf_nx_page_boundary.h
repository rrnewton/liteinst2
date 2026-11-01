#ifndef LI2_TF_NX_PAGE_BOUNDARY_H
#define LI2_TF_NX_PAGE_BOUNDARY_H
#include "tf_chain.h"
#if !defined(LI2_TF_NX_PAGE_BOUNDARY) || LI2_TF_NX_PAGE_BOUNDARY != 1
#error "the NX page-boundary policy requires LI2_TF_NX_PAGE_BOUNDARY=1"
#endif

/* Descriptive only. The caller must already have closed the real predecessor,
   released its fetch and classified the actual successor. A fetch's lookahead
   pages are not the pages opened by its step request. No pointer, permission,
   signal frame or execution authority is created or changed here.
   -1 refuses malformed eligible requests; otherwise return the exact reason. */
static inline int li2_tf_nx_page_boundary(const struct li2_step_request *previous,
                                         uintptr_t next_pc,int fallback) {
    if(fallback!=LI2_CHAIN_NO_FALLBACK && fallback!=LI2_CHAIN_OLD_STEP)return fallback;
    if(!previous || !previous->page_count || previous->page_count>2)return -1;
    uintptr_t page=next_pc&~(uintptr_t)(LI2_STEP_PAGE-1);
    for(size_t i=0;i<previous->page_count;i++)
        if(previous->pages[i].address&(LI2_STEP_PAGE-1))return -1;
    for(size_t i=0;i<previous->page_count;i++)
        if(previous->pages[i].address==page)return fallback;
    return LI2_CHAIN_PAGE_BOUNDARY;
}
#endif
