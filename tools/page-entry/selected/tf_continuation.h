#ifndef LI2_TF_CONTINUATION_H
#define LI2_TF_CONTINUATION_H
#include "lifecycle_loader.h"
struct li2_tf_continuation {
    uintptr_t pc;
    unsigned attempted,page_observed,complete;
    int result;
    struct li2_fetch_map_progress maps;
    struct li2_fetch_page page;
    struct li2_fetch_backing backing;
};
/* Fresh retained output; no bytes are fetched, no borrow or permission changes.
   The original source borrow remains held and must already be back at R/NX. */
int li2_lifecycle_tf_continuation(const struct li2_fetch_ref *,uintptr_t,
                                 struct li2_tf_continuation *);
#endif
