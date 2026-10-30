#ifndef LI2_CURRENT_TF_OBSERVE_H
#define LI2_CURRENT_TF_OBSERVE_H
/* Diagnostic-only, distinct from the component's supplied owner boundary. */
#include "tf_chain.h"
#include "fetch_current_custody.h"
#include "maps_view.h"
#if LI2_CURRENT_TF_CAPTURE != 1 || LI2_MAPS_CURRENT_TF != 1 || \
    LI2_UNROLLED_HASH_CAPTURE != 1 || defined(LI2_SCALAR_REGION)
#error "current TF capture requires its distinct complete unrolled profile"
#endif
enum { LI2_CTO_ATTEMPT=1,LI2_CTO_STAGE,LI2_CTO_COMMIT,LI2_CTO_PUBLISH,
       LI2_CTO_CANCEL,LI2_CTO_RETURN_BEFORE,LI2_CTO_RETURN_AFTER,LI2_CTO_POINTS=7 };
struct li2_cto_storage { uintptr_t address; size_t bytes,alignment; };
struct li2_cto_view_state {
    uint64_t stack_anchor,stack_first,stack_end;
    unsigned stack_retired,stack_pending;
    struct li2_maps_view_stats view;
};
/* Copy-only actual objects; neither helper validates or grants authority. */
void li2_current_tf_storage(struct li2_cto_storage [9]);
void li2_current_tf_view_state(struct li2_cto_view_state *);
void li2_current_tf_observe(unsigned,int,unsigned,const struct li2_tf_chain *,
                            const struct li2_fetch_ref *,const struct li2_fetch_rx_view *);
#endif
