/* Included last in the actual lifecycle TU. No RAW, decoder, callback or mutation. */
#include "current_tf_observe.h"
void li2_current_tf_storage(struct li2_cto_storage out[9]) {
#define STORAGE(i,name) out[i]=(struct li2_cto_storage){(uintptr_t)&name,sizeof name,__alignof__(name)}
    STORAGE(0,maps_current);STORAGE(1,mct_physical_receipt);STORAGE(2,mct_physical_id);
    STORAGE(3,rx_current);STORAGE(4,rx_current_busy);STORAGE(5,cc);
    STORAGE(6,cc_candidate);STORAGE(7,cc_serial);STORAGE(8,cc_stats);
#undef STORAGE
}
void li2_current_tf_view_state(struct li2_cto_view_state *out) {
    out->stack_anchor=mv_stack_anchor;out->stack_first=mv_stack_first;out->stack_end=mv_stack_end;
    out->stack_retired=mv_stack_retired;out->stack_pending=mv_stack_pending;
    li2_maps_view_snapshot(&out->view);
}
