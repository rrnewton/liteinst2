#ifndef LI2_EFFECT_B2_RECORD_H
#define LI2_EFFECT_B2_RECORD_H
#include "be_policy.h"
#include "b2_capture.h"
/* Real signal snapshots; before.h[4:6] are zero and h[15]=1 because its
   held-interval capture performs no base query. Entry/after use the original
   b2_capture and actual ARCH_GET_FS/GS. No earlier value is presented as a
   current query. Every byte remains private in the emitted record. */
struct be_row {
    uint64_t h[32],backend[32],publication[32];
    struct b2_snapshot entry,before,after;
    struct li2_effect_owner owner;
    struct li2_effect_state applied;
    struct li2_selected_completion random;
    struct selected_builtin_prefix builtin;
    struct li2_oneshot_plan plan;
};
struct be_record {
    uint64_t h[32],bases[32][5];
    struct li2_selected_hardware hardware;
    struct be_row rows[4];
    struct b2_snapshot final;
};
_Static_assert(sizeof(struct be_record)<(2U<<20),"bounded complete actual all-class record");
#endif
