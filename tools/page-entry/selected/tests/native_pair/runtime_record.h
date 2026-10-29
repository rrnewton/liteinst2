#ifndef LI2_NATIVE_PAIR_RUNTIME_RECORD_H
#define LI2_NATIVE_PAIR_RUNTIME_RECORD_H
#include "native_pair_record.h"
#include "native_pair.h"
#include "native_pair_hooks.h"
/* h[] words and raw payloads are decoded by the full-record readers. All owner records
   are descriptive copies; no observation is passed back as authority. */
struct npf_row {
    uint64_t h[32],permits[4][12];
    unsigned char signal_before[128],signal_after[128];
    struct rn_frame before,after,guard_before,guard_after;
    struct li2_native_pair_progress pair_before,pair_after;
    struct li2_native_pair_lifecycle life_before,life_after;
    struct li2_rseq_pair_progress rseq_before,rseq_after;
    struct li2_rseq_state guard_state;
    struct li2_native_close close;
};
struct npf_stage {
    uint64_t h[16];
    struct li2_native_pair_lifecycle life;
    struct li2_rseq_pair_progress rseq;
    struct li2_native_close close;
};
struct npf_record {
    uint64_t h[64],xstate[4][4];
    struct li2_selected_hardware hardware;
    struct npf_row rows[NPF_ROWS];
    struct npf_stage stages[NPF_STAGES];
    /* Fixed control record: exact call arguments/results or old/new values,
       distinguished by case/control; zero is never a success sentinel. */
    uint64_t control[64];
    struct rn_frame publication_frame,terminal_frame,nested_outer_frame;
    unsigned char nested_outer_signal[128];
    struct li2_native_pair_progress terminal_pair;
    struct li2_native_pair_lifecycle terminal_life;
    struct li2_rseq_pair_progress terminal_rseq_pair;
    struct li2_rseq_state terminal_rseq;
    struct li2_native_close terminal_close;
    unsigned char terminal_source[RN_SOURCE_BYTES];
    unsigned char terminal_data[RN_DATA_BYTES],terminal_page[4096];
};
_Static_assert(sizeof(struct npf_record)<(16U<<20),"complete pair capture stays below original cap");
#endif
