#ifndef LI2_RSEQ_NATIVE_BOUNDARY_RECORD_H
#define LI2_RSEQ_NATIVE_BOUNDARY_RECORD_H
/* The old complete frame format and fixed address/data domains stay exact. */
#include "../rseq_native/record.h"
#define RNB_MAGIC UINT64_C(0x31444e424e535252)
#define RNB_ROWS 4U
struct rnb_native_row {
 uint64_t h[32];
 struct rn_frame before,after;
};
struct rnb_native_record {
 uint64_t h[64],xstate[4][4];
 struct rnb_native_row rows[RNB_ROWS];
};
#endif
