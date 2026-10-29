#ifndef LI2_TF_LEASE_ORACLE_RECORD_H
#define LI2_TF_LEASE_ORACLE_RECORD_H
#include "../rseq_native/record.h"
#define LSO_MAGIC UINT64_C(0x31455341454c4654)
#define LSO_ROWS 12U
struct lso_native_row { uint64_t h[32];struct rn_frame before,after; };
struct lso_native_record { uint64_t h[64],xstate[4][4];struct lso_native_row rows[2]; };
#endif
