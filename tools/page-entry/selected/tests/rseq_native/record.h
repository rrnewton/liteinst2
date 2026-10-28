#ifndef LI2_RSEQ_NATIVE_FIXTURE_RECORD_H
#define LI2_RSEQ_NATIVE_FIXTURE_RECORD_H
#include <stdint.h>
#define RN_MAIN UINT64_C(0x200401000)
#define RN_HELPER (RN_MAIN+4096)
#define RN_BODY (RN_MAIN+8192)
#define RN_TAIL (RN_MAIN+12288)
#define RN_GUARD (RN_MAIN+16384)
#define RN_REFERENCE (RN_MAIN+20480)
#define RN_DATA (RN_MAIN+24576)
#define RN_SOURCE_BYTES 24576U
#define RN_DATA_BYTES 16384U
#define RN_ARENA UINT64_C(0x300000000)
#define RN_PAGE (RN_ARENA+4096)
#define RN_AREA (RN_PAGE+64)
#define RN_WORD (RN_AREA+8)
#define RN_DESCRIPTOR (RN_DATA+256)
#define RN_UC 2048U
#define RN_FP 65536U
#define RN_MAX_ROWS 4U
#define RN_MAGIC UINT64_C(0x31464954414e5352)
/* All payload bytes are retained. Actual DWARF, not assumed C packing, owns
   the complete serialized layout. The 64-word row header is a fixed protocol. */
struct rn_frame {
    uint64_t h[64];
    unsigned char uc[RN_UC],fp[RN_FP];
    unsigned char source[RN_SOURCE_BYTES],data[RN_DATA_BYTES],rseq[4096];
};
struct rn_native_record {
    uint64_t h[64],xstate[4][4];
    struct rn_frame before,after;
};
#endif
