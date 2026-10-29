#ifndef LI2_NATIVE_PAIR_FIXTURE_RECORD_H
#define LI2_NATIVE_PAIR_FIXTURE_RECORD_H
#include <stdint.h>
#define RN_MAIN UINT64_C(0x200401000)
#define RN_HELPER (RN_MAIN+4096)
#define RN_BODY (RN_MAIN+8192)
#define RN_TAIL (RN_MAIN+12288)
#define RN_GUARD (RN_MAIN+16384)
#define RN_REFERENCE (RN_MAIN+20480)
/* Two complete pages are reserved for the actual native observer. */
#define RN_DATA (RN_MAIN+28672)
#define RN_SOURCE_BYTES 28672U
#define RN_DATA_BYTES 16384U
#define RN_ARENA UINT64_C(0x300000000)
#define RN_PAGE (RN_ARENA+4096)
#define RN_AREA (RN_PAGE+64)
#define RN_WORD (RN_AREA+8)
#define RN_DESCRIPTOR (RN_DATA+256)
#define RN_UC 2048U
#define RN_FP 65536U
#define RN_MAGIC UINT64_C(0x31524941504e534c)
#define NPF_ROWS 12U
#define NPF_STAGES 24U
#define NPF_CALLS 32U
#define NPF_LEDGER (RN_DATA+12288)
#define NPF_START_GATE (RN_MAIN+3072)
#define NPF_CLOSE_GATE (RN_MAIN+3104)
/* Same complete field protocol as rseq_native/rn_frame. Source extent is
   explicitly seven pages; no raw UC, initialized FP, source or memory byte
   is omitted. DWARF owns actual structure offsets, never guessed packing. */
struct rn_frame {
    uint64_t h[64];
    unsigned char uc[RN_UC],fp[RN_FP];
    unsigned char source[RN_SOURCE_BYTES],data[RN_DATA_BYTES],rseq[4096];
};
struct npf_native_row {
    uint64_t h[32];
    /* Up to four actual mprotect calls: page,length,protection,result. */
    uint64_t permissions[4][4];
    unsigned char signal_before[128],signal_after[128];
    struct rn_frame before,after;
};
struct npf_native_record {
    uint64_t h[64],xstate[4][4];
    struct npf_native_row rows[NPF_ROWS];
};
#endif
