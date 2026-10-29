#ifndef LI2_TF_INTERVAL_RECORD_H
#define LI2_TF_INTERVAL_RECORD_H
#include "../rseq_native/record.h"
#define TFI_MAGIC UINT64_C(0x314c415652495446)
#define TFI_WAIT RN_BODY
#define TFI_READ (TFI_WAIT+4094)
#define TFI_BODY RN_TAIL
#define TFI_MAX_EVENTS 256U
#define TFI_R8 UINT64_C(0x1122334455667708)
#define TFI_GO_BYTE (RN_DATA+56)
/* Native has only the two genuine BODY/GUARD NX frames. Its read return is
   evidenced by BODY; there is no invented native syscall-ingress ucontext. */
struct tfi_endpoint { uint64_t h[32];struct rn_frame before,after; };
struct tfi_native_record {
 uint64_t h[64],xstate[4][4];struct tfi_endpoint endpoints[2];
};
/* Compact TRACE deliberately omits FP payload. Full initialized FP is kept
   in genuine endpoint/opening records; fp_bytes here describes extent only. */
struct tfi_trace_frame {
 uint64_t h[16],greg[23],mask;
 unsigned char siginfo[128];
};
#endif
