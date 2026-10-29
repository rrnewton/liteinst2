#ifndef LI2_PAGE_CUSTODY_STACK_RECORD_H
#define LI2_PAGE_CUSTODY_STACK_RECORD_H
#include "../rseq_native/record.h"
#define PCS_MAGIC UINT64_C(0x314b545359445443)
#define PCS_MAP_BYTES 65536U
#define PCS_READS 17U
/* Complete bounded kernel output; all unused bytes/words remain zero. */
struct pcs_maps {
    uint64_t h[16];
    int64_t reads[PCS_READS];
    unsigned char raw[PCS_MAP_BYTES];
};
struct pcs_stack_proof {
    uint64_t h[32],limit[2];
    struct pcs_maps before,after;
    unsigned char adjacent_before[4096],adjacent_after[4096],grown[4096];
    unsigned char code_before[4096],code_after[4096];
};
struct pcs_native_row { uint64_t h[32];struct rn_frame before,after; };
struct pcs_native_record { uint64_t h[64],xstate[4][4];struct pcs_native_row rows[4]; };
extern struct pcs_stack_proof pcs_stack;
extern unsigned char pcs_setup_stack[16384];
extern uint64_t rn_entry_rsp,rn_stack_target,rn_query_result,rn_setup_pid;
long pcs_stack_setup(void);
long pcs_stack_finish(void);
long pcs_stack_write(void);
#endif
