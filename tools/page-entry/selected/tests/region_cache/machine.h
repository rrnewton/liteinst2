#ifndef REGION_MACHINE_H
#define REGION_MACHINE_H
#define REGION_FP 65536
#define REGION_LIVE_FLAGS 128
#define REGION_LIVE_SELECTORS 136
#define REGION_LIVE_BYTES 152
#ifndef __ASSEMBLER__
#include <stdint.h>
struct region_live { uint64_t gpr[16],flags; uint16_t selectors[6]; uint32_t reserved; };
_Static_assert(sizeof(struct region_live)==REGION_LIVE_BYTES,"complete live wire");
extern uint64_t region_seed[16],region_input_flags,region_xcr0,region_target;
extern struct region_live region_before,region_after;
extern unsigned char region_fp_before[REGION_FP],region_fp_after[REGION_FP];
void region_enter(void);
void region_capture(void);
void region_restorer(void);
#endif
#endif
