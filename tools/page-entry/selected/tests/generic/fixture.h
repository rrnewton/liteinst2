#ifndef LI2_GENERIC_TF_FIXTURE_H
#define LI2_GENERIC_TF_FIXTURE_H
#define LIVE_FLAGS 128
#define LIVE_SELECTORS 136
#define LIVE_STARTED 152
#define LIVE_COMPLETE 160
#define FP_CAPACITY 65536
#define SUBJECT_BYTES 8192
#define DATA_BYTES 4096
#define PAIRS 20
#ifndef __ASSEMBLER__
#include <stddef.h>
#include <stdint.h>
struct live { uint64_t gpr[16],rflags; uint16_t selectors[6]; uint32_t reserved;
              uint64_t started,complete; };
_Static_assert(sizeof(struct live)==168,"live extent");
_Static_assert(offsetof(struct live,rflags)==LIVE_FLAGS &&
               offsetof(struct live,selectors)==LIVE_SELECTORS &&
               offsetof(struct live,started)==LIVE_STARTED &&
               offsetof(struct live,complete)==LIVE_COMPLETE,"live offsets");
extern uintptr_t fixture_target;
extern uint64_t fixture_seed[16],fixture_flags,fixture_input_flags,fixture_xcr0;
extern struct live fixture_live_before,fixture_live_after;
extern unsigned char fixture_fp_before[FP_CAPACITY],fixture_fp_after[FP_CAPACITY];
void fixture_enter(void);
void fixture_return(void);
void fixture_capture_return(void);
void fixture_vector_clobber(void);
#endif
#endif
