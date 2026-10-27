#ifndef LI2_STEP_FIXTURE_H
#define LI2_STEP_FIXTURE_H
#define LI2_LIVE_FLAGS 128
#define LI2_LIVE_SELECTORS 136
#define LI2_LIVE_STARTED 152
#define LI2_LIVE_COMPLETE 160
#ifndef __ASSEMBLER__
#include <stddef.h>
#include <stdint.h>
struct li2_live_capture {
    uint64_t gpr[16],rflags;
    uint16_t selectors[6]; /* actual CS,SS,DS,ES,FS,GS, in this order */
    uint32_t reserved;
    uint64_t started,complete;
};
_Static_assert(offsetof(struct li2_live_capture,rflags)==LI2_LIVE_FLAGS,"live flags offset");
_Static_assert(offsetof(struct li2_live_capture,selectors)==LI2_LIVE_SELECTORS,"live selectors offset");
_Static_assert(offsetof(struct li2_live_capture,started)==LI2_LIVE_STARTED,"live prefix offset");
_Static_assert(offsetof(struct li2_live_capture,complete)==LI2_LIVE_COMPLETE,"live completion offset");
_Static_assert(sizeof(struct li2_live_capture)==168,"live observation extent");
extern struct li2_live_capture fixture_live_before,fixture_live_after;
extern uintptr_t fixture_target;
extern uint64_t fixture_flags,fixture_xcr0;
void fixture_enter(void);
void fixture_return(void);
void fixture_capture_return(void);
void fixture_vector_clobber(void);
#endif
#endif
