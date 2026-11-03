#ifndef LI2_LOOP_CACHE8_EFFECT_APP_H
#define LI2_LOOP_CACHE8_EFFECT_APP_H
#if !defined(LI2_LOOP_CACHE8_EFFECT) || (LI2_LOOP_CACHE8_EFFECT != 2 && LI2_LOOP_CACHE8_EFFECT != 3 && LI2_LOOP_CACHE8_EFFECT != 4)
#error "exact CACHE8 real effect subject 2, 3 or 4 required"
#endif
#define LC8E_STATE_ADDRESS 0x800000
#define LC8E_STATE_BYTES 256
#ifndef __ASSEMBLER__
/* Descriptive application state. No word is a runtime permission or owner. */
struct lc8e_app_tail { uint64_t h[32],state[32]; };
_Static_assert(sizeof(struct lc8e_app_tail)==512,"literal real-effect application tail");
extern volatile uint64_t lc8e_state[32];
extern unsigned char region_app_effect_end[],region_app_effect_syscall0[],region_app_effect_syscall1[];
extern unsigned char region_app_effect_write[],region_app_effect_load[],region_app_effect_jump[];
#endif
#endif
