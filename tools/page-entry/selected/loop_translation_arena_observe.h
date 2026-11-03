#ifndef LI2_LOOP_TRANSLATION_ARENA_OBSERVE_H
#define LI2_LOOP_TRANSLATION_ARENA_OBSERVE_H
#if !defined(LI2_LOOP_TRANSLATION_ARENA) || LI2_LOOP_TRANSLATION_ARENA != 1 || \
    !defined(LI2_LOOP_TRANSLATION_ARENA_OBSERVE) || LI2_LOOP_TRANSLATION_ARENA_OBSERVE != 1 || \
    !defined(LI2_LOOP_CACHE8_OBSERVE) || LI2_LOOP_CACHE8_OBSERVE != 1 || \
    !defined(LI2_PG_LOOP_TRANSLATION_ARENA_OBSERVE_BINDING_VERSION) || LI2_PG_LOOP_TRANSLATION_ARENA_OBSERVE_BINDING_VERSION != 1 || \
    !defined(LI2_LOOP_CACHE8_CONTROL) || LI2_LOOP_CACHE8_CONTROL < 0 || LI2_LOOP_CACHE8_CONTROL > 2
#error "exact separate arena native observation binding required"
#endif
static void ltao_reentry(uintptr_t,int,const siginfo_t *,const ucontext_t *);
#endif
