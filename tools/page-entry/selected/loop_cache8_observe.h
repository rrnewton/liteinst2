#ifndef LI2_LOOP_CACHE8_OBSERVE_H
#define LI2_LOOP_CACHE8_OBSERVE_H
#include "persistent_group_config.h"
#if defined(LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE) && defined(LI2_LOOP_CACHE8_EFFECTS)
#error "descriptor and real-effect observation profiles are distinct"
#endif
#ifdef LI2_LOOP_TRANSLATION_ARENA_OBSERVE
#include "loop_translation_arena_observe.h"
#else
#ifdef LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE
#if !defined(LI2_LOOP_CACHE8_OBSERVE) || LI2_LOOP_CACHE8_OBSERVE != 1 || \
    !defined(LI2_LOOP_CACHE8_CONTROL) || \
    (LI2_LOOP_CACHE8_CONTROL < 0 || LI2_LOOP_CACHE8_CONTROL > 6) || \
    !defined(LI2_PG_LOOP_CACHE8_OBSERVE_BINDING_VERSION) || LI2_PG_LOOP_CACHE8_OBSERVE_BINDING_VERSION != 1
#error "exact distinct CACHE8 ABC169 observer binding required"
#endif
#else
#if !defined(LI2_LOOP_CACHE8_OBSERVE) || LI2_LOOP_CACHE8_OBSERVE != 1 || \
    !defined(LI2_LOOP_CACHE8_CONTROL) || \
    (LI2_LOOP_CACHE8_CONTROL != 0 && LI2_LOOP_CACHE8_CONTROL != 1 && \
     (!defined(LI2_LOOP_CACHE8_EFFECTS) || LI2_LOOP_CACHE8_EFFECTS != 1 || \
      LI2_LOOP_CACHE8_CONTROL < 2 || LI2_LOOP_CACHE8_CONTROL > 4)) || \
    !defined(LI2_PG_LOOP_CACHE8_OBSERVE_BINDING_VERSION) || LI2_PG_LOOP_CACHE8_OBSERVE_BINDING_VERSION != 1
#error "exact distinct CACHE8 ABC169 observer binding required"
#endif
#endif
#endif
#if (LI2_LOOP_CACHE8_CONTROL == 1 || ((defined(LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE) || defined(LI2_LOOP_TRANSLATION_ARENA_OBSERVE)) && LI2_LOOP_CACHE8_CONTROL != 0)) && (!defined(LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL) || LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL != 1)
#error "actual restored CACHE8 controls require every-hit differential certificates"
#endif
struct pda_completion;
#ifdef LI2_LOOP_CACHE8_EFFECTS
#include "loop_cache8_effects_observe.h"
#endif
static int lc8o_initialize(void);
static void lc8o_bound(void);
static void lc8o_enter(void);
static void lc8o_preentry(int,const siginfo_t *,const ucontext_t *);
static void lc8o_complete(const struct pda_completion *);
static void lc8o_report(unsigned,unsigned);
#endif
