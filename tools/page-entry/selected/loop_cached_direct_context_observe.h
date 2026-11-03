#ifndef LI2_LOOP_CACHED_DIRECT_CONTEXT_OBSERVE_H
#define LI2_LOOP_CACHED_DIRECT_CONTEXT_OBSERVE_H
#include "loop_cached_direct_context.h"
#if !defined(LI2_LOOP_CACHED_DIRECT_CONTEXT_OBSERVE) || LI2_LOOP_CACHED_DIRECT_CONTEXT_OBSERVE != 1 || \
    !defined(LI2_PG_LOOP_CACHED_DIRECT_CONTEXT_OBSERVE_BINDING_VERSION) || \
    LI2_PG_LOOP_CACHED_DIRECT_CONTEXT_OBSERVE_BINDING_VERSION != 1
#error "cached DIRECT observation requires its own complete binding"
#endif
#if defined(LI2_LOOP_CACHE8_OBSERVE) || defined(LI2_LOOP_TRANSLATION_ARENA_OBSERVE) || \
    defined(LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE)
#error "cached DIRECT and previous observer wires are distinct"
#endif
struct pda_completion;
static int lcxo_initialize(void);
static void lcxo_bound(void);
static void lcxo_enter(void);
static void lcxo_preentry(int,const siginfo_t *,const ucontext_t *);
static void lcxo_complete(const struct pda_completion *);
static void lcxo_report(unsigned,unsigned);
#endif
