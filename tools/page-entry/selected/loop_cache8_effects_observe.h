#ifndef LI2_LOOP_CACHE8_EFFECTS_OBSERVE_H
#define LI2_LOOP_CACHE8_EFFECTS_OBSERVE_H
#include "persistent_group_config.h"
#include "loop_cache8_effects_memory.h"
#if LI2_LOOP_CACHE8_EFFECTS != 1 || LI2_LOOP_CACHE8_OBSERVE != 1 || \
    (LI2_LOOP_CACHE8_CONTROL != 2 && LI2_LOOP_CACHE8_CONTROL != 3 && LI2_LOOP_CACHE8_CONTROL != 4) || \
    LI2_PG_LOOP_CACHE8_EFFECTS_BINDING_VERSION != 1
#error "exact independently bound CACHE8 real guest effect subject required"
#endif
struct pda_completion;
static int lc8e_initialize(void);
static void lc8e_completed_first(const struct pda_completion *);
static void lc8e_unsafe(unsigned);
static void lc8e_syscall_before(long,const long [6],const ucontext_t *);
static void lc8e_syscall_after(long,const long [6],long,const ucontext_t *);
static void lc8e_bound(void);
static void lc8e_enter(void);
static void lc8e_preentry(int,const siginfo_t *,const ucontext_t *);
static void lc8e_completed(const struct pda_completion *);
static void lc8e_report(unsigned,unsigned);
#endif
