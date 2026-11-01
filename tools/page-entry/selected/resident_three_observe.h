#ifndef LI2_RESIDENT_THREE_OBSERVE_H
#define LI2_RESIDENT_THREE_OBSERVE_H
#if LI2_RESIDENT_THREE_CAPTURE != 1 || LI2_RESIDENT_THREE != 1
#error "distinct typed three-resident observation only"
#endif
#include "resident_three_memory.h"
static void r3o_initialize(void);
static void r3o_ingress(int,siginfo_t *,ucontext_t *);
static void r3o_source_before_bind(void);
static void r3o_entered(const siginfo_t *,const ucontext_t *);
static void r3o_terminal(void);
static void r3o_finish(unsigned,unsigned,long);
struct li2_tf_chain;
struct li2_tf_chain_slot;
void li2_r3o_trace_closed(const struct li2_tf_chain *,const struct li2_tf_chain_slot *);
#endif
