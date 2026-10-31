#ifndef LI2_PERSISTENT_GROUP_OBSERVE_H
#define LI2_PERSISTENT_GROUP_OBSERVE_H
#if LI2_PERSISTENT_GROUP_CAPTURE != 1 || LI2_PERSISTENT_GROUP != 1 || LI2_PERSISTENT_EPOCH != 1 || defined(LI2_PERSISTENT_EPOCH_CAPTURE) || defined(LI2_PERSISTENT_DYNAMIC_CAPTURE) || defined(LI2_PERSISTENT_DYNAMIC)
#error "distinct loop-only group capture only"
#endif
static void pgo_initialize(void);
static void pgo_ingress(int,siginfo_t *,ucontext_t *);
static void pgo_begin(int,siginfo_t *,ucontext_t *);
static void pgo_closed(void);
static void pgo_miss_held(void);
static void pgo_entered(int,siginfo_t *,ucontext_t *);
static void pgo_cancelled(int,siginfo_t *,ucontext_t *,enum li2_chain_result);
static void pgo_terminal(unsigned);
static void pgo_finish(unsigned,unsigned,long);
#endif
