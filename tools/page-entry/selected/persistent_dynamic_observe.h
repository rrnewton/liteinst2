#ifndef LI2_PERSISTENT_DYNAMIC_OBSERVE_H
#define LI2_PERSISTENT_DYNAMIC_OBSERVE_H
#if LI2_PERSISTENT_DYNAMIC_CAPTURE != 1 || LI2_PERSISTENT_DYNAMIC != 1 || LI2_PERSISTENT_EPOCH != 1 || defined(LI2_PERSISTENT_EPOCH_CAPTURE)
#error "distinct dynamic finite capture only"
#endif
static void pdo_initialize(void);
static void pdo_ingress(int,siginfo_t *,ucontext_t *);
static void pdo_begin(int,siginfo_t *,ucontext_t *);
static void pdo_closed(void);
static void pdo_miss_held(void);
static void pdo_entered(int,siginfo_t *,ucontext_t *);
static void pdo_cancelled(int,siginfo_t *,ucontext_t *,enum li2_chain_result);
static void pdo_terminal(unsigned);
static void pdo_finish(unsigned,unsigned,long);
#endif
