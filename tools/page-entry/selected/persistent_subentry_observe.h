#ifndef LI2_PERSISTENT_SUBENTRY_OBSERVE_H
#define LI2_PERSISTENT_SUBENTRY_OBSERVE_H
#if LI2_PERSISTENT_SUBENTRY_CAPTURE != 1 || LI2_PERSISTENT_UNREGISTERED != 1 || LI2_PERSISTENT_SUBENTRY != 1 || defined(LI2_PERSISTENT_ACTIVE_DOMAIN_CAPTURE) || defined(LI2_PERSISTENT_STARTUP_CAPTURE) || LI2_PERSISTENT_ACTIVE_DOMAIN != 1 || LI2_RSEQ_CURRENT_DATA != 1 || LI2_PERSISTENT_RETAINED_TWO != 1 || LI2_PERSISTENT_DISPATCH != 1 || LI2_PERSISTENT_GROUP != 1 || LI2_PERSISTENT_EPOCH != 1 || defined(LI2_PERSISTENT_RETAINED_TWO_CAPTURE) || defined(LI2_PERSISTENT_RESIDENT_CAPTURE) || defined(LI2_PERSISTENT_GROUP_CAPTURE) || defined(LI2_PERSISTENT_GROUP_COUNTERS) || defined(LI2_PERSISTENT_EPOCH_CAPTURE) || defined(LI2_PERSISTENT_DYNAMIC_CAPTURE) || defined(LI2_PERSISTENT_DYNAMIC)
#error "distinct active-domain capture with maintained rseq evidence only"
#endif
static void pso_initialize(void);
static void pso_ingress(int,siginfo_t *,ucontext_t *);
static void pso_begin(int,siginfo_t *,ucontext_t *,unsigned);
static void pso_closed(void);
static void pso_entered(int,siginfo_t *,ucontext_t *);
static void pso_terminal(unsigned);
static void pso_finish(unsigned,unsigned,long);
void li2_pso_trace_closed(const struct li2_tf_chain *,const struct li2_tf_chain_slot *);
#endif
