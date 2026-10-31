#ifndef LI2_PERSISTENT_COLD_ADMISSION_OBSERVE_H
#define LI2_PERSISTENT_COLD_ADMISSION_OBSERVE_H
#if LI2_PERSISTENT_COLD_ADMISSION_CAPTURE != 1 || LI2_PERSISTENT_DIRECT_FRONTIER != 1 || defined(LI2_PERSISTENT_DIRECT_FRONTIER_CAPTURE) || defined(LI2_PERSISTENT_CROSS_PAIR_CAPTURE) || LI2_PERSISTENT_CROSS_PAIR != 1 || defined(LI2_PERSISTENT_SUBENTRY_CAPTURE) || defined(LI2_PERSISTENT_RETAINED_EIGHT) || LI2_PERSISTENT_UNREGISTERED != 1 || LI2_PERSISTENT_SUBENTRY != 1 || defined(LI2_PERSISTENT_ACTIVE_DOMAIN_CAPTURE) || defined(LI2_PERSISTENT_STARTUP_CAPTURE) || LI2_PERSISTENT_ACTIVE_DOMAIN != 1 || LI2_RSEQ_CURRENT_DATA != 1 || LI2_PERSISTENT_RETAINED_TWO != 1 || LI2_PERSISTENT_DISPATCH != 1 || LI2_PERSISTENT_GROUP != 1 || LI2_PERSISTENT_EPOCH != 1 || defined(LI2_PERSISTENT_RETAINED_TWO_CAPTURE) || defined(LI2_PERSISTENT_RESIDENT_CAPTURE) || defined(LI2_PERSISTENT_GROUP_CAPTURE) || defined(LI2_PERSISTENT_GROUP_COUNTERS) || defined(LI2_PERSISTENT_EPOCH_CAPTURE) || defined(LI2_PERSISTENT_DYNAMIC_CAPTURE) || defined(LI2_PERSISTENT_DYNAMIC)
#error "distinct direct-frontier capture with exact lifetime and lossless evidence"
#endif
static void pco_initialize(void);
static void pco_ingress(int,siginfo_t *,ucontext_t *);
static void pco_begin(int,siginfo_t *,ucontext_t *,unsigned);
static void pco_closed(void);
static void pco_entered(int,siginfo_t *,ucontext_t *);
static void pco_terminal(unsigned);
static void pco_finish(unsigned,unsigned,long);
void li2_pco_trace_closed(const struct li2_tf_chain *,const struct li2_tf_chain_slot *);
#endif
