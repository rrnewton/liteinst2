#ifndef LI2_PERSISTENT_CALL_OWNER_OBSERVE_H
#define LI2_PERSISTENT_CALL_OWNER_OBSERVE_H
#if LI2_PERSISTENT_CALL_OWNER_CAPTURE != 1 || LI2_PERSISTENT_CALL_DISPATCH != 1 || \
    LI2_PERSISTENT_DIRECT_FRONTIER != 1 || LI2_PERSISTENT_CROSS_PAIR != 1 || \
    LI2_PERSISTENT_UNREGISTERED != 1 || LI2_PERSISTENT_SUBENTRY != 1 || \
    LI2_PERSISTENT_ACTIVE_DOMAIN != 1 || LI2_RSEQ_CURRENT_DATA != 1 || \
    LI2_PERSISTENT_RETAINED_TWO != 1 || LI2_PERSISTENT_DISPATCH != 1 || \
    LI2_PERSISTENT_GROUP != 1 || LI2_PERSISTENT_EPOCH != 1 || \
    defined(LI2_PERSISTENT_RETAINED_EIGHT) || defined(LI2_REUSE_CENSUS) || \
    defined(LI2_ADD_GUARD) || defined(LI2_PERSISTENT_GROUP_COUNTERS) || \
    defined(LI2_PERSISTENT_COLD_ADMISSION_CAPTURE) || defined(LI2_PERSISTENT_DIRECT_FRONTIER_CAPTURE) || \
    defined(LI2_PERSISTENT_CROSS_PAIR_CAPTURE) || defined(LI2_PERSISTENT_SUBENTRY_CAPTURE) || \
    defined(LI2_PERSISTENT_ACTIVE_DOMAIN_CAPTURE) || defined(LI2_PERSISTENT_STARTUP_CAPTURE) || \
    defined(LI2_PERSISTENT_RETAINED_TWO_CAPTURE) || defined(LI2_PERSISTENT_RESIDENT_CAPTURE) || \
    defined(LI2_PERSISTENT_GROUP_CAPTURE) || defined(LI2_PERSISTENT_EPOCH_CAPTURE) || \
    defined(LI2_PERSISTENT_DYNAMIC_CAPTURE) || defined(LI2_PERSISTENT_DYNAMIC)
#error "distinct cold CALL owner witness; no older capture or counter schema"
#endif
static void pclo_initialize(void);
static void pclo_ingress(int,siginfo_t *,ucontext_t *);
static void pclo_begin(int,siginfo_t *,ucontext_t *,unsigned);
static void pclo_declined(const ucontext_t *);
static void pclo_miss(void);
static void pclo_entered(void);
static void pclo_terminal(void);
static void pclo_finish(unsigned,unsigned,long);
void li2_pclo_trace_closed(const struct li2_tf_chain *,const struct li2_tf_chain_slot *);
#endif
