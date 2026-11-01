#ifndef LI2_PERSISTENT_RET_OWNER_OBSERVE_H
#define LI2_PERSISTENT_RET_OWNER_OBSERVE_H
#if LI2_PERSISTENT_RET_OWNER_CAPTURE != 1 || LI2_PERSISTENT_RET_DISPATCH != 1 || LI2_PERSISTENT_CALL_DISPATCH != 1 || \
    LI2_PERSISTENT_DIRECT_FRONTIER != 1 || LI2_PERSISTENT_CROSS_PAIR != 1 || \
    LI2_PERSISTENT_UNREGISTERED != 1 || LI2_PERSISTENT_SUBENTRY != 1 || \
    LI2_PERSISTENT_ACTIVE_DOMAIN != 1 || LI2_RSEQ_CURRENT_DATA != 1 || \
    LI2_PERSISTENT_RETAINED_TWO != 1 || LI2_PERSISTENT_DISPATCH != 1 || \
    LI2_PERSISTENT_GROUP != 1 || LI2_PERSISTENT_EPOCH != 1 || \
    defined(LI2_PERSISTENT_RETAINED_EIGHT) || defined(LI2_REUSE_CENSUS) || \
    defined(LI2_PERSISTENT_CALL_OWNER_CAPTURE) || defined(LI2_ADD_GUARD) || defined(LI2_PERSISTENT_GROUP_COUNTERS) || \
    defined(LI2_PERSISTENT_COLD_ADMISSION_CAPTURE) || defined(LI2_PERSISTENT_DIRECT_FRONTIER_CAPTURE) || \
    defined(LI2_PERSISTENT_CROSS_PAIR_CAPTURE) || defined(LI2_PERSISTENT_SUBENTRY_CAPTURE) || \
    defined(LI2_PERSISTENT_ACTIVE_DOMAIN_CAPTURE) || defined(LI2_PERSISTENT_STARTUP_CAPTURE) || \
    defined(LI2_PERSISTENT_RETAINED_TWO_CAPTURE) || defined(LI2_PERSISTENT_RESIDENT_CAPTURE) || \
    defined(LI2_PERSISTENT_GROUP_CAPTURE) || defined(LI2_PERSISTENT_EPOCH_CAPTURE) || \
    defined(LI2_PERSISTENT_DYNAMIC_CAPTURE) || defined(LI2_PERSISTENT_DYNAMIC)
#error "distinct finite RET owner witness; no older capture or counter schema"
#endif
static void prto_initialize(void);
static void prto_ingress(int,siginfo_t *,ucontext_t *);
static void prto_begin(int,siginfo_t *,ucontext_t *,unsigned);
static void prto_declined(const ucontext_t *);
static void prto_miss(void);
static void prto_entered(void);
static void prto_terminal(void);
static void prto_loaded(void);
static void prto_drained(void);
static void prto_armed(void);
static void prto_observed(void);
static void prto_consumed(const ucontext_t *);
static void prto_finish(unsigned,unsigned,long);
void li2_prto_trace_closed(const struct li2_tf_chain *,const struct li2_tf_chain_slot *);
#endif
