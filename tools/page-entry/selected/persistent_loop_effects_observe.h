#ifndef LI2_PERSISTENT_LOOP_EFFECTS_OBSERVE_H
#define LI2_PERSISTENT_LOOP_EFFECTS_OBSERVE_H
#if LI2_PERSISTENT_DIRECT_FRONTIER_CAPTURE != 1 || LI2_PERSISTENT_DIRECT_FRONTIER != 1 || defined(LI2_PERSISTENT_CROSS_PAIR_CAPTURE) || LI2_PERSISTENT_CROSS_PAIR != 1 || defined(LI2_PERSISTENT_SUBENTRY_CAPTURE) || defined(LI2_PERSISTENT_RETAINED_EIGHT) || LI2_PERSISTENT_UNREGISTERED != 1 || LI2_PERSISTENT_SUBENTRY != 1 || defined(LI2_PERSISTENT_ACTIVE_DOMAIN_CAPTURE) || defined(LI2_PERSISTENT_STARTUP_CAPTURE) || LI2_PERSISTENT_ACTIVE_DOMAIN != 1 || LI2_RSEQ_CURRENT_DATA != 1 || LI2_PERSISTENT_RETAINED_TWO != 1 || LI2_PERSISTENT_DISPATCH != 1 || LI2_PERSISTENT_GROUP != 1 || LI2_PERSISTENT_EPOCH != 1 || defined(LI2_PERSISTENT_RETAINED_TWO_CAPTURE) || defined(LI2_PERSISTENT_RESIDENT_CAPTURE) || defined(LI2_PERSISTENT_GROUP_CAPTURE) || defined(LI2_PERSISTENT_GROUP_COUNTERS) || defined(LI2_PERSISTENT_EPOCH_CAPTURE) || defined(LI2_PERSISTENT_DYNAMIC_CAPTURE) || defined(LI2_PERSISTENT_DYNAMIC)
#error "distinct direct-frontier capture with exact lifetime and lossless evidence"
#endif
#if !defined(LI2_PERSISTENT_LOOP_CAPTURE) || LI2_PERSISTENT_LOOP_CAPTURE != 1 || !defined(LI2_PERSISTENT_LOOP_RUNTIME) || defined(LI2_PERSISTENT_FUSED_CAPTURE) || defined(LI2_PERSISTENT_BLOCK_CAPTURE)
#error "distinct loop policy14 observation, never a PF13 wire alias"
#endif
#if !defined(LI2_PERSISTENT_LOOP_EFFECTS_CAPTURE) || LI2_PERSISTENT_LOOP_EFFECTS_CAPTURE != 1 || LI2_PERSISTENT_LOOP_EFFECTS != 1 || LI2_LOOP_EFFECTS != 1 || defined(LI2_PERSISTENT_LOOP_LIFECYCLE_CAPTURE)
#error "separate schema16 effects capture; no old/lifecycle wire alias"
#endif
static void pbo_miss_held(void);
static void pbo_cancelled(int,siginfo_t *,ucontext_t *,enum li2_chain_result);
static void pdo_initialize(void);
static void pdo_ingress(int,siginfo_t *,ucontext_t *);
static void pdo_begin(int,siginfo_t *,ucontext_t *,unsigned);
static void pdo_closed(void);
static void pdo_entered(int,siginfo_t *,ucontext_t *);
static void pdo_terminal(unsigned);
static void pdo_finish(unsigned,unsigned,long);
void li2_pdo_trace_closed(const struct li2_tf_chain *,const struct li2_tf_chain_slot *);
#endif
