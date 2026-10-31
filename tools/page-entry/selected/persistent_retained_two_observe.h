#ifndef LI2_PERSISTENT_RETAINED_TWO_OBSERVE_H
#define LI2_PERSISTENT_RETAINED_TWO_OBSERVE_H
#if LI2_PERSISTENT_RETAINED_TWO_CAPTURE != 1 || LI2_PERSISTENT_RETAINED_TWO != 1 || defined(LI2_PERSISTENT_RESIDENT_CAPTURE) || LI2_PERSISTENT_DISPATCH != 1 || LI2_PERSISTENT_GROUP != 1 || LI2_PERSISTENT_EPOCH != 1 || defined(LI2_PERSISTENT_GROUP_CAPTURE) || defined(LI2_PERSISTENT_EPOCH_CAPTURE) || defined(LI2_PERSISTENT_DYNAMIC_CAPTURE) || defined(LI2_PERSISTENT_DYNAMIC)
#error "distinct retained-two capture only"
#endif
static void ptr2o_initialize(void);
static void ptr2o_ingress(int,siginfo_t *,ucontext_t *);
static void ptr2o_begin(int,siginfo_t *,ucontext_t *,unsigned);
static void ptr2o_closed(void);
static void ptr2o_miss_held(void);
static void ptr2o_entered(int,siginfo_t *,ucontext_t *);
static void ptr2o_cancelled(int,siginfo_t *,ucontext_t *,enum li2_chain_result);
static void ptr2o_terminal(unsigned);
static void ptr2o_finish(unsigned,unsigned,long);
void li2_ptr2o_trace_closed(const struct li2_tf_chain *,const struct li2_tf_chain_slot *);
#endif
