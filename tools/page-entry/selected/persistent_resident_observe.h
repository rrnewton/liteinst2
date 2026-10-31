#ifndef LI2_PERSISTENT_RESIDENT_OBSERVE_H
#define LI2_PERSISTENT_RESIDENT_OBSERVE_H
#if LI2_PERSISTENT_RESIDENT_CAPTURE != 1 || LI2_PERSISTENT_DISPATCH != 1 || LI2_PERSISTENT_GROUP != 1 || LI2_PERSISTENT_EPOCH != 1 || defined(LI2_PERSISTENT_GROUP_CAPTURE) || defined(LI2_PERSISTENT_EPOCH_CAPTURE) || defined(LI2_PERSISTENT_DYNAMIC_CAPTURE) || defined(LI2_PERSISTENT_DYNAMIC)
#error "distinct resident dispatch capture only"
#endif
static void pro_initialize(void);
static void pro_ingress(int,siginfo_t *,ucontext_t *);
static void pro_begin(int,siginfo_t *,ucontext_t *);
static void pro_closed(void);
static void pro_miss_held(void);
static void pro_entered(int,siginfo_t *,ucontext_t *);
static void pro_terminal(unsigned);
static void pro_finish(unsigned,unsigned,long);
void li2_pro_trace_closed(const struct li2_tf_chain *,const struct li2_tf_chain_slot *);
#endif
