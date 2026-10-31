#ifndef LI2_LINKED_PREEDGE_FAILURE_OBSERVE_H
#define LI2_LINKED_PREEDGE_FAILURE_OBSERVE_H
#if LI2_LINKED_PREEDGE_FAILURE_CAPTURE != 1 || LI2_LINKED_PREEDGE != 1 || LI2_LINKED_NATIVE_HINT != 1 || \
    defined(LI2_LINKED_EPOCH_CAPTURE) || defined(LI2_LINKED_PREEDGE_CAPTURE) || \
    defined(LI2_LINKED_PREEDGE_REUSE_CAPTURE) || defined(LI2_LINKED_PREEDGE_FULL_CAPTURE)
#error "dedicated v2 primitive capture"
#endif
static void lpec_initialize(void);
static void lpec_ingress(int,const siginfo_t *,const ucontext_t *);
static void lpec_end(int,const siginfo_t *,const ucontext_t *);
static void lpec_begin(void);static void lpec_closed(void);static void lpec_source(void);static void lpec_held(void);
static void lpec_redirected(int,siginfo_t *,ucontext_t *);
static void lpec_before_close(void);
static void lpec_complete(void);static void lpec_abort_observe(void);
static void lpec_finish(unsigned,unsigned,long);
#endif
