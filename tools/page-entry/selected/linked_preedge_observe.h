#ifndef LI2_LINKED_PREEDGE_OBSERVE_H
#define LI2_LINKED_PREEDGE_OBSERVE_H
#if LI2_LINKED_PREEDGE_CAPTURE != 1 || LI2_LINKED_PREEDGE != 1
#error "dedicated v2 primitive capture"
#endif
static void lpeo_initialize(void);
static void lpeo_ingress(int,const siginfo_t *,const ucontext_t *);
static void lpeo_end(int,const siginfo_t *,const ucontext_t *);
static void lpeo_begin(void);static void lpeo_closed(void);static void lpeo_source(void);static void lpeo_held(void);
static void lpeo_redirected(int,siginfo_t *,ucontext_t *);
static void lpeo_complete(void);static void lpeo_abort_observe(void);
static void lpeo_finish(unsigned,unsigned,long);
#endif
