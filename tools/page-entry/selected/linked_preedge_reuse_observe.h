#ifndef LI2_LINKED_PREEDGE_REUSE_OBSERVE_H
#define LI2_LINKED_PREEDGE_REUSE_OBSERVE_H
#if LI2_LINKED_PREEDGE_REUSE_CAPTURE != 1 || LI2_LINKED_PREEDGE != 1 || LI2_LINKED_NATIVE_HINT != 1 || defined(LI2_LINKED_EPOCH_CAPTURE) || defined(LI2_LINKED_PREEDGE_CAPTURE)
#error "distinct linked epoch capture only"
#endif
static void lpero_initialize(void);
static void lpero_ingress(int);
static void lpero_begin(void);
static void lpero_closed(void);
static void lpero_source(void);
static void lpero_held(void);
static void lpero_redirected(int,siginfo_t *,ucontext_t *);
static void lpero_before_close(void);
static void lpero_complete(void);
static void lpero_abort_observe(void);
static void lpero_finish(unsigned,unsigned,long);
#endif
