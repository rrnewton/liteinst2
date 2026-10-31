#ifndef LI2_PERSISTENT_EPOCH_OBSERVE_H
#define LI2_PERSISTENT_EPOCH_OBSERVE_H
#if LI2_PERSISTENT_EPOCH_CAPTURE != 1 || LI2_PERSISTENT_EPOCH != 1
#error "distinct persistent primitive capture only"
#endif
static void peo_initialize(void);
static void peo_ingress(int);
static void peo_begin(void);
static void peo_closed(void);
static void peo_entered(int,siginfo_t *,ucontext_t *);
static void peo_terminal(unsigned);
static void peo_finish(unsigned,unsigned,long);
#endif
