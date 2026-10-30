#ifndef LI2_LINKED_EPOCH_OBSERVE_H
#define LI2_LINKED_EPOCH_OBSERVE_H
#if LI2_LINKED_EPOCH_CAPTURE != 1 || LI2_LINKED_EPOCH != 1
#error "distinct linked epoch capture only"
#endif
static void leto_initialize(void);
static void leto_ingress(int);
static void leto_begin(void);
static void leto_closed(void);
static void leto_source(void);
static void leto_held(void);
static void leto_redirected(int,siginfo_t *,ucontext_t *);
static void leto_before_close(void);
static void leto_complete(void);
static void leto_abort_observe(void);
static void leto_finish(unsigned,unsigned,long);
static void leto_refault_before_release(int,siginfo_t *,ucontext_t *);
static void leto_refault_before(int,siginfo_t *,ucontext_t *);
static void leto_refault_after(int,siginfo_t *,ucontext_t *);
static void leto_refault_ingress(int,siginfo_t *,ucontext_t *);
static void leto_refault_end(int,siginfo_t *,ucontext_t *);
static void leto_refault_native(void);
#ifdef LI2_LINKED_NATIVE_HINT
static void leto_hint_before(int,siginfo_t *,ucontext_t *);
static void leto_hint_chosen(void);
static void leto_hint_after(void);
static void leto_hint_ingress(int,siginfo_t *,ucontext_t *);
static void leto_hint_end(int,siginfo_t *,ucontext_t *);
static void leto_hint_native(void);
static void leto_hint_abort(void);
#endif
#endif
