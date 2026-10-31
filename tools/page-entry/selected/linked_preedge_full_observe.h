#ifndef LI2_LINKED_PREEDGE_FULL_OBSERVE_H
#define LI2_LINKED_PREEDGE_FULL_OBSERVE_H
#if LI2_LINKED_PREEDGE_FULL_CAPTURE != 1 || LI2_LINKED_EPOCH != 1 || \
    LI2_LINKED_PREEDGE != 1 || LI2_LINKED_NATIVE_HINT != 1 || \
    defined(LI2_LINKED_EPOCH_CAPTURE) || defined(LI2_LINKED_PREEDGE_CAPTURE) || \
    defined(LI2_LINKED_PREEDGE_REUSE_CAPTURE)
#error "distinct linked epoch capture only"
#endif
static void lpef_initialize(void);
static void lpef_ingress(int);
static void lpef_begin(void);
static void lpef_closed(void);
static void lpef_source(void);
static void lpef_held(void);
static void lpef_redirected(int,siginfo_t *,ucontext_t *);
static void lpef_before_close(void);
static void lpef_complete(void);
static void lpef_abort_observe(void);
static void lpef_finish(unsigned,unsigned,long);
static void lpef_refault_before_release(int,siginfo_t *,ucontext_t *);
static void lpef_refault_before(int,siginfo_t *,ucontext_t *);
static void lpef_refault_after(int,siginfo_t *,ucontext_t *);
static void lpef_refault_ingress(int,siginfo_t *,ucontext_t *);
static void lpef_refault_end(int,siginfo_t *,ucontext_t *);
static void lpef_refault_native(void);
#ifdef LI2_LINKED_NATIVE_HINT
static void lpef_hint_before(int,siginfo_t *,ucontext_t *);
static void lpef_hint_chosen(void);
static void lpef_hint_after(void);
static void lpef_hint_ingress(int,siginfo_t *,ucontext_t *);
static void lpef_hint_end(int,siginfo_t *,ucontext_t *);
static void lpef_hint_native(void);
static void lpef_hint_abort(void);
#endif
#endif
