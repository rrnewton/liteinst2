#ifndef LI2_SPAN_TRACE_OBSERVE_H
#define LI2_SPAN_TRACE_OBSERVE_H
#if LI2_SCALAR_SPAN_CAPTURE != 1 || LI2_SCALAR_SPAN_TRACE != 1
#error "distinct genuine TRACE capture only"
#endif
static void spto_initialize(void);
static void spto_begin(void);
static void spto_closed(void);
static void spto_source(void);
static void spto_redirected(int,siginfo_t *,ucontext_t *);
static void spto_resumed(int,siginfo_t *,ucontext_t *);
static void spto_complete(void);
static void spto_abort_observe(void);
static void spto_finish(unsigned,unsigned,long);
#endif
