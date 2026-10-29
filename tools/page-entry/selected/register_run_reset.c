#include "register_run_reset.h"
#ifdef LI2_RUN_CACHE_REUSE
#include "register_run_reuse.h"
#endif
#include <sys/mman.h>
#include <sys/syscall.h>
#define RAW(n,a,b,c,d,e,f) li2_step_raw(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
static int same(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;
    for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;
    return 1;
}
static void copy(void *a,const void *b,size_t n) {
    unsigned char *x=a;const unsigned char *y=b;
    for(size_t i=0;i<n;i++)x[i]=y[i];
}
static int fail(struct li2_run_completion_history *h,long detail) {
    if(!h->first_error){h->first_error=LI2_CACHE_RESET;h->first_detail=detail;}
    return (int)h->first_error;
}
int li2_run_complete_reset(struct li2_run_owner *o,struct li2_run_completion_history *h,
                            const struct li2_run_protection *protect,const ucontext_t *uc) {
    if(!o || !h || !uc || !protect || !protect->contains)return LI2_CACHE_ARGUMENT;
    uintptr_t a=(uintptr_t)o,b=(uintptr_t)h;
    if(a>UINTPTR_MAX-sizeof(*o) || b>UINTPTR_MAX-sizeof(*h) ||
       (a<b+sizeof(*h) && b<a+sizeof(*o)))return LI2_CACHE_ARGUMENT;
    if(h->first_error)return (int)h->first_error;
    if(protect->contains(protect->context,a,sizeof(*o))!=1 ||
       protect->contains(protect->context,b,sizeof(*h))!=1)return fail(h,1);
    if(h->reset_started && !h->reset_complete)return fail(h,2);
    if(o->phase!=LI2_RUN_COMPLETE || o->in_handler || o->first_error || o->failure_notified ||
       !o->session || !o->session->initialized || !o->session->self_test_complete ||
       o->session->pid<=0 || o->session->pid!=o->session->tid ||
       RAW(SYS_getpid,0,0,0,0,0,0)!=o->session->pid ||
       RAW(SYS_gettid,0,0,0,0,0,0)!=o->session->tid)return fail(h,3);
    if(o->redirected!=1 || o->exit_seen!=1 || o->entry_event.observed!=1 ||
       o->exit_event.observed!=1 || o->nested.event.observed ||
       o->exit_event.number!=SIGSEGV || o->exit_event.code!=SEGV_ACCERR ||
       o->exit_event.error || (uintptr_t)o->after.greg[REG_RIP]!=o->plan.stop ||
       o->after.greg[REG_TRAPNO]!=14 || o->after.greg[REG_ERR]!=21 ||
       (uint64_t)o->after.greg[REG_EFL]!=(o->logical_flags|LI2_STEP_RF))return fail(h,4);
    const struct li2_tf_continuation *q=&o->exit_query;
    if(q->attempted!=1 || q->page_observed!=1 || q->complete!=1 || q->result ||
       q->pc!=o->plan.stop || q->page.address!=(q->pc&~(LI2_STEP_PAGE-1)) ||
       !q->page.allocation || !q->page.generation || q->page.logical!=(PROT_READ|PROT_EXEC) ||
       q->page.closed_prot!=PROT_READ || !q->maps.opened || !q->maps.closed ||
       q->maps.close_result || o->release_started!=1 || o->release_complete!=1 ||
       o->release_result)return fail(h,5);
    const struct li2_fetch_progress *p=li2_lifecycle_fetch_progress();
    if(!p || li2_lifecycle_fetch_interlock() || p->held || !p->complete || p->first_error ||
       p->sequence!=o->borrow.sequence || !same(p,&o->final_fetch,sizeof(*p)))return fail(h,6);
    uint64_t mask=0;copy(&mask,&uc->uc_sigmask,sizeof(mask));
    if(mask!=o->after.mask || mask!=o->session->application_mask ||
       !same(uc->uc_mcontext.gregs,o->after.greg,sizeof(o->after.greg)) ||
       (uintptr_t)uc->uc_mcontext.fpregs!=o->after.fp_address ||
       o->after.fp_bytes<512 || o->after.fp_bytes>LI2_STEP_FP_BYTES ||
       o->after.initialized!=o->after.fp_bytes ||
       !same(uc->uc_mcontext.fpregs,o->after.fp,o->after.fp_bytes))return fail(h,7);
    if(h->completed_runs==UINT64_MAX || o->plan.instruction_count<2 ||
       o->plan.instruction_count>LI2_RUN_MAX_INSTRUCTIONS ||
       h->copied_instructions>UINT64_MAX-o->plan.instruction_count)return fail(h,8);
#ifdef LI2_RUN_CACHE_REUSE
    int reuse_error=li2_run_reuse_reset_ready(o,h);
    if(reuse_error)return fail(h,reuse_error);
#endif
    /* No fallible operation is permitted between installing the retained
       COMPLETE record and releasing this one reusable attempt slot. */
    h->reset_started=1;h->reset_complete=0;
    copy(&h->last_complete,o,sizeof(*o));
    ++h->completed_runs;h->copied_instructions+=o->plan.instruction_count;
    unsigned char *bytes=(void *)o;
    for(size_t i=0;i<sizeof(*o);i++)bytes[i]=0;
#ifdef LI2_RUN_CACHE_REUSE
    h->reset_complete=1;li2_run_reuse_reset_committed();return 0;
#else
    h->reset_complete=1;return 0;
#endif
}
