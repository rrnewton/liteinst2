/* Included only by rseq_guard.c for the distinct scalar-region owner.
   Actual original descriptor bytes feed the unchanged NONE footprint guard.
   No region load operand is read; the existing actual rseq-word check stays.
   No old policy/counter is changed, and no
   caller-created old run/unroll description substitutes for this proof. */
#include "region_plan.h"

static int region_rseq_equal(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;
    for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;
    return 1;
}
static int region_rseq_current(const ucontext_t *uc) {
    /* quiet authenticates the real private pair owner and its complete saved
       session copy. Bootstrap quiet is deliberately insufficient here. */
    if(!uc || !li2_native_pair_quiet())return 0;
    const struct li2_native_pair_progress *p=li2_native_pair_progress();
    const struct li2_step_session *s=p->session;
    if(p->initialized!=1 || !s || s->initialized!=1 || s->self_test_complete!=1 ||
       s->pid<=0 || s->pid!=s->tid || p->pid!=s->pid || p->tid!=s->tid ||
       state.pid!=s->pid || state.tid!=s->tid || s->sync_register ||
       s->sync_query<0 || (s->sync_query&96)!=96 || state.registered>1 ||
       (state.registered?!native_pin():(state.held || state.phase!=LI2_RSEQ_IDLE)))return 0;
    /* Linux's actual kernel signal mask is eight bytes, not the unused
       userspace sigset_t tail. Frame provenance is the caller's obligation. */
    return region_rseq_equal(&uc->uc_sigmask,&s->application_mask,8);
}
int li2_rseq_check_region(const struct li2_region_plan *p,const ucontext_t *uc) {
    if(ready())return (int)state.first_error;
    if(!region_rseq_current(uc))return bad(LI2_RSEQ_STATE,100);
    if(word_zero())return (int)state.first_error;
    /* Complete owned storage is a caller precondition; numeric/alignment and
       all loop bounds are checked before descriptor or source indexing. */
    if(!p || (uintptr_t)p>UINTPTR_MAX-sizeof(*p) ||
       (uintptr_t)p%_Alignof(struct li2_region_plan) ||
       p->version!=LI2_REGION_PLAN_VERSION || p->ready!=1 || p->decoder_result ||
       !p->heads || p->heads>LI2_REGION_HEADS || !p->source_bytes ||
       p->source_bytes>LI2_REGION_BYTES || (p->page&(LI2_REGION_PAGE-1U)) ||
       p->page>UINTPTR_MAX-LI2_REGION_PAGE || p->entry<p->page ||
       p->entry>=p->page+LI2_REGION_PAGE || p->boundary_pc<=p->entry ||
       p->boundary_pc>=p->page+LI2_REGION_PAGE ||
       p->boundary_pc-p->entry!=p->source_bytes)
        return bad(LI2_RSEQ_PLAN,100);
    const struct li2_step_session *session=li2_native_pair_progress()->session;
    uint64_t epoch=state.epoch;unsigned registered=state.registered;
    size_t offset=(size_t)(p->entry-p->page),end=offset+p->source_bytes;
    for(size_t i=0;i<p->heads;i++) {
        const struct li2_region_head *h=&p->head[i];
        if(offset>=end || h->source_offset!=offset || !h->source_length ||
           h->source_length>15 || h->source_length>end-offset)
            return bad(LI2_RSEQ_PLAN,101);
        size_t available=LI2_REGION_PAGE-offset;if(available>15)available=15;
        struct li2_region_decoded actual={0};
        if(li2_decoder_region_describe(p->page+offset,p->source+offset,available,&actual) ||
           actual.version!=1 || actual.ready!=1 || actual.refusal ||
           actual.decoded.pc!=p->page+offset || actual.decoded.available!=available ||
           actual.decoded.length!=h->source_length ||
           actual.decoded.next_pc!=p->page+offset+h->source_length ||
           !region_rseq_equal(actual.decoded.bytes,p->source+offset,available) ||
           !region_rseq_equal(&actual,&p->original[i],sizeof(actual)))
            return bad(LI2_RSEQ_PLAN,102);
        /* Every selected head, including both kinds of direct branch, uses
           actual current GPR/TLS inputs and must independently be NONE.
           No initial-address calculation can admit a later copied writer. */
        int e=decoded_footprint(&actual.decoded,uc,1);if(e)return e;
        offset+=h->source_length;
    }
    if(offset!=end || p->page+offset!=p->boundary_pc)
        return bad(LI2_RSEQ_PLAN,103);
    if(li2_native_pair_progress()->session!=session || state.epoch!=epoch ||
       state.registered!=registered || !region_rseq_current(uc))
        return bad(LI2_RSEQ_STATE,101);
    return word_zero();
}
