/* Included only by rseq_guard.c for the distinct scalar-span TRACE owner.
   Actual original descriptor bytes feed the unchanged NONE footprint guard.
   No region load operand is read; the existing actual rseq-word check stays.
   No old policy/counter is changed, and no
   caller-created old run/unroll description substitutes for this proof. */
#include "region_plan.h"

int li2_rseq_check_span(const struct li2_span_plan *p,const ucontext_t *uc) {
    if(ready())return (int)state.first_error;
    if(!region_rseq_current(uc))return bad(LI2_RSEQ_STATE,100);
    if(word_zero())return (int)state.first_error;
    /* Complete owned storage is a caller precondition; numeric/alignment and
       all loop bounds are checked before descriptor or source indexing. */
    if(!p || (uintptr_t)p>UINTPTR_MAX-sizeof(*p) ||
       (uintptr_t)p%_Alignof(struct li2_span_plan) ||
       p->version!=LI2_SPAN_PLAN_VERSION || p->ready!=1 || p->decoder_result ||
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
        struct li2_span_decoded actual={0};
        if(li2_decoder_span_describe(p->page+offset,p->source+offset,available,&actual) ||
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
