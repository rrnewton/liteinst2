#include "linked_preedge_rseq.h"
int li2_rseq_check_preedge_cold(const struct li2_preedge_plan *p,const ucontext_t *uc) {
    if(ready())return (int)state.first_error;
    if(!region_rseq_current(uc))return bad(LI2_RSEQ_STATE,400);
    if(word_zero())return (int)state.first_error;
    if(!p || (uintptr_t)p>UINTPTR_MAX-sizeof(*p) || (uintptr_t)p%_Alignof(struct li2_preedge_plan) ||
       p->version!=LI2_PREEDGE_VERSION || p->bytes!=sizeof(*p) || p->reserved ||
       p->ready!=1 || p->decoder_result ||
       !p->heads || p->heads>LI2_PREEDGE_HEADS || !p->source_bytes ||
       p->source_bytes>15*LI2_PREEDGE_HEADS || (p->page&(LI2_REGION_PAGE-1)) ||
       p->page>UINTPTR_MAX-LI2_REGION_PAGE || p->entry<p->page ||
       p->entry>=p->page+LI2_REGION_PAGE)return bad(LI2_RSEQ_PLAN,400);
    const struct li2_step_session *session=li2_native_pair_progress()->session;
    uint64_t epoch=state.epoch;unsigned registered=state.registered,total=0;
    for(unsigned i=0;i<p->heads;i++) {
        const struct li2_region_head *h=&p->head[i];unsigned offset=h->source_offset;
        if(offset>=LI2_REGION_PAGE || !h->source_length || h->source_length>15 ||
           h->source_length>LI2_REGION_PAGE-offset)return bad(LI2_RSEQ_PLAN,401);
        size_t available=LI2_REGION_PAGE-offset;if(available>15)available=15;
        struct li2_span_decoded actual={0};struct li2_write_footprint independent={0};
        if(li2_decoder_span_describe(p->page+offset,p->source+offset,available,&actual) ||
           actual.version!=1 || actual.ready!=1 || actual.refusal ||
           actual.decoded.pc!=p->page+offset || actual.decoded.available!=available ||
           actual.decoded.length!=h->source_length ||
           !region_rseq_equal(&actual,&p->original[i],sizeof actual) ||
           li2_decoder_link_none(p->page+offset,p->source+offset,available,&independent) ||
           independent.abi_version!=1 || independent.policy!=LI2_WRITE_NONE ||
           independent.first || independent.end || independent.pc!=actual.decoded.pc ||
           independent.next_pc!=actual.decoded.next_pc || independent.code!=actual.decoded.code ||
           independent.length!=actual.decoded.length)return bad(LI2_RSEQ_PLAN,402);
        /* Keep the old actual per-head NONE proof too. Neither the current
           register input nor this sampled result substitutes for independent. */
        int e=decoded_footprint(&actual.decoded,uc,1);if(e)return e;
        total+=h->source_length;
    }
    if(total!=p->source_bytes || li2_native_pair_progress()->session!=session ||
       state.epoch!=epoch || state.registered!=registered || !region_rseq_current(uc))
        return bad(LI2_RSEQ_STATE,401);
    return word_zero();
}
