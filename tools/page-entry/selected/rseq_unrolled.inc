/* New no-write proof for the exact bounded-unroll tactic. Every original
   instruction is decoded and its actual write footprint must be NONE. No
   existing register-run/native-page predicate or report counter is changed. */
#include "unrolled_hash.h"
int li2_rseq_check_unrolled(const struct li2_unrolled_hash_plan *p,const ucontext_t *uc) {
    if(ready())return (int)state.first_error;
    if(!li2_native_pair_quiet() || !uc || !p || state.registered>1 ||
       (state.registered?!native_pin():(state.held || state.phase!=LI2_RSEQ_IDLE)))
        return bad(LI2_RSEQ_STATE,90);
    if(word_zero())return (int)state.first_error;
    struct li2_unrolled_hash_pc mapped={0};
    if(li2_unrolled_hash_map_pc(p,p->entry,&mapped) || mapped.original_pc!=p->pc ||
       mapped.copy_index || mapped.source_offset || mapped.kind!=LI2_UNROLLED_HASH_COPIED_INSTRUCTION)
        return bad(LI2_RSEQ_PLAN,90);
    size_t offset=0;
    for(size_t i=0;i<LI2_UNROLLED_HASH_INSNS;i++) {
        const struct li2_decoded *x=&p->instructions[i];struct li2_decoded d={0};
        size_t available=LI2_UNROLLED_HASH_SOURCE-offset;if(available>15)available=15;
        if(li2_decoder_decode(p->pc+offset,p->source+offset,available,&d) ||
           d.pc!=p->pc+offset || d.pc!=x->pc || d.code!=x->code || d.length!=x->length ||
           !d.length || offset+d.length>LI2_UNROLLED_HASH_BODY)
            return bad(LI2_RSEQ_PLAN,91);
        int e=decoded_footprint(&d,uc,1);if(e)return e;
        offset+=d.length;
    }
    if(offset!=LI2_UNROLLED_HASH_BODY || p->stop!=p->pc+offset)return bad(LI2_RSEQ_PLAN,92);
    return word_zero();
}
