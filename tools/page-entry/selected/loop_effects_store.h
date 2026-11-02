#ifndef LI2_LOOP_EFFECTS_STORE_H
#define LI2_LOOP_EFFECTS_STORE_H
#include "loop_effects_bridge.h"

/* Shared source-only description, not emission or an authority decision.
   Callers already checked owned/disjoint storage and a valid actual decoded
   instruction. Authenticate the complete old row before consulting BMG. */
static int les_equal(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;
    for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;
    return 1;
}
static int les_row(const struct li2_mg_store *s,unsigned version,
    uintptr_t pc,const unsigned char *b,size_t n,const struct li2_decoded *d) {
    if(s->version!=version || s->available!=n || s->reserved || s->ready>1 ||
       (s->ready?s->refusal!=0:s->refusal==0) || s->tf.abi_version!=1 ||
       s->tf.pc!=pc || s->tf.next_pc!=d->next_pc || s->tf.code!=d->code ||
       s->tf.length!=d->length || !les_equal(s->bytes,b,n))return 0;
    for(size_t i=n;i<16;i++)if(s->bytes[i])return 0;
    if(s->ready) {
        if(s->tf.policy!=1)return 0;
        if(version==1)return s->width_bytes==4 || s->width_bytes==8;
        if(version!=LI2_BMG_VERSION || s->width_bytes!=1)return 0;
        return (s->tf.code==LI2_BMG_REGISTER_CODE && s->source_kind==1 && s->source_reg<16 && !s->immediate) ||
            (s->tf.code==LI2_BMG_IMMEDIATE_CODE && s->source_kind==2 && s->source_reg==16 && s->immediate<=255);
    }
    return 1;
}
static int les_describe(uintptr_t pc,const unsigned char *b,size_t n,
    const struct li2_decoded *d,struct li2_mg_store *out) {
    struct li2_mg_store old={0},added={0};
    if(li2_decoder_mov_store(pc,b,n,&old) || !les_row(&old,1,pc,b,n,d))return LI2_LR_DECODER;
    if(old.ready) { *out=old;return 0; }
    if(li2_decoder_byte_mov_store(pc,b,n,&added) ||
       !les_row(&added,LI2_BMG_VERSION,pc,b,n,d))return LI2_LR_DECODER;
    *out=added;return 0;
}
#endif
