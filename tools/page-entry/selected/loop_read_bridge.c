#include "loop_read_bridge.h"
#include "linked_rseq.h"
static void lr_zero(void *p,size_t n) { unsigned char *b=p;for(size_t i=0;i<n;i++)b[i]=0; }
static void lr_copy(void *p,const void *q,size_t n) { unsigned char *b=p;const unsigned char *a=q;for(size_t i=0;i<n;i++)b[i]=a[i]; }
static int lr_equal(const void *p,const void *q,size_t n) { const unsigned char *a=p,*b=q;for(size_t i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1; }
static int lr_storage(const void *p,size_t n,size_t alignment) {
    return p && (uintptr_t)p%alignment==0 && (uintptr_t)p<=UINTPTR_MAX-n;
}
static int lr_overlap(const void *a,size_t an,const void *b,size_t bn) {
    return (uintptr_t)a<(uintptr_t)b+bn && (uintptr_t)b<(uintptr_t)a+an;
}
static int lr_source(const unsigned char *b,size_t n) {
    return n && n<=15 && lr_storage(b,n,1);
}
static int lr_row(const struct li2_span_decoded *d,unsigned version,
                  uintptr_t pc,const unsigned char *b,size_t n) {
    const struct li2_decoded *a=&d->decoded;
    if(d->version!=version || a->abi_version!=1 || a->reserved || a->pc!=pc ||
       a->available!=n || !lr_equal(a->bytes,b,n) || d->ready>1 ||
       (d->ready?d->refusal!=0:d->refusal==0))return 0;
    for(size_t i=n;i<16;i++)if(a->bytes[i])return 0;
    if(d->ready && (a->decode_status!=LI2_VALID || !a->length || a->length>n ||
        a->length>15 || pc>UINTPTR_MAX-a->length || a->next_pc!=pc+a->length))return 0;
    return 1;
}

int li2_lr_describe(uintptr_t pc,const unsigned char *b,size_t n,struct li2_span_decoded *out) {
    if(!lr_storage(out,sizeof *out,_Alignof(struct li2_span_decoded)))return LI2_LR_ARGUMENT;
    /* Check aliasing before clearing an output which could be the source. */
    if(!lr_source(b,n) || lr_overlap(out,sizeof *out,b,n))return LI2_LR_ARGUMENT;
    lr_zero(out,sizeof *out);
    struct li2_span_decoded old={0},added={0};
    if(li2_decoder_span_describe(pc,b,n,&old) ||
       li2_decoder_scalar_read_describe(pc,b,n,&added) ||
       !lr_row(&old,1,pc,b,n) || !lr_row(&added,LI2_SCALAR_READ_VERSION,pc,b,n) ||
       !lr_equal(&old.decoded,&added.decoded,sizeof old.decoded))return LI2_LR_DECODER;
    if(old.ready) {
        /* This exact relation is the scalar API's declared old-domain theorem.
           Only a local expected value changes; returned old bytes stay exact. */
        struct li2_span_decoded expected=old;expected.version=LI2_SCALAR_READ_VERSION;
        if(!lr_equal(&expected,&added,sizeof expected))return LI2_LR_CORRUPT;
        lr_copy(out,&old,sizeof *out);
    } else if(added.ready) {
        /* All five additions are nonbranch NONE forms. Refuse a future API
           expansion here until its new consumer contract is explicit. */
        if(added.flow!=LI2_REGION_NEXT || added.target)return LI2_LR_CORRUPT;
        lr_copy(out,&added,sizeof *out);
    } else {
        /* New-domain refusal reasons need not equal old ones. Preserve the
           complete actual old refusal for the unchanged MOV classifier. */
        lr_copy(out,&old,sizeof *out);
    }
    return 0;
}

int li2_lr_none(uintptr_t pc,const unsigned char *b,size_t n,const struct li2_span_decoded *d) {
    if(!lr_source(b,n) || !lr_storage(d,sizeof *d,_Alignof(struct li2_span_decoded)) ||
       lr_overlap(d,sizeof *d,b,n))return LI2_LR_ARGUMENT;
    struct li2_span_decoded actual={0};int e=li2_lr_describe(pc,b,n,&actual);
    if(e)return e;
    if(!lr_equal(d,&actual,sizeof actual))return LI2_LR_CORRUPT;
    if(actual.ready!=1 || actual.refusal)return LI2_LR_FORM;
    struct li2_write_footprint f={0};uint32_t status;
    if(actual.version==1)status=li2_decoder_link_none(pc,b,n,&f);
    else if(actual.version==LI2_SCALAR_READ_VERSION)status=li2_decoder_scalar_read_none(pc,b,n,&f);
    else return LI2_LR_CORRUPT;
    if(status || f.abi_version!=1 || f.policy!=LI2_WRITE_NONE || f.first || f.end ||
       f.pc!=pc || f.next_pc!=actual.decoded.next_pc || f.code!=actual.decoded.code ||
       f.length!=actual.decoded.length)return LI2_LR_DECODER;
    return 0;
}

int li2_lr_bridge_node(uintptr_t pc,const unsigned char *b,size_t n,
                       const struct li2_le_decoded *node,struct li2_lr_node *out) {
    if(!lr_storage(out,sizeof *out,_Alignof(struct li2_lr_node)))return LI2_LR_ARGUMENT;
    if(!lr_source(b,n) || !lr_storage(node,sizeof *node,_Alignof(struct li2_le_decoded)) ||
       lr_overlap(out,sizeof *out,b,n) || lr_overlap(out,sizeof *out,node,sizeof *node) ||
       lr_overlap(node,sizeof *node,b,n))return LI2_LR_ARGUMENT;
    lr_zero(out,sizeof *out);
    struct li2_lr_node candidate={0};struct li2_le_decoded expected={0};
    int e=li2_lr_describe(pc,b,n,&candidate.original);if(e)return e;
    if(li2_decoder_scalar_read_describe(pc,b,n,&expected.scalar) ||
       !lr_row(&expected.scalar,LI2_SCALAR_READ_VERSION,pc,b,n))return LI2_LR_DECODER;
    if(expected.scalar.ready) {
        if((e=li2_lr_none(pc,b,n,&candidate.original)))return e;
        expected.kind=LI2_LE_NONE;candidate.kind=LI2_LE_NONE;
    } else {
        struct li2_mg_store *m=&expected.mov;
        if(candidate.original.ready || li2_decoder_mov_store(pc,b,n,m) ||
           m->version!=1 || m->available!=n || m->reserved || m->ready!=1 || m->refusal ||
           m->tf.abi_version!=1 || m->tf.policy!=1 || m->tf.pc!=pc ||
           m->tf.next_pc!=candidate.original.decoded.next_pc || m->tf.code!=candidate.original.decoded.code ||
           m->tf.length!=candidate.original.decoded.length || (m->width_bytes!=4 && m->width_bytes!=8) ||
           !lr_equal(m->bytes,b,n))return LI2_LR_FORM;
        for(size_t i=n;i<16;i++)if(m->bytes[i])return LI2_LR_CORRUPT;
        expected.kind=LI2_LE_MOV;candidate.kind=LI2_LE_MOV;candidate.mov=*m;
    }
    if(!lr_equal(node,&expected,sizeof expected))return LI2_LR_CORRUPT;
    lr_copy(out,&candidate,sizeof *out);return 0;
}
