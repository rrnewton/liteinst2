#include "loop_envelope.h"
static void zero(void *p,size_t n) { unsigned char *b=p;for(size_t i=0;i<n;i++)b[i]=0; }
static void copy(void *p,const void *q,size_t n) { unsigned char *b=p;const unsigned char *a=q;for(size_t i=0;i<n;i++)b[i]=a[i]; }
static int equal(const void *p,const void *q,size_t n) { const unsigned char *a=p,*b=q;for(size_t i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1; }
static int storage(const void *p,size_t n) { return p && (uintptr_t)p<=UINTPTR_MAX-n; }
static int overlap(uintptr_t a,size_t an,uintptr_t b,size_t bn) { return a<b+bn && b<a+an; }
static int address(uintptr_t p,size_t n) { return n && p<UINT64_C(0x800000000000) && n<=UINT64_C(0x800000000000)-p; }
static int hosts(const void *const *p,const size_t *n,const size_t *align,unsigned count) {
    for(unsigned i=0;i<count;i++) {
        if(!storage(p[i],n[i]) || (uintptr_t)p[i]%align[i])return 0;
        for(unsigned j=0;j<i;j++)if(overlap((uintptr_t)p[i],n[i],(uintptr_t)p[j],n[j]))return 0;
    }
    return 1;
}
static int location(const struct li2_le_witness *w,uintptr_t pc,unsigned *page,unsigned *offset) {
    for(unsigned i=0;i<2;i++)if(pc>=w->page[i] && pc-w->page[i]<LI2_LE_PAGE) {
        *page=i;*offset=(unsigned)(pc-w->page[i]);return 1;
    }
    return 0;
}
static size_t window(const struct li2_le_witness *w,uintptr_t pc,unsigned char out[15]) {
    zero(out,15);size_t n=0;
    for(;n<15;n++) {
        unsigned page,offset;
        if(pc>UINTPTR_MAX-n || !location(w,pc+n,&page,&offset))break;
        out[n]=w->source[page][offset];
    }
    return n;
}
/* Cache actual descriptors, never caller-supplied graph facts. At most128
   distinct starts across the spine AND every prefix probe. */
static int fetch(struct li2_le_witness *w,uintptr_t pc,unsigned *index) {
    for(unsigned i=0;i<w->decoded;i++)if(w->node[i].scalar.decoded.pc==pc) { *index=i;return 0; }
    unsigned char bytes[15];size_t n=window(w,pc,bytes);
    if(!n)return LI2_LE_FETCH_END;
    if(w->decoded==LI2_LE_HEADS)return LI2_LE_DISCOVERY_LIMIT;
    const unsigned i=w->decoded++;struct li2_le_decoded *v=&w->node[i];
    struct li2_span_decoded *d=&v->scalar;*index=i;
    if(li2_decoder_scalar_read_describe(pc,bytes,n,d))return LI2_LE_DECODER;
    const struct li2_decoded *a=&d->decoded;
    if(d->version!=LI2_SCALAR_READ_VERSION || a->abi_version!=1 || a->reserved ||
       a->pc!=pc || a->available!=n || !equal(a->bytes,bytes,n))return LI2_LE_DECODER;
    for(size_t j=n;j<16;j++)if(a->bytes[j])return LI2_LE_DECODER;
    if(d->ready>1 || (d->ready && d->refusal) || (!d->ready && !d->refusal))return LI2_LE_DECODER;
    if(a->decode_status!=LI2_VALID || !a->length || a->length>n || a->length>15 ||
       a->next_pc!=pc+a->length) { v->stop=LI2_LE_FETCH_END;return 0; }
    if(d->ready) {
        struct li2_write_footprint f={0};
        if(li2_decoder_scalar_read_none(pc,bytes,n,&f) || f.abi_version!=1 ||
           f.policy!=LI2_WRITE_NONE || f.first || f.end || f.pc!=pc ||
           f.next_pc!=a->next_pc || f.code!=a->code || f.length!=a->length ||
           d->flow>LI2_REGION_JMP)return LI2_LE_DECODER;
        v->kind=LI2_LE_NONE;
    } else {
        struct li2_mg_store *s=&v->mov;
        if(li2_decoder_mov_store(pc,bytes,n,s) || s->version!=1 || s->available!=n ||
           s->reserved || s->ready>1 || (s->ready && s->refusal) || (!s->ready && !s->refusal) ||
           s->tf.abi_version!=1 || s->tf.pc!=pc || s->tf.next_pc!=a->next_pc ||
           s->tf.code!=a->code || s->tf.length!=a->length || !equal(s->bytes,bytes,n))return LI2_LE_DECODER;
        for(size_t j=n;j<16;j++)if(s->bytes[j])return LI2_LE_DECODER;
        if(s->ready) {
            if(s->tf.policy!=1 || (s->width_bytes!=4 && s->width_bytes!=8))return LI2_LE_DECODER;
            v->kind=LI2_LE_MOV;
        } else v->stop=LI2_LE_UNSUPPORTED;
    }
    return 0;
}
static unsigned flow(const struct li2_le_decoded *v) {
    return v->kind==LI2_LE_MOV?LI2_REGION_NEXT:v->scalar.flow;
}
/* An unavailable/unsupported prefix rejects this candidate; decoder and
   shared discovery-bound errors refuse the whole proposal. */
static int prefix(struct li2_le_witness *w,uintptr_t first,unsigned *accepted) {
    *accepted=0;uintptr_t pc=first;
    while(pc<w->entry) {
        unsigned i;int e=fetch(w,pc,&i);
        if(e==LI2_LE_FETCH_END)return 0;
        if(e)return e;
        const struct li2_le_decoded *v=&w->node[i];
        if(!v->kind || flow(v)==LI2_REGION_JMP || v->scalar.decoded.next_pc>w->entry)return 0;
        pc=v->scalar.decoded.next_pc;
    }
    *accepted=pc==w->entry;return 0;
}
static int shape(struct li2_le_witness *w,const struct li2_le_candidate *c,struct li2_le_shape *s) {
    zero(s,sizeof *s);s->choice=*c;s->choice.result=LI2_LE_PREFIX;
    unsigned list[LI2_LE_HEADS],count=0,entry=LI2_LE_HEADS;
    uintptr_t pc=c->first;
    while(pc<c->end) {
        unsigned i;int e=fetch(w,pc,&i);if(e==LI2_LE_FETCH_END)return 0;if(e)return e;
        const struct li2_le_decoded *v=&w->node[i];
        if(!v->kind || v->scalar.decoded.next_pc>c->end)return 0;
        if(count==LI2_LE_HEADS)return LI2_LE_DISCOVERY_LIMIT;
        if(pc==w->entry)entry=count;
        list[count++]=i;pc=v->scalar.decoded.next_pc;
    }
    if(pc!=c->end || !count || entry==LI2_LE_HEADS)return 0;
    s->choice.heads=count;
    /* Targets use linear indices until every reachable head gets its actual
       deterministic BFS number. Only real direct arms can be external. */
    unsigned target[LI2_LE_HEADS][2]={{0}},arms[LI2_LE_HEADS]={0};
    uint64_t target_pc[LI2_LE_HEADS][2]={{0}};
    for(unsigned i=0;i<count;i++) {
        const struct li2_le_decoded *v=&w->node[list[i]];const struct li2_span_decoded *d=&v->scalar;
        unsigned f=flow(v);arms[i]=f==LI2_REGION_JCC?2U:1U;
        s->choice.stores+=v->kind==LI2_LE_MOV;s->choice.source_bytes+=d->decoded.length;
        for(unsigned arm=0;arm<arms[i];arm++) {
            uintptr_t t=f==LI2_REGION_NEXT || arm?d->decoded.next_pc:d->target;
            target_pc[i][arm]=t;target[i][arm]=LI2_LE_HEADS;
            if(t>=c->first && t<c->end) {
                for(unsigned j=0;j<count;j++)if(w->node[list[j]].scalar.decoded.pc==t)target[i][arm]=j;
                if(target[i][arm]==LI2_LE_HEADS) { s->choice.result=LI2_LE_INTERIOR;return 0; }
                if(f!=LI2_REGION_NEXT && !arm && t<=d->decoded.pc)++s->choice.backwards;
            } else {
                if(f==LI2_REGION_NEXT) { s->choice.result=LI2_LE_PREFIX;return 0; }
                ++s->choice.exits;
            }
        }
    }
    if(!s->choice.exits) { s->choice.result=LI2_LE_NO_EXIT;return 0; }
    if(s->choice.exits>LI2_LE_BOUNDARIES) { s->choice.result=LI2_LE_EXIT_LIMIT;return 0; }
    unsigned queue[LI2_LE_HEADS]={0},number[LI2_LE_HEADS],n=1;
    for(unsigned i=0;i<LI2_LE_HEADS;i++)number[i]=LI2_LE_HEADS;
    queue[0]=entry;number[entry]=0;
    for(unsigned at=0;at<n;at++)for(unsigned arm=0;arm<arms[queue[at]];arm++) {
        unsigned t=target[queue[at]][arm];
        if(t<LI2_LE_HEADS && number[t]==LI2_LE_HEADS) { number[t]=n;queue[n++]=t; }
    }
    if(n!=count) { s->choice.result=LI2_LE_UNREACHABLE;return 0; }
    unsigned exits=0;
    for(unsigned at=0;at<n;at++) {
        unsigned i=queue[at];const struct li2_le_decoded *v=&w->node[list[i]];
        struct li2_le_head *h=&s->head[at];
        h->pc=v->scalar.decoded.pc;h->decoded=list[i];h->kind=v->kind;h->flow=flow(v);h->successors=arms[i];
        for(unsigned arm=0;arm<arms[i];arm++) {
            unsigned t=target[i][arm];
            if(t==LI2_LE_HEADS) {
                h->external_mask|=1U<<arm;h->token[arm]=LI2_LE_HEADS+exits;
                s->exit[exits++]=(struct li2_le_arm){target_pc[i][arm],at,arm};
            } else {
                unsigned k=number[t];h->token[arm]=k;
                if(at/LI2_LE_MEMBER_HEADS!=k/LI2_LE_MEMBER_HEADS) {
                    if(s->choice.exits+s->choice.links==LI2_LE_BOUNDARIES) {
                        s->choice.result=LI2_LE_LINK_LIMIT;return 0;
                    }
                    s->link[s->choice.links++]=(struct li2_le_link){at,arm,k,0};
                }
            }
        }
    }
    if(exits!=s->choice.exits)return LI2_LE_DECODER;
    s->choice.result=LI2_LE_ELIGIBLE;return 0;
}
static int better(const struct li2_le_candidate *a,const struct li2_le_candidate *b) {
    unsigned ac=a->exits+a->links,bc=b->exits+b->links;
    if(ac!=bc)return ac<bc;
    if(a->backwards!=b->backwards)return a->backwards>b->backwards;
    if(a->heads!=b->heads)return a->heads<b->heads;
    if(a->first!=b->first)return a->first<b->first;
    return a->end<b->end;
}
int li2_le_choose(const uintptr_t pages[2],const unsigned char source[2][LI2_LE_PAGE],
    uintptr_t entry,struct li2_le_witness *out) {
    const void *host[3]={pages,source,out};
    const size_t sizes[3]={2*sizeof *pages,2*LI2_LE_PAGE,sizeof *out};
    const size_t aligns[3]={_Alignof(uintptr_t),1,_Alignof(struct li2_le_witness)};
    if(!hosts(host,sizes,aligns,3))return LI2_LE_ARGUMENT;
    zero(out,sizeof *out);out->version=LI2_LE_VERSION;out->bytes=sizeof *out;
    int e=LI2_LE_ARGUMENT;
    if(pages[0]>=pages[1] || (pages[0]&4095U) || (pages[1]&4095U) ||
       !address(pages[0],LI2_LE_PAGE) || !address(pages[1],LI2_LE_PAGE))goto done;
    copy(out->page,pages,sizeof out->page);copy(out->source,source,sizeof out->source);out->entry=entry;
    unsigned pg,offset;if(!location(out,entry,&pg,&offset))goto done;
    unsigned spine[LI2_LE_HEADS],spine_count=0;uintptr_t pc=entry;
    for(;;) {
        unsigned i;e=fetch(out,pc,&i);
        if(e==LI2_LE_FETCH_END) { out->stop=LI2_LE_FETCH_END;out->stop_pc=pc;e=0;break; }
        if(e)goto done;
        spine[spine_count++]=i;
        const struct li2_le_decoded *v=&out->node[i];
        if(!v->kind) { out->stop=v->stop;out->stop_pc=pc;break; }
        if(flow(v)==LI2_REGION_JMP) { out->stop=LI2_LE_JUMP;out->stop_pc=pc;break; }
        pc=v->scalar.decoded.next_pc;
    }
    for(unsigned at=0;at<spine_count;at++) {
        const struct li2_le_decoded *v=&out->node[spine[at]];const struct li2_span_decoded *d=&v->scalar;
        if(!v->kind || v->kind==LI2_LE_MOV || d->flow==LI2_REGION_NEXT || d->target>entry)continue;
        if(out->candidates==LI2_LE_HEADS) { e=LI2_LE_DISCOVERY_LIMIT;goto done; }
        struct li2_le_candidate *c=&out->candidate[out->candidates++];
        c->first=d->target;c->end=d->decoded.next_pc;c->latch=d->decoded.pc;c->result=LI2_LE_PREFIX;
        unsigned accepted;e=prefix(out,c->first,&accepted);if(e)goto done;if(!accepted)continue;
        struct li2_le_shape current;e=shape(out,c,&current);if(e)goto done;
        *c=current.choice;
        if(c->result!=LI2_LE_ELIGIBLE)continue;
        if(!out->eligible || better(c,&out->selected.choice))out->selected=current;
        ++out->eligible;
    }
    e=out->eligible?LI2_LE_OK:LI2_LE_NO_ENVELOPE;
    if(!e)out->ready=1;
 done:
    /* An incomplete discovery may have examined earlier candidates. It must
       never return their ready/selected shape as a usable partial success. */
    if(e)zero(&out->selected,sizeof out->selected);
    out->result=(unsigned)e;return e;
}
int li2_le_validate(const uintptr_t pages[2],const unsigned char source[2][LI2_LE_PAGE],uintptr_t entry,
    const struct li2_le_witness *w,struct li2_le_witness *scratch) {
    const void *host[4]={pages,source,w,scratch};
    const size_t sizes[4]={2*sizeof *pages,2*LI2_LE_PAGE,sizeof *w,sizeof *scratch};
    const size_t aligns[4]={_Alignof(uintptr_t),1,_Alignof(struct li2_le_witness),_Alignof(struct li2_le_witness)};
    if(!hosts(host,sizes,aligns,4))return LI2_LE_ARGUMENT;
    int e=li2_le_choose(pages,source,entry,scratch);
    return (unsigned)e!=w->result || !equal(w,scratch,sizeof *w)?LI2_LE_CORRUPT:0;
}
