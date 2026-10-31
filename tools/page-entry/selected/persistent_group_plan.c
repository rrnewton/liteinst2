#include "persistent_group_plan.h"
#include "linked_rseq.h"
#include "tf_owner.h"
static void zero(void *p,size_t n) { unsigned char *b=p;for(size_t i=0;i<n;i++)b[i]=0; }
static void copy(void *p,const void *q,size_t n) { unsigned char *b=p;const unsigned char *a=q;for(size_t i=0;i<n;i++)b[i]=a[i]; }
static int equal(const void *p,const void *q,size_t n) { const unsigned char *a=p,*b=q;for(size_t i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1; }
static int storage(const void *p,size_t n) { return p && (uintptr_t)p<=UINTPTR_MAX-n; }
static int overlap(uintptr_t a,size_t an,uintptr_t b,size_t bn) { return a<b+bn && b<a+an; }
static int address(uintptr_t p,size_t n) { return n && p<UINT64_C(0x800000000000) && n<=UINT64_C(0x800000000000)-p; }
static int displacement(uintptr_t next,uintptr_t target,uint32_t *out) {
    if(target>=next) { uintptr_t n=target-next;if(n>UINT32_C(0x7fffffff))return 0;*out=(uint32_t)n; }
    else { uintptr_t n=next-target;if(n>UINT32_C(0x80000000))return 0;*out=0U-(uint32_t)n; }
    return 1;
}
static void put32(unsigned char *p,uint32_t n) { for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(n>>(8*i)); }
static int location(const struct li2_pg_plan *p,uintptr_t pc,unsigned *page,unsigned *offset) {
    for(unsigned i=0;i<LI2_PE_SOURCES;i++)if(pc>=p->page[i] && pc-p->page[i]<LI2_REGION_PAGE) {
        *page=i;*offset=(unsigned)(pc-p->page[i]);return 1;
    }
    return 0;
}
static size_t window(const struct li2_pg_plan *p,uintptr_t pc,unsigned char out[15]) {
    zero(out,15);size_t n=0;
    for(;n<15;n++) {
        unsigned page,offset;
        if(pc>UINTPTR_MAX-n || !location(p,pc+n,&page,&offset))break;
        out[n]=p->source[page][offset];
    }
    return n;
}
static int describe(struct li2_pg_plan *p,uintptr_t pc,const unsigned char *b,size_t n,struct li2_span_decoded *d) {
    p->decoder_result=li2_decoder_span_describe(pc,b,n,d);
    if(p->decoder_result)return LI2_PG_DECODER;
    const struct li2_decoded *a=&d->decoded;
    if(d->version!=1 || a->abi_version!=1 || a->reserved || a->pc!=pc || a->available!=n ||
       !equal(a->bytes,b,n))return LI2_PG_DECODER;
    for(size_t i=n;i<16;i++)if(a->bytes[i])return LI2_PG_DECODER;
    if(a->decode_status!=LI2_VALID || !a->length || a->length>n || a->length>15 ||
       a->next_pc!=pc+a->length)return LI2_PG_BOUNDARY;
    if(d->ready>1 || (d->ready && d->refusal) || (!d->ready && !d->refusal))return LI2_PG_DECODER;
    return 0;
}
static int static_none(struct li2_pg_plan *p,const struct li2_span_decoded *d,const unsigned char *b,size_t n) {
    struct li2_write_footprint f={0};
    p->decoder_result=li2_decoder_link_none(d->decoded.pc,b,n,&f);
    if(p->decoder_result || f.abi_version!=1 || f.policy!=LI2_WRITE_NONE || f.first || f.end ||
       f.pc!=d->decoded.pc || f.next_pc!=d->decoded.next_pc || f.code!=d->decoded.code ||
       f.length!=d->decoded.length)return LI2_PG_DECODER;
    return 0;
}
static int writer(struct li2_pg_plan *p,const struct li2_span_decoded *d,const unsigned char *b,size_t n,struct li2_mg_store *s) {
    p->decoder_result=li2_decoder_mov_store(d->decoded.pc,b,n,s);
    if(p->decoder_result)return LI2_PG_DECODER;
    if(s->version!=1 || s->available!=n || s->reserved || s->ready>1 ||
       (s->ready && s->refusal) || (!s->ready && !s->refusal) ||
       s->tf.abi_version!=1 || s->tf.pc!=d->decoded.pc || s->tf.next_pc!=d->decoded.next_pc ||
       s->tf.code!=d->decoded.code || s->tf.length!=d->decoded.length || !equal(s->bytes,b,n))return LI2_PG_DECODER;
    for(size_t i=n;i<16;i++)if(s->bytes[i])return LI2_PG_DECODER;
    if(s->ready && (s->tf.policy!=1 || (s->width_bytes!=4 && s->width_bytes!=8)))return LI2_PG_DECODER;
    return 0;
}
#ifdef LI2_ADD_GUARD
static int add_writer(struct li2_pg_plan *p,const struct li2_span_decoded *d,
    const unsigned char *b,size_t n,struct li2_ag_descriptor *a) {
    p->decoder_result=li2_decoder_add_rmw(d->decoded.pc,b,n,a);
    if(p->decoder_result || a->version!=LI2_AG_VERSION || a->available!=n || a->reserved ||
       a->ready>1 || (a->ready?a->refusal!=0:a->refusal==0) ||
       a->tf.abi_version!=1 || a->tf.pc!=d->decoded.pc || a->tf.next_pc!=d->decoded.next_pc ||
       a->tf.code!=d->decoded.code || a->tf.length!=d->decoded.length || !equal(a->bytes,b,n))
        return LI2_PG_DECODER;
    for(size_t i=n;i<16;i++)if(a->bytes[i])return LI2_PG_DECODER;
    if(a->ready && (d->ready || d->refusal!=LI2_REGION_OPERANDS || d->decoded.kind!=LI2_NONE ||
       a->tf.policy!=1 || a->tf.code!=8 || a->width_bytes!=8 || a->memory_access!=3 ||
       a->flags_written!=LI2_AG_STATUS || a->source_reg>=16))return LI2_PG_DECODER;
    return 0;
}
#endif
static int guarded_write(unsigned kind) {
    return kind==LI2_PE_MOV
#ifdef LI2_ADD_GUARD
        || kind==LI2_PG_ADD
#endif
        ;
}
struct node { uintptr_t pc;unsigned decoded,token; };
static int enqueue(struct li2_pg_plan *p,struct node q[LI2_PG_HEADS+LI2_PG_BOUNDARIES],unsigned *n,uintptr_t pc) {
    unsigned page,offset;if(!location(p,pc,&page,&offset))return -1;
    for(unsigned i=0;i<*n;i++)if(q[i].pc==pc)return (int)i;
    if(*n==LI2_PG_HEADS+LI2_PG_BOUNDARIES)return -1;
    unsigned i=(*n)++;q[i].pc=pc;return (int)i;
}
static int resolve(const struct node *q,unsigned n,uintptr_t pc,unsigned *token) {
    for(unsigned i=0;i<n;i++)if(q[i].pc==pc && q[i].decoded) { *token=q[i].token;return 1; }
    return 0;
}
static int token_valid(const struct li2_pg_plan *p,unsigned k) {
    return k<p->heads || (k>=LI2_PG_HEADS && k-LI2_PG_HEADS<p->exits);
}
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
static int layout_valid(const struct li2_pg_layout *l) {
    uintptr_t a[5]={l->generated[0],l->generated[1],l->stubs,l->slots,l->spill};
    size_t n[5]={LI2_PE_IMAGE_BYTES,LI2_PE_IMAGE_BYTES,LI2_REGION_PAGE,LI2_REGION_PAGE,LI2_REGION_PAGE};
    for(unsigned i=0;i<5;i++) {
        if(a[i]<LI2_REGION_PAGE || (a[i]&4095U) || !address(a[i],n[i]))return 0;
        for(unsigned j=0;j<i;j++)if(overlap(a[i],n[i],a[j],n[j]))return 0;
    }
    if(l->directory<LI2_REGION_PAGE || (l->directory&4095U) ||
       !address(l->directory,LI2_JD_DOMAIN_BYTES))return 0;
    for(unsigned i=0;i<5;i++)if(overlap(l->directory,LI2_JD_DOMAIN_BYTES,a[i],n[i]))return 0;
    return 1;
}
#else
static int layout_valid(const struct li2_pg_layout *l) {
    uintptr_t a[5]={l->generated[0],l->generated[1],l->stubs,l->slots,l->spill};
    size_t n[5]={LI2_PE_IMAGE_BYTES,LI2_PE_IMAGE_BYTES,LI2_REGION_PAGE,LI2_REGION_PAGE,LI2_REGION_PAGE};
    for(unsigned i=0;i<5;i++) {
        if(a[i]<LI2_REGION_PAGE || (a[i]&4095U) || !address(a[i],n[i]))return 0;
        for(unsigned j=0;j<i;j++)if(overlap(a[i],n[i],a[j],n[j]))return 0;
    }
    return 1;
}
#endif
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
int li2_pg_dispatch_binding(const uintptr_t pages[2],const struct li2_pg_layout *layout,
    uintptr_t table,unsigned heads,unsigned head,struct li2_jd_binding *out) {
    const void *host[3]={pages,layout,out};
    const size_t size[3]={2*sizeof *pages,sizeof *layout,sizeof *out};
    const size_t align[3]={_Alignof(uintptr_t),_Alignof(struct li2_pg_layout),_Alignof(struct li2_jd_binding)};
    for(unsigned i=0;i<3;i++) {
        if(!storage(host[i],size[i]) || (uintptr_t)host[i]%align[i])return LI2_PG_ARGUMENT;
        for(unsigned j=0;j<i;j++)if(overlap((uintptr_t)host[i],size[i],(uintptr_t)host[j],size[j]))return LI2_PG_ARGUMENT;
    }
    zero(out,sizeof *out);
    const size_t table_offset=offsetof(struct li2_pg_plan,table),row_offset=offsetof(struct li2_pg_plan,original);
    if(!heads || heads>LI2_PG_HEADS || head>=heads || !layout_valid(layout) ||
       pages[0]>=pages[1] || (pages[0]&4095U) || (pages[1]&4095U) ||
       !address(pages[0],LI2_REGION_PAGE) || !address(pages[1],LI2_REGION_PAGE) ||
       table<table_offset || (table&7U) || !address(table,sizeof(struct li2_mg_table)))return LI2_PG_ARGUMENT;
    const uintptr_t base=table-table_offset;
    if(base<LI2_REGION_PAGE || !address(base,table_offset+sizeof(struct li2_mg_table)) ||
       row_offset>table_offset || sizeof(((struct li2_pg_plan *)0)->original)>table_offset-row_offset)return LI2_PG_ARGUMENT;
    const uintptr_t rows=base+row_offset;
    const size_t bytes=sizeof(((struct li2_pg_plan *)0)->original);
    const uintptr_t at[7]={pages[0],pages[1],layout->generated[0],layout->generated[1],layout->stubs,layout->slots,layout->spill};
    const size_t extents[7]={LI2_REGION_PAGE,LI2_REGION_PAGE,LI2_PE_IMAGE_BYTES,LI2_PE_IMAGE_BYTES,
        LI2_REGION_PAGE,LI2_REGION_PAGE,LI2_REGION_PAGE};
    if(!address(rows,bytes))return LI2_PG_ARGUMENT;
    for(unsigned i=0;i<7;i++)if(overlap(rows,bytes,at[i],extents[i]))return LI2_PG_ARGUMENT;
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
    if(overlap(layout->directory,LI2_JD_DOMAIN_BYTES,base,table_offset+sizeof(struct li2_mg_table)))return LI2_PG_ARGUMENT;
    for(unsigned i=0;i<2;i++)if(overlap(layout->directory,LI2_JD_DOMAIN_BYTES,pages[i],LI2_REGION_PAGE))return LI2_PG_ARGUMENT;
    *out=(struct li2_jd_binding){rows,{layout->generated[0],layout->generated[1]},heads,head,layout->directory};
#else
    *out=(struct li2_jd_binding){rows,{layout->generated[0],layout->generated[1]},heads,head};
#endif
    return 0;
}
static int dispatch_form(const unsigned char *bytes,size_t n) {
    if(!n)return 0;
    const unsigned prefix=bytes[0]==0x41?1U:0U;
    return n>=prefix+2U && bytes[prefix]==0xff && bytes[prefix+1]>=0xe0 && bytes[prefix+1]<=0xe7;
}
static int dispatch_describe(struct li2_pg_plan *p,const struct li2_span_decoded *d,
    const unsigned char *bytes,size_t n,struct li2_jd_descriptor *out) {
    p->decoder_result=(unsigned)li2_jd_describe(d->decoded.pc,bytes,n,out);
    if(p->decoder_result || out->version!=LI2_JD_VERSION || out->ready!=1 || out->refusal ||
       out->available!=n || !equal(&out->decoded,&d->decoded,sizeof d->decoded))return LI2_PG_DECODER;
    struct li2_span_decoded expected={0};
    expected.decoded=out->decoded;expected.version=1;expected.refusal=LI2_REGION_UNSUPPORTED;
    return equal(d,&expected,sizeof expected)?0:LI2_PG_DECODER;
}
#endif
static uintptr_t head_generated(const struct li2_pg_plan *p,unsigned i) {
    return p->layout.generated[i/LI2_PE_HEADS]+(uintptr_t)(i%LI2_PE_HEADS)*LI2_PE_SLOT_BYTES;
}
static unsigned char *head_image(struct li2_pg_plan *p,unsigned i) {
    return p->image[i/LI2_PE_HEADS]+(size_t)(i%LI2_PE_HEADS)*LI2_PE_SLOT_BYTES;
}
static uintptr_t destination(const struct li2_pg_plan *p,unsigned i,unsigned ordinal) {
    const unsigned k=p->head[i].successors[ordinal];
    if(k>=LI2_PG_HEADS)return p->exit_pc[k-LI2_PG_HEADS];
    if(k/LI2_PE_HEADS==i/LI2_PE_HEADS)return head_generated(p,k);
    for(unsigned j=0;j<p->links;j++)
        if(p->edge[j].source_head==i && p->edge[j].successor==ordinal)return p->edge[j].stub;
    return 0;
}
static int jump(struct li2_pg_plan *p,unsigned i,unsigned offset,uintptr_t target) {
    uint32_t d;unsigned char *image=head_image(p,i);image[offset]=0xe9;
    if(!displacement(head_generated(p,i)+offset+5,target,&d))return 0;
    put32(image+offset+1,d);return 1;
}
static int same_effects(const struct li2_span_decoded *a,const struct li2_span_decoded *b) {
    struct li2_span_decoded x,y;copy(&x,a,sizeof x);copy(&y,b,sizeof y);
    x.decoded.pc=y.decoded.pc=0;x.decoded.next_pc=y.decoded.next_pc=0;
    x.decoded.available=y.decoded.available=0;zero(x.decoded.bytes,16);zero(y.decoded.bytes,16);
    if(a->flow!=LI2_REGION_NEXT) {
        x.decoded.code=y.decoded.code=0;x.decoded.length=y.decoded.length=0;x.target=y.target=0;
        if(x.operand_count!=1 || y.operand_count!=1 || x.operands[0].kind!=LI2_REGION_BRANCH || y.operands[0].kind!=LI2_REGION_BRANCH)return 0;
        x.operands[0].immediate=y.operands[0].immediate=0;x.operands[0].encoding_bits=y.operands[0].encoding_bits=0;
    }
    return equal(&x,&y,sizeof x);
}
static int synthetic(const struct li2_span_decoded *d,uintptr_t target) {
    return d->ready==1 && d->flow==LI2_REGION_JMP && d->target==target && d->decoded.length==5 &&
        d->condition==LI2_REGION_CONDITION_NONE && d->operand_count==1 && d->operands[0].kind==LI2_REGION_BRANCH &&
        d->operands[0].encoding_bits==32 && !d->register_count && !d->memory_count && !d->address_count &&
        !d->relocation && !d->rip_target && !d->displacement_offset && !d->displacement_bytes &&
        !d->flags_read && !d->flags_written && !d->flags_set && !d->flags_cleared && !d->flags_undefined &&
        !d->gpr_read && !d->gpr_write;
}
static void pgd_mark(struct li2_pg_miss *m,unsigned reason,unsigned site,uintptr_t pc,uint64_t detail) {
    m->reason=reason;m->site=site;m->pc=pc;m->detail=detail;
}
static void pgd_source_boundary(const struct li2_span_decoded *d,size_t n,struct li2_pg_miss *m) {
    const struct li2_decoded *a=&d->decoded;
    unsigned reason=a->decode_status==LI2_INVALID?LI2_PGD_SOURCE_INVALID:
        a->decode_status==LI2_TRUNCATED?LI2_PGD_SOURCE_TRUNCATED:0;
    if(!reason || !n || n>15 || !a->length || a->length>n || a->next_pc!=a->pc+a->length ||
       a->code!=0 || a->kind!=LI2_NONE || a->destination!=16 || a->width_bits || a->step_disposition!=LI2_STEP_INVALID)return;
    struct li2_span_decoded expected={0};expected.decoded=*a;expected.version=1;
    expected.refusal=reason==LI2_PGD_SOURCE_INVALID?LI2_REGION_INVALID:LI2_REGION_TRUNCATED;
    if(equal(d,&expected,sizeof expected))pgd_mark(m,reason,LI2_PGD_SOURCE,a->pc,n);
}
static void pgd_enqueue_refusal(const struct li2_pg_plan *p,const struct node *q,unsigned n,
    uintptr_t origin,uintptr_t target,struct li2_pg_miss *m) {
    unsigned page,offset;
    if(!location(p,target,&page,&offset)) {pgd_mark(m,LI2_PGD_OUTSIDE_PAIR,LI2_PGD_SOURCE,origin,target);return;}
    for(unsigned i=0;i<n;i++)if(q[i].pc==target)return;
    if(n==LI2_PG_HEADS+LI2_PG_BOUNDARIES)pgd_mark(m,LI2_PGD_QUEUE_LIMIT,LI2_PGD_SOURCE,origin,n);
}
/* The unchanged guard returns one relocation code for several sites. Classify
   only an actual retained early-LEA, late-store or successor-JMP reach failure.
   Internal/spill failures and malformed displacement metadata stay terminal. */
static int pgd_guard_reach(const struct li2_pg_plan *p,unsigned i,struct li2_pg_miss *m) {
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
    const struct li2_mg_plan *g=&p->guard[i].mov;const struct li2_mg_store *s=&p->instruction[i].mov;
#else
    const struct li2_mg_plan *g=&p->guard[i];const struct li2_mg_store *s=&p->store_original[i];
#endif
    const struct li2_pe_head *h=&p->head[i];uint32_t delta;
    if(g->version!=1 || g->ready || g->result!=LI2_MG_RELOCATION || g->reserved ||
       g->generated!=head_generated(p,i) || g->spill!=p->layout.spill ||
       !token_valid(p,h->successors[0]) || g->successor!=destination(p,i,0) ||
       !equal(&g->original,s,sizeof *s) || !equal(&g->table,&p->table,sizeof p->table) ||
       !g->boundaries || g->boundaries>LI2_MG_BOUNDARIES || g->image_bytes>LI2_MG_CODE_BYTES ||
       s->tf.length>15 || s->modrm_offset!=s->opcode_offset+1 || s->opcode_offset>1 ||
       s->source_kind<1 || s->source_kind>2 || s->rip_relative>1)return 0;
    unsigned immediate=s->source_kind==2?4:0;
    if(s->tf.length<immediate)return 0;
    unsigned end=s->tf.length-immediate;
    if(end<=s->modrm_offset || end-s->modrm_offset>6)return 0;
    unsigned en=2+end-s->modrm_offset;
    /* Every possible spill store/load within the bounded512-byte guard must
       fit, including both restore paths. A far/borderline spill remains
       terminal even if a separate external displacement also fails. */
    for(unsigned j=0;j<4;j++)
        if(!displacement(g->generated+7,g->spill+8*j,&delta) ||
           !displacement(g->generated+LI2_MG_CODE_BYTES,g->spill+8*j,&delta))return 0;
    if(s->rip_relative) {
        if(s->displacement_bytes!=4 || s->displacement_offset<s->modrm_offset ||
           s->displacement_offset>s->tf.length || s->tf.length-s->displacement_offset<4 ||
           2+s->displacement_offset-s->modrm_offset+4>en)return 0;
        if(g->image_bytes==28 && g->boundaries==4 && !g->store_offset && !g->reject_offset &&
           !displacement(g->generated+28+en,s->rip_target,&delta)) {
            pgd_mark(m,LI2_PGD_GUARD_RIP_REACH,LI2_PGD_EMIT,s->tf.pc,s->rip_target);return 1;
        }
        if(!displacement(g->generated+28+en,s->rip_target,&delta))return 0;
        if(g->store_offset && g->image_bytes==g->store_offset && !g->reject_offset &&
           !displacement(g->generated+g->store_offset+s->tf.length,s->rip_target,&delta)) {
            pgd_mark(m,LI2_PGD_GUARD_RIP_REACH,LI2_PGD_EMIT,s->tf.pc,s->rip_target);return 1;
        }
        if(!g->store_offset || !displacement(g->generated+g->store_offset+s->tf.length,s->rip_target,&delta))return 0;
    }
    const struct li2_mg_boundary *b=&g->boundary[g->boundaries-1];
    if(g->store_offset && !g->reject_offset && b->length==5 && b->phase==LI2_MG_AFTER &&
       b->flags==LI2_MG_PHYSICAL && b->dirty==0 && b->spill_valid==15 &&
       b->offset>=g->store_offset+s->tf.length && b->offset+5==g->image_bytes &&
       !displacement(g->generated+b->offset+5,g->successor,&delta)) {
        pgd_mark(m,LI2_PGD_GUARD_FOLLOW_REACH,LI2_PGD_EMIT,s->tf.pc,g->successor);return 1;
    }
    return 0;
}

/* A selected effect is outside both generated inventories. Authenticate the
   complete original decoder row independently, then require both descriptive
   refusals literally. A failed extra API call or any mismatch leaves the same
   unready group result and plan bytes untouched; it grants no cancellation. */
static int pgd_root_selected(const struct li2_span_decoded *d,const struct li2_mg_store *s,
                             const unsigned char *bytes,size_t count) {
    if(d->decoded.kind<LI2_CPUID || d->decoded.kind>LI2_SYSCALL)return 0;
    struct li2_decoded decoded={0};
    const uint32_t result=li2_decoder_decode(d->decoded.pc,bytes,count,&decoded);
    if(result || !equal(&decoded,&d->decoded,sizeof decoded))return 0;
    struct li2_span_decoded span={0};
    span.decoded=decoded;span.version=1;span.refusal=LI2_REGION_EFFECTS;
    if(!equal(d,&span,sizeof span))return 0;
    struct li2_mg_store store={0};
    store.tf.pc=decoded.pc;store.tf.next_pc=decoded.next_pc;store.tf.abi_version=1;
    store.tf.code=decoded.code;store.tf.length=decoded.length;
    copy(store.bytes,decoded.bytes,sizeof store.bytes);
    store.version=1;store.refusal=1;store.available=(uint32_t)count;
    return equal(s,&store,sizeof store);
}
static int pgd_graph(struct li2_pg_plan *p,struct li2_pg_miss *miss) {
    struct node q[LI2_PG_HEADS+LI2_PG_BOUNDARIES]={0};unsigned n=0;
    unsigned char occupied[LI2_PE_SOURCES][LI2_REGION_PAGE]={{0}};
    if(enqueue(p,q,&n,p->entry)!=0)return LI2_PG_GRAPH;
    for(unsigned at=0;at<n;at++) {
        unsigned char bytes[15];size_t count=window(p,q[at].pc,bytes);
        struct li2_span_decoded d;struct li2_mg_store s={0};
#ifdef LI2_ADD_GUARD
        struct li2_ag_descriptor add={0};
#endif
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
        struct li2_jd_descriptor dispatch={0};
#endif
        int e=describe(p,q[at].pc,bytes,count,&d);if(e) {
            if(e==LI2_PG_BOUNDARY)pgd_source_boundary(&d,count,miss);
            return e;
        }
        for(unsigned j=0;j<d.decoded.length;j++) {
            unsigned page,offset;if(!location(p,q[at].pc+j,&page,&offset))return LI2_PG_GRAPH;
            if(occupied[page][offset]) {pgd_mark(miss,LI2_PGD_SOURCE_OVERLAP,LI2_PGD_SOURCE,q[at].pc,q[at].pc+j);return LI2_PG_GRAPH;}
            occupied[page][offset]=1;p->source_mask|=1U<<page;
        }
        unsigned kind=LI2_PE_NONE;
        if(d.ready) { if((e=static_none(p,&d,bytes,count)))return e; }
        else { if((e=writer(p,&d,bytes,count,&s)))return e;kind=s.ready?LI2_PE_MOV:0; }
#ifdef LI2_ADD_GUARD
        if(!kind) {
            if((e=add_writer(p,&d,bytes,count,&add)))return e;
            if(add.ready)kind=LI2_PG_ADD;
        }
#endif
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
        if(!kind && dispatch_form(bytes,count)) {
            if((e=dispatch_describe(p,&d,bytes,count,&dispatch)))return e;
            kind=LI2_PG_DISPATCH;
        }
#endif
        q[at].decoded=1;
        if(!kind) {
            if(!at) {
                if(d.decoded.kind!=LI2_NONE) {
                    if(pgd_root_selected(&d,&s,bytes,count))
                        pgd_mark(miss,LI2_PGD_ROOT_SELECTED,LI2_PGD_SOURCE,q[at].pc,d.decoded.kind);
                } else if(d.refusal==LI2_REGION_UNSUPPORTED || d.refusal==LI2_REGION_PREFIX || d.refusal==LI2_REGION_OPERANDS)
                    pgd_mark(miss,LI2_PGD_ROOT_UNSUPPORTED,LI2_PGD_SOURCE,q[at].pc,d.refusal);
                return LI2_PG_MISS;
            }
            if(p->exits==LI2_PG_BOUNDARIES) {pgd_mark(miss,LI2_PGD_EXIT_LIMIT,LI2_PGD_SOURCE,q[at].pc,p->exits);return LI2_PG_GRAPH;}
            unsigned x=p->exits++;p->frontier[x]=d;p->exit_pc[x]=q[at].pc;q[at].token=LI2_PG_HEADS+x;continue;
        }
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
        if(kind==LI2_PG_DISPATCH && p->exits==LI2_PG_BOUNDARIES) {
            pgd_mark(miss,LI2_PGD_EXIT_LIMIT,LI2_PGD_SOURCE,q[at].pc,p->exits);return LI2_PG_GRAPH;
        }
#endif
        if(p->heads==LI2_PG_HEADS) {pgd_mark(miss,LI2_PGD_HEAD_LIMIT,LI2_PGD_SOURCE,q[at].pc,p->heads);return LI2_PG_GRAPH;}
        unsigned i=p->heads++;++p->member_heads[i/LI2_PE_HEADS];
        struct li2_pe_head *h=&p->head[i];q[at].token=i;
        if(!location(p,q[at].pc,&h->source_page,&h->source_offset))return LI2_PG_GRAPH;
        h->kind=kind;h->source_length=d.decoded.length;p->source_bytes+=h->source_length;p->original[i]=d;
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
        if(kind==LI2_PE_MOV) { p->instruction[i].mov=s;++p->stores; }
#ifdef LI2_ADD_GUARD
        if(kind==LI2_PG_ADD) { p->instruction[i].add=add;++p->stores; }
#endif
        if(kind==LI2_PG_DISPATCH) {
            p->instruction[i].dispatch=dispatch;
            /* This is one real BEFORE-JMP unknown-target exit, not a static
               successor or a second ownership claim for the same bytes. */
            unsigned x=p->exits++;p->frontier[x]=d;p->exit_pc[x]=q[at].pc;
            continue;
        }
#else
        if(kind==LI2_PE_MOV) { p->store_original[i]=s;++p->stores; }
#endif
        unsigned flow=guarded_write(kind)?LI2_REGION_NEXT:d.flow;
        if(flow==LI2_REGION_NEXT) {
            if(enqueue(p,q,&n,d.decoded.next_pc)<0) {pgd_enqueue_refusal(p,q,n,q[at].pc,d.decoded.next_pc,miss);return LI2_PG_GRAPH;}
        } else if(flow==LI2_REGION_JCC || flow==LI2_REGION_JMP) {
            if(enqueue(p,q,&n,d.target)<0) {pgd_enqueue_refusal(p,q,n,q[at].pc,d.target,miss);return LI2_PG_GRAPH;}
            if(flow==LI2_REGION_JCC && enqueue(p,q,&n,d.decoded.next_pc)<0) {pgd_enqueue_refusal(p,q,n,q[at].pc,d.decoded.next_pc,miss);return LI2_PG_GRAPH;}
        } else return LI2_PG_DECODER;
    }
    if(!p->heads || !p->exits) {
        if(p->heads && !p->exits)pgd_mark(miss,LI2_PGD_NO_EXIT,LI2_PGD_SOURCE,p->entry,p->heads);
        return LI2_PG_GRAPH;
    }
    for(unsigned i=0;i<p->heads;i++) {
        struct li2_pe_head *h=&p->head[i];const struct li2_span_decoded *d=&p->original[i];
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
        if(h->kind==LI2_PG_DISPATCH)continue;
#endif
        unsigned flow=guarded_write(h->kind)?LI2_REGION_NEXT:d->flow;
        h->successor_count=flow==LI2_REGION_JCC?2:1;
        if(!resolve(q,n,flow==LI2_REGION_NEXT?d->decoded.next_pc:d->target,&h->successors[0]) ||
           (h->successor_count==2 && !resolve(q,n,d->decoded.next_pc,&h->successors[1])))return LI2_PG_GRAPH;
    }
#if !defined(LI2_PERSISTENT_DISPATCH) || LI2_PERSISTENT_DISPATCH != 1
    if(p->heads<=LI2_PE_HEADS) {
        pgd_mark(miss,LI2_PGD_SINGLE_MEMBER,LI2_PGD_SOURCE,p->entry,p->heads);return LI2_PG_MISS;
    }
#endif
    for(unsigned i=0;i<p->heads;i++)for(unsigned j=0;j<p->head[i].successor_count;j++) {
        unsigned k=p->head[i].successors[j];
        if(!token_valid(p,k))return LI2_PG_GRAPH;
        if(k>=LI2_PG_HEADS || k/LI2_PE_HEADS==i/LI2_PE_HEADS)continue;
        if(p->links+p->exits==LI2_PG_BOUNDARIES) {
            pgd_mark(miss,LI2_PGD_LINK_LIMIT,LI2_PGD_SOURCE,p->original[i].decoded.pc,p->links+p->exits);
            return LI2_PG_GRAPH;
        }
        unsigned x=p->links++;
        p->edge[x]=(struct li2_pg_edge){LI2_PG_CAPACITY_LINK,i,j,k,
            p->original[k].decoded.pc,head_generated(p,k),p->layout.stubs+6*x,p->layout.slots+8*x};
    }
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
    if(p->member_heads[0]!=(p->heads<LI2_PE_HEADS?p->heads:LI2_PE_HEADS) ||
       p->member_heads[1]!=(p->heads>LI2_PE_HEADS?p->heads-LI2_PE_HEADS:0) ||
       (p->heads>LI2_PE_HEADS?!p->links:p->links!=0))return LI2_PG_GRAPH;
#else
    if(p->member_heads[0]!=LI2_PE_HEADS || !p->member_heads[1] ||
       p->member_heads[1]>LI2_PE_HEADS || !p->links)return LI2_PG_GRAPH;
#endif
    /* One global BFS and byte-ownership map, then deterministic partition.
       Every queued original PC has exactly one complete resolved token. */
    return 0;
}
static int emit_stubs(struct li2_pg_plan *p) {
    for(unsigned i=0;i<LI2_PG_STUB_BYTES;i++)p->stub_image[i]=0xcc;
    for(unsigned j=0;j<p->links;j++) {
        const struct li2_pg_edge *e=&p->edge[j];uint32_t delta;
        unsigned char *b=p->stub_image+6*j;
        if(e->kind!=LI2_PG_CAPACITY_LINK || e->source_head>=p->heads || e->target_head>=p->heads ||
           e->successor>=p->head[e->source_head].successor_count ||
           p->head[e->source_head].successors[e->successor]!=e->target_head ||
           e->source_head/LI2_PE_HEADS==e->target_head/LI2_PE_HEADS ||
           e->original_target!=p->original[e->target_head].decoded.pc ||
           e->generated_target!=head_generated(p,e->target_head) ||
           e->stub!=p->layout.stubs+6*j || e->slot!=p->layout.slots+8*j ||
           !displacement(e->stub+6,e->slot,&delta))return LI2_PG_CORRUPT;
        b[0]=0xff;b[1]=0x25;put32(b+2,delta);
        struct li2_decoded actual={0},expected={0};
        expected.pc=e->stub;expected.next_pc=e->stub+6;expected.abi_version=1;
        expected.code=765;expected.destination=16;expected.available=6;expected.length=6;
        copy(expected.bytes,b,6);
        p->decoder_result=li2_decoder_decode(e->stub,b,6,&actual);
        if(p->decoder_result || !equal(&actual,&expected,sizeof actual))return LI2_PG_DECODER;
        struct li2_tf_classification tf={0},wanted={e->stub,e->stub+6,1,1,765,6,2,3};
        p->decoder_result=li2_decoder_tf_classify(e->stub,b,6,&tf);
        if(p->decoder_result || !equal(&tf,&wanted,sizeof tf))return LI2_PG_DECODER;
    }
    return 0;
}
static int pgd_emit(struct li2_pg_plan *p,struct li2_pg_miss *miss) {
    for(unsigned m=0;m<LI2_PG_MEMBERS;m++)for(unsigned i=0;i<LI2_PE_IMAGE_BYTES;i++)p->image[m][i]=0xcc;
    int stub_result=emit_stubs(p);if(stub_result)return stub_result;
    for(unsigned i=0;i<p->heads;i++) {
        struct li2_pe_head *h=&p->head[i];const struct li2_span_decoded *d=&p->original[i];
        uintptr_t generated=head_generated(p,i);unsigned char *out=head_image(p,i);
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
        if(h->kind==LI2_PG_DISPATCH) {
            struct li2_jd_binding binding;
            if(h->successor_count || h->successors[0] || h->successors[1] ||
               li2_pg_dispatch_binding(p->page,&p->layout,p->table.address,p->heads,i,&binding))return LI2_PG_CORRUPT;
            unsigned exits=0;
            for(unsigned j=0;j<p->exits;j++)if(p->exit_pc[j]==d->decoded.pc) {
                if(!equal(&p->frontier[j],d,sizeof *d))return LI2_PG_CORRUPT;
                ++exits;
            }
            if(exits!=1)return LI2_PG_CORRUPT;
            unsigned char bytes[15];size_t n=window(p,d->decoded.pc,bytes);
            struct li2_jd_plan *g=&p->guard[i].dispatch;
            p->guard_result=(unsigned)li2_jd_emit(d->decoded.pc,bytes,n,generated,p->layout.spill,&binding,g);
            /* Exact original source and all generated bytes reconstruct below.
               An unclassified emitter error is terminal, never cold cancel. */
            if(p->guard_result)return p->guard_result==LI2_JD_RELOCATION?LI2_PG_RELOCATION:LI2_PG_DECODER;
            if(!equal(&g->original,&p->instruction[i].dispatch,sizeof g->original) ||
               !equal(&g->binding,&binding,sizeof binding) || g->record.ready!=1 ||
               !g->record.image_bytes || g->record.image_bytes>LI2_PE_SLOT_BYTES ||
               g->generated!=generated || g->spill!=p->layout.spill)return LI2_PG_DECODER;
            h->generated_length=g->record.image_bytes;copy(out,g->image,h->generated_length);continue;
        }
#endif
#ifdef LI2_ADD_GUARD
        if(h->kind==LI2_PG_ADD) {
            unsigned char bytes[15];size_t n=window(p,d->decoded.pc,bytes);
            struct li2_ag_plan *g=&p->guard[i].add;
            p->guard_result=(unsigned)li2_ag_emit(d->decoded.pc,bytes,n,generated,p->layout.spill,
                destination(p,i,0),&p->table,g);
            /* Until a distinct ADD relocation diagnosis exists, an emitter
               refusal remains terminal; never borrow a MOV cancellation. */
            if(p->guard_result)return p->guard_result==LI2_AG_RELOCATION?LI2_PG_RELOCATION:LI2_PG_DECODER;
            if(!equal(&g->original,&p->instruction[i].add,sizeof g->original) ||
               g->ready!=1 || !g->image_bytes || g->image_bytes>LI2_PE_SLOT_BYTES ||
               !equal(&g->table,&p->table,sizeof p->table))return LI2_PG_DECODER;
            h->generated_length=g->image_bytes;copy(out,g->image,h->generated_length);continue;
        }
#endif
        if(h->kind==LI2_PE_MOV) {
            unsigned char bytes[15];size_t n=window(p,d->decoded.pc,bytes);
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
            p->guard_result=(unsigned)li2_mg_emit(d->decoded.pc,bytes,n,generated,p->layout.spill,
                destination(p,i,0),&p->table,&p->guard[i].mov);
#else
            p->guard_result=(unsigned)li2_mg_emit(d->decoded.pc,bytes,n,generated,p->layout.spill,
                destination(p,i,0),&p->table,&p->guard[i]);
#endif
            if(p->guard_result) {
                if(p->guard_result==LI2_MG_RELOCATION)pgd_guard_reach(p,i,miss);
                return p->guard_result==LI2_MG_RELOCATION?LI2_PG_RELOCATION:LI2_PG_DECODER;
            }
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
            if(!equal(&p->guard[i].mov.original,&p->instruction[i].mov,sizeof p->instruction[i].mov) ||
               !p->guard[i].mov.ready || !p->guard[i].mov.image_bytes || p->guard[i].mov.image_bytes>LI2_PE_SLOT_BYTES ||
               !equal(&p->guard[i].mov.table,&p->table,sizeof p->table))return LI2_PG_DECODER;
            h->generated_length=p->guard[i].mov.image_bytes;copy(out,p->guard[i].mov.image,h->generated_length);continue;
#else
            if(!equal(&p->guard[i].original,&p->store_original[i],sizeof p->store_original[i]) ||
               !p->guard[i].ready || !p->guard[i].image_bytes || p->guard[i].image_bytes>LI2_PE_SLOT_BYTES ||
               !equal(&p->guard[i].table,&p->table,sizeof p->table))return LI2_PG_DECODER;
            h->generated_length=p->guard[i].image_bytes;copy(out,p->guard[i].image,h->generated_length);continue;
#endif
        }
        unsigned flow=d->flow,length=flow==LI2_REGION_NEXT?h->source_length:flow==LI2_REGION_JCC?6:5;
        h->generated_length=length+(flow==LI2_REGION_JMP?0:5);
        if(flow==LI2_REGION_NEXT) {
            copy(out,d->decoded.bytes,h->source_length);
            if(d->relocation==LI2_SPAN_RIP_DISP32) {
                uint32_t delta;
                if(d->displacement_bytes!=4 || d->displacement_offset>h->source_length || h->source_length-d->displacement_offset<4)return LI2_PG_RELOCATION;
                if(!displacement(generated+length,d->rip_target,&delta)) {
                    pgd_mark(miss,LI2_PGD_RIP_REACH,LI2_PGD_EMIT,d->decoded.pc,d->rip_target);return LI2_PG_RELOCATION;
                }
                put32(out+d->displacement_offset,delta);
            } else if(d->relocation || d->rip_target || d->displacement_offset || d->displacement_bytes)return LI2_PG_DECODER;
        } else if(flow==LI2_REGION_JCC) {
            uint32_t delta;if(d->condition>15)return LI2_PG_DECODER;
            out[0]=0x0f;out[1]=(unsigned char)(0x80+d->condition);
            if(!displacement(generated+6,destination(p,i,0),&delta)) {
                pgd_mark(miss,LI2_PGD_BRANCH_REACH,LI2_PGD_EMIT,d->decoded.pc,destination(p,i,0));return LI2_PG_RELOCATION;
            }
            put32(out+2,delta);
        } else if(!jump(p,i,0,destination(p,i,0))) {
            pgd_mark(miss,LI2_PGD_BRANCH_REACH,LI2_PGD_EMIT,d->decoded.pc,destination(p,i,0));return LI2_PG_RELOCATION;
        }
        struct li2_span_decoded actual;int e=describe(p,generated,out,15,&actual);if(e)return e;
        if(!actual.ready || actual.decoded.length!=length || !same_effects(d,&actual) ||
           (flow!=LI2_REGION_NEXT && actual.target!=destination(p,i,0)))return LI2_PG_DECODER;
        if(flow!=LI2_REGION_JMP) {
            unsigned k=flow==LI2_REGION_JCC?1:0;
            if(!jump(p,i,length,destination(p,i,k))) {
                pgd_mark(miss,LI2_PGD_FALLTHROUGH_REACH,LI2_PGD_EMIT,d->decoded.pc,destination(p,i,k));return LI2_PG_RELOCATION;
            }
            e=describe(p,generated+length,out+length,15,&actual);if(e)return e;
            if(!synthetic(&actual,destination(p,i,k)))return LI2_PG_DECODER;
        }
    }
    return 0;
}
int li2_pg_plan_pages(const uintptr_t pages[2],const unsigned char source[2][LI2_REGION_PAGE],
    uintptr_t entry,const struct li2_pg_layout *layout,const struct li2_mg_table *table,
    struct li2_pg_plan *out,struct li2_pg_miss *miss) {
    const void *host[6]={pages,source,layout,table,out,miss};
    const size_t size[6]={2*sizeof *pages,2*LI2_REGION_PAGE,sizeof *layout,sizeof *table,sizeof *out,sizeof *miss};
    const size_t align[6]={_Alignof(uintptr_t),1,_Alignof(struct li2_pg_layout),_Alignof(struct li2_mg_table),
        _Alignof(struct li2_pg_plan),_Alignof(struct li2_pg_miss)};
    for(unsigned i=0;i<6;i++) {
        if(!storage(host[i],size[i]) || (uintptr_t)host[i]%align[i])return LI2_PG_ARGUMENT;
        for(unsigned j=0;j<i;j++)if(overlap((uintptr_t)host[i],size[i],(uintptr_t)host[j],size[j]))return LI2_PG_ARGUMENT;
    }
    zero(miss,sizeof *miss);miss->version=LI2_PG_VERSION;
    zero(out,sizeof *out);out->version=LI2_PG_VERSION;out->bytes=sizeof *out;
    int e=LI2_PG_ARGUMENT;
    if(!layout_valid(layout) || li2_mg_table_validate(table) || pages[0]>=pages[1])goto done;
    uintptr_t at[8]={pages[0],pages[1],layout->generated[0],layout->generated[1],layout->stubs,layout->slots,layout->spill,table->address};
    size_t bytes[8]={LI2_REGION_PAGE,LI2_REGION_PAGE,LI2_PE_IMAGE_BYTES,LI2_PE_IMAGE_BYTES,
        LI2_REGION_PAGE,LI2_REGION_PAGE,LI2_REGION_PAGE,sizeof *table};
    for(unsigned i=0;i<8;i++) {
        if(!address(at[i],bytes[i]) || (i<2 && (at[i]&4095U)))goto done;
        for(unsigned j=0;j<i;j++)if(overlap(at[i],bytes[i],at[j],bytes[j]))goto done;
    }
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
    for(unsigned i=0;i<8;i++)if(overlap(layout->directory,LI2_JD_DOMAIN_BYTES,at[i],bytes[i]))goto done;
#endif
    copy(out->page,pages,sizeof out->page);copy(out->source,source,sizeof out->source);
    out->entry=entry;out->layout=*layout;copy(&out->table,table,sizeof *table);
    unsigned page,offset;if(!location(out,entry,&page,&offset))goto done;
    e=pgd_graph(out,miss);if(!e)e=pgd_emit(out,miss);if(!e)out->ready=1;
 done:out->result=(unsigned)e;miss->status=(unsigned)e;return e;
}
int li2_pg_plan_validate(const struct li2_pg_plan *p,struct li2_pg_plan *scratch) {
    if(!storage(p,sizeof *p) || !storage(scratch,sizeof *scratch) ||
       (uintptr_t)p%_Alignof(struct li2_pg_plan) || (uintptr_t)scratch%_Alignof(struct li2_pg_plan) ||
       overlap((uintptr_t)p,sizeof *p,(uintptr_t)scratch,sizeof *scratch))return LI2_PG_ARGUMENT;
    if(p->version!=LI2_PG_VERSION || p->bytes!=sizeof *p || p->ready!=1 || p->result || p->reserved || p->reserved2)
        return LI2_PG_CORRUPT;
    struct li2_pg_miss miss;
    int e=li2_pg_plan_pages(p->page,p->source,p->entry,&p->layout,&p->table,scratch,&miss);
    struct li2_pg_miss empty={.version=LI2_PG_VERSION};
    return e || !equal(&miss,&empty,sizeof miss) || !equal(p,scratch,sizeof *p)?LI2_PG_CORRUPT:0;
}
int li2_pg_miss_valid(const struct li2_pg_plan *p,const struct li2_pg_miss *m,int result) {
    if(!storage(p,sizeof *p) || !storage(m,sizeof *m) ||
       (uintptr_t)p%_Alignof(struct li2_pg_plan) || (uintptr_t)m%_Alignof(struct li2_pg_miss) ||
       overlap((uintptr_t)p,sizeof *p,(uintptr_t)m,sizeof *m) ||
       m->version!=LI2_PG_VERSION || m->status!=(unsigned)result ||
       !m->reason || m->reason>=LI2_PGD_REASON_COUNT || p->version!=LI2_PG_VERSION ||
       p->bytes!=sizeof *p || p->ready || p->result!=(unsigned)result || p->reserved || p->reserved2 ||
       p->decoder_result || p->heads>LI2_PG_HEADS || p->exits>LI2_PG_BOUNDARIES || p->stores>p->heads ||
       p->source_bytes>LI2_PG_HEADS*15 || (p->source_mask&~3U) ||
       p->page[0]>=p->page[1] || (p->page[0]&4095U) || (p->page[1]&4095U) ||
       !address(p->page[0],LI2_REGION_PAGE) || !address(p->page[1],LI2_REGION_PAGE) ||
       !layout_valid(&p->layout) || p->links>LI2_PG_BOUNDARIES || p->links+p->exits>LI2_PG_BOUNDARIES ||
       p->member_heads[0]!=(p->heads<LI2_PE_HEADS?p->heads:LI2_PE_HEADS) ||
       p->member_heads[1]!=(p->heads>LI2_PE_HEADS?p->heads-LI2_PE_HEADS:0))return 0;
    unsigned page,offset;
    if(!location(p,p->entry,&page,&offset) || !location(p,m->pc,&page,&offset))return 0;
    if(m->reason==LI2_PGD_SINGLE_MEMBER)
        return result==LI2_PG_MISS && m->site==LI2_PGD_SOURCE && m->pc==p->entry &&
            p->heads && p->heads<=LI2_PE_HEADS && p->exits && !p->links && !p->guard_result && m->detail==p->heads;
    if(m->reason==LI2_PGD_LINK_LIMIT)
        return result==LI2_PG_GRAPH && m->site==LI2_PGD_SOURCE && p->heads>LI2_PE_HEADS &&
            p->exits && p->links+p->exits==LI2_PG_BOUNDARIES && !p->guard_result && m->detail==LI2_PG_BOUNDARIES;
    if(m->reason==LI2_PGD_ROOT_SELECTED)
        return result==LI2_PG_MISS && m->site==LI2_PGD_SOURCE && m->pc==p->entry &&
            m->detail>=LI2_CPUID && m->detail<=LI2_SYSCALL && !p->heads && !p->exits &&
            !p->stores && !p->source_bytes && !p->guard_result;
    if(m->reason<=LI2_PGD_NO_EXIT) {
        if(m->site!=LI2_PGD_SOURCE || p->guard_result)return 0;
        switch(m->reason) {
        case LI2_PGD_ROOT_UNSUPPORTED:
            return result==LI2_PG_MISS && !p->heads && !p->exits && m->pc==p->entry &&
                (m->detail==LI2_REGION_UNSUPPORTED || m->detail==LI2_REGION_PREFIX || m->detail==LI2_REGION_OPERANDS);
        case LI2_PGD_SOURCE_INVALID: case LI2_PGD_SOURCE_TRUNCATED: {
            unsigned char bytes[15];size_t n=window(p,m->pc,bytes);
            return result==LI2_PG_BOUNDARY && n && n==m->detail;
        }
        case LI2_PGD_SOURCE_OVERLAP:
            return result==LI2_PG_GRAPH && m->detail>=m->pc && m->detail-m->pc<15 &&
                location(p,m->detail,&page,&offset);
        case LI2_PGD_OUTSIDE_PAIR:
            return result==LI2_PG_GRAPH && !location(p,m->detail,&page,&offset);
        case LI2_PGD_HEAD_LIMIT:return result==LI2_PG_GRAPH && p->heads==LI2_PG_HEADS && m->detail==LI2_PG_HEADS;
        case LI2_PGD_EXIT_LIMIT:return result==LI2_PG_GRAPH && p->exits==LI2_PG_BOUNDARIES && m->detail==LI2_PG_BOUNDARIES;
        case LI2_PGD_QUEUE_LIMIT:return result==LI2_PG_GRAPH && m->detail==LI2_PG_HEADS+LI2_PG_BOUNDARIES;
        case LI2_PGD_NO_EXIT:return result==LI2_PG_GRAPH && p->heads && !p->exits && m->pc==p->entry && m->detail==p->heads;
        default:return 0;
        }
    }
    if(m->site!=LI2_PGD_EMIT || result!=LI2_PG_RELOCATION || !p->heads || !p->exits)return 0;
    unsigned found=LI2_PG_HEADS;
    for(unsigned i=0;i<p->heads;i++)if(p->original[i].decoded.pc==m->pc) {
        if(found!=LI2_PG_HEADS)return 0;
        found=i;
    }
    if(found==LI2_PG_HEADS)return 0;
    const struct li2_pe_head *h=&p->head[found];const struct li2_span_decoded *d=&p->original[found];
    if(h->source_page>=LI2_PE_SOURCES || h->source_offset>=LI2_REGION_PAGE ||
       p->page[h->source_page]+h->source_offset!=m->pc || !h->source_length || h->source_length>15 ||
       d->decoded.length!=h->source_length || d->decoded.next_pc!=m->pc+h->source_length ||
       !token_valid(p,h->successors[0]))return 0;
    if(m->reason==LI2_PGD_GUARD_RIP_REACH || m->reason==LI2_PGD_GUARD_FOLLOW_REACH) {
        struct li2_pg_miss expected={.version=LI2_PG_VERSION,.status=LI2_PG_RELOCATION};
        return h->kind==LI2_PE_MOV && h->successor_count==1 && p->guard_result==LI2_MG_RELOCATION &&
            pgd_guard_reach(p,found,&expected) && equal(m,&expected,sizeof expected);
    }
    if(h->kind!=LI2_PE_NONE || p->guard_result)return 0;
    uintptr_t generated=head_generated(p,found);uint32_t delta;
    if(m->reason==LI2_PGD_RIP_REACH)
        return d->flow==LI2_REGION_NEXT && h->successor_count==1 && d->relocation==LI2_SPAN_RIP_DISP32 &&
            d->displacement_bytes==4 && d->displacement_offset<=h->source_length &&
            h->source_length-d->displacement_offset>=4 && m->detail==d->rip_target &&
            !displacement(generated+h->source_length,d->rip_target,&delta);
    if(m->reason==LI2_PGD_BRANCH_REACH)
        return (d->flow==LI2_REGION_JMP || d->flow==LI2_REGION_JCC) &&
            h->successor_count==(d->flow==LI2_REGION_JCC?2U:1U) &&
            m->detail==destination(p,found,0) &&
            !displacement(generated+(d->flow==LI2_REGION_JCC?6:5),m->detail,&delta);
    if(m->reason==LI2_PGD_FALLTHROUGH_REACH) {
        unsigned k=d->flow==LI2_REGION_JCC?1:0;
        return (d->flow==LI2_REGION_NEXT || d->flow==LI2_REGION_JCC) && h->successor_count==k+1 &&
            token_valid(p,h->successors[k]) && m->detail==destination(p,found,k) &&
            !displacement(generated+(d->flow==LI2_REGION_JCC?6:h->source_length)+5,m->detail,&delta);
    }
    return 0;
}

int li2_pg_placement(uintptr_t entry,const struct li2_pg_layout *layout) {
    const uintptr_t limit=UINT64_C(1)<<47;
    if(!storage(layout,sizeof *layout) || (uintptr_t)layout%_Alignof(struct li2_pg_layout) || !layout_valid(layout))return -1;
    const uintptr_t page=entry&~(uintptr_t)(LI2_REGION_PAGE-1U);
    if(entry>=limit || page<LI2_REGION_PAGE || entry-page>LI2_REGION_PAGE-15U || page>limit-2U*LI2_REGION_PAGE)return -1;
    const uintptr_t last=page+2U*LI2_REGION_PAGE-1U;
    for(unsigned i=0;i<2;i++) {
        uintptr_t start=layout->generated[i],end=start+LI2_PE_IMAGE_BYTES;
        if(last<start) {if(start-last<=UINT32_C(0x80000000))return 1;}
        else if(page>end) {if(page-end<=UINT32_C(0x7fffffff))return 1;}
        else return 1;
    }
    return 0;
}
