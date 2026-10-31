#include "persistent_plan.h"
#include "linked_rseq.h"
#if !defined(LI2_PERSISTENT_EPOCH) || LI2_PERSISTENT_EPOCH != 1 || \
    !defined(LI2_MOV_GUARD) || LI2_MOV_GUARD != 1
#error "separate persistent description plus unchanged MOV primitive required"
#endif
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
static int location(const struct li2_pe_plan *p,uintptr_t pc,unsigned *page,unsigned *offset) {
    for(unsigned i=0;i<LI2_PE_SOURCES;i++)if(pc>=p->page[i] && pc-p->page[i]<LI2_REGION_PAGE) {
        *page=i;*offset=(unsigned)(pc-p->page[i]);return 1;
    }
    return 0;
}
static size_t window(const struct li2_pe_plan *p,uintptr_t pc,unsigned char out[15]) {
    zero(out,15);size_t n=0;
    for(;n<15;n++) {
        unsigned page,offset;
        if(pc>UINTPTR_MAX-n || !location(p,pc+n,&page,&offset))break;
        out[n]=p->source[page][offset];
    }
    return n;
}
static int describe(struct li2_pe_plan *p,uintptr_t pc,const unsigned char *b,size_t n,struct li2_span_decoded *d) {
    p->decoder_result=li2_decoder_span_describe(pc,b,n,d);
    if(p->decoder_result)return LI2_PE_DECODER;
    const struct li2_decoded *a=&d->decoded;
    if(d->version!=1 || a->abi_version!=1 || a->reserved || a->pc!=pc || a->available!=n ||
       !equal(a->bytes,b,n))return LI2_PE_DECODER;
    for(size_t i=n;i<16;i++)if(a->bytes[i])return LI2_PE_DECODER;
    if(a->decode_status!=LI2_VALID || !a->length || a->length>n || a->length>15 ||
       a->next_pc!=pc+a->length)return LI2_PE_BOUNDARY;
    if(d->ready>1 || (d->ready && d->refusal) || (!d->ready && !d->refusal))return LI2_PE_DECODER;
    return 0;
}
static int static_none(struct li2_pe_plan *p,const struct li2_span_decoded *d,const unsigned char *b,size_t n) {
    struct li2_write_footprint f={0};
    p->decoder_result=li2_decoder_link_none(d->decoded.pc,b,n,&f);
    if(p->decoder_result || f.abi_version!=1 || f.policy!=LI2_WRITE_NONE || f.first || f.end ||
       f.pc!=d->decoded.pc || f.next_pc!=d->decoded.next_pc || f.code!=d->decoded.code ||
       f.length!=d->decoded.length)return LI2_PE_DECODER;
    return 0;
}
static int writer(struct li2_pe_plan *p,const struct li2_span_decoded *d,const unsigned char *b,size_t n,struct li2_mg_store *s) {
    p->decoder_result=li2_decoder_mov_store(d->decoded.pc,b,n,s);
    if(p->decoder_result)return LI2_PE_DECODER;
    if(s->version!=1 || s->available!=n || s->reserved || s->ready>1 ||
       (s->ready && s->refusal) || (!s->ready && !s->refusal) ||
       s->tf.abi_version!=1 || s->tf.pc!=d->decoded.pc || s->tf.next_pc!=d->decoded.next_pc ||
       s->tf.code!=d->decoded.code || s->tf.length!=d->decoded.length || !equal(s->bytes,b,n))return LI2_PE_DECODER;
    for(size_t i=n;i<16;i++)if(s->bytes[i])return LI2_PE_DECODER;
    if(s->ready && (s->tf.policy!=1 || (s->width_bytes!=4 && s->width_bytes!=8)))return LI2_PE_DECODER;
    return 0;
}
struct node { uintptr_t pc;unsigned decoded,token; };
static int enqueue(struct li2_pe_plan *p,struct node q[LI2_PE_HEADS+LI2_PE_EXITS],unsigned *n,uintptr_t pc) {
    unsigned page,offset;if(!location(p,pc,&page,&offset))return -1;
    for(unsigned i=0;i<*n;i++)if(q[i].pc==pc)return (int)i;
    if(*n==LI2_PE_HEADS+LI2_PE_EXITS)return -1;
    unsigned i=(*n)++;q[i].pc=pc;return (int)i;
}
static int resolve(const struct node *q,unsigned n,uintptr_t pc,unsigned *token) {
    for(unsigned i=0;i<n;i++)if(q[i].pc==pc && q[i].decoded) { *token=q[i].token;return 1; }
    return 0;
}
static int token_valid(const struct li2_pe_plan *p,unsigned k) {
    return k<p->heads || (k>=LI2_PE_HEADS && k-LI2_PE_HEADS<p->exits);
}
static int graph(struct li2_pe_plan *p) {
    struct node q[LI2_PE_HEADS+LI2_PE_EXITS]={0};unsigned n=0;
    unsigned char occupied[LI2_PE_SOURCES][LI2_REGION_PAGE]={{0}};
    if(enqueue(p,q,&n,p->entry)!=0)return LI2_PE_GRAPH;
    for(unsigned at=0;at<n;at++) {
        unsigned char bytes[15];size_t count=window(p,q[at].pc,bytes);
        struct li2_span_decoded d;struct li2_mg_store s={0};
        int e=describe(p,q[at].pc,bytes,count,&d);if(e)return e;
        for(unsigned j=0;j<d.decoded.length;j++) {
            unsigned page,offset;if(!location(p,q[at].pc+j,&page,&offset) || occupied[page][offset])return LI2_PE_GRAPH;
            occupied[page][offset]=1;p->source_mask|=1U<<page;
        }
        unsigned kind=LI2_PE_NONE;
        if(d.ready) { if((e=static_none(p,&d,bytes,count)))return e; }
        else { if((e=writer(p,&d,bytes,count,&s)))return e;kind=s.ready?LI2_PE_MOV:0; }
        q[at].decoded=1;
        if(!kind) {
            if(!at)return LI2_PE_MISS;
            if(p->exits==LI2_PE_EXITS)return LI2_PE_GRAPH;
            unsigned x=p->exits++;p->frontier[x]=d;p->exit_pc[x]=q[at].pc;q[at].token=LI2_PE_HEADS+x;continue;
        }
        if(p->heads==LI2_PE_HEADS)return LI2_PE_GRAPH;
        unsigned i=p->heads++;struct li2_pe_head *h=&p->head[i];q[at].token=i;
        if(!location(p,q[at].pc,&h->source_page,&h->source_offset))return LI2_PE_GRAPH;
        h->kind=kind;h->source_length=d.decoded.length;p->source_bytes+=h->source_length;p->original[i]=d;
        if(kind==LI2_PE_MOV) { p->store_original[i]=s;++p->stores; }
        unsigned flow=kind==LI2_PE_MOV?LI2_REGION_NEXT:d.flow;
        if(flow==LI2_REGION_NEXT) {
            if(enqueue(p,q,&n,d.decoded.next_pc)<0)return LI2_PE_GRAPH;
        } else if(flow==LI2_REGION_JCC || flow==LI2_REGION_JMP) {
            if(enqueue(p,q,&n,d.target)<0)return LI2_PE_GRAPH;
            if(flow==LI2_REGION_JCC && enqueue(p,q,&n,d.decoded.next_pc)<0)return LI2_PE_GRAPH;
        } else return LI2_PE_DECODER;
    }
    if(!p->heads || !p->exits)return LI2_PE_GRAPH;
    for(unsigned i=0;i<p->heads;i++) {
        struct li2_pe_head *h=&p->head[i];const struct li2_span_decoded *d=&p->original[i];
        unsigned flow=h->kind==LI2_PE_MOV?LI2_REGION_NEXT:d->flow;
        h->successor_count=flow==LI2_REGION_JCC?2:1;
        if(!resolve(q,n,flow==LI2_REGION_NEXT?d->decoded.next_pc:d->target,&h->successors[0]) ||
           (h->successor_count==2 && !resolve(q,n,d->decoded.next_pc,&h->successors[1])))return LI2_PE_GRAPH;
    }
    /* Breadth-first discovery proves reachability and finite exact targets.
       Cycles are retained, not topologically ranked; no termination claim. */
    return 0;
}
static uintptr_t destination(const struct li2_pe_plan *p,unsigned k) {
    return k<p->heads?p->generated+(uintptr_t)k*LI2_PE_SLOT_BYTES:p->exit_pc[k-LI2_PE_HEADS];
}
static uintptr_t original_destination(const struct li2_pe_plan *p,unsigned k) {
    return k<p->heads?p->original[k].decoded.pc:p->exit_pc[k-LI2_PE_HEADS];
}
static int jump(struct li2_pe_plan *p,unsigned offset,uintptr_t target) {
    uint32_t d;p->image[offset]=0xe9;
    if(!displacement(p->generated+offset+5,target,&d))return 0;
    put32(p->image+offset+1,d);return 1;
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
static int emit(struct li2_pe_plan *p) {
    for(unsigned i=0;i<LI2_PE_IMAGE_BYTES;i++)p->image[i]=0xcc;
    for(unsigned i=0;i<p->heads;i++) {
        struct li2_pe_head *h=&p->head[i];const struct li2_span_decoded *d=&p->original[i];
        unsigned at=i*LI2_PE_SLOT_BYTES;unsigned char *out=p->image+at;
        if(h->kind==LI2_PE_MOV) {
            unsigned char bytes[15];size_t n=window(p,d->decoded.pc,bytes);
            p->guard_result=(unsigned)li2_mg_emit(d->decoded.pc,bytes,n,p->generated+at,p->spill,
                destination(p,h->successors[0]),&p->table,&p->guard[i]);
            if(p->guard_result)return p->guard_result==LI2_MG_RELOCATION?LI2_PE_RELOCATION:LI2_PE_DECODER;
            if(!equal(&p->guard[i].original,&p->store_original[i],sizeof p->store_original[i]) ||
               !p->guard[i].ready || !p->guard[i].image_bytes || p->guard[i].image_bytes>LI2_PE_SLOT_BYTES ||
               !equal(&p->guard[i].table,&p->table,sizeof p->table))return LI2_PE_DECODER;
            h->generated_length=p->guard[i].image_bytes;copy(out,p->guard[i].image,h->generated_length);continue;
        }
        unsigned flow=d->flow,length=flow==LI2_REGION_NEXT?h->source_length:flow==LI2_REGION_JCC?6:5;
        h->generated_length=length+(flow==LI2_REGION_JMP?0:5);
        if(flow==LI2_REGION_NEXT) {
            copy(out,d->decoded.bytes,h->source_length);
            if(d->relocation==LI2_SPAN_RIP_DISP32) {
                uint32_t delta;
                if(d->displacement_bytes!=4 || d->displacement_offset>h->source_length || h->source_length-d->displacement_offset<4 ||
                   !displacement(p->generated+at+length,d->rip_target,&delta))return LI2_PE_RELOCATION;
                put32(out+d->displacement_offset,delta);
            } else if(d->relocation || d->rip_target || d->displacement_offset || d->displacement_bytes)return LI2_PE_DECODER;
        } else if(flow==LI2_REGION_JCC) {
            uint32_t delta;if(d->condition>15)return LI2_PE_DECODER;
            out[0]=0x0f;out[1]=(unsigned char)(0x80+d->condition);
            if(!displacement(p->generated+at+6,destination(p,h->successors[0]),&delta))return LI2_PE_RELOCATION;
            put32(out+2,delta);
        } else if(!jump(p,at,destination(p,h->successors[0])))return LI2_PE_RELOCATION;
        struct li2_span_decoded actual;int e=describe(p,p->generated+at,out,15,&actual);if(e)return e;
        if(!actual.ready || actual.decoded.length!=length || !same_effects(d,&actual) ||
           (flow!=LI2_REGION_NEXT && actual.target!=destination(p,h->successors[0])))return LI2_PE_DECODER;
        if(flow!=LI2_REGION_JMP) {
            unsigned k=h->successors[flow==LI2_REGION_JCC?1:0];
            if(!jump(p,at+length,destination(p,k)))return LI2_PE_RELOCATION;
            e=describe(p,p->generated+at+length,p->image+at+length,15,&actual);if(e)return e;
            if(!synthetic(&actual,destination(p,k)))return LI2_PE_DECODER;
        }
    }
    return 0;
}
int li2_pe_plan_pages(const uintptr_t pages[LI2_PE_SOURCES],const unsigned char source[LI2_PE_SOURCES][LI2_REGION_PAGE],
    uintptr_t entry,uintptr_t generated,uintptr_t spill,const struct li2_mg_table *table,struct li2_pe_plan *out) {
    if(!storage(out,sizeof *out) || (uintptr_t)out%_Alignof(struct li2_pe_plan) || !storage(pages,2*sizeof *pages) ||
       (uintptr_t)pages%_Alignof(uintptr_t) ||
       !storage(source,2*LI2_REGION_PAGE) || !storage(table,sizeof *table) || (uintptr_t)table%_Alignof(struct li2_mg_table) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)pages,2*sizeof *pages) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)source,2*LI2_REGION_PAGE) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)table,sizeof *table))return LI2_PE_ARGUMENT;
    zero(out,sizeof *out);out->version=LI2_PE_VERSION;out->bytes=sizeof *out;
    int e=LI2_PE_ARGUMENT;
    if((generated&4095U) || !address(generated,LI2_PE_IMAGE_BYTES) || !address(spill,32) || (spill&7) ||
       li2_mg_table_validate(table) || pages[0]>=pages[1])goto done;
    uintptr_t at[5]={pages[0],pages[1],generated,spill,table->address};
    size_t bytes[5]={LI2_REGION_PAGE,LI2_REGION_PAGE,LI2_PE_IMAGE_BYTES,32,sizeof *table};
    for(unsigned i=0;i<5;i++) {
        if(!address(at[i],bytes[i]) || (i<2 && (at[i]&4095U)))goto done;
        for(unsigned j=0;j<i;j++)if(overlap(at[i],bytes[i],at[j],bytes[j]))goto done;
    }
    copy(out->page,pages,sizeof out->page);copy(out->source,source,sizeof out->source);
    out->entry=entry;out->generated=generated;out->spill=spill;copy(&out->table,table,sizeof *table);
    unsigned page,offset;if(!location(out,entry,&page,&offset))goto done;
    e=graph(out);if(!e)e=emit(out);if(!e)out->ready=1;
 done:out->result=(unsigned)e;return e;
}
int li2_pe_plan_validate(const struct li2_pe_plan *p,struct li2_pe_plan *scratch) {
    if(!storage(p,sizeof *p) || !storage(scratch,sizeof *scratch) ||
       (uintptr_t)p%_Alignof(struct li2_pe_plan) || (uintptr_t)scratch%_Alignof(struct li2_pe_plan) ||
       overlap((uintptr_t)p,sizeof *p,(uintptr_t)scratch,sizeof *scratch))return LI2_PE_ARGUMENT;
    if(p->version!=LI2_PE_VERSION || p->bytes!=sizeof *p || p->ready!=1 || p->result || p->reserved)return LI2_PE_CORRUPT;
    int e=li2_pe_plan_pages(p->page,p->source,p->entry,p->generated,p->spill,&p->table,scratch);
    return e || !equal(p,scratch,sizeof *p)?LI2_PE_CORRUPT:0;
}
int li2_pe_recover(const struct li2_pe_plan *p,uintptr_t pc,const uint64_t raw[16],uint64_t flags,
    const uint64_t spill[4],struct li2_pe_recovered *out) {
    if(!storage(out,sizeof *out) || (uintptr_t)out%_Alignof(struct li2_pe_recovered) ||
       !storage(p,sizeof *p) || (uintptr_t)p%_Alignof(struct li2_pe_plan) ||
       !storage(raw,16*sizeof *raw) || (uintptr_t)raw%_Alignof(uint64_t) ||
       !storage(spill,4*sizeof *spill) || (uintptr_t)spill%_Alignof(uint64_t) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)p,sizeof *p) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)raw,16*sizeof *raw) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)spill,4*sizeof *spill))return LI2_PE_ARGUMENT;
    zero(out,sizeof *out);
    if(p->version!=LI2_PE_VERSION || p->bytes!=sizeof *p || p->ready!=1 || p->reserved ||
       p->result || !p->heads || p->heads>LI2_PE_HEADS || !p->exits || p->exits>LI2_PE_EXITS ||
       (p->generated&4095U) || !address(p->generated,LI2_PE_IMAGE_BYTES))return LI2_PE_CORRUPT;
    if(pc<p->generated || pc-p->generated>=LI2_PE_IMAGE_BYTES)return LI2_PE_MISS;
    unsigned i=(unsigned)((pc-p->generated)/LI2_PE_SLOT_BYTES),offset=(unsigned)((pc-p->generated)%LI2_PE_SLOT_BYTES);
    if(i>=p->heads)return LI2_PE_MISS;
    const struct li2_pe_head *h=&p->head[i];const struct li2_span_decoded *d=&p->original[i];
    unsigned flow=h->kind==LI2_PE_MOV?LI2_REGION_NEXT:d->flow;
    if(h->source_page>=LI2_PE_SOURCES || h->source_offset>=LI2_REGION_PAGE ||
       !h->source_length || h->source_length>15 || d->decoded.length!=h->source_length ||
       d->decoded.pc!=p->page[h->source_page]+h->source_offset ||
       d->decoded.next_pc!=d->decoded.pc+h->source_length ||
       (flow!=LI2_REGION_NEXT && flow!=LI2_REGION_JCC && flow!=LI2_REGION_JMP) ||
       h->successor_count!=(flow==LI2_REGION_JCC?2U:1U) ||
       !token_valid(p,h->successors[0]) ||
       (h->successor_count==2?!token_valid(p,h->successors[1]):h->successors[1]!=0) ||
       !h->generated_length || h->generated_length>LI2_PE_SLOT_BYTES)return LI2_PE_CORRUPT;
    if(offset>=h->generated_length)return LI2_PE_MISS;
    out->head=i;
    if(h->kind==LI2_PE_MOV) {
        const struct li2_mg_plan *g=&p->guard[i];struct li2_mg_recovered value;
        if(g->generated!=p->generated+(uintptr_t)i*LI2_PE_SLOT_BYTES || g->spill!=p->spill ||
           g->successor!=destination(p,h->successors[0]) || g->image_bytes!=h->generated_length ||
           !g->boundaries || g->boundaries>LI2_MG_BOUNDARIES ||
           g->original.tf.pc!=d->decoded.pc || g->original.tf.next_pc!=d->decoded.next_pc)return LI2_PE_CORRUPT;
        unsigned found=0;
        for(unsigned j=0;j<g->boundaries;j++)if(g->boundary[j].offset==offset)++found;
        if(!found)return LI2_PE_MISS;
        if(found!=1)return LI2_PE_CORRUPT;
        int e=li2_mg_recover(g,pc,raw,flags,spill,&value);
        if(e || value.complete!=1)return LI2_PE_CORRUPT;
        copy(out->gpr,value.gpr,sizeof out->gpr);out->flags=value.flags;out->original_pc=value.original_pc;
        out->phase=value.phase;out->kind=LI2_PE_GUARD;
    } else if(h->kind==LI2_PE_NONE) {
        unsigned length=d->flow==LI2_REGION_NEXT?h->source_length:d->flow==LI2_REGION_JCC?6:5;
        if(h->generated_length!=length+(flow==LI2_REGION_JMP?0U:5U))return LI2_PE_CORRUPT;
        if(offset==0) {
            out->original_pc=d->decoded.pc;out->phase=LI2_MG_BEFORE;
            out->kind=d->flow==LI2_REGION_NEXT?LI2_PE_COPIED:LI2_PE_BRANCH;
        } else if(d->flow!=LI2_REGION_JMP && offset==length) {
            unsigned k=h->successors[d->flow==LI2_REGION_JCC?1:0];out->original_pc=original_destination(p,k);
            out->phase=LI2_MG_AFTER;out->kind=LI2_PE_EDGE;
        } else return LI2_PE_MISS;
        copy(out->gpr,raw,sizeof out->gpr);out->flags=flags;
    } else return LI2_PE_CORRUPT;
    out->complete=1;return 0;
}
