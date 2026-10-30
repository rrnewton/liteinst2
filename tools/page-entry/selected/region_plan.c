#include "region_plan.h"

static void zero(void *p,size_t n) {
    unsigned char *b=p;for(size_t i=0;i<n;i++)b[i]=0;
}
static void copy(void *p,const void *q,size_t n) {
    unsigned char *b=p;const unsigned char *a=q;
    for(size_t i=0;i<n;i++)b[i]=a[i];
}
static int equal(const void *p,const void *q,size_t n) {
    const unsigned char *a=p,*b=q;
    for(size_t i=0;i<n;i++)if(a[i]!=b[i])return 0;
    return 1;
}
static int canonical(uintptr_t pc) {
    return pc<=UINT64_C(0x00007fffffffffff) || pc>=UINT64_C(0xffff800000000000);
}
static int page_range(uintptr_t page) {
    return !(page&4095U) && page<=UINTPTR_MAX-LI2_REGION_PAGE &&
        canonical(page) && canonical(page+LI2_REGION_PAGE-1);
}
static int storage(const void *p,size_t n) {
    return p && (uintptr_t)p<=UINTPTR_MAX-n;
}
static int overlap(const void *a,size_t an,const void *b,size_t bn) {
    return (uintptr_t)a<(uintptr_t)b+bn && (uintptr_t)b<(uintptr_t)a+an;
}
static int displacement(uintptr_t next,uintptr_t target,uint32_t *out) {
    if(target>=next) {
        uintptr_t n=target-next;if(n>UINT32_C(0x7fffffff))return 0;
        *out=(uint32_t)n;
    } else {
        uintptr_t n=next-target;if(n>UINT32_C(0x80000000))return 0;
        *out=0U-(uint32_t)n;
    }
    return 1;
}
static void put32(unsigned char *p,uint32_t n) {
    for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(n>>(8*i));
}
static int describe(struct li2_region_plan *p,uintptr_t pc,const unsigned char *s,
                    size_t available,struct li2_region_decoded *d) {
    p->decoder_calls++;
    p->decoder_result=li2_decoder_region_describe(pc,s,available,d);
    if(p->decoder_result)return LI2_REGION_PLAN_DECODER;
    const struct li2_decoded *a=&d->decoded;
    if(d->version!=1 || a->abi_version!=1 || a->reserved || a->pc!=pc ||
       a->available!=available || !equal(a->bytes,s,available))
        return LI2_REGION_PLAN_DECODER;
    for(size_t i=available;i<16;i++)if(a->bytes[i])return LI2_REGION_PLAN_DECODER;
    if(a->decode_status!=LI2_VALID || !a->length || a->length>available ||
       a->length>15 || a->next_pc!=pc+a->length)
        return LI2_REGION_PLAN_BOUNDARY;
    if(d->ready>1 || (d->ready && d->refusal) || (!d->ready && !d->refusal))
        return LI2_REGION_PLAN_DECODER;
    return LI2_REGION_PLAN_OK;
}
static int successor(struct li2_region_plan *p,uintptr_t pc,uint32_t *out) {
    if(pc<p->page || pc>=p->page+LI2_REGION_PAGE)return 0;
    if(pc>=p->entry && pc<p->boundary_pc) {
        for(unsigned i=0;i<p->heads;i++)if(p->original[i].decoded.pc==pc) {
            *out=i;return 1;
        }
        return 0; /* An interior byte is not an exit. */
    }
    unsigned i=0;while(i<p->exits && p->exit_pc[i]!=pc)i++;
    if(i==p->exits) {
        if(i==LI2_REGION_EXITS)return 0;
        p->exit_pc[p->exits++]=pc;
    }
    *out=LI2_REGION_HEADS+i;return 1;
}
static int graph(struct li2_region_plan *p) {
    unsigned leaders[LI2_REGION_HEADS]={0},incoming[LI2_REGION_HEADS]={0};
    unsigned reached[LI2_REGION_HEADS]={0},done[LI2_REGION_HEADS]={0};
    unsigned distance[LI2_REGION_HEADS]={0};
    leaders[0]=1;
    for(unsigned i=0;i<p->heads;i++) {
        const struct li2_region_decoded *d=&p->original[i];
        struct li2_region_head *h=&p->head[i];
        if(d->flow>LI2_REGION_JMP)return 0;
        if(d->flow==LI2_REGION_NEXT) {
            h->successor_count=1;
            if(!successor(p,d->decoded.next_pc,&h->successors[0]))return 0;
        } else {
            h->successor_count=d->flow==LI2_REGION_JCC?2:1;
            if(!successor(p,d->target,&h->successors[0]))return 0;
            if(h->successors[0]<p->heads)leaders[h->successors[0]]=1;
            if(i+1<p->heads)leaders[i+1]=1;
            if(h->successor_count==2 &&
               !successor(p,d->decoded.next_pc,&h->successors[1]))return 0;
        }
        for(unsigned j=0;j<h->successor_count;j++)
            if(h->successors[j]<p->heads)incoming[h->successors[j]]++;
    }
    for(unsigned i=0;i<p->heads;i++) {
        if(leaders[i])p->blocks++;
        p->head[i].block=p->blocks-1;
    }
    if(p->blocks>LI2_REGION_BLOCKS || !p->exits)return 0;
    reached[0]=distance[0]=1;
    for(unsigned pass=0;pass<p->heads;pass++) {
        unsigned i=0;while(i<p->heads && (done[i] || incoming[i]))i++;
        if(i==p->heads || !reached[i])return 0; /* Cycle or unreachable head. */
        done[i]=1;
        if(distance[i]>p->longest_path)p->longest_path=distance[i];
        for(unsigned j=0;j<p->head[i].successor_count;j++) {
            unsigned k=p->head[i].successors[j];
            if(k<p->heads) {
                if(!incoming[k])return 0;
                incoming[k]--;reached[k]=1;
                if(distance[k]<distance[i]+1)distance[k]=distance[i]+1;
            }
        }
    }
    return p->longest_path && p->longest_path<=LI2_REGION_HEADS;
}
static uintptr_t destination(const struct li2_region_plan *p,unsigned k) {
    return k<p->heads?p->generated+p->head[k].generated_offset:
        p->exit_pc[k-LI2_REGION_HEADS];
}
static void map_row(struct li2_region_plan *p,unsigned i,unsigned offset,
                    unsigned length,unsigned source,unsigned source_length,
                    unsigned kind,unsigned predecessor) {
    struct li2_region_pc *m=&p->map[i];
    m->version=1;m->ready=1;m->head_index=predecessor;m->kind=kind;
    m->source_offset=source;m->source_length=source_length;
    m->generated_offset=offset;m->generated_length=length;
    m->original_pc=p->page+source;m->generated_pc=p->generated+offset;
}
/* Only PC/encoding relocation facts differ. Every actual effect and old STEP
   disposition remains exact, including undefined flags and register rows. */
static int same_effects(const struct li2_region_decoded *a,
                        const struct li2_region_decoded *b) {
    struct li2_region_decoded x,y;copy(&x,a,sizeof(x));copy(&y,b,sizeof(y));
    x.decoded.pc=y.decoded.pc=0;x.decoded.next_pc=y.decoded.next_pc=0;
    x.decoded.available=y.decoded.available=0;
    zero(x.decoded.bytes,16);zero(y.decoded.bytes,16);
    if(a->flow!=LI2_REGION_NEXT) {
        x.decoded.code=y.decoded.code=0;x.decoded.length=y.decoded.length=0;
        x.target=y.target=0;
        if(x.operand_count!=1 || y.operand_count!=1 ||
           x.operands[0].kind!=LI2_REGION_BRANCH ||
           y.operands[0].kind!=LI2_REGION_BRANCH)return 0;
        x.operands[0].immediate=y.operands[0].immediate=0;
        x.operands[0].encoding_bits=y.operands[0].encoding_bits=0;
    }
    return equal(&x,&y,sizeof(x));
}
static int emit(struct li2_region_plan *p) {
    unsigned at=0;
    for(unsigned i=0;i<p->heads;i++) {
        struct li2_region_head *h=&p->head[i];
        unsigned flow=p->original[i].flow;
        h->generated_offset=at;
        h->generated_length=flow==LI2_REGION_NEXT?h->source_length:
            flow==LI2_REGION_JCC?6:5;
        if(h->generated_length>LI2_REGION_PAGE-at)return LI2_REGION_PLAN_RELOCATION;
        at+=h->generated_length;
    }
    unsigned tail=p->original[p->heads-1].flow!=LI2_REGION_JMP;
    if(tail && at>LI2_REGION_PAGE-5)return LI2_REGION_PLAN_RELOCATION;
    p->image_bytes=at+5*tail;p->maps=p->heads+tail;
    for(unsigned i=0;i<LI2_REGION_PAGE;i++)p->image[i]=0xcc;
    for(unsigned i=0;i<p->heads;i++) {
        const struct li2_region_decoded *d=&p->original[i];
        const struct li2_region_head *h=&p->head[i];
        unsigned char *s=p->image+h->generated_offset;
        if(d->flow==LI2_REGION_NEXT)
            copy(s,p->source+h->source_offset,h->source_length);
        else {
            uint32_t delta;unsigned skip=d->flow==LI2_REGION_JCC?2:1;
            if(d->flow==LI2_REGION_JCC) {
                if(d->condition>15)return LI2_REGION_PLAN_DECODER;
                s[0]=0x0f;s[1]=(unsigned char)(0x80+d->condition);
            } else s[0]=0xe9;
            if(!displacement(p->generated+h->generated_offset+h->generated_length,
                             destination(p,h->successors[0]),&delta))
                return LI2_REGION_PLAN_RELOCATION;
            put32(s+skip,delta);
        }
        map_row(p,i,h->generated_offset,h->generated_length,h->source_offset,
                h->source_length,d->flow==LI2_REGION_NEXT?LI2_REGION_PC_COPIED:
                LI2_REGION_PC_BRANCH,i);
    }
    if(tail) {
        uint32_t delta;p->image[at]=0xe9;
        if(!displacement(p->generated+at+5,p->boundary_pc,&delta))
            return LI2_REGION_PLAN_RELOCATION;
        put32(p->image+at+1,delta);
        map_row(p,p->heads,at,5,(unsigned)(p->boundary_pc-p->page),0,
                LI2_REGION_PC_EXIT,p->heads-1);
    }
    for(unsigned i=0;i<p->maps;i++) {
        const struct li2_region_pc *m=&p->map[i];
        size_t n=LI2_REGION_PAGE-m->generated_offset;if(n>15)n=15;
        int result=describe(p,m->generated_pc,p->image+m->generated_offset,n,&p->emitted[i]);
        if(result)return result;
        const struct li2_region_decoded *d=&p->emitted[i];
        if(!d->ready || d->decoded.length!=m->generated_length)return LI2_REGION_PLAN_DECODER;
        if(i<p->heads) {
            if(!same_effects(&p->original[i],d))return LI2_REGION_PLAN_DECODER;
            if(d->flow!=LI2_REGION_NEXT && d->target!=destination(p,p->head[i].successors[0]))
                return LI2_REGION_PLAN_DECODER;
        } else if(d->flow!=LI2_REGION_JMP || d->target!=p->boundary_pc ||
                  d->condition!=LI2_REGION_CONDITION_NONE || d->operand_count!=1 ||
                  d->operands[0].kind!=LI2_REGION_BRANCH || d->operands[0].encoding_bits!=32 ||
                  d->register_count || d->memory_count || d->flags_read || d->flags_written ||
                  d->flags_set || d->flags_cleared || d->flags_undefined || d->gpr_read || d->gpr_write)
            return LI2_REGION_PLAN_DECODER;
    }
    return LI2_REGION_PLAN_OK;
}
int li2_region_plan_page(uintptr_t page,const unsigned char *snapshot,uintptr_t entry,
                         uintptr_t generated,struct li2_region_plan *out) {
    if(!storage(out,sizeof(*out)) || (uintptr_t)out%_Alignof(struct li2_region_plan) ||
       !storage(snapshot,LI2_REGION_PAGE) || overlap(out,sizeof(*out),snapshot,LI2_REGION_PAGE))
        return LI2_REGION_PLAN_ARGUMENT;
    zero(out,sizeof(*out));out->version=1;
    if(!page_range(page) || !page_range(generated) || page==generated ||
       entry<page || entry>=page+LI2_REGION_PAGE)return LI2_REGION_PLAN_ARGUMENT;
    out->page=page;out->entry=entry;out->generated=generated;
    copy(out->source,snapshot,LI2_REGION_PAGE);
    unsigned offset=(unsigned)(entry-page);
    for(;;) {
        if(offset>=LI2_REGION_PAGE)return LI2_REGION_PLAN_BOUNDARY;
        size_t n=LI2_REGION_PAGE-offset;if(n>15)n=15;
        struct li2_region_decoded d;
        int result=describe(out,page+offset,out->source+offset,n,&d);
        if(result)return result;
        unsigned reason=!d.ready?LI2_REGION_STOP_UNSUPPORTED:
            out->heads==LI2_REGION_HEADS?LI2_REGION_STOP_HEADS:
            d.decoded.length>LI2_REGION_BYTES-out->source_bytes?LI2_REGION_STOP_BYTES:0;
        if(reason) {
            if(!out->heads)return LI2_REGION_PLAN_MISS;
            out->boundary=d;out->boundary_pc=page+offset;out->stop_reason=reason;break;
        }
        unsigned i=out->heads++;
        out->original[i]=d;out->head[i].source_offset=offset;
        out->head[i].source_length=d.decoded.length;
        offset+=d.decoded.length;out->source_bytes+=d.decoded.length;
    }
    if(!graph(out))return LI2_REGION_PLAN_GRAPH;
    int result=emit(out);if(result)return result;
    if(out->decoder_calls!=out->heads+1+out->maps)return LI2_REGION_PLAN_DECODER;
    out->ready=1;return LI2_REGION_PLAN_OK;
}
int li2_region_plan_validate(const struct li2_region_plan *p) {
    if(!storage(p,sizeof(*p)) || (uintptr_t)p%_Alignof(struct li2_region_plan))
        return LI2_REGION_PLAN_ARGUMENT;
    if(p->version!=1 || p->ready!=1)return LI2_REGION_PLAN_CORRUPT;
    struct li2_region_plan expected;
    int result=li2_region_plan_page(p->page,p->source,p->entry,p->generated,&expected);
    if(result==LI2_REGION_PLAN_DECODER)return result;
    if(result || !equal(p,&expected,sizeof(*p)))return LI2_REGION_PLAN_CORRUPT;
    return LI2_REGION_PLAN_OK;
}
int li2_region_map_pc(const struct li2_region_plan *p,uintptr_t pc,struct li2_region_pc *out) {
    if(!storage(p,sizeof(*p)) || !storage(out,sizeof(*out)) ||
       (uintptr_t)out%_Alignof(struct li2_region_pc) || overlap(p,sizeof(*p),out,sizeof(*out)))
        return LI2_REGION_PLAN_ARGUMENT;
    zero(out,sizeof(*out));
    int result=li2_region_plan_validate(p);if(result)return result;
    for(unsigned i=0;i<p->maps;i++)if(p->map[i].generated_pc==pc) {
        copy(out,&p->map[i],sizeof(*out));return LI2_REGION_PLAN_OK;
    }
    return LI2_REGION_PLAN_MISS;
}

/* Distinct opt-in implementation; all old functions above stay byte-exact.
   The whole emitted descriptor retains the original absolute RIP target. */
#if defined(LI2_SCALAR_SPAN) && LI2_SCALAR_SPAN == 1
static int span_describe(struct li2_span_plan *p,uintptr_t pc,const unsigned char *s,
                    size_t available,struct li2_span_decoded *d) {
    p->decoder_calls++;
    p->decoder_result=li2_decoder_span_describe(pc,s,available,d);
    if(p->decoder_result)return LI2_REGION_PLAN_DECODER;
    const struct li2_decoded *a=&d->decoded;
    if(d->version!=1 || a->abi_version!=1 || a->reserved || a->pc!=pc ||
       a->available!=available || !equal(a->bytes,s,available))
        return LI2_REGION_PLAN_DECODER;
    for(size_t i=available;i<16;i++)if(a->bytes[i])return LI2_REGION_PLAN_DECODER;
    if(a->decode_status!=LI2_VALID || !a->length || a->length>available ||
       a->length>15 || a->next_pc!=pc+a->length)
        return LI2_REGION_PLAN_BOUNDARY;
    if(d->ready>1 || (d->ready && d->refusal) || (!d->ready && !d->refusal))
        return LI2_REGION_PLAN_DECODER;
    return LI2_REGION_PLAN_OK;
}
static int span_successor(struct li2_span_plan *p,uintptr_t pc,uint32_t *out) {
    if(pc<p->page || pc>=p->page+LI2_REGION_PAGE)return 0;
    if(pc>=p->entry && pc<p->boundary_pc) {
        for(unsigned i=0;i<p->heads;i++)if(p->original[i].decoded.pc==pc) {
            *out=i;return 1;
        }
        return 0; /* An interior byte is not an exit. */
    }
    unsigned i=0;while(i<p->exits && p->exit_pc[i]!=pc)i++;
    if(i==p->exits) {
        if(i==LI2_REGION_EXITS)return 0;
        p->exit_pc[p->exits++]=pc;
    }
    *out=LI2_REGION_HEADS+i;return 1;
}
static int span_graph(struct li2_span_plan *p) {
    unsigned leaders[LI2_REGION_HEADS]={0},incoming[LI2_REGION_HEADS]={0};
    unsigned reached[LI2_REGION_HEADS]={0},done[LI2_REGION_HEADS]={0};
    unsigned distance[LI2_REGION_HEADS]={0};
    leaders[0]=1;
    for(unsigned i=0;i<p->heads;i++) {
        const struct li2_span_decoded *d=&p->original[i];
        struct li2_region_head *h=&p->head[i];
        if(d->flow>LI2_REGION_JMP)return 0;
        if(d->flow==LI2_REGION_NEXT) {
            h->successor_count=1;
            if(!span_successor(p,d->decoded.next_pc,&h->successors[0]))return 0;
        } else {
            h->successor_count=d->flow==LI2_REGION_JCC?2:1;
            if(!span_successor(p,d->target,&h->successors[0]))return 0;
            if(h->successors[0]<p->heads)leaders[h->successors[0]]=1;
            if(i+1<p->heads)leaders[i+1]=1;
            if(h->successor_count==2 &&
               !span_successor(p,d->decoded.next_pc,&h->successors[1]))return 0;
        }
        for(unsigned j=0;j<h->successor_count;j++)
            if(h->successors[j]<p->heads)incoming[h->successors[j]]++;
    }
    for(unsigned i=0;i<p->heads;i++) {
        if(leaders[i])p->blocks++;
        p->head[i].block=p->blocks-1;
    }
    if(p->blocks>LI2_REGION_BLOCKS || !p->exits)return 0;
    reached[0]=distance[0]=1;
    for(unsigned pass=0;pass<p->heads;pass++) {
        unsigned i=0;while(i<p->heads && (done[i] || incoming[i]))i++;
        if(i==p->heads || !reached[i])return 0; /* Cycle or unreachable head. */
        done[i]=1;
        if(distance[i]>p->longest_path)p->longest_path=distance[i];
        for(unsigned j=0;j<p->head[i].successor_count;j++) {
            unsigned k=p->head[i].successors[j];
            if(k<p->heads) {
                if(!incoming[k])return 0;
                incoming[k]--;reached[k]=1;
                if(distance[k]<distance[i]+1)distance[k]=distance[i]+1;
            }
        }
    }
    return p->longest_path && p->longest_path<=LI2_REGION_HEADS;
}
static uintptr_t span_destination(const struct li2_span_plan *p,unsigned k) {
    return k<p->heads?p->generated+p->head[k].generated_offset:
        p->exit_pc[k-LI2_REGION_HEADS];
}
static void span_map_row(struct li2_span_plan *p,unsigned i,unsigned offset,
                    unsigned length,unsigned source,unsigned source_length,
                    unsigned kind,unsigned predecessor) {
    struct li2_region_pc *m=&p->map[i];
    m->version=1;m->ready=1;m->head_index=predecessor;m->kind=kind;
    m->source_offset=source;m->source_length=source_length;
    m->generated_offset=offset;m->generated_length=length;
    m->original_pc=p->page+source;m->generated_pc=p->generated+offset;
}
/* Only PC/encoding relocation facts differ. Every actual effect and old STEP
   disposition remains exact, including undefined flags and register rows. */
static int span_same_effects(const struct li2_span_decoded *a,
                        const struct li2_span_decoded *b) {
    struct li2_span_decoded x,y;copy(&x,a,sizeof(x));copy(&y,b,sizeof(y));
    x.decoded.pc=y.decoded.pc=0;x.decoded.next_pc=y.decoded.next_pc=0;
    x.decoded.available=y.decoded.available=0;
    zero(x.decoded.bytes,16);zero(y.decoded.bytes,16);
    if(a->flow!=LI2_REGION_NEXT) {
        x.decoded.code=y.decoded.code=0;x.decoded.length=y.decoded.length=0;
        x.target=y.target=0;
        if(x.operand_count!=1 || y.operand_count!=1 ||
           x.operands[0].kind!=LI2_REGION_BRANCH ||
           y.operands[0].kind!=LI2_REGION_BRANCH)return 0;
        x.operands[0].immediate=y.operands[0].immediate=0;
        x.operands[0].encoding_bits=y.operands[0].encoding_bits=0;
    }
    return equal(&x,&y,sizeof(x));
}
static int span_emit(struct li2_span_plan *p) {
    unsigned at=0;
    for(unsigned i=0;i<p->heads;i++) {
        struct li2_region_head *h=&p->head[i];
        unsigned flow=p->original[i].flow;
        h->generated_offset=at;
        h->generated_length=flow==LI2_REGION_NEXT?h->source_length:
            flow==LI2_REGION_JCC?6:5;
        if(h->generated_length>LI2_REGION_PAGE-at)return LI2_REGION_PLAN_RELOCATION;
        at+=h->generated_length;
    }
    unsigned tail=p->original[p->heads-1].flow!=LI2_REGION_JMP;
    if(tail && at>LI2_REGION_PAGE-5)return LI2_REGION_PLAN_RELOCATION;
    p->image_bytes=at+5*tail;p->maps=p->heads+tail;
    for(unsigned i=0;i<LI2_REGION_PAGE;i++)p->image[i]=0xcc;
    for(unsigned i=0;i<p->heads;i++) {
        const struct li2_span_decoded *d=&p->original[i];
        const struct li2_region_head *h=&p->head[i];
        unsigned char *s=p->image+h->generated_offset;
        if(d->flow==LI2_REGION_NEXT) {
            copy(s,p->source+h->source_offset,h->source_length);
            if(d->relocation==LI2_SPAN_RIP_DISP32) {
                uint32_t delta;
                if(d->displacement_bytes!=4 || d->displacement_offset>h->source_length ||
                   h->source_length-d->displacement_offset<4 ||
                   !displacement(p->generated+h->generated_offset+h->generated_length,
                                 d->rip_target,&delta))return LI2_REGION_PLAN_RELOCATION;
                put32(s+d->displacement_offset,delta);
            } else if(d->relocation || d->rip_target || d->displacement_offset ||
                      d->displacement_bytes)return LI2_REGION_PLAN_DECODER;
        } else {
            uint32_t delta;unsigned skip=d->flow==LI2_REGION_JCC?2:1;
            if(d->flow==LI2_REGION_JCC) {
                if(d->condition>15)return LI2_REGION_PLAN_DECODER;
                s[0]=0x0f;s[1]=(unsigned char)(0x80+d->condition);
            } else s[0]=0xe9;
            if(!displacement(p->generated+h->generated_offset+h->generated_length,
                             span_destination(p,h->successors[0]),&delta))
                return LI2_REGION_PLAN_RELOCATION;
            put32(s+skip,delta);
        }
        span_map_row(p,i,h->generated_offset,h->generated_length,h->source_offset,
                h->source_length,d->flow!=LI2_REGION_NEXT?LI2_REGION_PC_BRANCH:
                d->relocation==LI2_SPAN_RIP_DISP32?LI2_SPAN_PC_RIP_RELOCATED:
                LI2_REGION_PC_COPIED,i);
    }
    if(tail) {
        uint32_t delta;p->image[at]=0xe9;
        if(!displacement(p->generated+at+5,p->boundary_pc,&delta))
            return LI2_REGION_PLAN_RELOCATION;
        put32(p->image+at+1,delta);
        span_map_row(p,p->heads,at,5,(unsigned)(p->boundary_pc-p->page),0,
                LI2_REGION_PC_EXIT,p->heads-1);
    }
    for(unsigned i=0;i<p->maps;i++) {
        const struct li2_region_pc *m=&p->map[i];
        size_t n=LI2_REGION_PAGE-m->generated_offset;if(n>15)n=15;
        int result=span_describe(p,m->generated_pc,p->image+m->generated_offset,n,&p->emitted[i]);
        if(result)return result;
        const struct li2_span_decoded *d=&p->emitted[i];
        if(!d->ready || d->decoded.length!=m->generated_length)return LI2_REGION_PLAN_DECODER;
        if(i<p->heads) {
            if(!span_same_effects(&p->original[i],d))return LI2_REGION_PLAN_DECODER;
            if(d->flow!=LI2_REGION_NEXT && d->target!=span_destination(p,p->head[i].successors[0]))
                return LI2_REGION_PLAN_DECODER;
        } else if(d->flow!=LI2_REGION_JMP || d->target!=p->boundary_pc ||
                  d->condition!=LI2_REGION_CONDITION_NONE || d->operand_count!=1 ||
                  d->operands[0].kind!=LI2_REGION_BRANCH || d->operands[0].encoding_bits!=32 ||
                  d->register_count || d->memory_count || d->address_count || d->relocation ||
                  d->rip_target || d->displacement_offset || d->displacement_bytes ||
                  d->flags_read || d->flags_written ||
                  d->flags_set || d->flags_cleared || d->flags_undefined || d->gpr_read || d->gpr_write)
            return LI2_REGION_PLAN_DECODER;
    }
    return LI2_REGION_PLAN_OK;
}
int li2_span_plan_page(uintptr_t page,const unsigned char *snapshot,uintptr_t entry,
                         uintptr_t generated,struct li2_span_plan *out) {
    if(!storage(out,sizeof(*out)) || (uintptr_t)out%_Alignof(struct li2_span_plan) ||
       !storage(snapshot,LI2_REGION_PAGE) || overlap(out,sizeof(*out),snapshot,LI2_REGION_PAGE))
        return LI2_REGION_PLAN_ARGUMENT;
    zero(out,sizeof(*out));out->version=1;
    if(!page_range(page) || !page_range(generated) || page==generated ||
       entry<page || entry>=page+LI2_REGION_PAGE)return LI2_REGION_PLAN_ARGUMENT;
    out->page=page;out->entry=entry;out->generated=generated;
    copy(out->source,snapshot,LI2_REGION_PAGE);
    unsigned offset=(unsigned)(entry-page);
    for(;;) {
        if(offset>=LI2_REGION_PAGE)return LI2_REGION_PLAN_BOUNDARY;
        size_t n=LI2_REGION_PAGE-offset;if(n>15)n=15;
        struct li2_span_decoded d;
        int result=span_describe(out,page+offset,out->source+offset,n,&d);
        if(result)return result;
        unsigned reason=!d.ready?LI2_REGION_STOP_UNSUPPORTED:
            out->heads==LI2_REGION_HEADS?LI2_REGION_STOP_HEADS:
            d.decoded.length>LI2_REGION_BYTES-out->source_bytes?LI2_REGION_STOP_BYTES:0;
        if(reason) {
            if(!out->heads)return LI2_REGION_PLAN_MISS;
            out->boundary=d;out->boundary_pc=page+offset;out->stop_reason=reason;break;
        }
        unsigned i=out->heads++;
        out->original[i]=d;out->head[i].source_offset=offset;
        out->head[i].source_length=d.decoded.length;
        offset+=d.decoded.length;out->source_bytes+=d.decoded.length;
    }
    if(!span_graph(out))return LI2_REGION_PLAN_GRAPH;
    int result=span_emit(out);if(result)return result;
    if(out->decoder_calls!=out->heads+1+out->maps)return LI2_REGION_PLAN_DECODER;
    out->ready=1;return LI2_REGION_PLAN_OK;
}
int li2_span_plan_validate(const struct li2_span_plan *p) {
    if(!storage(p,sizeof(*p)) || (uintptr_t)p%_Alignof(struct li2_span_plan))
        return LI2_REGION_PLAN_ARGUMENT;
    if(p->version!=1 || p->ready!=1)return LI2_REGION_PLAN_CORRUPT;
    struct li2_span_plan expected;
    int result=li2_span_plan_page(p->page,p->source,p->entry,p->generated,&expected);
    if(result==LI2_REGION_PLAN_DECODER)return result;
    if(result || !equal(p,&expected,sizeof(*p)))return LI2_REGION_PLAN_CORRUPT;
    return LI2_REGION_PLAN_OK;
}
int li2_span_map_pc(const struct li2_span_plan *p,uintptr_t pc,struct li2_region_pc *out) {
    if(!storage(p,sizeof(*p)) || !storage(out,sizeof(*out)) ||
       (uintptr_t)out%_Alignof(struct li2_region_pc) || overlap(p,sizeof(*p),out,sizeof(*out)))
        return LI2_REGION_PLAN_ARGUMENT;
    zero(out,sizeof(*out));
    int result=li2_span_plan_validate(p);if(result)return result;
    for(unsigned i=0;i<p->maps;i++)if(p->map[i].generated_pc==pc) {
        copy(out,&p->map[i],sizeof(*out));return LI2_REGION_PLAN_OK;
    }
    return LI2_REGION_PLAN_MISS;
}
#endif
