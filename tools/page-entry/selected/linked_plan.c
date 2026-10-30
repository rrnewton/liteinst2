#include "linked_plan.h"
#ifdef LI2_SPAN_FAST_BYTES
#include "span_fast_bytes.h"
#endif

#ifdef LI2_SPAN_FAST_BYTES
static void zero(void *p,size_t n) { li2_span_bytes_zero(p,n); }
#else
static void zero(void *p,size_t n) {
    unsigned char *b=p;for(size_t i=0;i<n;i++)b[i]=0;
}
#endif
#ifdef LI2_SPAN_FAST_BYTES
static void copy(void *p,const void *q,size_t n) { li2_span_bytes_copy(p,q,n); }
#else
static void copy(void *p,const void *q,size_t n) {
    unsigned char *b=p;const unsigned char *a=q;
    for(size_t i=0;i<n;i++)b[i]=a[i];
}
#endif
#ifdef LI2_SPAN_FAST_BYTES
static int equal(const void *p,const void *q,size_t n) { return li2_span_bytes_equal(p,q,n); }
#else
static int equal(const void *p,const void *q,size_t n) {
    const unsigned char *a=p,*b=q;
    for(size_t i=0;i<n;i++)if(a[i]!=b[i])return 0;
    return 1;
}
#endif
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
static int describe(struct li2_link_plan *p,uintptr_t pc,const unsigned char *s,
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
static int same_effects(const struct li2_span_decoded *a,
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
/* A queue entry is either a selected original head or a genuine unsupported
   frontier. All intervals, including frontiers, participate in overlap checks. */
struct link_node { uintptr_t pc; uint32_t token,decoded; };
static int enqueue(struct link_node *q,unsigned *count,uintptr_t page,uintptr_t pc) {
    if(pc<page || pc-page>=LI2_REGION_PAGE)return -1;
    for(unsigned i=0;i<*count;i++)if(q[i].pc==pc)return (int)i;
    if(*count==LI2_LINK_HEADS+LI2_LINK_EXITS)return -1;
    unsigned i=(*count)++;q[i].pc=pc;return (int)i;
}
static int resolve(const struct link_node *q,unsigned count,uintptr_t pc,uint32_t *out) {
    for(unsigned i=0;i<count;i++)if(q[i].pc==pc && q[i].decoded) {
        *out=q[i].token;return 1;
    }
    return 0;
}
#ifdef LI2_LINK_GRAPH_OBSERVE
static struct li2_link_graph_observation link_graph_counts;
const struct li2_link_graph_observation *li2_link_graph_observation(void) {
    return &link_graph_counts;
}
static void link_graph_refusal(unsigned reason) {
    if(reason>=LI2_LG_REASON_COUNT || link_graph_counts.reasons[reason]==UINT64_MAX) {
        link_graph_counts.overflow=1;return;
    }
    link_graph_counts.reasons[reason]++;
}
#define LG_GRAPH(reason) do { link_graph_refusal(reason); return LI2_REGION_PLAN_GRAPH; } while(0)
#define LG_ENQUEUE(page,pc) ((pc)<(page) || (pc)-(page)>=LI2_REGION_PAGE?LI2_LG_PAGE:LI2_LG_QUEUE)
#else
#define LG_GRAPH(reason) return LI2_REGION_PLAN_GRAPH
#endif

static int graph(struct li2_link_plan *p) {
    struct link_node q[LI2_LINK_HEADS+LI2_LINK_EXITS]={0};unsigned count=0;
    unsigned char occupied[LI2_REGION_PAGE]={0};
    if(enqueue(q,&count,p->page,p->entry)!=0)LG_GRAPH(LI2_LG_INITIAL);
    for(unsigned at=0;at<count;at++) {
        unsigned offset=(unsigned)(q[at].pc-p->page);
        size_t available=LI2_REGION_PAGE-offset;if(available>15)available=15;
        struct li2_span_decoded d;
        int result=describe(p,q[at].pc,p->source+offset,available,&d);
        if(result)return result;
        for(unsigned j=0;j<d.decoded.length;j++) {
            if(occupied[offset+j])LG_GRAPH(LI2_LG_OVERLAP);
            occupied[offset+j]=1;
        }
        q[at].decoded=1;
        if(!d.ready) {
            if(!at)return LI2_REGION_PLAN_MISS;
            if(p->exits==LI2_LINK_EXITS)LG_GRAPH(LI2_LG_EXITS);
            unsigned i=p->exits++;p->exit_pc[i]=q[at].pc;p->frontier[i]=d;
            q[at].token=LI2_LINK_HEADS+i;continue;
        }
        if(p->heads==LI2_LINK_HEADS)LG_GRAPH(LI2_LG_HEADS);
        unsigned i=p->heads++;q[at].token=i;p->original[i]=d;
        p->head[i].source_offset=offset;p->head[i].source_length=d.decoded.length;
        p->source_bytes+=d.decoded.length;
        if(d.flow==LI2_REGION_NEXT) {
            if(enqueue(q,&count,p->page,d.decoded.next_pc)<0)LG_GRAPH(LG_ENQUEUE(p->page,d.decoded.next_pc));
        } else if(d.flow==LI2_REGION_JCC || d.flow==LI2_REGION_JMP) {
            if(enqueue(q,&count,p->page,d.target)<0)LG_GRAPH(LG_ENQUEUE(p->page,d.target));
            if(d.flow==LI2_REGION_JCC && enqueue(q,&count,p->page,d.decoded.next_pc)<0)
                LG_GRAPH(LG_ENQUEUE(p->page,d.decoded.next_pc));
        } else return LI2_REGION_PLAN_DECODER;
    }
    if(!p->heads || !p->exits)LG_GRAPH(!p->heads?LI2_LG_EMPTY:LI2_LG_NO_FRONTIER);
    unsigned incoming[LI2_LINK_HEADS]={0},done[LI2_LINK_HEADS]={0};
    unsigned distance[LI2_LINK_HEADS]={0};distance[0]=1;
    for(unsigned i=0;i<p->heads;i++) {
        struct li2_region_head *h=&p->head[i];const struct li2_span_decoded *d=&p->original[i];
        h->successor_count=d->flow==LI2_REGION_JCC?2:1;
        if(!resolve(q,count,d->flow==LI2_REGION_NEXT?d->decoded.next_pc:d->target,&h->successors[0]))
            LG_GRAPH(LI2_LG_PRIMARY);
        if(h->successor_count==2 && !resolve(q,count,d->decoded.next_pc,&h->successors[1]))
            LG_GRAPH(LI2_LG_FALLTHROUGH);
        /* block is the exact original-head identity, not an old contiguous
           eight-block claim. Every head is a legal emitted link destination. */
        h->block=i;
        for(unsigned j=0;j<h->successor_count;j++)
            if(h->successors[j]<p->heads)incoming[h->successors[j]]++;
    }
    for(unsigned pass=0;pass<p->heads;pass++) {
        unsigned i=0;while(i<p->heads && (done[i] || incoming[i]))i++;
        if(i==p->heads || !distance[i])LG_GRAPH(i==p->heads?LI2_LG_KAHN_STALL:LI2_LG_DISTANCE);
        done[i]=1;if(distance[i]>p->longest_path)p->longest_path=distance[i];
        const struct li2_region_head *h=&p->head[i];
        for(unsigned j=0;j<h->successor_count;j++) {
            unsigned k=h->successors[j];if(k>=p->heads)continue;
            if(!incoming[k])LG_GRAPH(LI2_LG_INCOMING);
            incoming[k]--;
            if(distance[k]<distance[i]+1)distance[k]=distance[i]+1;
        }
    }
    return LI2_REGION_PLAN_OK;
}
#undef LG_GRAPH
#ifdef LI2_LINK_GRAPH_OBSERVE
#undef LG_ENQUEUE
#endif
static uintptr_t destination(const struct li2_link_plan *p,unsigned k) {
    return k<p->heads?p->generated+p->head[k].generated_offset:p->exit_pc[k-LI2_LINK_HEADS];
}
static uintptr_t original_destination(const struct li2_link_plan *p,unsigned k) {
    return k<p->heads?p->original[k].decoded.pc:p->exit_pc[k-LI2_LINK_HEADS];
}
static void map_row(struct li2_link_plan *p,unsigned head,unsigned offset,unsigned length,
                    uintptr_t original,unsigned original_length,unsigned kind) {
    struct li2_region_pc *m=&p->map[p->maps++];
    m->version=1;m->ready=1;m->head_index=head;m->kind=kind;
    m->source_offset=(unsigned)(original-p->page);m->source_length=original_length;
    m->generated_offset=offset;m->generated_length=length;
    m->original_pc=original;m->generated_pc=p->generated+offset;
}
static int jump(struct li2_link_plan *p,unsigned offset,uintptr_t target) {
    uint32_t delta;p->image[offset]=0xe9;
    if(!displacement(p->generated+offset+5,target,&delta))return 0;
    put32(p->image+offset+1,delta);return 1;
}
static int synthetic(const struct li2_span_decoded *d,uintptr_t target) {
    return d->ready==1 && d->flow==LI2_REGION_JMP && d->target==target &&
        d->decoded.length==5 && d->condition==LI2_REGION_CONDITION_NONE &&
        d->operand_count==1 && d->operands[0].kind==LI2_REGION_BRANCH &&
        d->operands[0].encoding_bits==32 && !d->register_count && !d->memory_count &&
        !d->address_count && !d->relocation && !d->rip_target && !d->displacement_offset &&
        !d->displacement_bytes && !d->flags_read && !d->flags_written && !d->flags_set &&
        !d->flags_cleared && !d->flags_undefined && !d->gpr_read && !d->gpr_write;
}
static int emit(struct li2_link_plan *p) {
    unsigned at=0;
    for(unsigned i=0;i<p->heads;i++) {
        struct li2_region_head *h=&p->head[i];unsigned flow=p->original[i].flow;
        h->generated_offset=at;h->generated_length=flow==LI2_REGION_NEXT?h->source_length:
            flow==LI2_REGION_JCC?6:5;
        unsigned n=h->generated_length+(flow==LI2_REGION_JMP?0:5);
        if(n>LI2_REGION_PAGE-at)return LI2_REGION_PLAN_RELOCATION;
        at+=n;
    }
    p->image_bytes=at;for(unsigned i=0;i<LI2_REGION_PAGE;i++)p->image[i]=0xcc;
    for(unsigned i=0;i<p->heads;i++) {
        const struct li2_region_head *h=&p->head[i];const struct li2_span_decoded *d=&p->original[i];
        unsigned char *s=p->image+h->generated_offset;
        if(d->flow==LI2_REGION_NEXT) {
            copy(s,p->source+h->source_offset,h->source_length);
            if(d->relocation==LI2_SPAN_RIP_DISP32) {
                uint32_t delta;
                if(d->displacement_bytes!=4 || d->displacement_offset>h->source_length ||
                   h->source_length-d->displacement_offset<4 ||
                   !displacement(p->generated+h->generated_offset+h->generated_length,d->rip_target,&delta))
                    return LI2_REGION_PLAN_RELOCATION;
                put32(s+d->displacement_offset,delta);
            } else if(d->relocation || d->rip_target || d->displacement_offset || d->displacement_bytes)
                return LI2_REGION_PLAN_DECODER;
        } else if(d->flow==LI2_REGION_JCC) {
            uint32_t delta;if(d->condition>15)return LI2_REGION_PLAN_DECODER;
            s[0]=0x0f;s[1]=(unsigned char)(0x80+d->condition);
            if(!displacement(p->generated+h->generated_offset+6,destination(p,h->successors[0]),&delta))
                return LI2_REGION_PLAN_RELOCATION;
            put32(s+2,delta);
        } else if(!jump(p,h->generated_offset,destination(p,h->successors[0])))
            return LI2_REGION_PLAN_RELOCATION;
        map_row(p,i,h->generated_offset,h->generated_length,d->decoded.pc,h->source_length,
            d->flow!=LI2_REGION_NEXT?LI2_REGION_PC_BRANCH:
            d->relocation?LI2_SPAN_PC_RIP_RELOCATED:LI2_REGION_PC_COPIED);
        if(d->flow!=LI2_REGION_JMP) {
            unsigned k=h->successors[d->flow==LI2_REGION_JCC?1:0],offset=h->generated_offset+h->generated_length;
            if(!jump(p,offset,destination(p,k)))return LI2_REGION_PLAN_RELOCATION;
            map_row(p,i,offset,5,original_destination(p,k),0,LI2_REGION_PC_EXIT);
        }
    }
    for(unsigned i=0;i<p->maps;i++) {
        const struct li2_region_pc *m=&p->map[i];const struct li2_region_head *h=&p->head[m->head_index];
        const struct li2_span_decoded *a=&p->original[m->head_index];struct li2_span_decoded b;
        size_t n=LI2_REGION_PAGE-m->generated_offset;if(n>15)n=15;
        int result=describe(p,m->generated_pc,p->image+m->generated_offset,n,&b);if(result)return result;
        if(!b.ready || b.decoded.length!=m->generated_length)return LI2_REGION_PLAN_DECODER;
        if(m->source_length) {
            if(!same_effects(a,&b) || (a->flow!=LI2_REGION_NEXT && b.target!=destination(p,h->successors[0])))
                return LI2_REGION_PLAN_DECODER;
        } else if(!synthetic(&b,destination(p,h->successors[a->flow==LI2_REGION_JCC?1:0])))
            return LI2_REGION_PLAN_DECODER;
    }
    return LI2_REGION_PLAN_OK;
}
int li2_link_plan_page(uintptr_t page,const unsigned char *source,uintptr_t entry,
                       uintptr_t generated,struct li2_link_plan *out) {
    if(!storage(out,sizeof(*out)) || (uintptr_t)out%_Alignof(struct li2_link_plan) ||
       !storage(source,LI2_REGION_PAGE) || overlap(out,sizeof(*out),source,LI2_REGION_PAGE))
        return LI2_REGION_PLAN_ARGUMENT;
    zero(out,sizeof(*out));out->version=LI2_LINK_VERSION;
    if(!page_range(page) || !page_range(generated) || page==generated ||
       entry<page || entry-page>=LI2_REGION_PAGE)return LI2_REGION_PLAN_ARGUMENT;
    out->page=page;out->entry=entry;out->generated=generated;copy(out->source,source,LI2_REGION_PAGE);
    int result=graph(out);if(result)return result;
    result=emit(out);if(result)return result;
    if(out->decoder_calls!=out->heads+out->exits+out->maps)return LI2_REGION_PLAN_DECODER;
    out->ready=1;return LI2_REGION_PLAN_OK;
}
int li2_link_plan_validate(const struct li2_link_plan *p) {
    if(!storage(p,sizeof(*p)) || (uintptr_t)p%_Alignof(struct li2_link_plan))
        return LI2_REGION_PLAN_ARGUMENT;
    if(p->version!=LI2_LINK_VERSION || p->ready!=1)return LI2_REGION_PLAN_CORRUPT;
    struct li2_link_plan expected;
    int result=li2_link_plan_page(p->page,p->source,p->entry,p->generated,&expected);
    if(result==LI2_REGION_PLAN_DECODER)return result;
    return result || !equal(p,&expected,sizeof(*p))?LI2_REGION_PLAN_CORRUPT:LI2_REGION_PLAN_OK;
}
