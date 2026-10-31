/* Included only after the exact old planner functions. No old ABI or result
   changes; source-local refusal sites are explicitly classified in new copies. */
#include "persistent_dynamic_plan.h"
static void ped_mark(struct li2_pe_dynamic_miss *m,unsigned reason,unsigned site,uintptr_t pc,uint64_t detail) {
    m->reason=reason;m->site=site;m->pc=pc;m->detail=detail;
}
static void ped_source_boundary(const struct li2_span_decoded *d,size_t n,struct li2_pe_dynamic_miss *m) {
    const struct li2_decoded *a=&d->decoded;
    unsigned reason=a->decode_status==LI2_INVALID?LI2_PED_SOURCE_INVALID:
        a->decode_status==LI2_TRUNCATED?LI2_PED_SOURCE_TRUNCATED:0;
    if(!reason || !n || n>15 || !a->length || a->length>n || a->next_pc!=a->pc+a->length ||
       a->code!=0 || a->kind!=LI2_NONE || a->destination!=16 || a->width_bits || a->step_disposition!=LI2_STEP_INVALID)return;
    struct li2_span_decoded expected={0};expected.decoded=*a;expected.version=1;
    expected.refusal=reason==LI2_PED_SOURCE_INVALID?LI2_REGION_INVALID:LI2_REGION_TRUNCATED;
    if(equal(d,&expected,sizeof expected))ped_mark(m,reason,LI2_PED_SOURCE,a->pc,n);
}
static void ped_enqueue_refusal(const struct li2_pe_plan *p,const struct node *q,unsigned n,
    uintptr_t origin,uintptr_t target,struct li2_pe_dynamic_miss *m) {
    unsigned page,offset;
    if(!location(p,target,&page,&offset)) {ped_mark(m,LI2_PED_OUTSIDE_PAIR,LI2_PED_SOURCE,origin,target);return;}
    for(unsigned i=0;i<n;i++)if(q[i].pc==target)return;
    if(n==LI2_PE_HEADS+LI2_PE_EXITS)ped_mark(m,LI2_PED_QUEUE_LIMIT,LI2_PED_SOURCE,origin,n);
}
/* The unchanged guard returns one relocation code for several sites. Classify
   only an actual retained early-LEA, late-store or successor-JMP reach failure.
   Internal/spill failures and malformed displacement metadata stay terminal. */
static int ped_guard_reach(const struct li2_pe_plan *p,unsigned i,struct li2_pe_dynamic_miss *m) {
    const struct li2_mg_plan *g=&p->guard[i];const struct li2_mg_store *s=&p->store_original[i];
    const struct li2_pe_head *h=&p->head[i];uint32_t delta;
    if(g->version!=1 || g->ready || g->result!=LI2_MG_RELOCATION || g->reserved ||
       g->generated!=p->generated+(uintptr_t)i*LI2_PE_SLOT_BYTES || g->spill!=p->spill ||
       !token_valid(p,h->successors[0]) || g->successor!=destination(p,h->successors[0]) ||
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
            ped_mark(m,LI2_PED_GUARD_RIP_REACH,LI2_PED_EMIT,s->tf.pc,s->rip_target);return 1;
        }
        if(!displacement(g->generated+28+en,s->rip_target,&delta))return 0;
        if(g->store_offset && g->image_bytes==g->store_offset && !g->reject_offset &&
           !displacement(g->generated+g->store_offset+s->tf.length,s->rip_target,&delta)) {
            ped_mark(m,LI2_PED_GUARD_RIP_REACH,LI2_PED_EMIT,s->tf.pc,s->rip_target);return 1;
        }
        if(!g->store_offset || !displacement(g->generated+g->store_offset+s->tf.length,s->rip_target,&delta))return 0;
    }
    const struct li2_mg_boundary *b=&g->boundary[g->boundaries-1];
    if(g->store_offset && !g->reject_offset && b->length==5 && b->phase==LI2_MG_AFTER &&
       b->flags==LI2_MG_PHYSICAL && b->dirty==0 && b->spill_valid==15 &&
       b->offset>=g->store_offset+s->tf.length && b->offset+5==g->image_bytes &&
       !displacement(g->generated+b->offset+5,g->successor,&delta)) {
        ped_mark(m,LI2_PED_GUARD_FOLLOW_REACH,LI2_PED_EMIT,s->tf.pc,g->successor);return 1;
    }
    return 0;
}

static int ped_graph(struct li2_pe_plan *p,struct li2_pe_dynamic_miss *miss) {
    struct node q[LI2_PE_HEADS+LI2_PE_EXITS]={0};unsigned n=0;
    unsigned char occupied[LI2_PE_SOURCES][LI2_REGION_PAGE]={{0}};
    if(enqueue(p,q,&n,p->entry)!=0)return LI2_PE_GRAPH;
    for(unsigned at=0;at<n;at++) {
        unsigned char bytes[15];size_t count=window(p,q[at].pc,bytes);
        struct li2_span_decoded d;struct li2_mg_store s={0};
        int e=describe(p,q[at].pc,bytes,count,&d);if(e) {
            if(e==LI2_PE_BOUNDARY)ped_source_boundary(&d,count,miss);
            return e;
        }
        for(unsigned j=0;j<d.decoded.length;j++) {
            unsigned page,offset;if(!location(p,q[at].pc+j,&page,&offset))return LI2_PE_GRAPH;
            if(occupied[page][offset]) {ped_mark(miss,LI2_PED_SOURCE_OVERLAP,LI2_PED_SOURCE,q[at].pc,q[at].pc+j);return LI2_PE_GRAPH;}
            occupied[page][offset]=1;p->source_mask|=1U<<page;
        }
        unsigned kind=LI2_PE_NONE;
        if(d.ready) { if((e=static_none(p,&d,bytes,count)))return e; }
        else { if((e=writer(p,&d,bytes,count,&s)))return e;kind=s.ready?LI2_PE_MOV:0; }
        q[at].decoded=1;
        if(!kind) {
            if(!at) {
                if(d.refusal==LI2_REGION_UNSUPPORTED || d.refusal==LI2_REGION_PREFIX || d.refusal==LI2_REGION_OPERANDS)
                    ped_mark(miss,LI2_PED_ROOT_UNSUPPORTED,LI2_PED_SOURCE,q[at].pc,d.refusal);
                return LI2_PE_MISS;
            }
            if(p->exits==LI2_PE_EXITS) {ped_mark(miss,LI2_PED_EXIT_LIMIT,LI2_PED_SOURCE,q[at].pc,p->exits);return LI2_PE_GRAPH;}
            unsigned x=p->exits++;p->frontier[x]=d;p->exit_pc[x]=q[at].pc;q[at].token=LI2_PE_HEADS+x;continue;
        }
        if(p->heads==LI2_PE_HEADS) {ped_mark(miss,LI2_PED_HEAD_LIMIT,LI2_PED_SOURCE,q[at].pc,p->heads);return LI2_PE_GRAPH;}
        unsigned i=p->heads++;struct li2_pe_head *h=&p->head[i];q[at].token=i;
        if(!location(p,q[at].pc,&h->source_page,&h->source_offset))return LI2_PE_GRAPH;
        h->kind=kind;h->source_length=d.decoded.length;p->source_bytes+=h->source_length;p->original[i]=d;
        if(kind==LI2_PE_MOV) { p->store_original[i]=s;++p->stores; }
        unsigned flow=kind==LI2_PE_MOV?LI2_REGION_NEXT:d.flow;
        if(flow==LI2_REGION_NEXT) {
            if(enqueue(p,q,&n,d.decoded.next_pc)<0) {ped_enqueue_refusal(p,q,n,q[at].pc,d.decoded.next_pc,miss);return LI2_PE_GRAPH;}
        } else if(flow==LI2_REGION_JCC || flow==LI2_REGION_JMP) {
            if(enqueue(p,q,&n,d.target)<0) {ped_enqueue_refusal(p,q,n,q[at].pc,d.target,miss);return LI2_PE_GRAPH;}
            if(flow==LI2_REGION_JCC && enqueue(p,q,&n,d.decoded.next_pc)<0) {ped_enqueue_refusal(p,q,n,q[at].pc,d.decoded.next_pc,miss);return LI2_PE_GRAPH;}
        } else return LI2_PE_DECODER;
    }
    if(!p->heads || !p->exits) {
        if(p->heads && !p->exits)ped_mark(miss,LI2_PED_NO_EXIT,LI2_PED_SOURCE,p->entry,p->heads);
        return LI2_PE_GRAPH;
    }
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
static int ped_emit(struct li2_pe_plan *p,struct li2_pe_dynamic_miss *miss) {
    for(unsigned i=0;i<LI2_PE_IMAGE_BYTES;i++)p->image[i]=0xcc;
    for(unsigned i=0;i<p->heads;i++) {
        struct li2_pe_head *h=&p->head[i];const struct li2_span_decoded *d=&p->original[i];
        unsigned at=i*LI2_PE_SLOT_BYTES;unsigned char *out=p->image+at;
        if(h->kind==LI2_PE_MOV) {
            unsigned char bytes[15];size_t n=window(p,d->decoded.pc,bytes);
            p->guard_result=(unsigned)li2_mg_emit(d->decoded.pc,bytes,n,p->generated+at,p->spill,
                destination(p,h->successors[0]),&p->table,&p->guard[i]);
            if(p->guard_result) {
                if(p->guard_result==LI2_MG_RELOCATION)ped_guard_reach(p,i,miss);
                return p->guard_result==LI2_MG_RELOCATION?LI2_PE_RELOCATION:LI2_PE_DECODER;
            }
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
                if(d->displacement_bytes!=4 || d->displacement_offset>h->source_length || h->source_length-d->displacement_offset<4)return LI2_PE_RELOCATION;
                if(!displacement(p->generated+at+length,d->rip_target,&delta)) {
                    ped_mark(miss,LI2_PED_RIP_REACH,LI2_PED_EMIT,d->decoded.pc,d->rip_target);return LI2_PE_RELOCATION;
                }
                put32(out+d->displacement_offset,delta);
            } else if(d->relocation || d->rip_target || d->displacement_offset || d->displacement_bytes)return LI2_PE_DECODER;
        } else if(flow==LI2_REGION_JCC) {
            uint32_t delta;if(d->condition>15)return LI2_PE_DECODER;
            out[0]=0x0f;out[1]=(unsigned char)(0x80+d->condition);
            if(!displacement(p->generated+at+6,destination(p,h->successors[0]),&delta)) {
                ped_mark(miss,LI2_PED_BRANCH_REACH,LI2_PED_EMIT,d->decoded.pc,destination(p,h->successors[0]));return LI2_PE_RELOCATION;
            }
            put32(out+2,delta);
        } else if(!jump(p,at,destination(p,h->successors[0]))) {
            ped_mark(miss,LI2_PED_BRANCH_REACH,LI2_PED_EMIT,d->decoded.pc,destination(p,h->successors[0]));return LI2_PE_RELOCATION;
        }
        struct li2_span_decoded actual;int e=describe(p,p->generated+at,out,15,&actual);if(e)return e;
        if(!actual.ready || actual.decoded.length!=length || !same_effects(d,&actual) ||
           (flow!=LI2_REGION_NEXT && actual.target!=destination(p,h->successors[0])))return LI2_PE_DECODER;
        if(flow!=LI2_REGION_JMP) {
            unsigned k=h->successors[flow==LI2_REGION_JCC?1:0];
            if(!jump(p,at+length,destination(p,k))) {
                ped_mark(miss,LI2_PED_FALLTHROUGH_REACH,LI2_PED_EMIT,d->decoded.pc,destination(p,k));return LI2_PE_RELOCATION;
            }
            e=describe(p,p->generated+at+length,p->image+at+length,15,&actual);if(e)return e;
            if(!synthetic(&actual,destination(p,k)))return LI2_PE_DECODER;
        }
    }
    return 0;
}
int li2_pe_plan_pages_dynamic(const uintptr_t pages[LI2_PE_SOURCES],const unsigned char source[LI2_PE_SOURCES][LI2_REGION_PAGE],
    uintptr_t entry,uintptr_t generated,uintptr_t spill,const struct li2_mg_table *table,struct li2_pe_plan *out,struct li2_pe_dynamic_miss *miss) {
    if(!storage(out,sizeof *out) || (uintptr_t)out%_Alignof(struct li2_pe_plan) || !storage(pages,2*sizeof *pages) ||
       (uintptr_t)pages%_Alignof(uintptr_t) ||
       !storage(source,2*LI2_REGION_PAGE) || !storage(table,sizeof *table) || (uintptr_t)table%_Alignof(struct li2_mg_table) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)pages,2*sizeof *pages) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)source,2*LI2_REGION_PAGE) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)table,sizeof *table) ||
       !storage(miss,sizeof *miss) || (uintptr_t)miss%_Alignof(struct li2_pe_dynamic_miss) ||
       overlap((uintptr_t)miss,sizeof *miss,(uintptr_t)out,sizeof *out) ||
       overlap((uintptr_t)miss,sizeof *miss,(uintptr_t)pages,2*sizeof *pages) ||
       overlap((uintptr_t)miss,sizeof *miss,(uintptr_t)source,2*LI2_REGION_PAGE) ||
       overlap((uintptr_t)miss,sizeof *miss,(uintptr_t)table,sizeof *table))return LI2_PE_ARGUMENT;
    zero(miss,sizeof *miss);miss->version=LI2_PE_DYNAMIC_MISS_VERSION;
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
    e=ped_graph(out,miss);if(!e)e=ped_emit(out,miss);if(!e)out->ready=1;
 done:out->result=(unsigned)e;miss->status=(unsigned)e;return e;
}
int li2_pe_dynamic_miss_valid(const struct li2_pe_plan *p,const struct li2_pe_dynamic_miss *m,int result) {
    if(!storage(p,sizeof *p) || !storage(m,sizeof *m) ||
       (uintptr_t)p%_Alignof(struct li2_pe_plan) || (uintptr_t)m%_Alignof(struct li2_pe_dynamic_miss) ||
       overlap((uintptr_t)p,sizeof *p,(uintptr_t)m,sizeof *m) ||
       m->version!=LI2_PE_DYNAMIC_MISS_VERSION || m->status!=(unsigned)result ||
       !m->reason || m->reason>=LI2_PED_REASON_COUNT || p->version!=LI2_PE_VERSION ||
       p->bytes!=sizeof *p || p->ready || p->result!=(unsigned)result || p->reserved ||
       p->decoder_result || p->heads>LI2_PE_HEADS || p->exits>LI2_PE_EXITS || p->stores>p->heads ||
       p->source_bytes>LI2_PE_HEADS*15 || (p->source_mask&~3U) ||
       p->page[0]>=p->page[1] || (p->page[0]&4095U) || (p->page[1]&4095U) ||
       !address(p->page[0],LI2_REGION_PAGE) || !address(p->page[1],LI2_REGION_PAGE) ||
       (p->generated&4095U) || !address(p->generated,LI2_PE_IMAGE_BYTES))return 0;
    unsigned page,offset;
    if(!location(p,p->entry,&page,&offset) || !location(p,m->pc,&page,&offset))return 0;
    if(m->reason<=LI2_PED_NO_EXIT) {
        if(m->site!=LI2_PED_SOURCE || p->guard_result)return 0;
        switch(m->reason) {
        case LI2_PED_ROOT_UNSUPPORTED:
            return result==LI2_PE_MISS && !p->heads && !p->exits && m->pc==p->entry &&
                (m->detail==LI2_REGION_UNSUPPORTED || m->detail==LI2_REGION_PREFIX || m->detail==LI2_REGION_OPERANDS);
        case LI2_PED_SOURCE_INVALID: case LI2_PED_SOURCE_TRUNCATED: {
            unsigned char bytes[15];size_t n=window(p,m->pc,bytes);
            return result==LI2_PE_BOUNDARY && n && n==m->detail;
        }
        case LI2_PED_SOURCE_OVERLAP:
            return result==LI2_PE_GRAPH && m->detail>=m->pc && m->detail-m->pc<15 &&
                location(p,m->detail,&page,&offset);
        case LI2_PED_OUTSIDE_PAIR:
            return result==LI2_PE_GRAPH && !location(p,m->detail,&page,&offset);
        case LI2_PED_HEAD_LIMIT:return result==LI2_PE_GRAPH && p->heads==LI2_PE_HEADS && m->detail==LI2_PE_HEADS;
        case LI2_PED_EXIT_LIMIT:return result==LI2_PE_GRAPH && p->exits==LI2_PE_EXITS && m->detail==LI2_PE_EXITS;
        case LI2_PED_QUEUE_LIMIT:return result==LI2_PE_GRAPH && m->detail==LI2_PE_HEADS+LI2_PE_EXITS;
        case LI2_PED_NO_EXIT:return result==LI2_PE_GRAPH && p->heads && !p->exits && m->pc==p->entry && m->detail==p->heads;
        default:return 0;
        }
    }
    if(m->site!=LI2_PED_EMIT || result!=LI2_PE_RELOCATION || !p->heads || !p->exits)return 0;
    unsigned found=LI2_PE_HEADS;
    for(unsigned i=0;i<p->heads;i++)if(p->original[i].decoded.pc==m->pc) {
        if(found!=LI2_PE_HEADS)return 0;
        found=i;
    }
    if(found==LI2_PE_HEADS)return 0;
    const struct li2_pe_head *h=&p->head[found];const struct li2_span_decoded *d=&p->original[found];
    if(h->source_page>=LI2_PE_SOURCES || h->source_offset>=LI2_REGION_PAGE ||
       p->page[h->source_page]+h->source_offset!=m->pc || !h->source_length || h->source_length>15 ||
       d->decoded.length!=h->source_length || d->decoded.next_pc!=m->pc+h->source_length ||
       !token_valid(p,h->successors[0]))return 0;
    if(m->reason==LI2_PED_GUARD_RIP_REACH || m->reason==LI2_PED_GUARD_FOLLOW_REACH) {
        struct li2_pe_dynamic_miss expected={.version=LI2_PE_DYNAMIC_MISS_VERSION,.status=LI2_PE_RELOCATION};
        return h->kind==LI2_PE_MOV && h->successor_count==1 && p->guard_result==LI2_MG_RELOCATION &&
            ped_guard_reach(p,found,&expected) && equal(m,&expected,sizeof expected);
    }
    if(h->kind!=LI2_PE_NONE || p->guard_result)return 0;
    uintptr_t generated=p->generated+(uintptr_t)found*LI2_PE_SLOT_BYTES;uint32_t delta;
    if(m->reason==LI2_PED_RIP_REACH)
        return d->flow==LI2_REGION_NEXT && h->successor_count==1 && d->relocation==LI2_SPAN_RIP_DISP32 &&
            d->displacement_bytes==4 && d->displacement_offset<=h->source_length &&
            h->source_length-d->displacement_offset>=4 && m->detail==d->rip_target &&
            !displacement(generated+h->source_length,d->rip_target,&delta);
    if(m->reason==LI2_PED_BRANCH_REACH)
        return (d->flow==LI2_REGION_JMP || d->flow==LI2_REGION_JCC) &&
            h->successor_count==(d->flow==LI2_REGION_JCC?2U:1U) &&
            m->detail==destination(p,h->successors[0]) &&
            !displacement(generated+(d->flow==LI2_REGION_JCC?6:5),m->detail,&delta);
    if(m->reason==LI2_PED_FALLTHROUGH_REACH) {
        unsigned k=d->flow==LI2_REGION_JCC?1:0;
        return (d->flow==LI2_REGION_NEXT || d->flow==LI2_REGION_JCC) && h->successor_count==k+1 &&
            token_valid(p,h->successors[k]) && m->detail==destination(p,h->successors[k]) &&
            !displacement(generated+(d->flow==LI2_REGION_JCC?6:h->source_length)+5,m->detail,&delta);
    }
    return 0;
}

/* Every ready plan has a reached original frontier inside its two-page
   source set. All exits (Jcc, JMP, NEXT and MOV-guard follow) use rel32;
   their instruction ends lie in this conservative closed image interval.
   Passing only keeps the exact old planner eligible to decide. */
int li2_pe_dynamic_placement(uintptr_t entry,uintptr_t generated) {
    const uintptr_t limit=UINT64_C(1)<<47;
    const uintptr_t page=entry&~(uintptr_t)(LI2_REGION_PAGE-1U);
    if(entry>=limit || page<LI2_REGION_PAGE ||
       entry-page>LI2_REGION_PAGE-15U || page>limit-2U*LI2_REGION_PAGE ||
       generated<LI2_REGION_PAGE || (generated&(LI2_REGION_PAGE-1U)) ||
       generated>limit-LI2_PE_IMAGE_BYTES)return -1;
    const uintptr_t last=page+2U*LI2_REGION_PAGE-1U;
    const uintptr_t end=generated+LI2_PE_IMAGE_BYTES;
    if(last<generated)return generated-last<=UINT32_C(0x80000000);
    if(page>end)return page-end<=UINT32_C(0x7fffffff);
    return 1;
}
