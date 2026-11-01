/* Separate opt-in partition; unchanged BFS helpers and emitter stay above. */
#include "persistent_fused_plan.h"

static int pf_graph(struct li2_pg_plan *p,struct li2_pg_miss *miss) {
    struct node q[LI2_PG_HEADS+LI2_PG_BOUNDARIES]={0};unsigned n=0;
    unsigned char occupied[LI2_PE_SOURCES][LI2_REGION_PAGE]={{0}};
    if(enqueue(p,q,&n,p->entry)!=0)return LI2_PG_GRAPH;
    for(unsigned at=0;at<n;at++) {
        unsigned char bytes[15];size_t count=window(p,q[at].pc,bytes);
        struct li2_span_decoded d;struct li2_mg_store s={0};
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
        unsigned external=0;
        if(kind==LI2_PE_NONE && (d.flow==LI2_REGION_JMP || d.flow==LI2_REGION_JCC)) {
            external=li2_pf_cut_mask(p->page,&d);
            if(external)kind=LI2_PG_DIRECT;
        }
        if(p->heads==LI2_PG_HEADS) {pgd_mark(miss,LI2_PGD_HEAD_LIMIT,LI2_PGD_SOURCE,q[at].pc,p->heads);return LI2_PG_GRAPH;}
        unsigned i=p->heads++;++p->member_heads[i/LI2_PE_HEADS];
        struct li2_pe_head *h=&p->head[i];q[at].token=i;
        if(!location(p,q[at].pc,&h->source_page,&h->source_offset))return LI2_PG_GRAPH;
        h->kind=kind;h->source_length=d.decoded.length;p->source_bytes+=h->source_length;p->original[i]=d;
        if(kind==LI2_PE_MOV) { p->instruction[i].mov=s;++p->stores; }
        if(kind==LI2_PG_DIRECT) {
            p->decoder_result=(unsigned)li2_dd_describe(d.decoded.pc,bytes,count,external,&p->instruction[i].direct);
            if(p->decoder_result)return LI2_PG_DECODER;
            const unsigned arms=d.flow==LI2_REGION_JCC?2:1;
            for(unsigned arm=0;arm<arms;arm++)if(external&(1U<<arm)) {
                if(p->exits==LI2_PG_BOUNDARIES) {
                    pgd_mark(miss,LI2_PGD_EXIT_LIMIT,LI2_PGD_SOURCE,q[at].pc,p->exits);return LI2_PG_GRAPH;
                }
                /* Arm identity is (this head, this ordinal, this token).
                   Equal targets must not collapse two conditional arms. */
                unsigned x=p->exits++;p->frontier[x]=d;p->exit_pc[x]=d.decoded.pc;
                h->successors[arm]=LI2_PG_HEADS+x;
            }
        }
        unsigned flow=guarded_write(kind)?LI2_REGION_NEXT:d.flow;
        if(flow==LI2_REGION_NEXT) {
            if(enqueue(p,q,&n,d.decoded.next_pc)<0) {pgd_enqueue_refusal(p,q,n,q[at].pc,d.decoded.next_pc,miss);return LI2_PG_GRAPH;}
        } else if(flow==LI2_REGION_JCC || flow==LI2_REGION_JMP) {
            if(!(external&1U) && enqueue(p,q,&n,d.target)<0) {pgd_enqueue_refusal(p,q,n,q[at].pc,d.target,miss);return LI2_PG_GRAPH;}
            if(flow==LI2_REGION_JCC && !(external&2U) && enqueue(p,q,&n,d.decoded.next_pc)<0) {
                pgd_enqueue_refusal(p,q,n,q[at].pc,d.decoded.next_pc,miss);return LI2_PG_GRAPH;
            }
        } else return LI2_PG_DECODER;
    }
    if(!p->heads || !p->exits) {
        if(p->heads && !p->exits)pgd_mark(miss,LI2_PGD_NO_EXIT,LI2_PGD_SOURCE,p->entry,p->heads);
        return LI2_PG_GRAPH;
    }
    for(unsigned i=0;i<p->heads;i++) {
        const struct li2_span_decoded *d=&p->original[i];
        if(p->head[i].kind!=LI2_PE_NONE && p->head[i].kind!=LI2_PG_DIRECT)continue;
        if(d->flow!=LI2_REGION_JMP && d->flow!=LI2_REGION_JCC)continue;
        const uintptr_t targets[2]={d->target,d->decoded.next_pc};
        const unsigned arms=d->flow==LI2_REGION_JCC?2U:1U;
        for(unsigned arm=0;arm<arms;arm++) {
            unsigned page,offset;
            if(location(p,targets[arm],&page,&offset) && occupied[page][offset]) {
                unsigned exact=0;
                for(unsigned j=0;j<p->heads;j++)if(p->original[j].decoded.pc==targets[arm])++exact;
                /* An unsupported frontier is also an exact decoded boundary. */
                for(unsigned j=0;j<p->exits;j++)if(p->exit_pc[j]==targets[arm] &&
                    p->frontier[j].decoded.pc==targets[arm] && !p->frontier[j].ready)++exact;
                if(exact!=1) {
                    pgd_mark(miss,LI2_PGD_SOURCE_OVERLAP,LI2_PGD_SOURCE,d->decoded.pc,targets[arm]);
                    return LI2_PG_GRAPH;
                }
            }
        }
    }
    for(unsigned i=0;i<p->heads;i++) {
        struct li2_pe_head *h=&p->head[i];const struct li2_span_decoded *d=&p->original[i];
        if(h->kind==LI2_PG_DIRECT) {
            const struct li2_dd_descriptor *a=&p->instruction[i].direct;
            h->successor_count=d->flow==LI2_REGION_JCC?2:1;
            for(unsigned arm=0;arm<h->successor_count;arm++) {
                if(a->external_mask&(1U<<arm)) {
                    unsigned k=h->successors[arm];
                    if(k<LI2_PG_HEADS || k-LI2_PG_HEADS>=p->exits ||
                       p->exit_pc[k-LI2_PG_HEADS]!=d->decoded.pc ||
                       !equal(&p->frontier[k-LI2_PG_HEADS],d,sizeof *d))return LI2_PG_GRAPH;
                } else {
                    if(!resolve(q,n,a->target[arm],&h->successors[arm]))return LI2_PG_GRAPH;
                    /* Backward closure requires a generated exact head, not an
                       unsupported frontier. Unclassified failure is terminal;
                       a caller must not invent a cancel diagnosis for it. */
                    if(arm==0 && h->successors[arm]>=p->heads)return LI2_PG_GRAPH;
                }
            }
            continue;
        }
        unsigned flow=guarded_write(h->kind)?LI2_REGION_NEXT:d->flow;
        h->successor_count=flow==LI2_REGION_JCC?2:1;
        if(!resolve(q,n,flow==LI2_REGION_NEXT?d->decoded.next_pc:d->target,&h->successors[0]) ||
           (h->successor_count==2 && !resolve(q,n,d->decoded.next_pc,&h->successors[1])))return LI2_PG_GRAPH;
        if(flow==LI2_REGION_JMP && h->successors[0]>=p->heads)return LI2_PG_GRAPH;
    }
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
    if(p->member_heads[0]!=(p->heads<LI2_PE_HEADS?p->heads:LI2_PE_HEADS) ||
       p->member_heads[1]!=(p->heads>LI2_PE_HEADS?p->heads-LI2_PE_HEADS:0) ||
       (p->heads>LI2_PE_HEADS?!p->links:p->links!=0))return LI2_PG_GRAPH;
    /* One global BFS and byte-ownership map, then deterministic partition.
       Every queued original PC has exactly one complete resolved token. */
    return 0;
}

int li2_pf_plan_pages(const uintptr_t pages[2],const unsigned char source[2][LI2_REGION_PAGE],
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
    zero(miss,sizeof *miss);miss->version=LI2_PF_VERSION;
    zero(out,sizeof *out);out->version=LI2_PF_VERSION;out->bytes=sizeof *out;
    int e=LI2_PG_ARGUMENT;
    if(!layout_valid(layout) || li2_mg_table_validate(table) || pages[0]>=pages[1])goto done;
    uintptr_t at[8]={pages[0],pages[1],layout->generated[0],layout->generated[1],layout->stubs,layout->slots,layout->spill,table->address};
    size_t bytes[8]={LI2_REGION_PAGE,LI2_REGION_PAGE,LI2_PE_IMAGE_BYTES,LI2_PE_IMAGE_BYTES,
        LI2_REGION_PAGE,LI2_REGION_PAGE,LI2_REGION_PAGE,sizeof *table};
    for(unsigned i=0;i<8;i++) {
        if(!address(at[i],bytes[i]) || (i<2 && (at[i]&4095U)))goto done;
        for(unsigned j=0;j<i;j++)if(overlap(at[i],bytes[i],at[j],bytes[j]))goto done;
    }
    for(unsigned i=0;i<8;i++)if(overlap(layout->directory,LI2_JD_DOMAIN_BYTES,at[i],bytes[i]))goto done;
    copy(out->page,pages,sizeof out->page);copy(out->source,source,sizeof out->source);
    out->entry=entry;out->layout=*layout;copy(&out->table,table,sizeof *table);
    unsigned page,offset;if(!location(out,entry,&page,&offset))goto done;
    e=pf_graph(out,miss);if(!e)e=pgd_emit(out,miss);if(!e)out->ready=1;
 done:out->result=(unsigned)e;miss->status=(unsigned)e;return e;
}

int li2_pf_plan_validate(const struct li2_pg_plan *p,struct li2_pg_plan *scratch) {
    if(!storage(p,sizeof *p) || !storage(scratch,sizeof *scratch) ||
       (uintptr_t)p%_Alignof(struct li2_pg_plan) || (uintptr_t)scratch%_Alignof(struct li2_pg_plan) ||
       overlap((uintptr_t)p,sizeof *p,(uintptr_t)scratch,sizeof *scratch))return LI2_PG_ARGUMENT;
    if(p->version!=LI2_PF_VERSION || p->bytes!=sizeof *p || p->ready!=1 || p->result || p->reserved || p->reserved2)
        return LI2_PG_CORRUPT;
    struct li2_pg_miss miss;
    int e=li2_pf_plan_pages(p->page,p->source,p->entry,&p->layout,&p->table,scratch,&miss);
    struct li2_pg_miss empty={.version=LI2_PF_VERSION};
    return e || !equal(&miss,&empty,sizeof miss) || !equal(p,scratch,sizeof *p)?LI2_PG_CORRUPT:0;
}

int li2_pf_miss_validate(const struct li2_pg_plan *p,const struct li2_pg_miss *m,int result,
    struct li2_pg_plan *scratch) {
    const void *host[3]={p,m,scratch};
    const size_t size[3]={sizeof *p,sizeof *m,sizeof *scratch};
    const size_t align[3]={_Alignof(struct li2_pg_plan),_Alignof(struct li2_pg_miss),_Alignof(struct li2_pg_plan)};
    for(unsigned i=0;i<3;i++) {
        if(!storage(host[i],size[i]) || (uintptr_t)host[i]%align[i])return LI2_PG_ARGUMENT;
        for(unsigned j=0;j<i;j++)if(overlap((uintptr_t)host[i],size[i],(uintptr_t)host[j],size[j]))return LI2_PG_ARGUMENT;
    }
    if(!result || p->version!=LI2_PF_VERSION || p->bytes!=sizeof *p || p->ready ||
       p->result!=(unsigned)result || m->version!=LI2_PF_VERSION || m->status!=(unsigned)result)
        return LI2_PG_CORRUPT;
    struct li2_pg_miss actual;
    int e=li2_pf_plan_pages(p->page,p->source,p->entry,&p->layout,&p->table,scratch,&actual);
    return e!=result || !equal(p,scratch,sizeof *p) || !equal(m,&actual,sizeof actual)?LI2_PG_CORRUPT:0;
}
