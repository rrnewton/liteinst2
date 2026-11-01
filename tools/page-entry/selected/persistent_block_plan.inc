/* Included only by the separate opt-in appended to the unchanged BFS unit. */
#include "persistent_block_plan.h"
static int pb_graph(struct li2_pg_plan *p,struct li2_pg_miss *miss) {
    unsigned char occupied[2][LI2_REGION_PAGE]={{0}};
    uintptr_t pc=p->entry;
    for(;;) {
        unsigned char bytes[15];size_t count=window(p,pc,bytes);
        struct li2_span_decoded d;
        int e=describe(p,pc,bytes,count,&d);
        if(e) {if(e==LI2_PG_BOUNDARY)pgd_source_boundary(&d,count,miss);return e;}
        for(unsigned j=0;j<d.decoded.length;j++) {
            unsigned page,offset;
            if(!location(p,pc+j,&page,&offset))return LI2_PG_GRAPH;
            if(occupied[page][offset]) {
                pgd_mark(miss,LI2_PGD_SOURCE_OVERLAP,LI2_PGD_SOURCE,pc,pc+j);return LI2_PG_GRAPH;
            }
            occupied[page][offset]=1;p->source_mask|=1U<<page;
        }
        if(!d.ready) {
            if(!p->heads) {
                struct li2_mg_store s={0};
                if((e=writer(p,&d,bytes,count,&s)))return e;
                if(pgd_root_selected(&d,&s,bytes,count))
                    pgd_mark(miss,LI2_PGD_ROOT_SELECTED,LI2_PGD_SOURCE,pc,d.decoded.kind);
                else pgd_mark(miss,LI2_PGD_ROOT_UNSUPPORTED,LI2_PGD_SOURCE,pc,d.refusal);
                return LI2_PG_MISS;
            }
            /* This policy does not borrow old MOV/CALL/RET/indirect admission. */
            p->exits=1;p->frontier[0]=d;p->exit_pc[0]=pc;break;
        }
        if((e=static_none(p,&d,bytes,count)))return e;
        if(d.flow!=LI2_REGION_NEXT && d.flow!=LI2_REGION_JMP && d.flow!=LI2_REGION_JCC)
            return LI2_PG_DECODER;
        if(p->heads==LI2_PG_HEADS) {
            pgd_mark(miss,LI2_PGD_HEAD_LIMIT,LI2_PGD_SOURCE,pc,p->heads);return LI2_PG_GRAPH;
        }
        const unsigned i=p->heads++;
        ++p->member_heads[i/LI2_PE_HEADS];
        struct li2_pe_head *h=&p->head[i];
        if(!location(p,pc,&h->source_page,&h->source_offset))return LI2_PG_GRAPH;
        h->kind=LI2_PE_NONE;h->source_length=d.decoded.length;
        p->source_bytes+=h->source_length;p->original[i]=d;
        if(d.flow!=LI2_REGION_NEXT) {
            const unsigned arms=d.flow==LI2_REGION_JCC?2U:1U;
            const uintptr_t targets[2]={d.target,d.decoded.next_pc};
            for(unsigned arm=0;arm<arms;arm++) {
                unsigned page,offset;
                if(location(p,targets[arm],&page,&offset) && occupied[page][offset]) {
                    unsigned exact=0;
                    for(unsigned j=0;j<p->heads;j++)if(p->original[j].decoded.pc==targets[arm])++exact;
                    if(exact!=1) {
                        pgd_mark(miss,LI2_PGD_SOURCE_OVERLAP,LI2_PGD_SOURCE,pc,targets[arm]);return LI2_PG_GRAPH;
                    }
                }
            }
            h->kind=LI2_PG_DIRECT;h->successor_count=arms;
            p->decoder_result=(unsigned)li2_dd_describe(pc,bytes,count,(1U<<arms)-1U,&p->instruction[i].direct);
            if(p->decoder_result || !equal(&p->instruction[i].direct.decoded,&d.decoded,sizeof d.decoded))return LI2_PG_DECODER;
            for(unsigned arm=0;arm<arms;arm++) {
                if(p->exits==LI2_PG_BOUNDARIES)return LI2_PG_GRAPH;
                unsigned x=p->exits++;h->successors[arm]=LI2_PG_HEADS+x;
                p->frontier[x]=d;p->exit_pc[x]=pc;
            }
            break;
        }
        unsigned page,offset;
        if(!location(p,d.decoded.next_pc,&page,&offset)) {
            pgd_mark(miss,LI2_PGD_OUTSIDE_PAIR,LI2_PGD_SOURCE,pc,d.decoded.next_pc);return LI2_PG_GRAPH;
        }
        pc=d.decoded.next_pc;
    }
    if(!p->heads || !p->exits || p->exits>2 || p->stores)return LI2_PG_GRAPH;
    for(unsigned i=0;i<p->heads;i++) {
        struct li2_pe_head *h=&p->head[i];
        if(h->kind==LI2_PG_DIRECT) {
            if(i+1!=p->heads)return LI2_PG_GRAPH;
            continue;
        }
        if(h->kind!=LI2_PE_NONE || p->original[i].flow!=LI2_REGION_NEXT)return LI2_PG_GRAPH;
        h->successor_count=1;
        h->successors[0]=i+1<p->heads?i+1:LI2_PG_HEADS;
        if(i+1<p->heads) {
            if(p->original[i].decoded.next_pc!=p->original[i+1].decoded.pc)return LI2_PG_GRAPH;
        } else if(p->exits!=1 || p->original[i].decoded.next_pc!=p->exit_pc[0])return LI2_PG_GRAPH;
        const unsigned k=h->successors[0];
        if(k<LI2_PG_HEADS && k/LI2_PE_HEADS!=i/LI2_PE_HEADS) {
            if(p->links+p->exits==LI2_PG_BOUNDARIES) {
                pgd_mark(miss,LI2_PGD_LINK_LIMIT,LI2_PGD_SOURCE,p->original[i].decoded.pc,p->links+p->exits);
                return LI2_PG_GRAPH;
            }
            unsigned x=p->links++;
            p->edge[x]=(struct li2_pg_edge){LI2_PG_CAPACITY_LINK,i,0,k,
                p->original[k].decoded.pc,head_generated(p,k),p->layout.stubs+6*x,p->layout.slots+8*x};
        }
    }
    if(p->member_heads[0]!=(p->heads<LI2_PE_HEADS?p->heads:LI2_PE_HEADS) ||
       p->member_heads[1]!=(p->heads>LI2_PE_HEADS?p->heads-LI2_PE_HEADS:0) ||
       p->links!=(p->heads>LI2_PE_HEADS?1U:0U))return LI2_PG_GRAPH;
    return 0;
}
int li2_pb_plan_pages(const uintptr_t pages[2],const unsigned char source[2][LI2_REGION_PAGE],
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
    zero(miss,sizeof *miss);miss->version=LI2_PB_VERSION;
    zero(out,sizeof *out);out->version=LI2_PB_VERSION;out->bytes=sizeof *out;
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
#ifdef LI2_PERSISTENT_CALL_DISPATCH
    for(unsigned i=0;i<8;i++)if(overlap(layout->window,LI2_CD_WINDOW_PAGE,at[i],bytes[i]))goto done;
#endif
#endif
    copy(out->page,pages,sizeof out->page);copy(out->source,source,sizeof out->source);
    out->entry=entry;out->layout=*layout;copy(&out->table,table,sizeof *table);
    unsigned page,offset;if(!location(out,entry,&page,&offset))goto done;
    e=pb_graph(out,miss);if(!e)e=pgd_emit(out,miss);if(!e)out->ready=1;
 done:out->result=(unsigned)e;miss->status=(unsigned)e;return e;
}
int li2_pb_plan_validate(const struct li2_pg_plan *p,struct li2_pg_plan *scratch) {
    if(!storage(p,sizeof *p) || !storage(scratch,sizeof *scratch) ||
       (uintptr_t)p%_Alignof(struct li2_pg_plan) || (uintptr_t)scratch%_Alignof(struct li2_pg_plan) ||
       overlap((uintptr_t)p,sizeof *p,(uintptr_t)scratch,sizeof *scratch))return LI2_PG_ARGUMENT;
    if(p->version!=LI2_PB_VERSION || p->bytes!=sizeof *p || p->ready!=1 || p->result || p->reserved || p->reserved2)
        return LI2_PG_CORRUPT;
    struct li2_pg_miss miss;
    int e=li2_pb_plan_pages(p->page,p->source,p->entry,&p->layout,&p->table,scratch,&miss);
    struct li2_pg_miss empty={.version=LI2_PB_VERSION};
    return e || !equal(&miss,&empty,sizeof miss) || !equal(p,scratch,sizeof *p)?LI2_PG_CORRUPT:0;
}
int li2_pb_miss_validate(const struct li2_pg_plan *p,const struct li2_pg_miss *m,int result,
    struct li2_pg_plan *scratch) {
    const void *host[3]={p,m,scratch};
    const size_t size[3]={sizeof *p,sizeof *m,sizeof *scratch};
    const size_t align[3]={_Alignof(struct li2_pg_plan),_Alignof(struct li2_pg_miss),_Alignof(struct li2_pg_plan)};
    for(unsigned i=0;i<3;i++) {
        if(!storage(host[i],size[i]) || (uintptr_t)host[i]%align[i])return LI2_PG_ARGUMENT;
        for(unsigned j=0;j<i;j++)if(overlap((uintptr_t)host[i],size[i],(uintptr_t)host[j],size[j]))return LI2_PG_ARGUMENT;
    }
    if(!result || p->version!=LI2_PB_VERSION || p->bytes!=sizeof *p || p->ready ||
       p->result!=(unsigned)result || m->version!=LI2_PB_VERSION || m->status!=(unsigned)result)
        return LI2_PG_CORRUPT;
    struct li2_pg_miss actual;
    int e=li2_pb_plan_pages(p->page,p->source,p->entry,&p->layout,&p->table,scratch,&actual);
    return e!=result || !equal(p,scratch,sizeof *p) || !equal(m,&actual,sizeof actual)?LI2_PG_CORRUPT:0;
}
