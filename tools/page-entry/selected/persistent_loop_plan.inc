/* Separate policy12 realization. Old PF11 functions and output stay exact. */
#include "persistent_loop_plan.h"

static int lp_describe(struct li2_pg_plan *p,uintptr_t pc,const unsigned char *b,
    size_t n,struct li2_span_decoded *d) {
    p->decoder_result=(unsigned)li2_lr_describe(pc,b,n,d);
    if(p->decoder_result)return LI2_PG_DECODER;
    const struct li2_decoded *a=&d->decoded;
    if(a->decode_status!=LI2_VALID || !a->length || a->length>n || a->length>15 ||
       pc>UINTPTR_MAX-a->length || a->next_pc!=pc+a->length)return LI2_PG_BOUNDARY;
    return 0;
}

static int lp_graph(struct li2_pg_plan *p,const struct li2_le_witness *w) {
    const struct li2_le_shape *s=&w->selected;const struct li2_le_candidate *c=&s->choice;
    if(w->version!=LI2_LE_VERSION || w->bytes!=sizeof *w || w->ready!=1 || w->result ||
       !equal(w->page,p->page,sizeof p->page) || w->entry!=p->entry ||
       !equal(w->source,p->source,sizeof p->source) || c->result || !c->heads ||
       c->heads>LI2_PG_HEADS || !c->exits || c->exits+c->links>LI2_PG_BOUNDARIES ||
       c->first>p->entry || c->end<=p->entry || s->head[0].pc!=p->entry)return LI2_PG_CORRUPT;
    unsigned char occupied[LI2_PE_SOURCES][LI2_REGION_PAGE]={{0}};
    for(unsigned i=0;i<c->heads;i++) {
        const struct li2_le_head *a=&s->head[i];struct li2_pe_head *h=&p->head[i];
        if(a->decoded>=w->decoded || w->decoded>LI2_LE_HEADS || a->reserved ||
           a->pc<c->first || a->pc>=c->end || a->successors<1 || a->successors>2 ||
           (a->successors==1 && a->token[1]))return LI2_PG_CORRUPT;
        unsigned char b[15];size_t n=window(p,a->pc,b);struct li2_lr_node node;
        p->decoder_result=(unsigned)li2_lr_bridge_node(a->pc,b,n,&w->node[a->decoded],&node);
        if(p->decoder_result)return LI2_PG_DECODER;
        const struct li2_span_decoded *d=&node.original;const unsigned flow=node.kind==LI2_LE_MOV?LI2_REGION_NEXT:d->flow;
        if(node.kind!=a->kind || flow!=a->flow || a->successors!=(flow==LI2_REGION_JCC?2U:1U) ||
           d->decoded.next_pc>c->end || !location(p,a->pc,&h->source_page,&h->source_offset))return LI2_PG_CORRUPT;
        for(unsigned j=0;j<d->decoded.length;j++) {
            unsigned page,offset;
            if(!location(p,a->pc+j,&page,&offset) || occupied[page][offset])return LI2_PG_CORRUPT;
            occupied[page][offset]=1;p->source_mask|=1U<<page;
        }
        h->kind=node.kind==LI2_LE_MOV?LI2_PE_MOV:LI2_PE_NONE;
        h->source_length=d->decoded.length;h->successor_count=a->successors;p->original[i]=*d;
        ++p->heads;++p->member_heads[i/LI2_PE_HEADS];p->source_bytes+=h->source_length;
        if(h->kind==LI2_PE_MOV) {p->instruction[i].mov=node.mov;++p->stores;}
        if(a->external_mask) {
            if(h->kind!=LI2_PE_NONE || (flow!=LI2_REGION_JMP && flow!=LI2_REGION_JCC) ||
               li2_dd_span(d,a->external_mask,&p->instruction[i].direct))return LI2_PG_CORRUPT;
            h->kind=LI2_PG_DIRECT;
        }
        unsigned external=0;
        for(unsigned arm=0;arm<a->successors;arm++) {
            const uintptr_t target=flow==LI2_REGION_NEXT || arm?d->decoded.next_pc:d->target;
            const unsigned k=a->token[arm];h->successors[arm]=k;
            if(target>=c->first && target<c->end) {
                if(k>=c->heads || s->head[k].pc!=target)return LI2_PG_CORRUPT;
            } else {
                external|=1U<<arm;
                if(flow==LI2_REGION_NEXT || k!=LI2_PG_HEADS+p->exits || p->exits>=c->exits ||
                   s->exit[p->exits].head!=i || s->exit[p->exits].arm!=arm ||
                   s->exit[p->exits].target!=target)return LI2_PG_CORRUPT;
                p->frontier[p->exits]=*d;p->exit_pc[p->exits]=d->decoded.pc;++p->exits;
            }
        }
        if(external!=a->external_mask)return LI2_PG_CORRUPT;
    }
    for(unsigned i=0;i<p->heads;i++)for(unsigned arm=0;arm<p->head[i].successor_count;arm++) {
        unsigned k=p->head[i].successors[arm];if(!token_valid(p,k))return LI2_PG_CORRUPT;
        if(k>=LI2_PG_HEADS || k/LI2_PE_HEADS==i/LI2_PE_HEADS)continue;
        if(p->links>=c->links || p->links+p->exits>=LI2_PG_BOUNDARIES)return LI2_PG_CORRUPT;
        const struct li2_le_link expected={i,arm,k,0};
        if(!equal(&s->link[p->links],&expected,sizeof expected))return LI2_PG_CORRUPT;
        unsigned x=p->links++;
        p->edge[x]=(struct li2_pg_edge){LI2_PG_CAPACITY_LINK,i,arm,k,p->original[k].decoded.pc,
            head_generated(p,k),p->layout.stubs+6*x,p->layout.slots+8*x};
    }
    return p->heads!=c->heads || p->exits!=c->exits || p->links!=c->links ||
        p->stores!=c->stores || p->source_bytes!=c->source_bytes ||
        p->member_heads[0]!=(p->heads<LI2_PE_HEADS?p->heads:LI2_PE_HEADS) ||
        p->member_heads[1]!=(p->heads>LI2_PE_HEADS?p->heads-LI2_PE_HEADS:0) ||
        (p->heads>LI2_PE_HEADS?!p->links:p->links!=0)?LI2_PG_CORRUPT:0;
}

int li2_lp_plan_pages(const uintptr_t pages[2],const unsigned char source[2][LI2_REGION_PAGE],
    uintptr_t entry,const struct li2_pg_layout *layout,const struct li2_mg_table *table,
    struct li2_pg_plan *out,struct li2_pg_miss *miss,struct li2_le_witness *w) {
    const void *host[7]={pages,source,layout,table,out,miss,w};
    const size_t size[7]={2*sizeof *pages,2*LI2_REGION_PAGE,sizeof *layout,sizeof *table,sizeof *out,sizeof *miss,sizeof *w};
    const size_t align[7]={_Alignof(uintptr_t),1,_Alignof(struct li2_pg_layout),_Alignof(struct li2_mg_table),
        _Alignof(struct li2_pg_plan),_Alignof(struct li2_pg_miss),_Alignof(struct li2_le_witness)};
    for(unsigned i=0;i<7;i++) {
        if(!storage(host[i],size[i]) || (uintptr_t)host[i]%align[i])return LI2_PG_ARGUMENT;
        for(unsigned j=0;j<i;j++)if(overlap((uintptr_t)host[i],size[i],(uintptr_t)host[j],size[j]))return LI2_PG_ARGUMENT;
    }
    zero(miss,sizeof *miss);miss->version=LI2_LP_VERSION;
    zero(out,sizeof *out);out->version=LI2_LP_VERSION;out->bytes=sizeof *out;zero(w,sizeof *w);
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
    for(unsigned i=0;i<8;i++)if(!pf_excluded(table,at[i],bytes[i]))goto done;
    if(!pf_excluded(table,layout->directory,LI2_JD_DOMAIN_BYTES))goto done;
    copy(out->page,pages,sizeof out->page);copy(out->source,source,sizeof out->source);
    out->entry=entry;out->layout=*layout;copy(&out->table,table,sizeof *table);
    unsigned page,offset;if(!location(out,entry,&page,&offset))goto done;
    e=li2_le_choose(out->page,out->source,entry,w);
    if(e) {miss->site=LI2_PGD_SOURCE;miss->pc=entry;miss->detail=(unsigned)e;goto done;}
    e=lp_graph(out,w);if(!e)e=pgd_emit_selected(out,miss,lp_describe);if(!e)out->ready=1;
 done:out->result=(unsigned)e;miss->status=(unsigned)e;return e;
}

int li2_lp_plan_validate(const struct li2_pg_plan *p,struct li2_pg_plan *scratch,struct li2_le_witness *w) {
    if(!storage(p,sizeof *p) || !storage(scratch,sizeof *scratch) || !storage(w,sizeof *w) ||
       (uintptr_t)p%_Alignof(struct li2_pg_plan) || (uintptr_t)scratch%_Alignof(struct li2_pg_plan) ||
       (uintptr_t)w%_Alignof(struct li2_le_witness) || overlap((uintptr_t)p,sizeof *p,(uintptr_t)scratch,sizeof *scratch) ||
       overlap((uintptr_t)w,sizeof *w,(uintptr_t)p,sizeof *p) || overlap((uintptr_t)w,sizeof *w,(uintptr_t)scratch,sizeof *scratch))return LI2_PG_ARGUMENT;
    if(p->version!=LI2_LP_VERSION || p->bytes!=sizeof *p || p->ready!=1 || p->result || p->reserved || p->reserved2)return LI2_PG_CORRUPT;
    struct li2_pg_miss miss,empty={.version=LI2_LP_VERSION};
    int e=li2_lp_plan_pages(p->page,p->source,p->entry,&p->layout,&p->table,scratch,&miss,w);
    return e || !equal(&miss,&empty,sizeof miss) || !equal(p,scratch,sizeof *p)?LI2_PG_CORRUPT:0;
}

int li2_lp_miss_validate(const struct li2_pg_plan *p,const struct li2_pg_miss *m,int result,
    struct li2_pg_plan *scratch,struct li2_le_witness *w) {
    const void *host[4]={p,m,scratch,w};
    const size_t size[4]={sizeof *p,sizeof *m,sizeof *scratch,sizeof *w};
    const size_t align[4]={_Alignof(struct li2_pg_plan),_Alignof(struct li2_pg_miss),_Alignof(struct li2_pg_plan),_Alignof(struct li2_le_witness)};
    for(unsigned i=0;i<4;i++) {
        if(!storage(host[i],size[i]) || (uintptr_t)host[i]%align[i])return LI2_PG_ARGUMENT;
        for(unsigned j=0;j<i;j++)if(overlap((uintptr_t)host[i],size[i],(uintptr_t)host[j],size[j]))return LI2_PG_ARGUMENT;
    }
    if(!result || p->version!=LI2_LP_VERSION || p->bytes!=sizeof *p || p->ready ||
       p->result!=(unsigned)result || m->version!=LI2_LP_VERSION || m->status!=(unsigned)result)return LI2_PG_CORRUPT;
    struct li2_pg_miss actual;
    int e=li2_lp_plan_pages(p->page,p->source,p->entry,&p->layout,&p->table,scratch,&actual,w);
    return e!=result || !equal(p,scratch,sizeof *p) || !equal(m,&actual,sizeof actual)?LI2_PG_CORRUPT:0;
}
