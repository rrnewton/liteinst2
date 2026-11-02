/* LOOP encoding-domain2 entry points; policy11 graph and exclusions above
   are shared verbatim with the unchanged PF implementation. */
#include "persistent_loop_fused_plan.h"

int li2_lpf_plan_pages(const uintptr_t pages[2],const unsigned char source[2][LI2_REGION_PAGE],
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
    for(unsigned i=0;i<8;i++)if(!pf_excluded(table,at[i],bytes[i]))goto done;
    if(!pf_excluded(table,layout->directory,LI2_JD_DOMAIN_BYTES))goto done;
    copy(out->page,pages,sizeof out->page);copy(out->source,source,sizeof out->source);
    out->entry=entry;out->layout=*layout;copy(&out->table,table,sizeof *table);
    unsigned page,offset;if(!location(out,entry,&page,&offset))goto done;
    e=pf_graph(out,miss);if(!e)e=pgd_emit_with_direct(out,miss,describe,li2_ld_emit);if(!e)out->ready=1;
 done:out->result=(unsigned)e;miss->status=(unsigned)e;return e;
}

int li2_lpf_plan_validate(const struct li2_pg_plan *p,struct li2_pg_plan *scratch) {
    if(!storage(p,sizeof *p) || !storage(scratch,sizeof *scratch) ||
       (uintptr_t)p%_Alignof(struct li2_pg_plan) || (uintptr_t)scratch%_Alignof(struct li2_pg_plan) ||
       overlap((uintptr_t)p,sizeof *p,(uintptr_t)scratch,sizeof *scratch))return LI2_PG_ARGUMENT;
    if(p->version!=LI2_PF_VERSION || p->bytes!=sizeof *p || p->ready!=1 || p->result || p->reserved || p->reserved2)
        return LI2_PG_CORRUPT;
    struct li2_pg_miss miss;
    int e=li2_lpf_plan_pages(p->page,p->source,p->entry,&p->layout,&p->table,scratch,&miss);
    struct li2_pg_miss empty={.version=LI2_PF_VERSION};
    return e || !equal(&miss,&empty,sizeof miss) || !equal(p,scratch,sizeof *p)?LI2_PG_CORRUPT:0;
}

int li2_lpf_miss_validate(const struct li2_pg_plan *p,const struct li2_pg_miss *m,int result,
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
    int e=li2_lpf_plan_pages(p->page,p->source,p->entry,&p->layout,&p->table,scratch,&actual);
    return e!=result || !equal(p,scratch,sizeof *p) || !equal(m,&actual,sizeof actual)?LI2_PG_CORRUPT:0;
}

/* A saved completion retains the authenticated table address, not its old
   exclusion tree. Reconstruct only source graph and address geometry here:
   no fabricated tree, emitted guard, ready bit or publication authority. */
int li2_lpf_graph_history(const uintptr_t pages[2],const unsigned char source[2][LI2_REGION_PAGE],
    uintptr_t entry,const struct li2_pg_layout *layout,uintptr_t table_address,
    struct li2_pg_plan *out) {
    const void *host[4]={pages,source,layout,out};
    const size_t size[4]={2*sizeof *pages,2*LI2_REGION_PAGE,sizeof *layout,sizeof *out};
    const size_t align[4]={_Alignof(uintptr_t),1,_Alignof(struct li2_pg_layout),_Alignof(struct li2_pg_plan)};
    for(unsigned i=0;i<4;i++) {
        if(!storage(host[i],size[i]) || (uintptr_t)host[i]%align[i])return LI2_PG_ARGUMENT;
        for(unsigned j=0;j<i;j++)if(overlap((uintptr_t)host[i],size[i],(uintptr_t)host[j],size[j]))return LI2_PG_ARGUMENT;
    }
    zero(out,sizeof *out);out->version=LI2_PF_VERSION;out->bytes=sizeof *out;
    int e=LI2_PG_ARGUMENT;
    if(!layout_valid(layout) || pages[0]>=pages[1] || (table_address&7U))goto done;
    uintptr_t at[8]={pages[0],pages[1],layout->generated[0],layout->generated[1],layout->stubs,layout->slots,layout->spill,table_address};
    size_t bytes[8]={LI2_REGION_PAGE,LI2_REGION_PAGE,LI2_PE_IMAGE_BYTES,LI2_PE_IMAGE_BYTES,
        LI2_REGION_PAGE,LI2_REGION_PAGE,LI2_REGION_PAGE,sizeof(struct li2_mg_table)};
    for(unsigned i=0;i<8;i++) {
        if(!address(at[i],bytes[i]) || (i<2 && (at[i]&4095U)))goto done;
        for(unsigned j=0;j<i;j++)if(overlap(at[i],bytes[i],at[j],bytes[j]))goto done;
    }
    for(unsigned i=0;i<8;i++)if(overlap(layout->directory,LI2_JD_DOMAIN_BYTES,at[i],bytes[i]))goto done;
    copy(out->page,pages,sizeof out->page);copy(out->source,source,sizeof out->source);
    out->entry=entry;out->layout=*layout;out->table.address=table_address;
    unsigned page,offset;if(!location(out,entry,&page,&offset))goto done;
    struct li2_pg_miss miss={.version=LI2_PF_VERSION};struct li2_jd_binding binding;
    e=pf_graph(out,&miss);
    if(!e)e=li2_pg_dispatch_binding(pages,layout,table_address,out->heads,0,&binding);
 done:out->result=(unsigned)e;return e;
}

/* Separate LOOP-only cancellation proof for an unready policy11 MOV guard.
   Keep both old PF miss classifiers exact. Whole LPF reconstruction and the
   retained precise guard failure must agree; no ready publication is produced.
   The owner separately authenticates its source lease and NO_ENVELOPE. */
unsigned li2_lpf_guard_relocation_reason(const struct li2_pg_plan *p,const struct li2_pg_miss *m,int result,
    struct li2_pg_plan *scratch) {
    if(!p || !m || !scratch || result!=LI2_PG_RELOCATION || p->version!=LI2_PF_VERSION ||
       p->decoder_result || p->guard_result!=LI2_MG_RELOCATION ||
       m->version!=LI2_PF_VERSION || m->status!=LI2_PG_RELOCATION ||
       m->site!=LI2_PGD_EMIT || m->reason!=LI2_PGD_GUARD_RIP_REACH ||
       li2_lpf_miss_validate(p,m,result,scratch))return 0;
    unsigned found=LI2_PG_HEADS;
    for(unsigned i=0;i<p->heads;i++)if(p->original[i].decoded.pc==m->pc) {
        if(found!=LI2_PG_HEADS)return 0;
        found=i;
    }
    if(found==LI2_PG_HEADS)return 0;
    const struct li2_pe_head *h=&p->head[found];const struct li2_span_decoded *d=&p->original[found];
    if(h->kind!=LI2_PE_MOV || h->source_length!=d->decoded.length ||
       d->decoded.next_pc!=m->pc+h->source_length || h->successor_count!=1 ||
       !token_valid(p,h->successors[0]) || p->instruction[found].mov.rip_relative!=1)return 0;
    struct li2_pg_miss expected={.version=LI2_PF_VERSION,.status=LI2_PG_RELOCATION};
    return pgd_guard_reach(p,found,&expected) && expected.reason==LI2_PGD_GUARD_RIP_REACH &&
        equal(m,&expected,sizeof expected)?LI2_PGD_GUARD_RIP_REACH:0;
}
