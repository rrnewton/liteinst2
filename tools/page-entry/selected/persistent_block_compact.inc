/* Separate versioned compact policy; old projector and validators are untouched. */
#include "persistent_block_plan.h"
static int pb_header(const struct li2_pg_compact *p) {
    return p->version==LI2_PB_VERSION && p->bytes==sizeof *p && p->ready==1 &&
#if defined(LI2_PERSISTENT_DISPATCH) && LI2_PERSISTENT_DISPATCH == 1
        !p->result && !p->reserved && !p->reserved2 && !p->stores && !p->decoder_result && !p->guard_result && p->heads && p->heads<=LI2_PG_HEADS &&
        p->member_heads[0]==(p->heads<LI2_PE_HEADS?p->heads:LI2_PE_HEADS) &&
        p->member_heads[1]==(p->heads>LI2_PE_HEADS?p->heads-LI2_PE_HEADS:0U) &&
        p->exits && p->exits<=LI2_PG_BOUNDARIES && p->links<=LI2_PG_BOUNDARIES &&
        (p->heads>LI2_PE_HEADS?p->links!=0:p->links==0) &&
#else
        !p->result && !p->reserved && !p->reserved2 && p->heads>LI2_PE_HEADS && p->heads<=LI2_PG_HEADS &&
        p->member_heads[0]==LI2_PE_HEADS && p->member_heads[1]==p->heads-LI2_PE_HEADS &&
        p->exits && p->exits<=LI2_PG_BOUNDARIES && p->links && p->links<=LI2_PG_BOUNDARIES &&
#endif
        p->links+p->exits<=LI2_PG_BOUNDARIES && layout_valid(&p->layout);
}
static int pb_direct_shape(const struct li2_pg_compact *p,unsigned i) {
    if(!p->heads || p->heads>LI2_PG_HEADS || i+1!=p->heads || p->exits>2)return 0;
    const struct li2_pe_head *h=&p->head[i];const struct li2_span_decoded *d=&p->original[i];
    const struct li2_dd_descriptor *a=&p->instruction[i].direct;
    const struct li2_dd_record *g=&p->guard[i].direct;
    const unsigned arms=d->flow==LI2_REGION_JCC?2U:1U;
    struct li2_dd_descriptor expected;
    if(h->kind!=LI2_PG_DIRECT || h->source_page>=2 || h->source_offset>=LI2_REGION_PAGE ||
       !h->source_length || h->source_length>15 || d->decoded.length!=h->source_length ||
       d->decoded.pc!=p->page[h->source_page]+h->source_offset ||
       li2_dd_span(d,(1U<<arms)-1U,&expected) || !equal(a,&expected,sizeof *a) ||
       h->successor_count!=arms || p->exits!=arms || (arms==1 && h->successors[1]) ||
       !h->generated_length || h->generated_length>LI2_PE_SLOT_BYTES || g->image_bytes!=h->generated_length ||
       g->version!=LI2_DD_VERSION || g->ready!=1 || g->result || g->reserved ||
       !g->boundaries || g->boundaries>LI2_DD_BOUNDARIES ||
       g->hit_offset>=g->image_bytes || g->miss_offset>=g->image_bytes)return 0;
    for(unsigned arm=0;arm<arms;arm++)
        if(h->successors[arm]!=LI2_PG_HEADS+arm || p->exit_pc[arm]!=d->decoded.pc ||
           !equal(&p->frontier[arm],d,sizeof *d))return 0;
    return 1;
}
static int pb_shape(const struct li2_pg_compact *p) {
    if(!pb_header(p) || p->exits>2 || p->links!=(p->heads>LI2_PE_HEADS?1U:0U) ||
       p->entry!=p->original[0].decoded.pc)return 0;
    unsigned total=0;
    for(unsigned i=0;i<p->heads;i++) {
        const struct li2_pe_head *h=&p->head[i];const struct li2_span_decoded *d=&p->original[i];
        if(h->source_page>=2 || h->source_offset>=LI2_REGION_PAGE || !h->source_length ||
           h->source_length>15 || h->source_length!=d->decoded.length ||
           d->decoded.pc!=p->page[h->source_page]+h->source_offset ||
           d->decoded.next_pc!=d->decoded.pc+h->source_length)return 0;
        total+=h->source_length;
        if(h->kind==LI2_PG_DIRECT) {if(!pb_direct_shape(p,i))return 0;continue;}
        if(h->kind!=LI2_PE_NONE || d->ready!=1 || d->flow!=LI2_REGION_NEXT ||
           h->successor_count!=1 || h->successors[1] || h->generated_length!=h->source_length+5U ||
           h->successors[0]!=(i+1<p->heads?i+1:LI2_PG_HEADS) ||
           d->decoded.next_pc!=original_destination(p,h->successors[0]))return 0;
        if(i+1==p->heads && (p->exits!=1 || p->frontier[0].ready ||
           p->frontier[0].decoded.pc!=p->exit_pc[0]))return 0;
    }
    return total==p->source_bytes && (!p->links || edge_valid(p,0));
}
static int pb_materialize_direct(const struct li2_pg_compact *p,unsigned i,struct li2_dd_plan *out) {
    if(!pb_direct_shape(p,i))return LI2_PG_CORRUPT;
    zero(out,sizeof *out);
    if(li2_pg_dispatch_binding(p->page,&p->layout,p->table.address,p->heads,i,&out->binding))return LI2_PG_CORRUPT;
    copy(&out->record,&p->guard[i].direct,sizeof out->record);
    copy(&out->original,&p->instruction[i].direct,sizeof out->original);
    out->generated=head_generated(p,i);out->spill=p->layout.spill;
    copy(out->image,head_image(p,i),out->record.image_bytes);return 0;
}
static int pb_project(const struct li2_pg_plan *p,struct li2_pg_compact *out) {
    zero(out,sizeof *out);out->version=LI2_PB_VERSION;out->bytes=sizeof *out;
#define PB_FIELD(f) copy(&out->f,&p->f,sizeof out->f)
    PB_FIELD(result);PB_FIELD(heads);PB_FIELD(exits);PB_FIELD(stores);PB_FIELD(source_bytes);
    PB_FIELD(source_mask);PB_FIELD(decoder_result);PB_FIELD(guard_result);PB_FIELD(reserved);
    PB_FIELD(member_heads);PB_FIELD(links);PB_FIELD(reserved2);
    PB_FIELD(page);PB_FIELD(entry);PB_FIELD(layout);PB_FIELD(source);PB_FIELD(image);PB_FIELD(stub_image);
    PB_FIELD(head);PB_FIELD(original);PB_FIELD(frontier);PB_FIELD(instruction);PB_FIELD(exit_pc);
    PB_FIELD(edge);PB_FIELD(table);
#undef PB_FIELD
    for(unsigned i=0;i<LI2_PG_HEADS;i++) {
        union li2_pg_guard actual;zero(&actual,sizeof actual);
        if(i<p->heads && p->head[i].kind==LI2_PG_DIRECT) {
            copy(&out->guard[i].direct,&p->guard[i].direct.record,sizeof out->guard[i].direct);
            if(pb_materialize_direct(out,i,&actual.direct))goto corrupt;
        }
        if(!equal(&p->guard[i],&actual,sizeof actual))goto corrupt;
    }
    out->ready=1;
    if(!pb_shape(out))goto corrupt;
    return 0;
 corrupt:out->ready=0;out->result=LI2_PG_CORRUPT;return LI2_PG_CORRUPT;
}
int li2_pb_compact_build(const struct li2_pg_plan *p,struct li2_pg_plan *scratch,struct li2_pg_compact *out) {
    if(!storage(p,sizeof *p) || !storage(scratch,sizeof *scratch) || !storage(out,sizeof *out) ||
       (uintptr_t)p%_Alignof(struct li2_pg_plan) || (uintptr_t)scratch%_Alignof(struct li2_pg_plan) ||
       (uintptr_t)out%_Alignof(struct li2_pg_compact) ||
       overlap((uintptr_t)p,sizeof *p,(uintptr_t)scratch,sizeof *scratch) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)p,sizeof *p) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)scratch,sizeof *scratch))return LI2_PG_ARGUMENT;
    zero(out,sizeof *out);out->version=LI2_PB_VERSION;out->bytes=sizeof *out;
    if(li2_pb_plan_validate(p,scratch)) {out->result=LI2_PG_CORRUPT;return LI2_PG_CORRUPT;}
    return pb_project(p,out);
}
int li2_pb_compact_validate(const struct li2_pg_compact *p,struct li2_pg_plan *scratch,struct li2_pg_compact *rebuilt) {
    if(!storage(p,sizeof *p) || !storage(scratch,sizeof *scratch) || !storage(rebuilt,sizeof *rebuilt) ||
       (uintptr_t)p%_Alignof(struct li2_pg_compact) || (uintptr_t)scratch%_Alignof(struct li2_pg_plan) ||
       (uintptr_t)rebuilt%_Alignof(struct li2_pg_compact) ||
       overlap((uintptr_t)p,sizeof *p,(uintptr_t)scratch,sizeof *scratch) ||
       overlap((uintptr_t)rebuilt,sizeof *rebuilt,(uintptr_t)p,sizeof *p) ||
       overlap((uintptr_t)rebuilt,sizeof *rebuilt,(uintptr_t)scratch,sizeof *scratch))return LI2_PG_ARGUMENT;
    if(!pb_shape(p))return LI2_PG_CORRUPT;
    struct li2_pg_miss miss,empty={.version=LI2_PB_VERSION};
    int e=li2_pb_plan_pages(p->page,p->source,p->entry,&p->layout,&p->table,scratch,&miss);
    if(e || !equal(&miss,&empty,sizeof miss) || pb_project(scratch,rebuilt) || !equal(p,rebuilt,sizeof *p))return LI2_PG_CORRUPT;
    return 0;
}
int li2_pb_compact_direct(const struct li2_pg_compact *p,unsigned member,unsigned head,struct li2_dd_plan *out) {
    if(!storage(p,sizeof *p) || !storage(out,sizeof *out) ||
       (uintptr_t)p%_Alignof(struct li2_pg_compact) || (uintptr_t)out%_Alignof(struct li2_dd_plan) ||
       overlap((uintptr_t)p,sizeof *p,(uintptr_t)out,sizeof *out))return LI2_PG_ARGUMENT;
    zero(out,sizeof *out);
    return pb_shape(p) && member<2 && head<p->member_heads[member]?
        pb_materialize_direct(p,member*LI2_PE_HEADS+head,out):LI2_PG_CORRUPT;
}
int li2_pb_compact_exit(const struct li2_pg_compact *p,uintptr_t pc,uint64_t flags) {
    if(!storage(p,sizeof *p) || (uintptr_t)p%_Alignof(struct li2_pg_compact) || !pb_shape(p))return -2;
    unsigned i=p->heads-1;
    if(p->head[i].kind==LI2_PG_DIRECT) {
        if(pc!=p->original[i].decoded.pc)return -1;
        int arm=li2_dd_arm(&p->instruction[i].direct,flags);
        return arm<0?-2:arm;
    }
    return pc==p->exit_pc[0]?0:-1;
}
int li2_pb_compact_recover(const struct li2_pg_compact *p,uintptr_t pc,const uint64_t raw[16],uint64_t flags,
    const uint64_t spill[4],struct li2_dd_plan *guard,struct li2_pg_recovered *out) {
    const void *host[5]={p,raw,spill,guard,out};
    const size_t size[5]={sizeof *p,16*sizeof *raw,4*sizeof *spill,sizeof *guard,sizeof *out};
    const size_t align[5]={_Alignof(struct li2_pg_compact),_Alignof(uint64_t),_Alignof(uint64_t),
        _Alignof(struct li2_dd_plan),_Alignof(struct li2_pg_recovered)};
    for(unsigned i=0;i<5;i++) {
        if(!storage(host[i],size[i]) || (uintptr_t)host[i]%align[i])return LI2_PG_ARGUMENT;
        for(unsigned j=0;j<i;j++)if(overlap((uintptr_t)host[i],size[i],(uintptr_t)host[j],size[j]))return LI2_PG_ARGUMENT;
    }
    zero(out,sizeof *out);zero(guard,sizeof *guard);
    if(!pb_shape(p))return LI2_PG_CORRUPT;
    if(pc>=p->layout.stubs && pc-p->layout.stubs<LI2_PG_STUB_BYTES) {
        if(pc!=p->layout.stubs || p->links!=1)return LI2_PG_MISS;
        copy(out->gpr,raw,sizeof out->gpr);out->flags=flags;
        out->original_pc=p->edge[0].original_target;out->member=out->head=UINT32_MAX;
        out->link=0;out->kind=LI2_PG_LINK;out->phase=LI2_PG_COMMITTED_EDGE;out->complete=1;return 0;
    }
    unsigned member=2;
    for(unsigned j=0;j<2;j++)if(pc>=p->layout.generated[j] && pc-p->layout.generated[j]<LI2_PE_IMAGE_BYTES) {
        if(member!=2)return LI2_PG_CORRUPT;
        member=j;
    }
    if(member==2)return LI2_PG_MISS;
    const unsigned local=(unsigned)((pc-p->layout.generated[member])/LI2_PE_SLOT_BYTES);
    const unsigned offset=(unsigned)((pc-p->layout.generated[member])%LI2_PE_SLOT_BYTES);
    if(local>=p->member_heads[member])return LI2_PG_MISS;
    const unsigned i=member*LI2_PE_HEADS+local;
    const struct li2_pe_head *h=&p->head[i];const struct li2_span_decoded *d=&p->original[i];
    if(offset>=h->generated_length)return LI2_PG_MISS;
    out->member=member;out->head=local;out->link=UINT32_MAX;
    if(h->kind==LI2_PG_DIRECT) {
        if(pb_materialize_direct(p,i,guard))return LI2_PG_CORRUPT;
        unsigned matches=0;
        for(unsigned j=0;j<guard->record.boundaries;j++)if(guard->record.boundary[j].offset==offset)++matches;
        if(!matches)return LI2_PG_MISS;
        if(matches!=1)return LI2_PG_CORRUPT;
        struct li2_dd_recovered value;
        int e=li2_dd_recover(guard,pc,raw,flags,spill,&value);
        if(e || value.complete!=1 || value.phase!=LI2_DD_BEFORE || value.original_pc!=d->decoded.pc)return LI2_PG_CORRUPT;
        copy(out->gpr,value.gpr,sizeof out->gpr);out->flags=value.flags;out->original_pc=value.original_pc;
        out->kind=LI2_PG_DIRECT_MAP;out->phase=value.phase;
    } else {
        if(offset!=0 && offset!=h->source_length)return LI2_PG_MISS;
        copy(out->gpr,raw,sizeof out->gpr);out->flags=flags;
        out->original_pc=offset?d->decoded.next_pc:d->decoded.pc;
        out->phase=offset?LI2_MG_AFTER:LI2_MG_BEFORE;out->kind=offset?LI2_PG_EDGE:LI2_PG_COPIED;
    }
    out->complete=1;return 0;
}
