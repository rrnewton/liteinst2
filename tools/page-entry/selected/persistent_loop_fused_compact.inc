/* LOOP-bound policy11 projection and typed recovery; original PF remains separate. */
#include "persistent_loop_fused_plan.h"

static int lpf_header(const struct li2_pg_compact *p) {
    if(!(p->version==LI2_PF_VERSION && p->bytes==sizeof *p && p->ready==1 &&
        !p->result && !p->reserved && !p->reserved2 && p->heads && p->heads<=LI2_PG_HEADS &&
        p->member_heads[0]==(p->heads<LI2_PE_HEADS?p->heads:LI2_PE_HEADS) &&
        p->member_heads[1]==(p->heads>LI2_PE_HEADS?p->heads-LI2_PE_HEADS:0U) &&
        p->exits && p->exits<=LI2_PG_BOUNDARIES && p->links<=LI2_PG_BOUNDARIES &&
        (p->heads>LI2_PE_HEADS?p->links!=0:p->links==0) &&
        p->links+p->exits<=LI2_PG_BOUNDARIES && layout_valid(&p->layout)))return 0;
    if(p->original[0].decoded.pc!=p->entry || !p->source_mask || (p->source_mask&~3U))return 0;
    unsigned stores=0;
    for(unsigned i=0;i<p->heads;i++) {
        const unsigned kind=p->head[i].kind;
        if(kind!=LI2_PE_NONE && kind!=LI2_PE_MOV && kind!=LI2_PG_DIRECT)return 0;
        stores+=kind==LI2_PE_MOV;
    }
    return stores==p->stores;
}

static int lpf_direct_shape(const struct li2_pg_compact *p,unsigned i,uintptr_t internal[2]) {
    if(i>=p->heads || i>=LI2_PG_HEADS || p->exits>LI2_PG_BOUNDARIES)return 0;
    const struct li2_pe_head *h=&p->head[i];const struct li2_span_decoded *d=&p->original[i];
    const struct li2_dd_descriptor *a=&p->instruction[i].direct;const struct li2_dd_record *g=&p->guard[i].direct;
    struct li2_dd_descriptor expected;
    if(h->kind!=LI2_PG_DIRECT || h->source_page>=2 || h->source_offset>=LI2_REGION_PAGE ||
       !h->source_length || h->source_length>15 || d->decoded.length!=h->source_length ||
       d->decoded.pc!=p->page[h->source_page]+h->source_offset ||
       li2_dd_span(d,a->external_mask,&expected) || !equal(a,&expected,sizeof *a) ||
       h->successor_count!=(d->flow==LI2_REGION_JCC?2U:1U) ||
       (h->successor_count==1 && h->successors[1]) ||
       !h->generated_length || h->generated_length>LI2_PE_SLOT_BYTES || g->image_bytes!=h->generated_length ||
       (g->version!=LI2_DD_VERSION && g->version!=LI2_LD_VERSION) || g->ready!=1 || g->result || g->reserved ||
       !g->boundaries || g->boundaries>LI2_DD_BOUNDARIES ||
       g->hit_offset>=g->image_bytes || g->miss_offset>=g->image_bytes)return 0;
    /* The original-PC displacement selects exactly one version. The eight
       far-target bytes are immutable image data and never recovery rows. */
    unsigned prefix=d->flow==LI2_REGION_JCC?(a->external_mask==3?21U:11U):0U;
    unsigned old_miss=153U+prefix,old_length=206U+prefix;
    uintptr_t generated=head_generated(p,i),next=generated+old_miss+5;
    unsigned far=d->decoded.pc>=next?d->decoded.pc-next>UINT32_C(0x7fffffff):
        next-d->decoded.pc>UINT32_C(0x80000000);
    if(g->version!=(far?LI2_LD_VERSION:LI2_DD_VERSION) || g->miss_offset!=old_miss ||
       g->image_bytes!=old_length+9U*far || g->hit_offset!=old_length-6U+9U*far ||
       g->boundaries!=37U+(d->flow==LI2_REGION_JCC?(a->external_mask==3?3U:2U):0U))return 0;
    if(far) {
        const unsigned char *code=head_image(p,i);unsigned miss_rows=0;
        if((generated&4095U)+old_miss+14U>4096U || code[old_miss]!=0xff || code[old_miss+1]!=0x25 ||
           code[old_miss+2] || code[old_miss+3] || code[old_miss+4] || code[old_miss+5])return 0;
        for(unsigned k=0;k<8;k++)if(code[old_miss+6+k]!=(unsigned char)(d->decoded.pc>>(8*k)))return 0;
        for(unsigned k=0;k<g->boundaries;k++) {
            const struct li2_mg_boundary *m=&g->boundary[k];
            if(m->offset>=old_miss+6 && m->offset<old_miss+14)return 0;
            if(m->offset==old_miss) {
                if(m->length!=6 || m->spill_valid!=15 || m->dirty || m->flags!=LI2_MG_PHYSICAL ||
                   m->phase!=LI2_DD_BEFORE)return 0;
                ++miss_rows;
            }
        }
        if(miss_rows!=1)return 0;
    }
    internal[0]=internal[1]=0;const unsigned external=li2_pf_cut_mask(p->page,d);unsigned exits=0;
    for(unsigned arm=0;arm<h->successor_count;arm++) {
        unsigned in_pair=0;for(unsigned page=0;page<2;page++)
            if(a->target[arm]>=p->page[page] && a->target[arm]-p->page[page]<LI2_REGION_PAGE)++in_pair;
        if(in_pair>1)return 0;
        unsigned k=h->successors[arm];if(!token_valid(p,k))return 0;
        if(a->external_mask&(1U<<arm)) {
            if(k<LI2_PG_HEADS || p->exit_pc[k-LI2_PG_HEADS]!=d->decoded.pc ||
               !equal(&p->frontier[k-LI2_PG_HEADS],d,sizeof *d))return 0;
            if(arm && (a->external_mask&1U) && k==h->successors[0])return 0;
        } else {
            if(in_pair!=1 || (arm==0 && k>=p->heads) || original_destination(p,k)!=a->target[arm] || !(internal[arm]=destination(p,i,arm)))return 0;
        }
    }
    if(external!=a->external_mask)return 0;
    for(unsigned j=0;j<p->exits;j++)if(p->exit_pc[j]==d->decoded.pc) {
        unsigned matches=0;
        for(unsigned arm=0;arm<h->successor_count;arm++)if((external&(1U<<arm)) && h->successors[arm]==LI2_PG_HEADS+j)++matches;
        if(matches!=1 || !equal(&p->frontier[j],d,sizeof *d))return 0;
        ++exits;
    }
    return exits==(unsigned)((external&1U)!=0)+(unsigned)((external&2U)!=0);
}

static int lpf_materialize_direct(const struct li2_pg_compact *p,unsigned i,struct li2_dd_plan *out) {
    uintptr_t internal[2];if(!lpf_direct_shape(p,i,internal))return LI2_PG_CORRUPT;
    zero(out,sizeof *out);
    if(li2_pg_dispatch_binding(p->page,&p->layout,p->table.address,p->heads,i,&out->binding))return LI2_PG_CORRUPT;
    copy(&out->record,&p->guard[i].direct,sizeof out->record);
    copy(&out->original,&p->instruction[i].direct,sizeof out->original);
    out->generated=head_generated(p,i);out->spill=p->layout.spill;copy(out->internal,internal,sizeof internal);
    copy(out->image,head_image(p,i),out->record.image_bytes);return 0;
}

static int lpf_project(const struct li2_pg_plan *p,struct li2_pg_compact *out) {
    union li2_pg_guard actual;
    zero(out,sizeof *out);out->version=LI2_PF_VERSION;out->bytes=sizeof *out;
#define FIELD(f) copy(&out->f,&p->f,sizeof out->f)
    FIELD(result);FIELD(heads);FIELD(exits);FIELD(stores);FIELD(source_bytes);
    FIELD(source_mask);FIELD(decoder_result);FIELD(guard_result);FIELD(reserved);
    FIELD(member_heads);FIELD(links);FIELD(reserved2);
    FIELD(page);FIELD(entry);FIELD(layout);FIELD(source);FIELD(image);FIELD(stub_image);FIELD(edge);
    FIELD(head);FIELD(original);FIELD(frontier);FIELD(instruction);FIELD(exit_pc);FIELD(table);
#undef FIELD
    for(unsigned i=0;i<LI2_PG_HEADS;i++) {
        const union li2_pg_guard *whole=&p->guard[i];
        zero(&actual,sizeof actual);
        if(i<p->heads && p->head[i].kind==LI2_PG_DIRECT) {
            copy(&out->guard[i].direct,&whole->direct.record,sizeof out->guard[i].direct);
            if(lpf_materialize_direct(out,i,&actual.direct) || !equal(whole,&actual,sizeof actual))goto corrupt;
            continue;
        }
        const struct li2_mg_plan *g=&whole->mov;struct li2_pe_guard_record *r=&out->guard[i].mov;
        if(i>=p->heads || p->head[i].kind!=LI2_PE_MOV) {
            if((i<p->heads && p->head[i].kind!=LI2_PE_NONE) || !all_zero(whole,sizeof *whole))goto corrupt;
            continue;
        }
        r->version=g->version;r->ready=g->ready;r->result=g->result;r->image_bytes=g->image_bytes;
        r->boundaries=g->boundaries;r->store_offset=g->store_offset;r->reject_offset=g->reject_offset;r->reserved=g->reserved;
        copy(r->scratch_regs,g->scratch_regs,sizeof r->scratch_regs);
        copy(r->boundary,g->boundary,sizeof r->boundary);
        if(materialize(out,i,&actual.mov) || !equal(whole,&actual,sizeof actual))goto corrupt;
    }
    out->ready=1;return 0;
 corrupt:out->result=LI2_PG_CORRUPT;return LI2_PG_CORRUPT;
}

int li2_lpf_compact_build(const struct li2_pg_plan *p,struct li2_pg_plan *scratch,struct li2_pg_compact *out) {
    if(!storage(p,sizeof *p) || !storage(scratch,sizeof *scratch) || !storage(out,sizeof *out) ||
       (uintptr_t)p%_Alignof(struct li2_pg_plan) || (uintptr_t)scratch%_Alignof(struct li2_pg_plan) ||
       (uintptr_t)out%_Alignof(struct li2_pg_compact) ||
       overlap((uintptr_t)p,sizeof *p,(uintptr_t)scratch,sizeof *scratch) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)p,sizeof *p) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)scratch,sizeof *scratch))return LI2_PG_ARGUMENT;
    zero(out,sizeof *out);out->version=LI2_PF_VERSION;out->bytes=sizeof *out;
    if(li2_lpf_plan_validate(p,scratch)) { out->result=LI2_PG_CORRUPT;return LI2_PG_CORRUPT; }
    return lpf_project(p,out);
}

int li2_lpf_compact_validate(const struct li2_pg_compact *p,struct li2_pg_plan *scratch,struct li2_pg_compact *rebuilt) {
    if(!storage(p,sizeof *p) || !storage(scratch,sizeof *scratch) || !storage(rebuilt,sizeof *rebuilt) ||
       (uintptr_t)p%_Alignof(struct li2_pg_compact) || (uintptr_t)scratch%_Alignof(struct li2_pg_plan) ||
       (uintptr_t)rebuilt%_Alignof(struct li2_pg_compact) ||
       overlap((uintptr_t)p,sizeof *p,(uintptr_t)scratch,sizeof *scratch) ||
       overlap((uintptr_t)rebuilt,sizeof *rebuilt,(uintptr_t)p,sizeof *p) ||
       overlap((uintptr_t)rebuilt,sizeof *rebuilt,(uintptr_t)scratch,sizeof *scratch))return LI2_PG_ARGUMENT;
    if(!lpf_header(p))return LI2_PG_CORRUPT;
    struct li2_pg_miss miss,empty={.version=LI2_PF_VERSION};
    int e=li2_lpf_plan_pages(p->page,p->source,p->entry,&p->layout,&p->table,scratch,&miss);
    if(e || !equal(&miss,&empty,sizeof miss) || lpf_project(scratch,rebuilt) || !equal(p,rebuilt,sizeof *p))return LI2_PG_CORRUPT;
    return 0;
}

int li2_lpf_compact_direct(const struct li2_pg_compact *p,unsigned member,unsigned head,struct li2_dd_plan *out) {
    if(!storage(p,sizeof *p) || !storage(out,sizeof *out) ||
       (uintptr_t)p%_Alignof(struct li2_pg_compact) || (uintptr_t)out%_Alignof(struct li2_dd_plan) ||
       overlap((uintptr_t)p,sizeof *p,(uintptr_t)out,sizeof *out))return LI2_PG_ARGUMENT;
    zero(out,sizeof *out);
    return lpf_header(p) && member<2 && head<p->member_heads[member]?lpf_materialize_direct(p,member*LI2_PE_HEADS+head,out):LI2_PG_CORRUPT;
}

int li2_lpf_compact_exit(const struct li2_pg_compact *p,uintptr_t pc,uint64_t flags) {
    if(!storage(p,sizeof *p) || (uintptr_t)p%_Alignof(struct li2_pg_compact) || !lpf_header(p))return -2;
    unsigned direct=0;int selected=-1;
    for(unsigned i=0;i<p->heads;i++)if(p->head[i].kind==LI2_PG_DIRECT && p->original[i].decoded.pc==pc) {
        uintptr_t internal[2];if(++direct!=1 || !lpf_direct_shape(p,i,internal))return -2;
        const struct li2_dd_descriptor *a=&p->instruction[i].direct;
        int arm=li2_dd_arm(a,flags);if(arm<0)return -2;
        if(a->external_mask&(1U<<(unsigned)arm))selected=(int)(p->head[i].successors[arm]-LI2_PG_HEADS);
    }
    if(direct)return selected;
    for(unsigned j=0;j<p->exits;j++)if(p->exit_pc[j]==pc) {
        if(selected>=0)return -2;
        selected=(int)j;
    }
    return selected;
}

int li2_lpf_compact_guard(const struct li2_pg_compact *p,unsigned member,unsigned head,struct li2_mg_plan *out) {
    if(!storage(p,sizeof *p) || !storage(out,sizeof *out) ||
       (uintptr_t)p%_Alignof(struct li2_pg_compact) || (uintptr_t)out%_Alignof(struct li2_mg_plan) ||
       overlap((uintptr_t)p,sizeof *p,(uintptr_t)out,sizeof *out))return LI2_PG_ARGUMENT;
    zero(out,sizeof *out);
    return lpf_header(p) && member<2 && head<p->member_heads[member]?materialize(p,member*LI2_PE_HEADS+head,out):LI2_PG_CORRUPT;
}

int li2_lpf_compact_recover(const struct li2_pg_compact *p,uintptr_t pc,const uint64_t raw[16],uint64_t flags,
    const uint64_t spill[4],union li2_pg_guard *guard_scratch,struct li2_pg_recovered *out) {
    if(!storage(out,sizeof *out) || (uintptr_t)out%_Alignof(struct li2_pg_recovered) ||
       !storage(p,sizeof *p) || (uintptr_t)p%_Alignof(struct li2_pg_compact) ||
       !storage(raw,16*sizeof *raw) || (uintptr_t)raw%_Alignof(uint64_t) ||
       !storage(spill,4*sizeof *spill) || (uintptr_t)spill%_Alignof(uint64_t) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)p,sizeof *p) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)raw,16*sizeof *raw) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)spill,4*sizeof *spill) ||
       !storage(guard_scratch,sizeof *guard_scratch) || (uintptr_t)guard_scratch%_Alignof(struct li2_mg_plan) ||
       overlap((uintptr_t)guard_scratch,sizeof *guard_scratch,(uintptr_t)p,sizeof *p) ||
       overlap((uintptr_t)guard_scratch,sizeof *guard_scratch,(uintptr_t)raw,16*sizeof *raw) ||
       overlap((uintptr_t)guard_scratch,sizeof *guard_scratch,(uintptr_t)spill,4*sizeof *spill) ||
       overlap((uintptr_t)guard_scratch,sizeof *guard_scratch,(uintptr_t)out,sizeof *out))return LI2_PG_ARGUMENT;
    zero(out,sizeof *out);
    if(!lpf_header(p))return LI2_PG_CORRUPT;
    if(pc>=p->layout.stubs && pc-p->layout.stubs<LI2_PG_STUB_BYTES) {
        unsigned offset=(unsigned)(pc-p->layout.stubs),j=offset/6;
        if(offset%6 || j>=p->links)return LI2_PG_MISS;
        if(!edge_valid(p,j))return LI2_PG_CORRUPT;
        copy(out->gpr,raw,sizeof out->gpr);out->flags=flags;
        out->original_pc=p->edge[j].original_target;out->member=out->head=UINT32_MAX;
        out->link=j;out->kind=LI2_PG_LINK;out->phase=LI2_PG_COMMITTED_EDGE;out->complete=1;return 0;
    }
    unsigned member=2;
    for(unsigned j=0;j<2;j++)if(pc>=p->layout.generated[j] && pc-p->layout.generated[j]<LI2_PE_IMAGE_BYTES) {
        if(member!=2)return LI2_PG_CORRUPT;
        member=j;
    }
    if(member==2)return LI2_PG_MISS;
    unsigned local=(unsigned)((pc-p->layout.generated[member])/LI2_PE_SLOT_BYTES);
    unsigned offset=(unsigned)((pc-p->layout.generated[member])%LI2_PE_SLOT_BYTES);
    if(local>=p->member_heads[member])return LI2_PG_MISS;
    unsigned i=member*LI2_PE_HEADS+local;
    const struct li2_pe_head *h=&p->head[i];const struct li2_span_decoded *d=&p->original[i];
    if(h->kind==LI2_PG_DIRECT) {
        zero(guard_scratch,sizeof *guard_scratch);
        if(li2_lpf_compact_direct(p,member,local,&guard_scratch->direct))return LI2_PG_CORRUPT;
        const struct li2_dd_plan *g=&guard_scratch->direct;struct li2_dd_recovered value;
        if(offset>=g->record.image_bytes)return LI2_PG_MISS;
        unsigned found=0;
        for(unsigned j=0;j<g->record.boundaries;j++)if(g->record.boundary[j].offset==offset)++found;
        if(!found)return LI2_PG_MISS;
        if(found!=1)return LI2_PG_CORRUPT;
        int e=li2_ld_recover(g,pc,raw,flags,spill,&value);
        if(e || value.complete!=1 || value.phase!=LI2_DD_BEFORE || value.original_pc!=d->decoded.pc)return LI2_PG_CORRUPT;
        copy(out->gpr,value.gpr,sizeof out->gpr);out->flags=value.flags;out->original_pc=value.original_pc;
        out->member=member;out->head=local;out->link=UINT32_MAX;
        out->kind=LI2_PG_DIRECT_MAP;out->phase=LI2_DD_BEFORE;out->complete=1;return 0;
    }
    unsigned write=h->kind==LI2_PE_MOV;
    unsigned flow=write?LI2_REGION_NEXT:d->flow;
    if(h->source_page>=LI2_PE_SOURCES || h->source_offset>=LI2_REGION_PAGE ||
       !h->source_length || h->source_length>15 || d->decoded.length!=h->source_length ||
       d->decoded.pc!=p->page[h->source_page]+h->source_offset ||
       d->decoded.next_pc!=d->decoded.pc+h->source_length ||
       (flow!=LI2_REGION_NEXT && flow!=LI2_REGION_JCC && flow!=LI2_REGION_JMP) ||
       h->successor_count!=(flow==LI2_REGION_JCC?2U:1U) ||
       !token_valid(p,h->successors[0]) ||
       (h->successor_count==2?!token_valid(p,h->successors[1]):h->successors[1]!=0) ||
       !h->generated_length || h->generated_length>LI2_PE_SLOT_BYTES)return LI2_PG_CORRUPT;
    if(offset>=h->generated_length)return LI2_PG_MISS;
    out->member=member;out->head=local;out->link=UINT32_MAX;
    if(h->kind==LI2_PE_MOV) {
        if(li2_lpf_compact_guard(p,member,local,&guard_scratch->mov))return LI2_PG_CORRUPT;
        const struct li2_mg_plan *g=&guard_scratch->mov;struct li2_mg_recovered value;
        if(g->generated!=head_generated(p,i) || g->spill!=p->layout.spill ||
           g->successor!=destination(p,i,0) || g->image_bytes!=h->generated_length ||
           !g->boundaries || g->boundaries>LI2_MG_BOUNDARIES ||
           g->original.tf.pc!=d->decoded.pc || g->original.tf.next_pc!=d->decoded.next_pc)return LI2_PG_CORRUPT;
        unsigned found=0;
        for(unsigned j=0;j<g->boundaries;j++)if(g->boundary[j].offset==offset)++found;
        if(!found)return LI2_PG_MISS;
        if(found!=1)return LI2_PG_CORRUPT;
        int e=li2_mg_recover(g,pc,raw,flags,spill,&value);
        if(e || value.complete!=1)return LI2_PG_CORRUPT;
        copy(out->gpr,value.gpr,sizeof out->gpr);out->flags=value.flags;out->original_pc=value.original_pc;
        out->phase=value.phase;out->kind=LI2_PG_GUARD;
    } else if(h->kind==LI2_PE_NONE) {
        unsigned length=d->flow==LI2_REGION_NEXT?h->source_length:d->flow==LI2_REGION_JCC?6:5;
        if(h->generated_length!=length+(flow==LI2_REGION_JMP?0U:5U))return LI2_PG_CORRUPT;
        if(offset==0) {
            out->original_pc=d->decoded.pc;out->phase=LI2_MG_BEFORE;
            out->kind=d->flow==LI2_REGION_NEXT?LI2_PG_COPIED:LI2_PG_BRANCH;
        } else if(d->flow!=LI2_REGION_JMP && offset==length) {
            unsigned k=h->successors[d->flow==LI2_REGION_JCC?1:0];out->original_pc=original_destination(p,k);
            out->phase=LI2_MG_AFTER;out->kind=LI2_PG_EDGE;
        } else return LI2_PG_MISS;
        copy(out->gpr,raw,sizeof out->gpr);out->flags=flags;
    } else return LI2_PG_CORRUPT;
    out->complete=1;return 0;
}
