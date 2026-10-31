#include "persistent_compact.h"
#if !defined(LI2_PERSISTENT_EPOCH) || LI2_PERSISTENT_EPOCH != 1 || \
    !defined(LI2_MOV_GUARD) || LI2_MOV_GUARD != 1
#error "separate persistent description plus unchanged MOV primitive required"
#endif
static void zero(void *p,size_t n) { unsigned char *b=p;for(size_t i=0;i<n;i++)b[i]=0; }
static void copy(void *p,const void *q,size_t n) { unsigned char *b=p;const unsigned char *a=q;for(size_t i=0;i<n;i++)b[i]=a[i]; }
static int equal(const void *p,const void *q,size_t n) { const unsigned char *a=p,*b=q;for(size_t i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1; }
static int all_zero(const void *p,size_t n) { const unsigned char *a=p;for(size_t i=0;i<n;i++)if(a[i])return 0;return 1; }
static int storage(const void *p,size_t n) { return p && (uintptr_t)p<=UINTPTR_MAX-n; }
static int overlap(uintptr_t a,size_t an,uintptr_t b,size_t bn) { return a<b+bn && b<a+an; }
static int address(uintptr_t p,size_t n) { return n && p<UINT64_C(0x800000000000) && n<=UINT64_C(0x800000000000)-p; }
static int token_valid(const struct li2_pe_compact *p,unsigned k) {
    return k<p->heads || (k>=LI2_PE_HEADS && k-LI2_PE_HEADS<p->exits);
}
static uintptr_t destination(const struct li2_pe_compact *p,unsigned k) {
    return k<p->heads?p->generated+(uintptr_t)k*LI2_PE_SLOT_BYTES:p->exit_pc[k-LI2_PE_HEADS];
}
static uintptr_t original_destination(const struct li2_pe_compact *p,unsigned k) {
    return k<p->heads?p->original[k].decoded.pc:p->exit_pc[k-LI2_PE_HEADS];
}
static int header(const struct li2_pe_compact *p) {
    return p->version==LI2_PE_COMPACT_VERSION && p->bytes==sizeof *p && p->ready==1 &&
        !p->result && !p->reserved && p->heads && p->heads<=LI2_PE_HEADS &&
        p->exits && p->exits<=LI2_PE_EXITS && !(p->generated&4095U) &&
        address(p->generated,LI2_PE_IMAGE_BYTES);
}
/* Caller has already checked pointers; readiness is deliberately not read
   here so the cold projector cannot publish it before every exact join. */
static int materialize(const struct li2_pe_compact *p,unsigned i,struct li2_mg_plan *out) {
    if(i>=p->heads || i>=LI2_PE_HEADS)return LI2_PE_CORRUPT;
    const struct li2_pe_head *h=&p->head[i];const struct li2_pe_guard_record *g=&p->guard[i];
    if(h->kind!=LI2_PE_MOV || h->successor_count!=1 || h->successors[1] ||
       !token_valid(p,h->successors[0]) || !h->generated_length ||
       h->generated_length>LI2_PE_SLOT_BYTES || g->image_bytes!=h->generated_length ||
       g->version!=LI2_MG_VERSION || g->ready!=1 || g->result || g->reserved ||
       !g->boundaries || g->boundaries>LI2_MG_BOUNDARIES)return LI2_PE_CORRUPT;
    zero(out,sizeof *out);
    out->version=g->version;out->ready=g->ready;out->result=g->result;
    out->image_bytes=g->image_bytes;out->boundaries=g->boundaries;
    out->store_offset=g->store_offset;out->reject_offset=g->reject_offset;out->reserved=g->reserved;
    out->generated=p->generated+(uintptr_t)i*LI2_PE_SLOT_BYTES;out->spill=p->spill;
    out->successor=destination(p,h->successors[0]);
    copy(out->scratch_regs,g->scratch_regs,sizeof out->scratch_regs);
    copy(&out->original,&p->store_original[i],sizeof out->original);
    copy(&out->table,&p->table,sizeof out->table);
    copy(out->boundary,g->boundary,sizeof out->boundary);
    /* The common unused code tail is CC. The donor's unused image tail is
       zero; cold projection proves both exact tails, without dropping either. */
    copy(out->image,p->image+(size_t)i*LI2_PE_SLOT_BYTES,g->image_bytes);
    return 0;
}
static int project(const struct li2_pe_plan *p,struct li2_pe_compact *out) {
    struct li2_mg_plan actual;
    zero(out,sizeof *out);out->version=LI2_PE_COMPACT_VERSION;out->bytes=sizeof *out;
#define FIELD(f) copy(&out->f,&p->f,sizeof out->f)
    FIELD(result);FIELD(heads);FIELD(exits);FIELD(stores);FIELD(source_bytes);
    FIELD(source_mask);FIELD(decoder_result);FIELD(guard_result);FIELD(reserved);
    FIELD(page);FIELD(entry);FIELD(generated);FIELD(spill);FIELD(source);FIELD(image);
    FIELD(head);FIELD(original);FIELD(frontier);FIELD(store_original);FIELD(exit_pc);FIELD(table);
#undef FIELD
    for(unsigned i=0;i<LI2_PE_HEADS;i++) {
        const struct li2_mg_plan *g=&p->guard[i];struct li2_pe_guard_record *r=&out->guard[i];
        if(i>=p->heads || p->head[i].kind!=LI2_PE_MOV) {
            if(!all_zero(g,sizeof *g))goto corrupt;
            continue;
        }
        r->version=g->version;r->ready=g->ready;r->result=g->result;r->image_bytes=g->image_bytes;
        r->boundaries=g->boundaries;r->store_offset=g->store_offset;r->reject_offset=g->reject_offset;r->reserved=g->reserved;
        copy(r->scratch_regs,g->scratch_regs,sizeof r->scratch_regs);
        copy(r->boundary,g->boundary,sizeof r->boundary);
        if(materialize(out,i,&actual) || !equal(g,&actual,sizeof actual))goto corrupt;
    }
    out->ready=1;return 0;
 corrupt:out->result=LI2_PE_CORRUPT;return LI2_PE_CORRUPT;
}
int li2_pe_compact_build(const struct li2_pe_plan *p,struct li2_pe_plan *scratch,struct li2_pe_compact *out) {
    if(!storage(p,sizeof *p) || !storage(scratch,sizeof *scratch) || !storage(out,sizeof *out) ||
       (uintptr_t)p%_Alignof(struct li2_pe_plan) || (uintptr_t)scratch%_Alignof(struct li2_pe_plan) ||
       (uintptr_t)out%_Alignof(struct li2_pe_compact) ||
       overlap((uintptr_t)p,sizeof *p,(uintptr_t)scratch,sizeof *scratch) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)p,sizeof *p) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)scratch,sizeof *scratch))return LI2_PE_ARGUMENT;
    zero(out,sizeof *out);out->version=LI2_PE_COMPACT_VERSION;out->bytes=sizeof *out;
    if(li2_pe_plan_validate(p,scratch)) { out->result=LI2_PE_CORRUPT;return LI2_PE_CORRUPT; }
    return project(p,out);
}
int li2_pe_compact_validate(const struct li2_pe_compact *p,struct li2_pe_plan *scratch,struct li2_pe_compact *rebuilt) {
    if(!storage(p,sizeof *p) || !storage(scratch,sizeof *scratch) || !storage(rebuilt,sizeof *rebuilt) ||
       (uintptr_t)p%_Alignof(struct li2_pe_compact) || (uintptr_t)scratch%_Alignof(struct li2_pe_plan) ||
       (uintptr_t)rebuilt%_Alignof(struct li2_pe_compact) ||
       overlap((uintptr_t)p,sizeof *p,(uintptr_t)scratch,sizeof *scratch) ||
       overlap((uintptr_t)rebuilt,sizeof *rebuilt,(uintptr_t)p,sizeof *p) ||
       overlap((uintptr_t)rebuilt,sizeof *rebuilt,(uintptr_t)scratch,sizeof *scratch))return LI2_PE_ARGUMENT;
    if(!header(p))return LI2_PE_CORRUPT;
    int e=li2_pe_plan_pages(p->page,p->source,p->entry,p->generated,p->spill,&p->table,scratch);
    if(e || project(scratch,rebuilt) || !equal(p,rebuilt,sizeof *p))return LI2_PE_CORRUPT;
    return 0;
}
int li2_pe_compact_guard(const struct li2_pe_compact *p,unsigned i,struct li2_mg_plan *out) {
    if(!storage(p,sizeof *p) || !storage(out,sizeof *out) ||
       (uintptr_t)p%_Alignof(struct li2_pe_compact) || (uintptr_t)out%_Alignof(struct li2_mg_plan) ||
       overlap((uintptr_t)p,sizeof *p,(uintptr_t)out,sizeof *out))return LI2_PE_ARGUMENT;
    zero(out,sizeof *out);
    return header(p)?materialize(p,i,out):LI2_PE_CORRUPT;
}
int li2_pe_compact_recover(const struct li2_pe_compact *p,uintptr_t pc,const uint64_t raw[16],uint64_t flags,
    const uint64_t spill[4],struct li2_mg_plan *guard_scratch,struct li2_pe_recovered *out) {
    if(!storage(out,sizeof *out) || (uintptr_t)out%_Alignof(struct li2_pe_recovered) ||
       !storage(p,sizeof *p) || (uintptr_t)p%_Alignof(struct li2_pe_compact) ||
       !storage(raw,16*sizeof *raw) || (uintptr_t)raw%_Alignof(uint64_t) ||
       !storage(spill,4*sizeof *spill) || (uintptr_t)spill%_Alignof(uint64_t) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)p,sizeof *p) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)raw,16*sizeof *raw) ||
       overlap((uintptr_t)out,sizeof *out,(uintptr_t)spill,4*sizeof *spill) ||
       !storage(guard_scratch,sizeof *guard_scratch) || (uintptr_t)guard_scratch%_Alignof(struct li2_mg_plan) ||
       overlap((uintptr_t)guard_scratch,sizeof *guard_scratch,(uintptr_t)p,sizeof *p) ||
       overlap((uintptr_t)guard_scratch,sizeof *guard_scratch,(uintptr_t)raw,16*sizeof *raw) ||
       overlap((uintptr_t)guard_scratch,sizeof *guard_scratch,(uintptr_t)spill,4*sizeof *spill) ||
       overlap((uintptr_t)guard_scratch,sizeof *guard_scratch,(uintptr_t)out,sizeof *out))return LI2_PE_ARGUMENT;
    zero(out,sizeof *out);
    if(p->version!=LI2_PE_COMPACT_VERSION || p->bytes!=sizeof *p || p->ready!=1 || p->reserved ||
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
        if(li2_pe_compact_guard(p,i,guard_scratch))return LI2_PE_CORRUPT;
        const struct li2_mg_plan *g=guard_scratch;struct li2_mg_recovered value;
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
