/* Actual two-page R/NX lease. Included in lifecycle_loader.c after the exact
   old fetch/span/link helpers; no old fetch storage or API is enlarged. */
#include "persistent_runtime.h"
static struct {
    struct li2_pe_source_progress p;
    struct li2_pe_token token;
    struct owned_page original[2];
} pe_source;
static int pes_bad(unsigned code,long detail) {
    if(!pe_source.p.first_error) {pe_source.p.first_error=code;pe_source.p.first_detail=detail;}
    return (int)pe_source.p.first_error;
}
int li2_pe_source_initialize(void) {
    if(pe_source.p.initialized || pe_source.p.phase || !hooks.protected_range)return LI2_FETCH_STATE;
    for(size_t i=0;i<sizeof pe_source;i++)
        if(!hooks.protected_range((uintptr_t)&pe_source+i,1))return LI2_FETCH_STATE;
    pe_source.p.initialized=1;return 0;
}
int li2_pe_source_interlock(void) {
    unsigned p=pe_source.p.phase;
    return p!=LI2_PES_IDLE && p!=LI2_PES_RELEASED;
}
const struct li2_pe_source_progress *li2_pe_source_progress(void) {return &pe_source.p;}
static int pes_token(const struct li2_pe_token *t) {
    return t && t->owner==pe_source.token.owner && t->serial && t->serial==pe_source.token.serial &&
        li2_pe_owner_phase(t) && pe_source.p.initialized && pe_source.p.serial==t->serial;
}
int li2_pe_source_begin(const struct li2_pe_token *t,uintptr_t generated) {
    if(!t || li2_pe_owner_phase(t)!=LI2_PE_SEEDING || !pe_source.p.initialized ||
       li2_pe_source_interlock() || pe_source.p.first_error || pe_source.p.serial ||
       !generated || (generated&(PAGE-1)) || generated>(UINT64_C(1)<<47)-LI2_PE_IMAGE_BYTES ||
       li2_lifecycle_fetch_interlock() || li2_lifecycle_run_reuse_quiet(0))return LI2_FETCH_STATE;
    pe_source.token=*t;pe_source.p.serial=t->serial;pe_source.p.generated=generated;
    pe_source.p.phase=LI2_PES_SEEDING;return 0;
}
static int pes_page(unsigned i,uintptr_t address) {
    const struct owned_page *p=current(address);const struct map_row *r=mapping(address);
    if(!p || !p->live || !p->allocation || !p->generation || p->admitted ||
       p->backing!=SEALED || p->object>=object_count || p->logical!=(PROT_READ|PROT_EXEC) ||
       p->actual!=PROT_READ)return pes_bad(LI2_FETCH_PAGE,i);
    struct check_error e={0};
    if(verify_page_checked(p,r,&e) || alias_check_checked(p->object,p->offset,PAGE,p->logical,
            p->address,p->address+PAGE,&e))return pes_bad(e.code,e.detail);
    if(!r || !r->private || r->prot!=PROT_READ || address<r->first ||
       address>=r->end || r->end-address<PAGE)return pes_bad(LI2_FETCH_PAGE,2+i);
    /* Actual retained identity is installed before the next descriptor RAW. */
    pe_source.original[i]=*p;
    struct li2_pe_source_page *out=&pe_source.p.source.key.page[i];
    out->identity=(struct li2_fetch_page){.address=p->address,.allocation=p->allocation,
        .generation=p->generation,.offset=p->offset,.initial_extent=p->initial_extent,
        .backing=p->backing,.object=p->object,.logical=p->logical,.closed_prot=p->actual,
        .vma_first=r->first,.vma_end=r->end,.vma_major=r->major,.vma_minor=r->minor,
        .vma_inode=r->inode,.vma_offset=r->offset};
    pe_source.p.pages_copied=i+1;
    int result=fetch_backing_check(p,&out->backing);
    return result?pes_bad((unsigned)result,3+i):0;
}
int li2_pe_source_prepare(const struct li2_pe_token *t,const struct li2_fetch_ref *ref,const uintptr_t pages[2]) {
    if(!pes_token(t) || li2_pe_owner_phase(t)!=LI2_PE_PREPARING || pe_source.p.phase!=LI2_PES_SEEDING ||
       pe_source.p.first_error || !pages || !ref || fetch_ref(ref) || !span_source_geometry() ||
       pages[0]>=pages[1] || (pages[0]&(PAGE-1)) || (pages[1]&(PAGE-1)) ||
       pages[1]>(UINT64_C(1)<<47)-PAGE ||
       (fetch.pages[0].address!=pages[0] && fetch.pages[0].address!=pages[1]))return LI2_FETCH_ARGUMENT;
    struct li2_pe_sources *s=&pe_source.p.source;
    pe_source.p.phase=LI2_PES_PREPARING;s->anchor=*ref;s->serial=t->serial;
    s->allocation_epoch=allocation_id;s->generation_epoch=generation;
    s->transactions_epoch=counts.transactions;s->records_epoch=used;s->key.entry=fetch.pc;
    int e=li2_lifecycle_run_reuse_quiet(ref);if(e)return pes_bad((unsigned)e,10);
    if((e=li2_lifecycle_fetch_validate(ref,0,PROT_READ)))return pes_bad((unsigned)e,11);
    struct check_error check={0};
    if(read_maps_checked(&check,&pe_source.p.preparation))return pes_bad(check.code,check.detail);
    for(unsigned i=0;i<2;i++)if((e=pes_page(i,pages[i])))return e;
    /* Both complete mappings/backings were authenticated before either read. */
    for(unsigned i=0;i<2;i++) {
        const volatile unsigned char *b=(const void *)pages[i];
        for(size_t j=0;j<PAGE;j++) {s->key.page[i].bytes[j]=b[j];pe_source.p.bytes_copied[i]=(unsigned)j+1;}
    }
    unsigned entry_page=fetch.pages[0].address==pages[0]?0:1;
    const struct li2_pe_source_page *p=&s->key.page[entry_page];
    if(!span_source_page_equal(&p->identity,&fetch.pages[0]) ||
       !span_source_backing_equal(&p->backing,&fetch.backing[0]) ||
       !equal(p->bytes+(fetch.pc-p->identity.address),fetch.bytes,15))return pes_bad(LI2_FETCH_SOURCE,12);
    s->complete=1;pe_source.p.phase=LI2_PES_HELD;return 0;
}
const struct li2_pe_sources *li2_pe_source_view(const struct li2_pe_token *t) {
    return pes_token(t) && pe_source.p.source.complete?&pe_source.p.source:0;
}
static int pes_live(const struct li2_pe_token *t) {
    const struct li2_pe_sources *s=&pe_source.p.source;
    if(!pes_token(t) || !s->complete || s->serial!=t->serial ||
       allocation_id!=s->allocation_epoch || generation!=s->generation_epoch ||
       counts.transactions!=s->transactions_epoch || used!=s->records_epoch ||
       pe_source.p.validations==UINT64_MAX)return pes_bad(LI2_FETCH_STALE,20);
    int e=li2_lifecycle_run_reuse_quiet(&s->anchor);if(e)return pes_bad((unsigned)e,21);
    if((e=li2_lifecycle_fetch_validate(&s->anchor,0,PROT_READ)))return pes_bad((unsigned)e,22);
    pe_source.p.validation=(struct li2_fetch_map_progress){0};struct check_error check={0};
    if(read_maps_checked(&check,&pe_source.p.validation))return pes_bad(check.code,check.detail);
    for(unsigned i=0;i<2;i++) {
        const struct li2_pe_source_page *saved=&s->key.page[i];
        const struct owned_page *p=current(saved->identity.address);const struct map_row *r=mapping(saved->identity.address);
        if(!fetch_owned_equal(p,&pe_source.original[i]) || !r || !r->private || r->prot!=PROT_READ ||
           r->first!=saved->identity.vma_first || r->end!=saved->identity.vma_end ||
           r->major!=saved->identity.vma_major || r->minor!=saved->identity.vma_minor ||
           r->inode!=saved->identity.vma_inode || r->offset!=saved->identity.vma_offset)
            return pes_bad(LI2_FETCH_STALE,23+i);
        if(verify_page_checked(p,r,&check) || alias_check_checked(p->object,p->offset,PAGE,p->logical,
                p->address,p->address+PAGE,&check))return pes_bad(check.code,check.detail);
        if((e=fetch_backing_check(p,&pe_source.p.last_backing[i])))return pes_bad((unsigned)e,25+i);
        if(!span_source_backing_equal(&saved->backing,&pe_source.p.last_backing[i]))return pes_bad(LI2_FETCH_BACKING,27+i);
    }
    for(unsigned i=0;i<2;i++) {
        const volatile unsigned char *b=(const void *)s->key.page[i].identity.address;
        for(size_t j=0;j<PAGE;j++)if(b[j]!=s->key.page[i].bytes[j])return pes_bad(LI2_FETCH_SOURCE,(long)(i*PAGE+j));
    }
    ++pe_source.p.validations;return 0;
}
int li2_pe_source_validate(const struct li2_pe_token *t,const struct li2_pe_compact *p) {
    const struct li2_pe_sources *s=&pe_source.p.source;
    if(!pes_token(t) || pe_source.p.first_error ||
       (pe_source.p.phase!=LI2_PES_HELD && pe_source.p.phase!=LI2_PES_RX && pe_source.p.phase!=LI2_PES_CLOSED) ||
       !p || p->version!=LI2_PE_COMPACT_VERSION || p->bytes!=sizeof *p || p->ready!=1 || p->result ||
       p->entry!=s->key.entry || p->generated!=pe_source.p.generated || !p->heads || p->heads>64 ||
       !p->exits || p->exits>8)return pes_bad(LI2_FETCH_SOURCE,30);
    for(unsigned i=0;i<2;i++)if(p->page[i]!=s->key.page[i].identity.address ||
        !equal(p->source[i],s->key.page[i].bytes,PAGE))return pes_bad(LI2_FETCH_SOURCE,31+i);
    return pes_live(t);
}
int li2_pe_source_opened(const struct li2_pe_token *t,const struct li2_pe_compact *p) {
    if(!pes_token(t) || li2_pe_owner_phase(t)!=LI2_PE_OPENING || pe_source.p.phase!=LI2_PES_HELD)
        return pes_bad(LI2_FETCH_STATE,40);
    int e=li2_lifecycle_private_code_query(pe_source.p.generated,LI2_PE_IMAGE_BYTES,PROT_READ|PROT_EXEC,&pe_source.p.opened);
    if(e || !pe_source.p.opened.complete || pe_source.p.opened.pages_checked!=8 ||
       pe_source.p.opened.actual_prot!=(PROT_READ|PROT_EXEC))return pes_bad(LI2_FETCH_PAGE,40);
    if((e=li2_pe_source_validate(t,p)))return e;
    pe_source.p.phase=LI2_PES_RX;return 0;
}
int li2_pe_source_release(const struct li2_pe_token *t,const struct li2_pe_compact *p) {
    if(!pes_token(t) || li2_pe_owner_phase(t)!=LI2_PE_RELEASING || pe_source.p.phase!=LI2_PES_RX)
        return pes_bad(LI2_FETCH_STATE,50);
    int e=li2_lifecycle_private_code_query(pe_source.p.generated,LI2_PE_IMAGE_BYTES,PROT_READ,&pe_source.p.closed);
    if(e || !pe_source.p.closed.complete || pe_source.p.closed.pages_checked!=8 ||
       pe_source.p.closed.actual_prot!=PROT_READ)return pes_bad(LI2_FETCH_PAGE,50);
    pe_source.p.phase=LI2_PES_CLOSED;
    if((e=li2_pe_source_validate(t,p)))return e;
    pe_source.p.release_started=1;e=li2_lifecycle_fetch_release(&pe_source.p.source.anchor);
    if(e)return pes_bad((unsigned)e,51);
    pe_source.p.release_complete=1;pe_source.p.phase=LI2_PES_RELEASED;return 0;
}
int li2_pe_source_abort(const struct li2_pe_token *t) {
    if(!pes_token(t) || pe_source.p.aborted || pe_source.p.phase==LI2_PES_RELEASED)return LI2_FETCH_STATE;
    pe_source.p.aborted=1;
    /* A partially acquired source is retained truthfully. Never read/release
       an invented second page or a failed old fetch. Process termination owns it. */
    if(!pe_source.p.source.complete || pe_source.p.first_error) {pe_source.p.phase=LI2_PES_FAILED;return LI2_FETCH_STATE;}
    pe_source.p.closed=(struct li2_private_code_query){0};
    int e=li2_lifecycle_private_code_query(pe_source.p.generated,LI2_PE_IMAGE_BYTES,PROT_READ,&pe_source.p.closed);
    if(e || !pe_source.p.closed.complete || pe_source.p.closed.pages_checked!=8 ||
       pe_source.p.closed.actual_prot!=PROT_READ) {pe_source.p.phase=LI2_PES_FAILED;return pes_bad(LI2_FETCH_PAGE,60);}
    e=pes_live(t);
    if(!e) {pe_source.p.release_started=1;e=li2_lifecycle_fetch_release(&pe_source.p.source.anchor);if(!e)pe_source.p.release_complete=1;}
    pe_source.p.phase=LI2_PES_FAILED;return e?pes_bad((unsigned)e,61):0;
}
