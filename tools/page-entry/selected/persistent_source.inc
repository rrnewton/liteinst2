/* Actual two-page R/NX lease. Included in lifecycle_loader.c after the exact
   old fetch/span/link helpers; no old fetch storage or API is enlarged. */
#include "persistent_runtime.h"
static struct {
    struct li2_pe_source_progress p;
    struct li2_pe_token token;
    struct owned_page original[2];
#ifdef LI2_PERSISTENT_DYNAMIC
    struct li2_pe_source_progress previous;
#endif
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
#ifdef LI2_PERSISTENT_DYNAMIC
    return p!=LI2_PES_IDLE && p!=LI2_PES_RELEASED && p!=LI2_PES_CANCELLED;
#else
    return p!=LI2_PES_IDLE && p!=LI2_PES_RELEASED;
#endif
}
const struct li2_pe_source_progress *li2_pe_source_progress(void) {return &pe_source.p;}
static int pes_token(const struct li2_pe_token *t) {
    return t && t->owner==pe_source.token.owner && t->serial && t->serial==pe_source.token.serial &&
        li2_pe_owner_phase(t) && pe_source.p.initialized && pe_source.p.serial==t->serial;
}
int li2_pe_source_begin(const struct li2_pe_token *t,uintptr_t generated) {
#ifdef LI2_PERSISTENT_DYNAMIC
    if(!t || !t->serial || li2_pe_owner_phase(t)!=LI2_PE_SEEDING || !pe_source.p.initialized ||
       li2_pe_source_interlock() || pe_source.p.first_error || pe_source.p.aborted ||
       t->serial<=pe_source.p.serial || !generated || (generated&(PAGE-1)) ||
       generated>(UINT64_C(1)<<47)-LI2_PE_IMAGE_BYTES ||
       li2_lifecycle_fetch_interlock() || li2_lifecycle_run_reuse_quiet(0))return LI2_FETCH_STATE;
    const struct li2_pe_rseq_progress *r=li2_pe_rseq_progress();
    if(!r || r->active || r->checking || r->first_error || r->unsafe_terminal)return LI2_FETCH_STATE;
    if(pe_source.p.serial) {
        const struct li2_pe_source_progress *p=&pe_source.p;
        if(pe_source.token.owner!=t->owner || pe_source.token.serial!=p->serial ||
           r->token.owner!=t->owner || r->token.serial!=p->serial || r->seed_complete!=1 ||
           !p->source.complete || p->source.serial!=p->serial ||
           p->release_started!=1 || p->release_complete!=1 ||
           !((p->phase==LI2_PES_RELEASED && !p->cancel_started && !p->cancel_complete &&
              r->entry_complete==1 && r->close_complete==1 && !r->cancel_started && !r->cancel_complete &&
              p->closed.complete==1 && !p->closed.result && p->closed.pages_checked==8 &&
              p->closed.actual_prot==PROT_READ) ||
             (p->phase==LI2_PES_CANCELLED && p->cancel_started==1 && p->cancel_complete==1 &&
              !r->close_complete && r->cancel_started==1 && r->cancel_complete==1 &&
              p->cancel_code.complete==1 && !p->cancel_code.result &&
              p->cancel_code.pages_checked==8 && p->cancel_code.actual_prot==p->cancel_expected_prot &&
              (p->cancel_expected_prot==PROT_READ || p->cancel_expected_prot==(PROT_READ|PROT_WRITE)) &&
              p->cancelled_fetch.complete==1 && !p->cancelled_fetch.progress.held)))return LI2_FETCH_STATE;
        pe_source.previous=pe_source.p;
        /* Previous terminal evidence stays in bounded protected storage. The
           new controller's SEEDING token/busy owner is installed before this. */
        volatile unsigned char *b=(void *)&pe_source.p;
        for(size_t i=0;i<sizeof pe_source.p;i++)b[i]=0;
        b=(void *)pe_source.original;for(size_t i=0;i<sizeof pe_source.original;i++)b[i]=0;
        pe_source.p.initialized=1;
    } else if(pe_source.p.phase!=LI2_PES_IDLE || pe_source.token.owner || pe_source.token.serial ||
              r->token.owner || r->token.serial || r->seed_complete || r->entry_complete ||
              r->close_complete || r->cancel_started || r->cancel_complete)
        return LI2_FETCH_STATE;
#else
    if(!t || li2_pe_owner_phase(t)!=LI2_PE_SEEDING || !pe_source.p.initialized ||
       li2_pe_source_interlock() || pe_source.p.first_error || pe_source.p.serial ||
       !generated || (generated&(PAGE-1)) || generated>(UINT64_C(1)<<47)-LI2_PE_IMAGE_BYTES ||
       li2_lifecycle_fetch_interlock() || li2_lifecycle_run_reuse_quiet(0))return LI2_FETCH_STATE;
#endif
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
#ifdef LI2_PERSISTENT_DYNAMIC
int li2_pe_source_key_equal(const struct li2_pe_source_key *a,const struct li2_pe_source_key *b) {
    if(!a || !b || a->entry!=b->entry)return 0;
    for(unsigned i=0;i<LI2_PE_SOURCES;i++)
        if(!span_source_page_equal(&a->page[i].identity,&b->page[i].identity) ||
           !span_source_backing_equal(&a->page[i].backing,&b->page[i].backing) ||
           !equal(a->page[i].bytes,b->page[i].bytes,LI2_REGION_PAGE))return 0;
    return 1;
}
int li2_pe_source_pair_advisory(uintptr_t pc) {
    uintptr_t page=pc&~(PAGE-1);
    if(!active || tx.guard || used>RECORDS || object_count>OBJECTS || pc>=(UINT64_C(1)<<47) ||
       pc-page>PAGE-15 || page>(UINT64_C(1)<<47)-2*PAGE)return 0;
    /* Direct read-only scan: current() also writes a location memo. The old
       entry page can still be RX under its real predecessor at this point. */
    for(unsigned j=0;j<2;j++) {
        const struct owned_page *p=0;uintptr_t address=page+(uintptr_t)j*PAGE;
        for(size_t i=used;i;i--)if(records[i-1].live && records[i-1].address==address) {
            p=&records[i-1];break;
        }
        if(!p || !p->allocation || !p->generation || p->admitted ||
           p->backing!=SEALED || p->object>=object_count ||
           p->logical!=(PROT_READ|PROT_EXEC) || p->actual!=PROT_READ)return 0;
    }
    return 1;
}
int li2_pe_source_cancel(const struct li2_pe_token *t) {
    struct li2_pe_source_progress *p=&pe_source.p;
    if(!pes_token(t) || li2_pe_owner_phase(t)!=LI2_PE_CANCELLING ||
       p->phase!=LI2_PES_HELD || p->source.complete!=1 || p->first_error || p->aborted ||
       p->cancel_started || p->cancel_complete || p->release_started || p->release_complete ||
       p->opened.attempted || p->closed.attempted || fetch_ref(&p->source.anchor))return LI2_FETCH_STATE;
    int prot=li2_pe_owner_cancel_prot(t);
    if(prot!=PROT_READ && prot!=(PROT_READ|PROT_WRITE))return LI2_FETCH_STATE;
    p->cancel_expected_prot=prot;p->cancel_started=1;
    int e=li2_lifecycle_private_code_query(p->generated,LI2_PE_IMAGE_BYTES,prot,&p->cancel_code);
    if(e || !p->cancel_code.complete || p->cancel_code.pages_checked!=8 ||
       p->cancel_code.actual_prot!=prot)return pes_bad(LI2_FETCH_PAGE,70);
    if((e=pes_live(t)))return e;
    p->release_started=1;e=li2_lifecycle_fetch_release(&p->source.anchor);
    if(e)return pes_bad((unsigned)e,71);
    p->release_complete=1;e=li2_lifecycle_span_fetch_snapshot(&p->cancelled_fetch);
    const struct li2_span_fetch_observation *f=&p->cancelled_fetch;
    if(e || f->complete!=1 || f->progress.held || !f->progress.complete ||
       f->progress.first_error || f->length!=15 || f->page_count!=1 ||
       f->pc!=p->source.key.entry || f->ref.owner!=p->source.anchor.owner ||
       f->ref.sequence!=p->source.anchor.sequence || f->progress.sequence!=f->ref.sequence ||
       !f->progress.validation_calls || !f->progress.last_backing_observed)
        return pes_bad(LI2_FETCH_STALE,e?e:72);
    p->cancel_complete=1;p->phase=LI2_PES_CANCELLED;return 0;
}
#endif
