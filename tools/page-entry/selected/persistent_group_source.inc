/* Actual two-page R/NX lease. Included in lifecycle_loader.c after the exact
   old fetch/span/link helpers; no old fetch storage or API is enlarged. */
#include "persistent_group_runtime.h"
static struct {
    struct li2_pg_source_progress p;
    struct li2_pg_token token;
    struct owned_page original[2];
    struct li2_pg_source_progress previous;
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
    struct li2_pgd_source_progress domain,domain_previous;
#endif
} pg_source;
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
static int pgsd_reset(const struct li2_pg_token *,const struct li2_pg_rseq_progress *);
static int pgsd_primary(const struct li2_pg_token *,unsigned);
#endif

static uintptr_t pgs_address(const struct li2_pg_layout *l,unsigned i) {
    return i<2?l->generated[i]:l->stubs;
}
static size_t pgs_bytes(unsigned i) {return i<2?LI2_PE_IMAGE_BYTES:LI2_PG_STUB_BYTES;}
static int pgs_layout(const struct li2_pg_layout *l) {
    if(!l)return 0;
    uintptr_t a[5]={l->generated[0],l->generated[1],l->stubs,l->slots,l->spill};
    size_t n[5]={LI2_PE_IMAGE_BYTES,LI2_PE_IMAGE_BYTES,LI2_PG_STUB_BYTES,LI2_PG_SLOT_BYTES,PAGE};
    for(unsigned i=0;i<5;i++) {
        if(!a[i] || (a[i]&(PAGE-1)) || a[i]>(UINT64_C(1)<<47)-n[i])return 0;
        for(unsigned j=0;j<i;j++)if(a[i]<a[j]+n[j] && a[j]<a[i]+n[i])return 0;
    }
    return 1;
}
static int pgs_layout_bound(const struct li2_pg_token *t,const struct li2_pg_layout *l) {
    const struct li2_pg_layout *actual=li2_pg_owner_layout(t);
    return pgs_layout(l) && actual && equal(l,actual,sizeof *l);
}
static int pgs_query_done(const struct li2_pg_layout *l,unsigned i,int prot,const struct li2_private_code_query *q) {
    return i<3 && q->attempted==1 && q->complete==1 && !q->result &&
        q->first==pgs_address(l,i) && q->end==q->first+pgs_bytes(i) &&
        q->pages_checked==pgs_bytes(i)/PAGE && q->expected_prot==prot && q->actual_prot==prot;
}
static int pgs_closed(const struct li2_pg_source_progress *p) {
    if(p->opened_extents!=3 || p->opened_pages!=17 || p->closed_extents!=3 || p->closed_pages!=17)return 0;
    for(unsigned i=0;i<3;i++)if(!pgs_query_done(&p->layout,i,PROT_READ|PROT_EXEC,&p->opened[i]) ||
        !pgs_query_done(&p->layout,i,PROT_READ,&p->closed[i]))return 0;
    return 1;
}
static int pgs_cancelled(const struct li2_pg_source_progress *p) {
    if(p->opened_extents || p->opened_pages || p->closed_extents || p->closed_pages ||
       p->cancel_extents!=3 || p->cancel_pages!=17)return 0;
    for(unsigned i=0;i<3;i++)if(p->opened[i].attempted || p->closed[i].attempted ||
        (p->cancel_expected_prot[i]!=PROT_READ && p->cancel_expected_prot[i]!=(PROT_READ|PROT_WRITE)) ||
        !pgs_query_done(&p->layout,i,p->cancel_expected_prot[i],&p->cancel_code[i]))return 0;
    return 1;
}

static int pgs_bad(unsigned code,long detail) {
    if(!pg_source.p.first_error) {pg_source.p.first_error=code;pg_source.p.first_detail=detail;}
    return (int)pg_source.p.first_error;
}
int li2_pg_source_initialize(void) {
    if(pg_source.p.initialized || pg_source.p.phase || !hooks.protected_range)return LI2_FETCH_STATE;
    for(size_t i=0;i<sizeof pg_source;i++)
        if(!hooks.protected_range((uintptr_t)&pg_source+i,1))return LI2_FETCH_STATE;
    pg_source.p.initialized=1;return 0;
}
int li2_pg_source_interlock(void) {
    unsigned p=pg_source.p.phase;
    return p!=LI2_PGS_IDLE && p!=LI2_PGS_RELEASED && p!=LI2_PGS_CANCELLED;
}
const struct li2_pg_source_progress *li2_pg_source_progress(void) {return &pg_source.p;}
static int pgs_token(const struct li2_pg_token *t) {
    return t && t->owner==pg_source.token.owner && t->serial && t->serial==pg_source.token.serial &&
        li2_pg_owner_phase(t) && pg_source.p.initialized && pg_source.p.serial==t->serial &&
        pgs_layout_bound(t,&pg_source.p.layout);
}
int li2_pg_source_begin(const struct li2_pg_token *t,const struct li2_pg_layout *layout) {
    if(!t || !t->serial || li2_pg_owner_phase(t)!=LI2_PG_SEEDING || !pg_source.p.initialized ||
       li2_pg_source_interlock() || pg_source.p.first_error || pg_source.p.aborted ||
       t->serial<=pg_source.p.serial || !pgs_layout_bound(t,layout) ||
       li2_lifecycle_fetch_interlock() || li2_lifecycle_run_reuse_quiet(0))return LI2_FETCH_STATE;
    const struct li2_pg_rseq_progress *r=li2_pg_rseq_progress();
    if(!r || r->active || r->checking || r->first_error || r->unsafe_terminal)return LI2_FETCH_STATE;
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
    if(!pgsd_reset(t,r))return LI2_FETCH_STATE;
#endif
    if(pg_source.p.serial) {
        const struct li2_pg_source_progress *p=&pg_source.p;
        if(pg_source.token.owner!=t->owner || pg_source.token.serial!=p->serial ||
           r->token.owner!=t->owner || r->token.serial!=p->serial || r->seed_complete!=1 ||
           !p->source.complete || p->source.serial!=p->serial ||
           p->release_started!=1 || p->release_complete!=1 ||
           !((p->phase==LI2_PGS_RELEASED && !p->cancel_started && !p->cancel_complete &&
              r->entry_complete==1 && r->close_complete==1 && !r->cancel_started && !r->cancel_complete &&
              pgs_closed(p)) ||
             (p->phase==LI2_PGS_CANCELLED && p->cancel_started==1 && p->cancel_complete==1 &&
              !r->close_complete && r->cancel_started==1 && r->cancel_complete==1 && pgs_cancelled(p) &&
              p->cancelled_fetch.complete==1 && !p->cancelled_fetch.progress.held)))return LI2_FETCH_STATE;
        pg_source.previous=pg_source.p;
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
        pg_source.domain_previous=pg_source.domain;
        volatile unsigned char *db=(void *)&pg_source.domain;
        for(size_t i=0;i<sizeof pg_source.domain;i++)db[i]=0;
#endif
        volatile unsigned char *b=(void *)&pg_source.p;
        for(size_t i=0;i<sizeof pg_source.p;i++)b[i]=0;
        b=(void *)pg_source.original;for(size_t i=0;i<sizeof pg_source.original;i++)b[i]=0;
        pg_source.p.initialized=1;
    } else if(pg_source.p.phase!=LI2_PGS_IDLE || pg_source.token.owner || pg_source.token.serial ||
              r->token.owner || r->token.serial || r->seed_complete || r->entry_complete ||
              r->close_complete || r->cancel_started || r->cancel_complete)return LI2_FETCH_STATE;
    pg_source.token=*t;pg_source.p.serial=t->serial;pg_source.p.layout=*layout;
    pg_source.p.phase=LI2_PGS_SEEDING;return 0;
}
static int pgs_page(unsigned i,uintptr_t address) {
    const struct owned_page *p=current(address);const struct map_row *r=mapping(address);
    if(!p || !p->live || !p->allocation || !p->generation || p->admitted ||
       p->backing!=SEALED || p->object>=object_count || p->logical!=(PROT_READ|PROT_EXEC) ||
       p->actual!=PROT_READ)return pgs_bad(LI2_FETCH_PAGE,i);
    struct check_error e={0};
    if(verify_page_checked(p,r,&e) || alias_check_checked(p->object,p->offset,PAGE,p->logical,
            p->address,p->address+PAGE,&e))return pgs_bad(e.code,e.detail);
    if(!r || !r->private || r->prot!=PROT_READ || address<r->first ||
       address>=r->end || r->end-address<PAGE)return pgs_bad(LI2_FETCH_PAGE,2+i);
    /* Actual retained identity is installed before the next descriptor RAW. */
    pg_source.original[i]=*p;
    struct li2_pg_source_page *out=&pg_source.p.source.key.page[i];
    out->identity=(struct li2_fetch_page){.address=p->address,.allocation=p->allocation,
        .generation=p->generation,.offset=p->offset,.initial_extent=p->initial_extent,
        .backing=p->backing,.object=p->object,.logical=p->logical,.closed_prot=p->actual,
        .vma_first=r->first,.vma_end=r->end,.vma_major=r->major,.vma_minor=r->minor,
        .vma_inode=r->inode,.vma_offset=r->offset};
    pg_source.p.pages_copied=i+1;
    int result=fetch_backing_check(p,&out->backing);
    return result?pgs_bad((unsigned)result,3+i):0;
}
int li2_pg_source_prepare(const struct li2_pg_token *t,const struct li2_fetch_ref *ref,const uintptr_t pages[2]) {
    if(!pgs_token(t) || li2_pg_owner_phase(t)!=LI2_PG_PREPARING || pg_source.p.phase!=LI2_PGS_SEEDING ||
       pg_source.p.first_error || !pages || !ref || fetch_ref(ref) || !span_source_geometry() ||
       pages[0]>=pages[1] || (pages[0]&(PAGE-1)) || (pages[1]&(PAGE-1)) ||
       pages[1]>(UINT64_C(1)<<47)-PAGE ||
       (fetch.pages[0].address!=pages[0] && fetch.pages[0].address!=pages[1]))return LI2_FETCH_ARGUMENT;
    struct li2_pg_sources *s=&pg_source.p.source;
    pg_source.p.phase=LI2_PGS_PREPARING;s->anchor=*ref;s->serial=t->serial;
    s->allocation_epoch=allocation_id;s->generation_epoch=generation;
    s->transactions_epoch=counts.transactions;s->records_epoch=used;s->key.entry=fetch.pc;
    int e=li2_lifecycle_run_reuse_quiet(ref);if(e)return pgs_bad((unsigned)e,10);
    if((e=li2_lifecycle_fetch_validate(ref,0,PROT_READ)))return pgs_bad((unsigned)e,11);
    struct check_error check={0};
    if(read_maps_checked(&check,&pg_source.p.preparation))return pgs_bad(check.code,check.detail);
    for(unsigned i=0;i<2;i++)if((e=pgs_page(i,pages[i])))return e;
    /* Both complete mappings/backings were authenticated before either read. */
    for(unsigned i=0;i<2;i++) {
        const volatile unsigned char *b=(const void *)pages[i];
        for(size_t j=0;j<PAGE;j++) {s->key.page[i].bytes[j]=b[j];pg_source.p.bytes_copied[i]=(unsigned)j+1;}
    }
    unsigned entry_page=fetch.pages[0].address==pages[0]?0:1;
    const struct li2_pg_source_page *p=&s->key.page[entry_page];
    if(!span_source_page_equal(&p->identity,&fetch.pages[0]) ||
       !span_source_backing_equal(&p->backing,&fetch.backing[0]) ||
       !equal(p->bytes+(fetch.pc-p->identity.address),fetch.bytes,15))return pgs_bad(LI2_FETCH_SOURCE,12);
    s->complete=1;pg_source.p.phase=LI2_PGS_HELD;return 0;
}
const struct li2_pg_sources *li2_pg_source_view(const struct li2_pg_token *t) {
    return pgs_token(t) && pg_source.p.source.complete?&pg_source.p.source:0;
}
static int pgs_live(const struct li2_pg_token *t) {
    const struct li2_pg_sources *s=&pg_source.p.source;
    if(!pgs_token(t) || !s->complete || s->serial!=t->serial ||
       allocation_id!=s->allocation_epoch || generation!=s->generation_epoch ||
       counts.transactions!=s->transactions_epoch || used!=s->records_epoch ||
       pg_source.p.validations==UINT64_MAX)return pgs_bad(LI2_FETCH_STALE,20);
    int e=li2_lifecycle_run_reuse_quiet(&s->anchor);if(e)return pgs_bad((unsigned)e,21);
    if((e=li2_lifecycle_fetch_validate(&s->anchor,0,PROT_READ)))return pgs_bad((unsigned)e,22);
    pg_source.p.validation=(struct li2_fetch_map_progress){0};struct check_error check={0};
    if(read_maps_checked(&check,&pg_source.p.validation))return pgs_bad(check.code,check.detail);
    for(unsigned i=0;i<2;i++) {
        const struct li2_pg_source_page *saved=&s->key.page[i];
        const struct owned_page *p=current(saved->identity.address);const struct map_row *r=mapping(saved->identity.address);
        if(!fetch_owned_equal(p,&pg_source.original[i]) || !r || !r->private || r->prot!=PROT_READ ||
           r->first!=saved->identity.vma_first || r->end!=saved->identity.vma_end ||
           r->major!=saved->identity.vma_major || r->minor!=saved->identity.vma_minor ||
           r->inode!=saved->identity.vma_inode || r->offset!=saved->identity.vma_offset)
            return pgs_bad(LI2_FETCH_STALE,23+i);
        if(verify_page_checked(p,r,&check) || alias_check_checked(p->object,p->offset,PAGE,p->logical,
                p->address,p->address+PAGE,&check))return pgs_bad(check.code,check.detail);
        if((e=fetch_backing_check(p,&pg_source.p.last_backing[i])))return pgs_bad((unsigned)e,25+i);
        if(!span_source_backing_equal(&saved->backing,&pg_source.p.last_backing[i]))return pgs_bad(LI2_FETCH_BACKING,27+i);
    }
    for(unsigned i=0;i<2;i++) {
        const volatile unsigned char *b=(const void *)s->key.page[i].identity.address;
        for(size_t j=0;j<PAGE;j++)if(b[j]!=s->key.page[i].bytes[j])return pgs_bad(LI2_FETCH_SOURCE,(long)(i*PAGE+j));
    }
    ++pg_source.p.validations;return 0;
}
int li2_pg_source_validate(const struct li2_pg_token *t,const struct li2_pg_compact *p) {
    const struct li2_pg_sources *s=&pg_source.p.source;
    if(!pgs_token(t) || pg_source.p.first_error ||
       (pg_source.p.phase!=LI2_PGS_HELD && pg_source.p.phase!=LI2_PGS_RX && pg_source.p.phase!=LI2_PGS_CLOSED) ||
       !p || p->version!=LI2_PG_COMPACT_VERSION || p->bytes!=sizeof *p || p->ready!=1 || p->result ||
       p->reserved || p->reserved2 || p->entry!=s->key.entry ||
       !equal(&p->layout,&pg_source.p.layout,sizeof p->layout) ||
#ifdef LI2_PERSISTENT_DISPATCH
       !p->heads || p->heads>128 ||
       p->member_heads[0]!=(p->heads<64?p->heads:64) ||
       p->member_heads[1]!=(p->heads>64?p->heads-64:0) ||
       !p->exits || p->exits>8 || p->links>8 || p->links+p->exits>8)
#else
       p->heads<=64 || p->heads>128 ||
       p->member_heads[0]!=64 || p->member_heads[1]!=p->heads-64 ||
       !p->exits || p->exits>8 || !p->links || p->links>8 || p->links+p->exits>8)
#endif
        return pgs_bad(LI2_FETCH_SOURCE,30);
    for(unsigned i=0;i<2;i++)if(p->page[i]!=s->key.page[i].identity.address ||
        !equal(p->source[i],s->key.page[i].bytes,PAGE))return pgs_bad(LI2_FETCH_SOURCE,31+i);
    return pgs_live(t);
}
int li2_pg_source_opened(const struct li2_pg_token *t,const struct li2_pg_compact *p) {
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
    if(!pgsd_primary(t,0))return pgs_bad(LI2_FETCH_STATE,80);
#endif
    if(!pgs_token(t) || li2_pg_owner_phase(t)!=LI2_PG_OPENING || pg_source.p.phase!=LI2_PGS_HELD ||
       pg_source.p.first_error || pg_source.p.opened_extents || pg_source.p.opened_pages)
        return pgs_bad(LI2_FETCH_STATE,40);
    for(unsigned i=0;i<3;i++) {
        int e=li2_lifecycle_private_code_query(pgs_address(&pg_source.p.layout,i),pgs_bytes(i),
            PROT_READ|PROT_EXEC,&pg_source.p.opened[i]);
        if(e || !pgs_query_done(&pg_source.p.layout,i,PROT_READ|PROT_EXEC,&pg_source.p.opened[i]))
            return pgs_bad(LI2_FETCH_PAGE,40+i);
        ++pg_source.p.opened_extents;pg_source.p.opened_pages+=(unsigned)(pgs_bytes(i)/PAGE);
    }
    if(pg_source.p.opened_extents!=3 || pg_source.p.opened_pages!=17)return pgs_bad(LI2_FETCH_PAGE,43);
    int e=li2_pg_source_validate(t,p);if(e)return e;
    pg_source.p.phase=LI2_PGS_RX;return 0;
}
int li2_pg_source_release(const struct li2_pg_token *t,const struct li2_pg_compact *p) {
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
    if(!pgsd_primary(t,1))return pgs_bad(LI2_FETCH_STATE,81);
#endif
    if(!pgs_token(t) || li2_pg_owner_phase(t)!=LI2_PG_RELEASING || pg_source.p.phase!=LI2_PGS_RX ||
       pg_source.p.first_error || pg_source.p.closed_extents || pg_source.p.closed_pages ||
       pg_source.p.release_started || pg_source.p.release_complete)return pgs_bad(LI2_FETCH_STATE,50);
    for(unsigned i=0;i<3;i++) {
        int e=li2_lifecycle_private_code_query(pgs_address(&pg_source.p.layout,i),pgs_bytes(i),
            PROT_READ,&pg_source.p.closed[i]);
        if(e || !pgs_query_done(&pg_source.p.layout,i,PROT_READ,&pg_source.p.closed[i]))
            return pgs_bad(LI2_FETCH_PAGE,50+i);
        ++pg_source.p.closed_extents;pg_source.p.closed_pages+=(unsigned)(pgs_bytes(i)/PAGE);
    }
    if(!pgs_closed(&pg_source.p))return pgs_bad(LI2_FETCH_PAGE,53);
    pg_source.p.phase=LI2_PGS_CLOSED;
    int e=li2_pg_source_validate(t,p);if(e)return e;
    pg_source.p.release_started=1;e=li2_lifecycle_fetch_release(&pg_source.p.source.anchor);
    if(e)return pgs_bad((unsigned)e,54);
    pg_source.p.release_complete=1;pg_source.p.phase=LI2_PGS_RELEASED;return 0;
}
int li2_pg_source_abort(const struct li2_pg_token *t) {
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
    /* The primary abort cannot release a source shared by another open bank.
       A failed domain remains terminal, with its actual partial rows intact. */
    if(pg_source.domain.bound) {
        if(!pgs_token(t))return LI2_FETCH_STATE;
        pg_source.p.aborted=1;pg_source.p.phase=LI2_PGS_FAILED;
        return pgs_bad(LI2_FETCH_STATE,82);
    }
#endif
    if(!pgs_token(t) || pg_source.p.aborted || pg_source.p.phase==LI2_PGS_RELEASED ||
       pg_source.p.phase==LI2_PGS_CANCELLED)return LI2_FETCH_STATE;
    pg_source.p.aborted=1;
    /* Preserve incomplete source/query prefixes. Never overwrite a failed
       query or invent a second source or completed group closure. */
    if(!pg_source.p.source.complete || pg_source.p.first_error) {
        pg_source.p.phase=LI2_PGS_FAILED;return LI2_FETCH_STATE;
    }
    for(unsigned i=0;i<3;i++) {
        struct li2_private_code_query *q=&pg_source.p.closed[i];
        if(q->attempted) {pg_source.p.phase=LI2_PGS_FAILED;return pgs_bad(LI2_FETCH_STATE,60+i);}
        int e=li2_lifecycle_private_code_query(pgs_address(&pg_source.p.layout,i),pgs_bytes(i),PROT_READ,q);
        if(e || !pgs_query_done(&pg_source.p.layout,i,PROT_READ,q)) {
            pg_source.p.phase=LI2_PGS_FAILED;return pgs_bad(LI2_FETCH_PAGE,63+i);
        }
        ++pg_source.p.closed_extents;pg_source.p.closed_pages+=(unsigned)(pgs_bytes(i)/PAGE);
    }
    if(pg_source.p.closed_extents!=3 || pg_source.p.closed_pages!=17) {
        pg_source.p.phase=LI2_PGS_FAILED;return pgs_bad(LI2_FETCH_PAGE,66);
    }
    int e=pgs_live(t);
    if(!e) {pg_source.p.release_started=1;e=li2_lifecycle_fetch_release(&pg_source.p.source.anchor);if(!e)pg_source.p.release_complete=1;}
    pg_source.p.phase=LI2_PGS_FAILED;return e?pgs_bad((unsigned)e,67):0;
}
int li2_pg_source_key_equal(const struct li2_pg_source_key *a,const struct li2_pg_source_key *b) {
    if(!a || !b || a->entry!=b->entry)return 0;
    for(unsigned i=0;i<LI2_PE_SOURCES;i++)
        if(!span_source_page_equal(&a->page[i].identity,&b->page[i].identity) ||
           !span_source_backing_equal(&a->page[i].backing,&b->page[i].backing) ||
           !equal(a->page[i].bytes,b->page[i].bytes,LI2_REGION_PAGE))return 0;
    return 1;
}
int li2_pg_source_pair_advisory(uintptr_t pc) {
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
int li2_pg_source_cancel(const struct li2_pg_token *t) {
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
    if(pg_source.domain.bound || pg_source.domain.first_error)return LI2_FETCH_STATE;
#endif
    struct li2_pg_source_progress *p=&pg_source.p;
    if(!pgs_token(t) || li2_pg_owner_phase(t)!=LI2_PG_CANCELLING ||
       p->phase!=LI2_PGS_HELD || p->source.complete!=1 || p->first_error || p->aborted ||
       p->cancel_started || p->cancel_complete || p->release_started || p->release_complete ||
       p->opened_extents || p->opened_pages || p->closed_extents || p->closed_pages ||
       p->cancel_extents || p->cancel_pages || fetch_ref(&p->source.anchor))return LI2_FETCH_STATE;
    for(unsigned i=0;i<3;i++) {
        if(p->opened[i].attempted || p->closed[i].attempted || p->cancel_code[i].attempted)return LI2_FETCH_STATE;
        int prot=li2_pg_owner_cancel_prot(t,i);
        if(prot!=PROT_READ && prot!=(PROT_READ|PROT_WRITE))return LI2_FETCH_STATE;
        p->cancel_expected_prot[i]=prot;
    }
    p->cancel_started=1;
    for(unsigned i=0;i<3;i++) {
        int e=li2_lifecycle_private_code_query(pgs_address(&p->layout,i),pgs_bytes(i),
            p->cancel_expected_prot[i],&p->cancel_code[i]);
        if(e || !pgs_query_done(&p->layout,i,p->cancel_expected_prot[i],&p->cancel_code[i]))
            return pgs_bad(LI2_FETCH_PAGE,70+i);
        ++p->cancel_extents;p->cancel_pages+=(unsigned)(pgs_bytes(i)/PAGE);
    }
    if(!pgs_cancelled(p))return pgs_bad(LI2_FETCH_PAGE,73);
    int e=pgs_live(t);if(e)return e;
    p->release_started=1;e=li2_lifecycle_fetch_release(&p->source.anchor);
    if(e)return pgs_bad((unsigned)e,74);
    p->release_complete=1;e=li2_lifecycle_span_fetch_snapshot(&p->cancelled_fetch);
    const struct li2_span_fetch_observation *f=&p->cancelled_fetch;
    if(e || f->complete!=1 || f->progress.held || !f->progress.complete ||
       f->progress.first_error || f->length!=15 || f->page_count!=1 ||
       f->pc!=p->source.key.entry || f->ref.owner!=p->source.anchor.owner ||
       f->ref.sequence!=p->source.anchor.sequence || f->progress.sequence!=f->ref.sequence ||
       !f->progress.validation_calls || !f->progress.last_backing_observed)
        return pgs_bad(LI2_FETCH_STALE,e?e:75);
    p->cancel_complete=1;p->phase=LI2_PGS_CANCELLED;return 0;
}
#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN
static int pgsd_zero(const void *value,size_t bytes) {
    const unsigned char *p=value;
    for(size_t i=0;i<bytes;i++)if(p[i])return 0;
    return 1;
}
static int pgsd_bad(unsigned code,long detail) {
    struct li2_pgd_source_progress *d=&pg_source.domain;
    if(!d->first_error) {d->first_error=code;d->first_detail=detail;}
    return pgs_bad(code,detail);
}
int li2_pgd_source_pair_equal(const struct li2_pg_source_key *a,const struct li2_pg_source_key *b) {
    /* Deliberately only pair identity. Each root is separately authenticated
       by the protected member reference and its own immutable plan. */
    if(!a || !b)return 0;
    for(unsigned i=0;i<LI2_PE_SOURCES;i++)
        if(!span_source_page_equal(&a->page[i].identity,&b->page[i].identity) ||
           !span_source_backing_equal(&a->page[i].backing,&b->page[i].backing) ||
           !equal(a->page[i].bytes,b->page[i].bytes,LI2_REGION_PAGE))return 0;
    return 1;
}
static int pgsd_member(const struct li2_pgd_member *m,const struct li2_pg_sources *s,uintptr_t directory) {
    const struct li2_pgd_ref *r=&m->identity;
    const struct li2_pg_compact *p=m->plan;
    if(!p || !m->key || !r->generation || r->slot>=LI2_PGD_MEMBERS || r->bank>=2 ||
       !r->proof || (r->proof&(PAGE-1)) || r->proof>=(UINT64_C(1)<<47) ||
       !r->root || r->root!=m->key->entry || r->root!=p->entry ||
       !pgs_layout(&r->layout) || r->layout.directory!=directory ||
       !equal(&r->layout,&p->layout,sizeof p->layout) ||
       p->version!=LI2_PG_COMPACT_VERSION || p->bytes!=sizeof *p || p->ready!=1 || p->result ||
       p->reserved || p->reserved2 || !p->heads || p->heads>LI2_PG_HEADS ||
       p->member_heads[0]!=(p->heads<64?p->heads:64) ||
       p->member_heads[1]!=(p->heads>64?p->heads-64:0) ||
       !p->exits || p->exits>8 || p->links>8 || p->links+p->exits>8 ||
       !li2_pgd_source_pair_equal(m->key,&s->key))return 0;
    unsigned root=0;
    for(unsigned i=0;i<LI2_PE_SOURCES;i++) {
        if(p->page[i]!=s->key.page[i].identity.address ||
           !equal(p->source[i],s->key.page[i].bytes,PAGE))return 0;
        if(r->root>=p->page[i] && r->root-p->page[i]<PAGE)root=1;
    }
    return root;
}
static int pgsd_separate(const struct li2_pg_layout *a,const struct li2_pg_layout *b,uintptr_t directory) {
    uintptr_t first[2][5]={{a->generated[0],a->generated[1],a->stubs,a->slots,a->spill},
        {b->generated[0],b->generated[1],b->stubs,b->slots,b->spill}};
    size_t bytes[5]={LI2_PE_IMAGE_BYTES,LI2_PE_IMAGE_BYTES,LI2_PG_STUB_BYTES,LI2_PG_SLOT_BYTES,PAGE};
    for(unsigned i=0;i<5;i++) {
        for(unsigned k=0;k<2;k++)if(first[k][i]<directory+LI2_JD_DOMAIN_BYTES &&
            directory<first[k][i]+bytes[i])return 0;
        if(a!=b)for(unsigned j=0;j<5;j++)if(first[0][i]<first[1][j]+bytes[j] &&
            first[1][j]<first[0][i]+bytes[i])return 0;
    }
    return 1;
}
static const struct li2_pgd_view *pgsd_view(const struct li2_pg_token *t,unsigned bound) {
    const struct li2_pgd_view *v=li2_pgd_owner_view(t);
    const struct li2_pgd_source_progress *d=&pg_source.domain;
    const struct li2_pg_sources *s=&pg_source.p.source;
    if(!pgs_token(t) || pg_source.p.first_error || pg_source.p.aborted || !s->complete ||
       s->serial!=t->serial || !v || v->token.owner!=t->owner || v->token.serial!=t->serial ||
       !v->count || v->count>LI2_PGD_MEMBERS || v->reserved ||
       !v->directory || (v->directory&(PAGE-1)) ||
       v->directory>(UINT64_C(1)<<47)-LI2_JD_DOMAIN_BYTES ||
       !equal(&v->member[0].identity.layout,&pg_source.p.layout,sizeof pg_source.p.layout) ||
       !v->member[0].key || v->member[0].key->entry!=s->key.entry ||
       d->first_error)return 0;
    if(bound && (d->bound!=1 || d->token.owner!=t->owner || d->token.serial!=t->serial ||
       d->count!=v->count))return 0;
    for(unsigned i=0;i<v->count;i++) {
        if(!pgsd_member(&v->member[i],s,v->directory) ||
           !pgsd_separate(&v->member[i].identity.layout,&v->member[i].identity.layout,v->directory) ||
           (bound && !equal(&d->ref[i],&v->member[i].identity,sizeof d->ref[i])))return 0;
        for(unsigned j=0;j<i;j++)if(v->member[i].identity.slot==v->member[j].identity.slot ||
            v->member[i].identity.generation==v->member[j].identity.generation ||
            v->member[i].identity.proof==v->member[j].identity.proof ||
            !pgsd_separate(&v->member[i].identity.layout,&v->member[j].identity.layout,v->directory))return 0;
    }
    return v;
}
static int pgsd_terminal_record(void) {
    const struct li2_pgd_source_progress *d=&pg_source.domain;
    const struct li2_pg_source_progress *p=&pg_source.p;
    if(d->bound!=1 || d->opened!=1 || d->closed!=1 || d->released!=1 || d->first_error ||
       d->first_detail || !d->count || d->count>LI2_PGD_MEMBERS ||
       d->token.owner!=pg_source.token.owner || d->token.serial!=p->serial ||
       !p->serial || p->phase!=LI2_PGS_RELEASED || p->first_error || p->aborted ||
       p->cancel_started || p->cancel_complete || p->release_started!=1 || p->release_complete!=1 ||
       !p->source.complete || p->source.serial!=p->serial || !pgs_closed(p) ||
       !equal(&d->ref[0].layout,&p->layout,sizeof p->layout) ||
       !equal(d->open[0],p->opened,sizeof p->opened) ||
       !equal(d->close[0],p->closed,sizeof p->closed))return 0;
    for(unsigned i=0;i<d->count;i++)for(unsigned j=0;j<3;j++)
        if(!pgs_query_done(&d->ref[i].layout,j,PROT_READ|PROT_EXEC,&d->open[i][j]) ||
           !pgs_query_done(&d->ref[i].layout,j,PROT_READ,&d->close[i][j]))return 0;
    for(unsigned i=d->count;i<LI2_PGD_MEMBERS;i++)
        if(!pgsd_zero(&d->ref[i],sizeof d->ref[i]) || !pgsd_zero(d->open[i],sizeof d->open[i]) ||
           !pgsd_zero(d->close[i],sizeof d->close[i]))return 0;
    return 1;
}
static int pgsd_reset(const struct li2_pg_token *t,const struct li2_pg_rseq_progress *r) {
    const struct li2_pgd_source_progress *d=&pg_source.domain;
    if(!d->bound)return pgsd_zero(d,sizeof *d) && !r->domain_bound && !r->domain_count &&
        pgsd_zero(r->domain_ref,sizeof r->domain_ref);
    return pg_source.p.serial && d->token.owner==t->owner && pgsd_terminal_record() &&
        r->domain_bound==1 && r->domain_count==d->count &&
        equal(r->domain_ref,d->ref,sizeof d->ref);
}
static int pgsd_primary(const struct li2_pg_token *t,unsigned closing) {
    const struct li2_pgd_source_progress *d=&pg_source.domain;
    if(!pgsd_view(t,1) || d->closed || d->released || d->opened!=closing)return 0;
    if(closing && !equal(d->open[0],pg_source.p.opened,sizeof pg_source.p.opened))return 0;
    for(unsigned i=1;i<d->count;i++)for(unsigned j=0;j<3;j++)
        if(!pgs_query_done(&d->ref[i].layout,j,PROT_READ|PROT_EXEC,&d->open[i][j]) ||
           (closing && !pgs_query_done(&d->ref[i].layout,j,PROT_READ,&d->close[i][j])))return 0;
    return 1;
}
const struct li2_pgd_source_progress *li2_pgd_source_progress(void) {return &pg_source.domain;}
int li2_pgd_source_bind(const struct li2_pg_token *t) {
    struct li2_pgd_source_progress *d=&pg_source.domain;
    const struct li2_pgd_view *v=pgsd_view(t,0);
    if(!v || li2_pg_owner_phase(t)!=LI2_PG_BOUND || pg_source.p.phase!=LI2_PGS_HELD ||
       pg_source.p.opened_extents || pg_source.p.closed_extents || pg_source.p.release_started ||
       pg_source.p.cancel_started || !pgsd_zero(d,sizeof *d))return pgsd_bad(LI2_FETCH_STATE,83);
    int e=li2_pg_source_validate(t,v->member[0].plan);if(e)return pgsd_bad((unsigned)e,84);
    d->token=*t;d->count=v->count;
    for(unsigned i=0;i<v->count;i++)d->ref[i]=v->member[i].identity;
    __asm__ volatile("":::"memory");d->bound=1;return 0;
}
int li2_pgd_source_opened(const struct li2_pg_token *t) {
    struct li2_pgd_source_progress *d=&pg_source.domain;
    const struct li2_pgd_view *v=pgsd_view(t,1);
    if(!v || li2_pg_owner_phase(t)!=LI2_PG_OPENING || pg_source.p.phase!=LI2_PGS_HELD ||
       d->opened || d->closed || d->released || !pgsd_zero(d->open,sizeof d->open) ||
       !pgsd_zero(d->close,sizeof d->close))return pgsd_bad(LI2_FETCH_STATE,85);
    for(unsigned i=1;i<d->count;i++)for(unsigned j=0;j<3;j++) {
        int e=li2_lifecycle_private_code_query(pgs_address(&d->ref[i].layout,j),pgs_bytes(j),
            PROT_READ|PROT_EXEC,&d->open[i][j]);
        if(e || !pgs_query_done(&d->ref[i].layout,j,PROT_READ|PROT_EXEC,&d->open[i][j]))
            return pgsd_bad(LI2_FETCH_PAGE,86+(long)(3*i+j));
    }
    int e=li2_pg_source_opened(t,v->member[0].plan);if(e)return pgsd_bad((unsigned)e,92);
    for(unsigned j=0;j<3;j++)d->open[0][j]=pg_source.p.opened[j];
    d->opened=1;return 0;
}
int li2_pgd_source_release(const struct li2_pg_token *t) {
    struct li2_pgd_source_progress *d=&pg_source.domain;
    const struct li2_pgd_view *v=pgsd_view(t,1);
    if(!v || li2_pg_owner_phase(t)!=LI2_PG_RELEASING || pg_source.p.phase!=LI2_PGS_RX ||
       d->opened!=1 || d->closed || d->released || !pgsd_zero(d->close,sizeof d->close))
        return pgsd_bad(LI2_FETCH_STATE,93);
    for(unsigned i=1;i<d->count;i++)for(unsigned j=0;j<3;j++) {
        int e=li2_lifecycle_private_code_query(pgs_address(&d->ref[i].layout,j),pgs_bytes(j),PROT_READ,&d->close[i][j]);
        if(e || !pgs_query_done(&d->ref[i].layout,j,PROT_READ,&d->close[i][j]))
            return pgsd_bad(LI2_FETCH_PAGE,94+(long)(3*i+j));
    }
    int e=li2_pg_source_release(t,v->member[0].plan);if(e)return pgsd_bad((unsigned)e,100);
    for(unsigned j=0;j<3;j++)d->close[0][j]=pg_source.p.closed[j];
    d->closed=1;d->released=1;return 0;
}
int li2_pgd_source_terminal(const struct li2_pg_token *t) {
    return pgsd_view(t,1) && pgsd_terminal_record();
}
#endif
