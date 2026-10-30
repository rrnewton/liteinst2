/* Included after unchanged span_source.inc. Direct lifecycle entry points
   reject this actual private owner before callbacks or permission changes. */
#include "linked_preedge_source.h"
struct li2_preedge_epoch {
    struct li2_preedge_epoch_progress p;
    struct li2_fetch_ref ref;
};
static struct li2_preedge_epoch preedge_epoch;
static unsigned preedge_registered;
int li2_lifecycle_preedge_initialize(void) {
    /* Keep the real inactive v1 flag addressable for complete private-storage binding. */
    __asm__ volatile(""::"r"(&linked_registered):"memory");
    if(preedge_registered || preedge_epoch.p.phase || li2_lifecycle_link_interlock() || !hooks.protected_range)return LI2_FETCH_STATE;
    /* The bridge protects its actual full RW/NX PT_LOAD. Independently check
       every metadata byte with the existing strict mutation guard, since its
       full-range predicate means intersection, not containment. */
    for(size_t i=0;i<sizeof preedge_epoch;i++)
        if(!hooks.protected_range((uintptr_t)&preedge_epoch+i,1))return LI2_FETCH_STATE;
    for(size_t i=0;i<sizeof preedge_registered;i++)
        if(!hooks.protected_range((uintptr_t)&preedge_registered+i,1))return LI2_FETCH_STATE;
    preedge_registered=1;return 0;
}
int li2_lifecycle_preedge_interlock(void) {
    unsigned p=preedge_epoch.p.phase;
    return p!=LI2_PREEDGE_IDLE && p!=LI2_PREEDGE_RELEASED;
}
const struct li2_preedge_epoch_progress *li2_lifecycle_preedge_progress(void) {return &preedge_epoch.p;}
static int preedge_bad(unsigned code,long detail) {
    if(!preedge_epoch.p.first_error) {
        preedge_epoch.p.first_error=code;preedge_epoch.p.first_detail=detail;
    }
    return (int)code;
}
static int preedge_epoch_identity(const struct li2_preedge_epoch_token *token,const struct li2_preedge_plan *p) {
    /* Authenticate the retained serial before reading source/plan fields or
       issuing a query. An old pointer to this singleton is never authority. */
    if(!token || token->owner!=&preedge_epoch || !token->serial ||
       token->serial!=preedge_epoch.p.serial)return 0;
    const struct li2_preedge_epoch *e=&preedge_epoch;
    return preedge_registered==1 && !e->p.first_error && li2_lifecycle_preedge_interlock() &&
        e->p.serial && e->p.publication && e->p.borrow==e->ref.sequence &&
        e->p.allocation_epoch==allocation_id && e->p.generation_epoch==generation &&
        e->p.transactions_epoch==counts.transactions && e->p.records_epoch==used &&
        p && p->version==LI2_PREEDGE_VERSION && p->bytes==sizeof(*p) && !p->reserved &&
        p->ready==1 && e->p.source==p->page && e->p.generated==p->generated;
}
int li2_lifecycle_preedge_validate(const struct li2_fetch_ref *ref,const struct li2_span_source *s,
                                const struct li2_preedge_plan *p) {
    int e=fetch_ref(ref);if(e)return e;
    if(!s || __atomic_load_n(&s->ready,__ATOMIC_ACQUIRE)!=1 ||
       s->borrow.owner!=ref->owner || s->borrow.sequence!=ref->sequence ||
       !span_source_geometry() || s->key.entry!=fetch.pc ||
       !span_source_page_equal(&s->key.page,&fetch.pages[0]) ||
       !p || p->version!=LI2_PREEDGE_VERSION || p->bytes!=sizeof(*p) || p->reserved ||
       p->ready!=1 || p->decoder_result ||
       p->page!=s->key.page.address || p->entry!=s->key.entry ||
       !p->heads || p->heads>LI2_PREEDGE_HEADS || !p->exits || p->exits>LI2_PREEDGE_EXITS ||
       !equal(p->source,s->key.bytes,LI2_REGION_PAGE))return fetch_error(LI2_FETCH_SOURCE,400);
    for(unsigned i=0;i<p->heads;i++) {
        const struct li2_region_head *h=&p->head[i];
        if(h->source_offset>=PAGE || !h->source_length || h->source_length>15 ||
           h->source_length>PAGE-h->source_offset ||
           p->original[i].decoded.pc!=p->page+h->source_offset)
            return fetch_error(LI2_FETCH_SOURCE,401);
    }
    for(unsigned i=0;i<LI2_PREEDGE_EXITS;i++) {
        uintptr_t pc=p->exit_pc[i];
        if(i>=p->exits) {
            if(pc || p->frontier_kind[i])return fetch_error(LI2_FETCH_SOURCE,402);
            continue;
        }
        const struct li2_span_decoded *d=&p->frontier[i];
        unsigned kind=p->frontier_kind[i];
        if(pc<p->page || pc-p->page>=PAGE || d->decoded.pc!=pc ||
           (kind!=LI2_PREEDGE_UNSUPPORTED && kind!=LI2_PREEDGE_PAGE_CUT) ||
           li2_preedge_frontier_kind(p->page,d)!=kind)
            return fetch_error(LI2_FETCH_SOURCE,403);
        size_t available=PAGE-(pc-p->page);if(available>15)available=15;
        if(d->decoded.available!=available || !equal(d->decoded.bytes,
           s->key.bytes+(pc-p->page),available))return fetch_error(LI2_FETCH_SOURCE,406);
        for(size_t j=available;j<sizeof d->decoded.bytes;j++)
            if(d->decoded.bytes[j])return fetch_error(LI2_FETCH_SOURCE,407);
        for(unsigned j=0;j<i;j++)if(pc==p->exit_pc[j])return fetch_error(LI2_FETCH_SOURCE,404);
        for(unsigned j=0;j<p->heads;j++) {
            const struct li2_region_head *h=&p->head[j];
            if(pc>=p->page+h->source_offset && pc<p->page+h->source_offset+h->source_length)
                return fetch_error(LI2_FETCH_SOURCE,405);
        }
    }
    if((e=span_source_live(ref)))return e;
    if(!span_source_backing_equal(&s->key.backing,&fetch.last_backing))
        return fetch_error(LI2_FETCH_BACKING,400);
    const volatile unsigned char *b=(const void *)p->page;
    for(size_t i=0;i<PAGE;i++)if(b[i]!=s->key.bytes[i])return fetch_error(LI2_FETCH_SOURCE,(long)i);
    return 0;
}
int li2_lifecycle_preedge_begin(const struct li2_fetch_ref *ref,const struct li2_span_source *s,
                             const struct li2_preedge_plan *p,uint64_t publication,
                             struct li2_preedge_epoch_token *out) {
    if(preedge_registered!=1 || !out || out->owner || out->serial || !publication || li2_lifecycle_link_interlock() || preedge_epoch.p.first_error ||
       preedge_epoch.p.serial==UINT64_MAX || !ref || !p)return LI2_FETCH_BUSY;
    uint64_t serial=preedge_epoch.p.serial+1;
    /* Owner and stable addresses precede every validation/returning RAW. */
    unsigned char *bytes=(void *)&preedge_epoch;
    for(size_t i=0;i<sizeof preedge_epoch;i++)bytes[i]=0;
    preedge_epoch.ref=*ref;
    preedge_epoch.p.serial=serial;preedge_epoch.p.publication=publication;
    preedge_epoch.p.borrow=ref->sequence;preedge_epoch.p.source=p->page;preedge_epoch.p.generated=p->generated;
    preedge_epoch.p.allocation_epoch=allocation_id;preedge_epoch.p.generation_epoch=generation;
    preedge_epoch.p.transactions_epoch=counts.transactions;preedge_epoch.p.records_epoch=used;
    preedge_epoch.p.phase=LI2_PREEDGE_HELD;
    out->owner=&preedge_epoch;out->serial=serial;
    /* A failed validation still leaves the actual HELD owner and this token
       installed for nonreturning cleanup; it never publishes RELEASED. */
    int e=li2_lifecycle_preedge_validate(ref,s,p);
    return e?preedge_bad((unsigned)e,400):0;
}
int li2_lifecycle_preedge_opened(const struct li2_preedge_epoch_token *token,const struct li2_span_source *s,
                              const struct li2_preedge_plan *p) {
    if(!preedge_epoch_identity(token,p) || preedge_epoch.p.phase!=LI2_PREEDGE_HELD)return preedge_bad(LI2_FETCH_STALE,401);
    const struct li2_preedge_epoch *e=&preedge_epoch;
    int result=li2_lifecycle_private_code_query(p->generated,PAGE,PROT_READ|PROT_EXEC,&preedge_epoch.p.opened);
    if(result || !preedge_epoch.p.opened.complete || preedge_epoch.p.opened.pages_checked!=1 ||
       preedge_epoch.p.opened.actual_prot!=(PROT_READ|PROT_EXEC))return preedge_bad(LI2_FETCH_PAGE,401);
    result=li2_lifecycle_preedge_validate(&e->ref,s,p);
    if(result)return preedge_bad((unsigned)result,402);
    preedge_epoch.p.phase=LI2_PREEDGE_RX;return 0;
}
int li2_lifecycle_preedge_release(const struct li2_preedge_epoch_token *token,const struct li2_span_source *s,
                               const struct li2_preedge_plan *p) {
    if(!preedge_epoch_identity(token,p) || preedge_epoch.p.phase!=LI2_PREEDGE_RX)return preedge_bad(LI2_FETCH_STALE,403);
    const struct li2_preedge_epoch *e=&preedge_epoch;
    int result=li2_lifecycle_private_code_query(p->generated,PAGE,PROT_READ,&preedge_epoch.p.closed);
    if(result || !preedge_epoch.p.closed.complete || preedge_epoch.p.closed.pages_checked!=1 ||
       preedge_epoch.p.closed.actual_prot!=PROT_READ)return preedge_bad(LI2_FETCH_PAGE,403);
    preedge_epoch.p.phase=LI2_PREEDGE_CLOSED;
    result=li2_lifecycle_preedge_validate(&e->ref,s,p);
    if(result)return preedge_bad((unsigned)result,404);
    preedge_epoch.p.release_started=1;result=li2_lifecycle_fetch_release(&e->ref);
    if(result)return preedge_bad((unsigned)result,405);
    preedge_epoch.p.release_complete=1;preedge_epoch.p.phase=LI2_PREEDGE_RELEASED;return 0;
}
