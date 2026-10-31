/* Included after unchanged span_source.inc. Direct lifecycle entry points
   reject this actual private owner before callbacks or permission changes. */
#include "linked_source.h"
struct li2_link_epoch {
    struct li2_link_epoch_progress p;
    struct li2_fetch_ref ref;
};
static struct li2_link_epoch linked_epoch;
static unsigned linked_registered;
int li2_lifecycle_link_initialize(void) {
    if(linked_registered || linked_epoch.p.phase || !hooks.protected_range)return LI2_FETCH_STATE;
    /* The bridge protects its actual full RW/NX PT_LOAD. Independently check
       every metadata byte with the existing strict mutation guard, since its
       full-range predicate means intersection, not containment. */
    for(size_t i=0;i<sizeof linked_epoch;i++)
        if(!hooks.protected_range((uintptr_t)&linked_epoch+i,1))return LI2_FETCH_STATE;
    for(size_t i=0;i<sizeof linked_registered;i++)
        if(!hooks.protected_range((uintptr_t)&linked_registered+i,1))return LI2_FETCH_STATE;
    linked_registered=1;return 0;
}
int li2_lifecycle_link_interlock(void) {
#if defined(LI2_PERSISTENT_GROUP)
    if(li2_pg_source_interlock())return 1;
#elif defined(LI2_PERSISTENT_EPOCH)
    if(li2_pe_source_interlock())return 1;
#endif
#ifdef LI2_LINKED_PREEDGE
    if(li2_lifecycle_preedge_interlock())return 1;
#endif
    unsigned p=linked_epoch.p.phase;
    return p!=LI2_LINK_IDLE && p!=LI2_LINK_RELEASED;
}
const struct li2_link_epoch_progress *li2_lifecycle_link_progress(void) {return &linked_epoch.p;}
static int link_bad(unsigned code,long detail) {
    if(!linked_epoch.p.first_error) {
        linked_epoch.p.first_error=code;linked_epoch.p.first_detail=detail;
    }
    return (int)code;
}
static int link_epoch_identity(const struct li2_link_epoch_token *token,const struct li2_link_plan *p) {
    /* Authenticate the retained serial before reading source/plan fields or
       issuing a query. An old pointer to this singleton is never authority. */
    if(!token || token->owner!=&linked_epoch || !token->serial ||
       token->serial!=linked_epoch.p.serial)return 0;
    const struct li2_link_epoch *e=&linked_epoch;
    return linked_registered==1 && !e->p.first_error && li2_lifecycle_link_interlock() &&
        e->p.serial && e->p.publication && e->p.borrow==e->ref.sequence &&
        e->p.allocation_epoch==allocation_id && e->p.generation_epoch==generation &&
        e->p.transactions_epoch==counts.transactions && e->p.records_epoch==used &&
        p && e->p.source==p->page && e->p.generated==p->generated;
}
int li2_lifecycle_link_validate(const struct li2_fetch_ref *ref,const struct li2_span_source *s,
                                const struct li2_link_plan *p) {
    int e=fetch_ref(ref);if(e)return e;
    if(!s || __atomic_load_n(&s->ready,__ATOMIC_ACQUIRE)!=1 ||
       s->borrow.owner!=ref->owner || s->borrow.sequence!=ref->sequence ||
       !span_source_geometry() || s->key.entry!=fetch.pc ||
       !span_source_page_equal(&s->key.page,&fetch.pages[0]) ||
       !p || p->version!=LI2_LINK_VERSION || p->ready!=1 || p->decoder_result ||
       p->page!=s->key.page.address || p->entry!=s->key.entry ||
       !p->heads || p->heads>LI2_LINK_HEADS || !p->exits || p->exits>LI2_LINK_EXITS ||
       !equal(p->source,s->key.bytes,LI2_REGION_PAGE))return fetch_error(LI2_FETCH_SOURCE,400);
    for(unsigned i=0;i<p->heads;i++) {
        const struct li2_region_head *h=&p->head[i];
        if(h->source_offset>=PAGE || !h->source_length || h->source_length>15 ||
           h->source_length>PAGE-h->source_offset ||
           p->original[i].decoded.pc!=p->page+h->source_offset)
            return fetch_error(LI2_FETCH_SOURCE,401);
    }
    for(unsigned i=0;i<LI2_LINK_EXITS;i++) {
        uintptr_t pc=p->exit_pc[i];
        if(i>=p->exits) {if(pc)return fetch_error(LI2_FETCH_SOURCE,402);continue;}
        if(pc<p->page || pc-p->page>=PAGE || p->frontier[i].ready ||
           p->frontier[i].decoded.pc!=pc || p->frontier[i].decoded.decode_status!=LI2_VALID)
            return fetch_error(LI2_FETCH_SOURCE,403);
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
int li2_lifecycle_link_begin(const struct li2_fetch_ref *ref,const struct li2_span_source *s,
                             const struct li2_link_plan *p,uint64_t publication,
                             struct li2_link_epoch_token *out) {
    if(linked_registered!=1 || !out || out->owner || out->serial || !publication || li2_lifecycle_link_interlock() || linked_epoch.p.first_error ||
       linked_epoch.p.serial==UINT64_MAX || !ref || !p)return LI2_FETCH_BUSY;
    uint64_t serial=linked_epoch.p.serial+1;
    /* Owner and stable addresses precede every validation/returning RAW. */
    unsigned char *bytes=(void *)&linked_epoch;
    for(size_t i=0;i<sizeof linked_epoch;i++)bytes[i]=0;
    linked_epoch.ref=*ref;
    linked_epoch.p.serial=serial;linked_epoch.p.publication=publication;
    linked_epoch.p.borrow=ref->sequence;linked_epoch.p.source=p->page;linked_epoch.p.generated=p->generated;
    linked_epoch.p.allocation_epoch=allocation_id;linked_epoch.p.generation_epoch=generation;
    linked_epoch.p.transactions_epoch=counts.transactions;linked_epoch.p.records_epoch=used;
    linked_epoch.p.phase=LI2_LINK_HELD;
    out->owner=&linked_epoch;out->serial=serial;
    /* A failed validation still leaves the actual HELD owner and this token
       installed for nonreturning cleanup; it never publishes RELEASED. */
    int e=li2_lifecycle_link_validate(ref,s,p);
    return e?link_bad((unsigned)e,400):0;
}
int li2_lifecycle_link_opened(const struct li2_link_epoch_token *token,const struct li2_span_source *s,
                              const struct li2_link_plan *p) {
    if(!link_epoch_identity(token,p) || linked_epoch.p.phase!=LI2_LINK_HELD)return link_bad(LI2_FETCH_STALE,401);
    const struct li2_link_epoch *e=&linked_epoch;
    int result=li2_lifecycle_private_code_query(p->generated,PAGE,PROT_READ|PROT_EXEC,&linked_epoch.p.opened);
    if(result || !linked_epoch.p.opened.complete || linked_epoch.p.opened.pages_checked!=1 ||
       linked_epoch.p.opened.actual_prot!=(PROT_READ|PROT_EXEC))return link_bad(LI2_FETCH_PAGE,401);
    result=li2_lifecycle_link_validate(&e->ref,s,p);
    if(result)return link_bad((unsigned)result,402);
    linked_epoch.p.phase=LI2_LINK_RX;return 0;
}
int li2_lifecycle_link_release(const struct li2_link_epoch_token *token,const struct li2_span_source *s,
                               const struct li2_link_plan *p) {
    if(!link_epoch_identity(token,p) || linked_epoch.p.phase!=LI2_LINK_RX)return link_bad(LI2_FETCH_STALE,403);
    const struct li2_link_epoch *e=&linked_epoch;
    int result=li2_lifecycle_private_code_query(p->generated,PAGE,PROT_READ,&linked_epoch.p.closed);
    if(result || !linked_epoch.p.closed.complete || linked_epoch.p.closed.pages_checked!=1 ||
       linked_epoch.p.closed.actual_prot!=PROT_READ)return link_bad(LI2_FETCH_PAGE,403);
    linked_epoch.p.phase=LI2_LINK_CLOSED;
    result=li2_lifecycle_link_validate(&e->ref,s,p);
    if(result)return link_bad((unsigned)result,404);
    linked_epoch.p.release_started=1;result=li2_lifecycle_fetch_release(&e->ref);
    if(result)return link_bad((unsigned)result,405);
    linked_epoch.p.release_complete=1;linked_epoch.p.phase=LI2_LINK_RELEASED;return 0;
}
#ifdef LI2_LINKED_PREEDGE
#include "linked_preedge_source.inc"
#endif
