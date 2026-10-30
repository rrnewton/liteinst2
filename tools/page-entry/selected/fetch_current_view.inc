/* Included after the unchanged fetch/RX/custody implementation. */
#include "fetch_current_view.h"
static struct li2_fetch_rx_current_view rx_current;
static unsigned rx_current_busy;
#define RXC_LOAD() __atomic_load_n(&rx_current_busy,__ATOMIC_ACQUIRE)
#define RXC_STORE(v) __atomic_store_n(&rx_current_busy,(v),__ATOMIC_RELEASE)
static int rx_current_error(int error) {
    if(!rx_current.result)rx_current.result=error;
    if(rx_current.ticket.owner)(void)li2_maps_current_release(&rx_current.ticket);
    RXC_STORE(0);return rx_current.result;
}
int li2_lifecycle_fetch_rx_current_stage(const struct li2_fetch_ref *ref,uintptr_t pc,
                                        const struct li2_fetch_rx_current_view **out) {
    if(!out)return LI2_FETCH_ARGUMENT;
    *out=0;int e=fetch_ref(ref);if(e)return e;
    if(CUSTODY_LOAD(&custody_stats.phase)!=LI2_CUSTODY_EMPTY ||
       RXC_LOAD() || (rx_current.complete && !rx_current.result &&
                          rx_current.stage.phase!=LI2_RX_CANCELLED &&
                          rx_current.stage.phase!=LI2_RX_COMMITTED) ||
       fetch.page_count!=1 || rx_view.phase==LI2_RX_STAGING || rx_view.phase==LI2_RX_STAGED ||
       rx_view.phase==LI2_RX_COMMITTING || rx_serial==UINT64_MAX ||
       fetch_sequence==UINT64_MAX)return LI2_FETCH_STATE;
    uintptr_t page=fetch.original[0].address;
    if(pc<page || pc-page>=PAGE)return LI2_FETCH_ARGUMENT;
    const struct owned_page *p=current(page);
    if(!fetch_owned_equal(p,&fetch.original[0]))return fetch_error(LI2_FETCH_STALE,0);
    if(p->backing!=SEALED)return LI2_MAPS_CURRENT_UNAVAILABLE;
    RXC_STORE(1);rx_current=(struct li2_fetch_rx_current_view){.version=1,.borrow=*ref};
    /* Exact old phase/identity/source/backing validator. It can use the
       maintained table but has no fabricated physical acquisition receipt. */
    li2_maps_phase_end();
    if((e=li2_maps_phase_begin()))return rx_current_error(fetch_error((unsigned)e,0));
    if((e=li2_lifecycle_fetch_validate(ref,0,PROT_READ|PROT_EXEC)))return rx_current_error(e);
    /* In particular, the preceding actual fstat rearms the stack frontier.
       The checked query resolves it, and every differential hit still reads
       and compares the complete canonical table before issuing this ticket. */
    e=li2_maps_current_acquire(&rx_current.ticket,&rx_current.query);
    if(e)return rx_current_error(e==LI2_MAPS_CURRENT_UNAVAILABLE?e:
        fetch_error((unsigned)e,rx_current.query?rx_current.query->detail:0));
    p=current(page);const struct map_row *r=mapping(page);struct check_error error={0};
    if(!fetch_owned_equal(p,&fetch.original[0]) || !p || p->backing!=SEALED ||
       p->object>=object_count || !r || r->prot!=(PROT_READ|PROT_EXEC))
        return rx_current_error(fetch_error(LI2_FETCH_STALE,0));
    /* Reapply the original complete row and negative-alias predicates to the
       final ticket's table. Backing was actually checked above and no app,
       descriptor/mapping effect or permission change intervened. */
    if(verify_page_checked(p,r,&error) ||
       alias_check_checked(p->object,p->offset,PAGE,p->logical,p->address,p->address+PAGE,&error))
        return rx_current_error(fetch_check_error(&error));
    const volatile unsigned char *old=(const void *)fetch.pc;
    for(size_t i=0;i<fetch.requested;i++)if(old[i]!=fetch.bytes[i])
        return rx_current_error(fetch_error(LI2_FETCH_SOURCE,(long)i));
    size_t n=PAGE-(pc-page);if(n>15)n=15;
    struct li2_fetch_rx_view *s=&rx_current.stage;
    s->phase=LI2_RX_STAGED;s->serial=rx_current.ticket.serial;
    s->before_sequence=ref->sequence;s->pc=pc;s->length=n;
    s->pid=fetch.pid;s->tid=fetch.tid;s->page=fetch.pages[0];s->backing=fetch.last_backing;
    s->page.vma_first=r->first;s->page.vma_end=r->end;s->page.vma_major=r->major;
    s->page.vma_minor=r->minor;s->page.vma_inode=r->inode;s->page.vma_offset=r->offset;
    s->maps=rx_current.query->query;
    const volatile unsigned char *bytes=(const void *)pc;
    for(size_t i=0;i<n;i++)s->bytes[i]=bytes[i];
    if((e=fetch_ref(ref)) || (e=li2_maps_current_validate(&rx_current.ticket,rx_current.query)))
        return rx_current_error(e);
    s->complete=1;rx_current.complete=1;RXC_STORE(0);*out=&rx_current;return 0;
}
int li2_lifecycle_fetch_rx_current_cancel(const struct li2_fetch_rx_current_view *v) {
    if(v!=&rx_current || RXC_LOAD() || !v->complete || v->result)return LI2_FETCH_STALE;
    int e=li2_maps_current_release(&v->ticket);
    if(e && !rx_current.result)rx_current.result=e;
    rx_current.stage.phase=LI2_RX_CANCELLED;return e;
}

#undef RXC_LOAD
#undef RXC_STORE
