/* Included after the complete old fetch implementation. No permission call;
   source/mapping/backing checks remain actual observations at this handler. */
#include "tf_same_page.h"
static struct li2_fetch rx_candidate;
static struct li2_fetch_rx_view rx_view;
static uint64_t rx_serial;
const struct li2_fetch_rx_view *li2_lifecycle_fetch_rx_progress(void) { return &rx_view; }
static int rx_error(int result) { rx_view.result=result;return result; }
int li2_lifecycle_fetch_rx_stage(const struct li2_fetch_ref *ref,uintptr_t pc,
                                const struct li2_fetch_rx_view **out) {
    if(!out)return LI2_FETCH_ARGUMENT;
    *out=0;
    int e=fetch_ref(ref);if(e)return e;
    if(fetch.page_count!=1 || rx_view.phase==LI2_RX_STAGING ||
       rx_view.phase==LI2_RX_STAGED || rx_view.phase==LI2_RX_COMMITTING ||
       rx_serial==UINT64_MAX || fetch_sequence==UINT64_MAX)return LI2_FETCH_STATE;
    uintptr_t page=fetch.original[0].address;
    if(pc<page || pc-page>=PAGE)return LI2_FETCH_ARGUMENT;
    size_t bytes=PAGE-(pc-page);if(bytes>15)bytes=15;
    rx_view=(struct li2_fetch_rx_view){.phase=LI2_RX_STAGING,.serial=++rx_serial,
        .before_sequence=ref->sequence,.pc=pc,.length=bytes};
    /* Explicit fresh acquisition; no map image crosses application execution. */
    li2_maps_phase_end();
    if((e=li2_maps_phase_begin()))return rx_error(fetch_error((unsigned)e,0));
    if((e=li2_lifecycle_fetch_validate(ref,0,PROT_READ|PROT_EXEC)))return rx_error(e);
    const struct owned_page *p=current(page);const struct map_row *r=mapping(page);
    if(!fetch_owned_equal(p,&fetch.original[0]) || !r ||
       r->prot!=(PROT_READ|PROT_EXEC))return rx_error(fetch_error(LI2_FETCH_STALE,0));
    rx_candidate=fetch;
    rx_candidate.pc=pc;rx_candidate.requested=bytes;
    rx_candidate.progress=(struct li2_fetch_progress){.identity_observed=1,
        .pages_copied=1,.preparation=fetch.progress.validation};
    struct li2_fetch_page *q=&rx_candidate.pages[0];
    q->vma_first=r->first;q->vma_end=r->end;q->vma_major=r->major;
    q->vma_minor=r->minor;q->vma_inode=r->inode;q->vma_offset=r->offset;
    rx_candidate.backing[0]=fetch.last_backing;
    for(size_t i=0;i<sizeof rx_candidate.bytes;i++)rx_candidate.bytes[i]=0;
    const volatile unsigned char *source=(const void *)pc;
    for(size_t i=0;i<bytes;i++) {
        unsigned char byte=source[i];rx_candidate.bytes[i]=byte;rx_view.bytes[i]=byte;
        rx_candidate.progress.bytes_copied=i+1;
    }
    rx_candidate.progress.complete=1;
    rx_view.pid=fetch.pid;rx_view.tid=fetch.tid;rx_view.page=*q;
    rx_view.backing=rx_candidate.backing[0];rx_view.maps=fetch.progress.validation;
    rx_view.complete=1;__asm__ volatile("":::"memory");rx_view.phase=LI2_RX_STAGED;
    *out=&rx_view;return 0;
}
static int rx_binding(const struct li2_fetch_ref *ref,const struct li2_fetch_rx_view *v) {
    int e=fetch_ref(ref);if(e)return e;
    if(v!=&rx_view || rx_view.phase!=LI2_RX_STAGED || !rx_view.complete ||
       rx_view.result || rx_view.before_sequence!=ref->sequence ||
       rx_candidate.progress.held || !rx_candidate.progress.complete ||
       rx_candidate.page_count!=1 || rx_candidate.pc!=rx_view.pc ||
       rx_candidate.requested!=rx_view.length ||
       !fetch_owned_equal(&rx_candidate.original[0],&fetch.original[0]))return LI2_FETCH_STALE;
    return 0;
}
int li2_lifecycle_fetch_rx_cancel(const struct li2_fetch_ref *ref,const struct li2_fetch_rx_view *v) {
    int e=rx_binding(ref,v);if(e)return rx_error(e);
    rx_view.phase=LI2_RX_CANCELLED;return 0;
}
int li2_lifecycle_fetch_rx_commit(const struct li2_fetch_ref *ref,
                                 const struct li2_fetch_rx_view *v,struct li2_fetch_ref *out) {
    if(!out)return LI2_FETCH_ARGUMENT;
    int e=rx_binding(ref,v);if(e)return rx_error(e);
    if(fetch_sequence==UINT64_MAX)return rx_error(LI2_FETCH_STATE);
    if((e=li2_lifecycle_fetch_validate(ref,0,PROT_READ|PROT_EXEC)))return rx_error(e);
    const volatile unsigned char *source=(const void *)rx_candidate.pc;
    for(size_t i=0;i<rx_candidate.requested;i++)
        if(source[i]!=rx_candidate.bytes[i] || source[i]!=rx_view.bytes[i])
            return rx_error(fetch_error(LI2_FETCH_SOURCE,(long)i));
    rx_view.phase=LI2_RX_COMMITTING;__asm__ volatile("":::"memory");
    rx_candidate.progress.held=1;rx_candidate.progress.sequence=++fetch_sequence;
    /* held never becomes zero. Until out is installed, nested cleanup may
       find a stale ref, but the unchanged permission owner still revokes its
       real page before that failed validation. No such prefix can resume. */
    fetch=rx_candidate;
    *out=(struct li2_fetch_ref){&fetch,fetch.progress.sequence};
    rx_view.after_sequence=fetch.progress.sequence;
    __asm__ volatile("":::"memory");rx_view.phase=LI2_RX_COMMITTED;return 0;
}
