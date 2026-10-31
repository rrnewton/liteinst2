/* Included after span_source and linked_source in the actual lifecycle TU.
   This protected bridge-BSS object is advisory only. No hint grants X, skips
   the native policy scan, or substitutes for the next hardware NX frame. */
#include "linked_native_hint.h"
static struct li2_link_native_hint_progress lnh;
const struct li2_link_native_hint_progress *li2_lifecycle_link_native_hint_progress(void) { return &lnh; }
static void lnh_identity(struct li2_link_native_hint_identity *out,const struct owned_page *p) {
    *out=(struct li2_link_native_hint_identity){.address=p->address,.allocation=p->allocation,
        .generation=p->generation,.offset=p->offset,.initial_extent=p->initial_extent,
        .backing=p->backing,.object=p->object,.logical=p->logical};
}
static int lnh_same(const struct li2_link_native_hint_identity *a,const struct owned_page *p) {
    return p && p->live==1 && a->address==p->address && a->allocation==p->allocation &&
        a->generation==p->generation && a->offset==p->offset && a->initial_extent==p->initial_extent &&
        a->backing==p->backing && a->object==p->object && a->logical==p->logical;
}
/* Called only at the successful end of the original full publication path:
   actual policy == 0, original source/backing/halo proof, original mprotect,
   sync, and complete post-publication maps/source verification all preceded
   this call. Original rseq publication/whole-frame gates still follow. */
static void link_native_hint_published(unsigned index) {
    if(index>=LI2_NATIVE_PAIR_SLOTS || index>=np_life.live)DIE(LI2_NP_STATE,80);
    const struct li2_native_pair_slot *s=&np_life.slots[index];
    if(!np_life.post_verified ||
       np_life.first_error || !np_life.busy || !np_life.opening ||
       s->prepared!=1 || s->published!=1 || s->policy || s->page.address<NATIVE_LOW_LIMIT ||
       s->page.address>UINTPTR_MAX-2*PAGE || s->window_initialized!=s->window_bytes ||
       s->window_bytes!=PAGE+s->window_before+s->window_after || s->window_bytes>sizeof s->window ||
       (s->window_before!=0 && s->window_before!=14) ||
       (s->window_after!=0 && s->window_after!=14) || !np_life_epoch())DIE(LI2_NP_STATE,80);
    if(lnh.ready)native_increment(&lnh.evictions);
    lnh.ready=0;__asm__ volatile("":::"memory");
    lnh.receipt=*s;lnh.receipt_sequence=np_life.sequence;lnh.receipt_publication=np_life.published;
    lnh.allocation_epoch=allocation_id;lnh.generation_epoch=generation;lnh.records_epoch=used;
    for(unsigned i=0;i<3;i++) {
        uintptr_t address=i==0?s->page.address:(i==1?s->page.address-PAGE:s->page.address+PAGE);
        const struct owned_page *p=current(address);
        unsigned present=i==0?1:(i==1?s->window_before==14:s->window_after==14);
        lnh.identity[i]=(struct li2_link_native_hint_identity){0};
        if(i)lnh.neighbors[i-1]=present;
        if(present) {
            if(!p || !p->live || p->backing!=SEALED || p->object>=object_count ||
               p->logical!=(PROT_READ|PROT_EXEC))DIE(LI2_NP_STALE,80);
            lnh_identity(&lnh.identity[i],p);
        } else if(p && (p->logical&PROT_EXEC))DIE(LI2_NP_STALE,81);
    }
    native_increment(&lnh.publications);
    __asm__ volatile("":::"memory");lnh.ready=1;
}
static int lnh_current(const struct li2_span_source *s) {
    if(!s || __atomic_load_n(&s->ready,__ATOMIC_ACQUIRE)!=1 ||
       s->borrow.owner!=&fetch || !s->borrow.sequence || s->borrow.sequence!=fetch.progress.sequence ||
       fetch.progress.held || !fetch.progress.complete || fetch.progress.first_error ||
       fetch.progress.first_detail || !fetch.progress.identity_observed ||
       !active || tx.guard || allocation_id!=fetch.allocation_epoch || generation!=fetch.generation_epoch ||
       used!=fetch.records_epoch || counts.transactions!=fetch.transactions_epoch || tx.phase!=fetch.phase_epoch ||
       fetch.pid<=0 || fetch.pid!=fetch.tid || !span_source_geometry() ||
       s->key.entry!=fetch.pc || !span_source_page_equal(&s->key.page,&fetch.pages[0]) ||
       !span_source_backing_equal(&s->key.backing,&fetch.last_backing) ||
       li2_lifecycle_run_reuse_quiet(0) || li2_lifecycle_link_interlock() || !li2_native_pair_quiet())return 0;
    const struct owned_page *p=current(s->key.page.address);
    if(!fetch_owned_equal(p,&fetch.original[0]) || p->actual!=PROT_READ || p->admitted)return 0;
    size_t at=s->key.entry-s->key.page.address;
    return equal(s->key.bytes+at,fetch.bytes,15);
}
static int lnh_matches(const struct li2_span_source *s) {
    const struct li2_native_pair_slot *r=&lnh.receipt;
    if(lnh.allocation_epoch!=allocation_id || lnh.generation_epoch!=generation || lnh.records_epoch!=used ||
       !lnh.receipt_sequence || !lnh.receipt_publication || lnh.receipt_publication>np_life.published ||
       r->prepared!=1 || r->published!=1 || r->policy || r->page.address!=s->key.page.address ||
       r->window_initialized!=r->window_bytes || r->window_bytes>sizeof r->window ||
       r->window_bytes!=PAGE+r->window_before+r->window_after ||
       r->window_before!=14*lnh.neighbors[0] || r->window_after!=14*lnh.neighbors[1] ||
       lnh.neighbors[0]>1 || lnh.neighbors[1]>1 ||
       !span_source_backing_equal(&r->backing,&s->key.backing) ||
       !equal(r->window+r->window_before,s->key.bytes,PAGE))return 0;
    for(unsigned i=0;i<3;i++) {
        uintptr_t address=i==0?r->page.address:(i==1?r->page.address-PAGE:r->page.address+PAGE);
        const struct owned_page *p=current(address);
        if(!i || lnh.neighbors[i-1]) {
            if(!lnh_same(&lnh.identity[i],p) || p->backing!=SEALED ||
               p->logical!=(PROT_READ|PROT_EXEC) || p->actual!=PROT_READ || p->admitted)return 0;
        } else if(p && (p->logical&PROT_EXEC))return 0;
    }
    return 1;
}
int li2_lifecycle_link_native_hint_choose(const struct li2_span_source *s,uint64_t serial,uint64_t *publication) {
    if(!publication || *publication || !serial || lnh.pending)DIE(LI2_NP_STATE,81);
    native_increment(&lnh.lookups);
    if(!lnh_current(s))return 0;
    if(!lnh.ready)return 0;
    /* Another page is a normal cache miss, not evidence that this receipt is
       invalid. Global lifetime changes or same-page identity drift evict it. */
    if(lnh.allocation_epoch!=allocation_id || lnh.generation_epoch!=generation || lnh.records_epoch!=used ||
       (lnh.receipt.page.address==s->key.page.address && !lnh_matches(s))) {
        lnh.ready=0;native_increment(&lnh.invalidations);return 0;
    }
    if(lnh.receipt.page.address!=s->key.page.address)return 0;
    const struct li2_native_pair_progress *p=li2_native_pair_progress();
    if(!p || p->events==UINT64_MAX || p->seeds==UINT64_MAX || np_life.published==UINT64_MAX)
        DIE(LI2_NP_OVERFLOW,80);
    lnh.ready=0;native_increment(&lnh.hits);
    lnh.selected_publication=lnh.receipt_publication;lnh.selected_serial=serial;lnh.selected_pc=s->key.entry;
    lnh.selected_event=p->events;lnh.selected_seeds=p->seeds;lnh.selected_published=np_life.published;
    lnh.outcome_complete=0;lnh.outcome_result=0;*publication=lnh.selected_publication;
    __asm__ volatile("":::"memory");lnh.pending=1;return 1;
}
#if (defined(LI2_LINKED_EPOCH_CAPTURE) && !defined(LI2_LINKED_EPOCH_REUSE_CAPTURE)) || defined(LI2_LINKED_PREEDGE_FULL_CAPTURE)
/* Deliberate qualification-only corruption of the actual advisory receipt.
   A nonmatching candidate is untouched. Once the complete unmodified pure
   predicates hold, the caller must terminate after the real lookup; it may
   never restore the receipt or return this negative stimulus to the guest. */
int li2_lifecycle_link_native_hint_probe(const struct li2_span_source *s,uint64_t serial,
    unsigned control,unsigned *attempted,size_t *at,uint64_t *publication,
    struct li2_link_native_hint_progress *before,
    struct li2_link_native_hint_progress *changed,
    struct li2_link_native_hint_progress *after) {
    if(control<1 || control>3 || !attempted || *attempted || !at || *at ||
       !publication || *publication || !before || !changed || !after || !serial)
        DIE(LI2_NP_STATE,82);
    if(!lnh.ready || lnh.pending || !lnh_current(s) || !lnh_matches(s))return 0;
    if(control==3 && !lnh.neighbors[0] && !lnh.neighbors[1])return 0;
    *before=lnh;*attempted=1;
    if(control==1) {
        /* Outside the complete actual first15, inside the retained page. */
        *at=(s->key.entry-s->key.page.address+15)%PAGE;
        lnh.receipt.window[lnh.receipt.window_before+*at]^=1;
    } else {
        *at=control==2?0U:(lnh.neighbors[0]?1U:2U);
        lnh.identity[*at].generation^=1;
    }
    *changed=lnh;
    int result=li2_lifecycle_link_native_hint_choose(s,serial,publication);
    *after=lnh;return result;
}
#endif
int li2_lifecycle_link_native_hint_outcome(int result) {
    if(!lnh.pending)return 0;
    const struct li2_native_pair_progress *p=li2_native_pair_progress();
    lnh.outcome_result=result;
    if(!p || p->events!=lnh.selected_event+1 || p->pc!=lnh.selected_pc ||
       p->signal_number!=SIGSEGV || p->signal_code!=SEGV_ACCERR || p->signal_errno ||
       p->signal_address!=p->pc || !p->first_observed)return LI2_NP_STATE;
    native_increment(&lnh.next_nx);
    if(result==LI2_NP_RESUME) {
        if(p->first_error || p->phase!=LI2_NP_EXECUTING_ONE || p->live!=1 || p->in_handler || p->entry_pending ||
           p->seeds!=lnh.selected_seeds+1 || np_life.published!=lnh.selected_published+1 ||
           np_life.first_error || !np_life.post_verified || np_life.busy || np_life.opening || np_life.live!=1 ||
           np_life.slots[0].pc!=p->pc || np_life.slots[0].published!=1 || np_life.slots[0].policy)return LI2_NP_STATE;
        native_increment(&lnh.admitted);
    } else if(result==LI2_NP_FALLBACK) {
        if(!li2_native_pair_quiet() || p->seeds!=lnh.selected_seeds ||
           np_life.published!=lnh.selected_published)return LI2_NP_STATE;
        native_increment(&lnh.refused);
    } else {
        /* Fatal actual API result is retained, never counted as native entry. */
        if(result<=LI2_NP_REFAULT || !p->first_error || result!=(int)p->first_error)return LI2_NP_STATE;
        native_increment(&lnh.errors);
    }
    lnh.outcome_complete=1;lnh.pending=0;return 0;
}
