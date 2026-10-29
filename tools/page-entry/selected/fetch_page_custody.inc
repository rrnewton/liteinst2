/* Opt-in only, after the unchanged RX stage/commit implementations. The cold
   transfer still runs both original validators. A later transfer can retain
   only one managed SEALED page's VMA/negative-alias proof, never rows[]. */
#include "page_custody.h"
static struct li2_page_custody_stats custody_stats;
static struct {
    struct li2_custody_owner owner;
    const struct li2_step_session *session_pointer;
    struct li2_step_session session;
    struct li2_step_hooks hooks;
    struct li2_step_request opening,previous;
    struct owned_page original;
    struct li2_fetch_page page;
    struct li2_fetch_map_progress origin;
    uint64_t ticket,sequence,serial,origin_sequence;
    uint64_t major,minor,inode;
    struct stat object_stat;
    int retained_fd;
} custody;
#define CUSTODY_LOAD(p) __atomic_load_n((p),__ATOMIC_ACQUIRE)
#define CUSTODY_STORE(p,v) __atomic_store_n((p),(v),__ATOMIC_RELEASE)
_Static_assert(__atomic_always_lock_free(4,0),"signal-safe custody phase");
_Static_assert(__atomic_always_lock_free(8,0),"signal-safe custody epoch");
static int custody_equal(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;
    for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;
    return 1;
}
static int custody_increment(uint64_t *p) {
    uint64_t old=CUSTODY_LOAD(p);
    do {
        if(old==UINT64_MAX) {
            CUSTODY_STORE(&custody_stats.phase,LI2_CUSTODY_POISONED);
            return LI2_FETCH_STATE;
        }
    } while(!__atomic_compare_exchange_n(p,&old,old+1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE));
    return 0;
}
void li2_page_custody_discard(unsigned reason) {
    unsigned phase=CUSTODY_LOAD(&custody_stats.phase);
    do {
        if(phase==LI2_CUSTODY_POISONED)return;
    } while(!__atomic_compare_exchange_n(&custody_stats.phase,&phase,LI2_CUSTODY_EMPTY,
                                        0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE));
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    custody_stats.last_reason=reason;
    if(custody_increment(&custody_stats.epoch) ||
       custody_increment(&custody_stats.discards))return;
}
void li2_page_custody_boundary(void) {
    unsigned expected=LI2_CUSTODY_READY;
    /* Consume before ordinary routing. An unexpected/nested event cannot
       leave externally reusable authority while its frame is being checked. */
    if(__atomic_compare_exchange_n(&custody_stats.phase,&expected,
           LI2_CUSTODY_ENTRY,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return;
    li2_page_custody_discard(LI2_CUSTODY_EVENT);
}
const struct li2_page_custody_stats *li2_page_custody_snapshot(void) { return &custody_stats; }
static int custody_error(int error) {
    li2_page_custody_discard(LI2_CUSTODY_ERROR);
    return rx_error(fetch_error((unsigned)error,0));
}
static int custody_phase(unsigned before,unsigned after) {
    unsigned expected=before;
    if(CUSTODY_LOAD(&custody_stats.epoch)!=custody.ticket ||
       !__atomic_compare_exchange_n(&custody_stats.phase,&expected,after,0,
                                    __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return LI2_FETCH_STALE;
    return 0;
}
static int custody_owner_live(const struct li2_custody_owner *k,
                              const struct li2_fetch_ref *ref,unsigned in_handler) {
    int e=fetch_ref(ref);if(e)return e;
    if(!k || !k->chain || !k->owner || k->slot>=2 || !k->generation || !k->event ||
       fetch.page_count!=1)return LI2_FETCH_STATE;
    const struct li2_step_owner *p=k->owner;
    const struct owned_page *q=&fetch.original[0];
    if(p->phase!=LI2_STEP_RUNNING || p->first_error || p->self_test ||
       p->in_handler!=in_handler || p->trace_seen || p->revoke_sync_started ||
       !p->session || !p->session->initialized || !p->session->self_test_complete ||
       p->session->pid!=fetch.pid || p->session->tid!=fetch.tid ||
       !p->hooks.context || !p->hooks.authenticate || !p->hooks.failure ||
       p->request.page_count!=1 || p->request.pages[0].address!=q->address ||
       p->request.pages[0].object!=q->allocation || p->request.pages[0].generation!=q->generation ||
       p->request.pages[0].offset!=q->offset || p->request.pages[0].closed_prot!=PROT_READ ||
       p->request.pages[0].open_prot!=(PROT_READ|PROT_EXEC) ||
       p->request.decoded.pc!=fetch.pc || !p->request.decoded.length ||
       p->request.decoded.length>fetch.requested ||
       !custody_equal(p->request.decoded.bytes,fetch.bytes,p->request.decoded.length) ||
       p->open_started[0]!=1 || p->opened[0]!=1 || p->open_result[0] || p->open_sync ||
       p->open_started[1] || p->opened[1] || p->revoke_started[0] || p->revoke_started[1] ||
       p->revoked[0] || p->revoked[1])return LI2_FETCH_STALE;
    return 0;
}
static int custody_owner_same(const struct li2_custody_owner *k) {
    const struct li2_step_owner *p=k->owner;
    return k->chain==custody.owner.chain && p==custody.owner.owner &&
        k->slot==custody.owner.slot && k->generation==custody.owner.generation &&
        p->session==custody.session_pointer &&
        custody_equal(p->session,&custody.session,sizeof custody.session) &&
        p->hooks.context==custody.hooks.context && p->hooks.authenticate==custody.hooks.authenticate &&
        p->hooks.failure==custody.hooks.failure;
}
static void custody_receipt(unsigned kind) {
    rx_view.custody=(struct li2_page_custody_receipt){.kind=kind,
        .provenance=LI2_CUSTODY_MANAGED_SEALED,.epoch=custody.ticket,
        .origin_sequence=custody.origin_sequence,.chain=(uintptr_t)custody.owner.chain,
        .owner=(uintptr_t)custody.owner.owner,.session=(uintptr_t)custody.owner.owner->session,
        .slot=custody.owner.slot,.owner_generation=custody.owner.generation,
        .event=custody.owner.event,.origin=custody.origin};
}
static int custody_seed(const struct li2_custody_owner *k,const struct li2_fetch_ref *ref) {
    const struct owned_page *p=current(fetch.original[0].address);
    /* SEALED has only the audited initial-image and private lifecycle-map
       constructors. Those reject shared/growing mappings; seals alone are
       not this provenance proof. Anonymous pages keep the original path. */
    if(!p)return LI2_FETCH_STALE;
    if(p->backing!=SEALED)return 0;
    const struct map_row *r=mapping(p->address);
    const struct li2_fetch_map_progress *m=&rx_view.maps;
    if(!fetch_owned_equal(p,&fetch.original[0]) || p->object>=object_count ||
       p->admitted || !p->live || p->actual!=PROT_READ || p->logical!=(PROT_READ|PROT_EXEC) ||
       !r || !r->private || r->prot!=(PROT_READ|PROT_EXEC) ||
       !m->opened || !m->closed || !m->close_started || m->close_result || m->last_read ||
       !m->rows || !m->bytes || m->observation.kind!=LI2_MAPS_FRESH ||
       m->observation.io_performed!=1 || !m->observation.acquisition_id ||
       !CUSTODY_LOAD(&maps_stats.valid) || !CUSTODY_LOAD(&maps_stats.active) || CUSTODY_LOAD(&maps_stats.poisoned) ||
       m->observation.handler_id!=CUSTODY_LOAD(&maps_stats.handler_id) ||
       m->observation.mutation_epoch!=CUSTODY_LOAD(&maps_stats.mutation_epoch))return LI2_FETCH_STALE;
    unsigned expected=LI2_CUSTODY_EMPTY;
    if(!__atomic_compare_exchange_n(&custody_stats.phase,&expected,LI2_CUSTODY_BUILDING,
           0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return LI2_FETCH_STATE;
    custody.ticket=CUSTODY_LOAD(&custody_stats.epoch);
    custody.owner=*k;custody.session_pointer=k->owner->session;
    custody.session=*k->owner->session;custody.hooks=k->owner->hooks;
    custody.opening=k->owner->request;custody.previous=k->owner->request;
    custody.original=*p;custody.page=rx_view.page;custody.origin=*m;
    custody.sequence=ref->sequence;custody.origin_sequence=ref->sequence;custody.serial=rx_view.serial;
    const struct object *o=&objects[p->object];
    custody.major=o->major;custody.minor=o->minor;custody.inode=o->inode;custody.retained_fd=o->retained_fd;
    custody.object_stat=o->stat;
    custody_receipt(LI2_CUSTODY_FRESH);
    return custody_phase(LI2_CUSTODY_BUILDING,LI2_CUSTODY_STAGED);
}
static int custody_validate(const struct li2_fetch_ref *ref) {
    int e=fetch_ref(ref);if(e)return e;
    if(ref->sequence!=custody.sequence || fetch.page_count!=1 ||
       !fetch_owned_equal(&fetch.original[0],&custody.original))return LI2_FETCH_STALE;
    if((e=fetch_identity()))return e;
    const struct owned_page *p=current(custody.original.address);
    if(!fetch_owned_equal(p,&custody.original) || p->object>=object_count)return LI2_FETCH_STALE;
    const struct object *o=&objects[p->object];
    if(o->major!=custody.major || o->minor!=custody.minor || o->inode!=custody.inode ||
       o->retained_fd!=custody.retained_fd || o->stat.st_dev!=custody.object_stat.st_dev ||
       o->stat.st_ino!=custody.object_stat.st_ino || o->stat.st_size!=custody.object_stat.st_size ||
       o->stat.st_mode!=custody.object_stat.st_mode)return LI2_FETCH_BACKING;
    /* No maps receipt is created. Every retained use still observes the real
       descriptor seals/stat/extent and rereads every currently borrowed byte. */
    fetch.progress.validation=(struct li2_fetch_map_progress){0};
    fetch.progress.last_backing_page=0;fetch.progress.last_backing_observed=1;
    if((e=fetch_backing_check(p,&fetch.last_backing)))return e;
    const volatile unsigned char *source=(const void *)fetch.pc;
    for(size_t i=0;i<fetch.requested;i++)if(source[i]!=fetch.bytes[i])
        return fetch_error(LI2_FETCH_SOURCE,(long)i);
    if(CUSTODY_LOAD(&custody_stats.epoch)!=custody.ticket)return LI2_FETCH_STALE;
    if((e=custody_increment(&custody_stats.retained_checks)))return e;
    ++rx_view.custody.checks;return 0;
}
int li2_lifecycle_fetch_rx_stage_custody(const struct li2_fetch_ref *ref,uintptr_t pc,
        const struct li2_custody_owner *k,const struct li2_fetch_rx_view **out) {
    if(!out){li2_page_custody_discard(LI2_CUSTODY_ERROR);return LI2_FETCH_ARGUMENT;}
    *out=0;int e=custody_owner_live(k,ref,1);if(e)return custody_error(e);
    unsigned phase=CUSTODY_LOAD(&custody_stats.phase);
    if(phase==LI2_CUSTODY_EMPTY) {
        e=li2_lifecycle_fetch_rx_stage(ref,pc,out);if(e)return custody_error(e);
        rx_view.maps_observed=1;
        e=custody_seed(k,ref);if(e)return custody_error(e);
        return 0;
    }
    if(phase!=LI2_CUSTODY_ENTRY || !custody_owner_same(k) || custody.owner.event==UINT64_MAX ||
       k->event!=custody.owner.event+1 || ref->sequence!=custody.sequence ||
       rx_view.phase!=LI2_RX_COMMITTED || rx_view.after_sequence!=ref->sequence ||
       rx_view.serial!=custody.serial ||
       !custody_equal(&k->owner->request,&custody.previous,sizeof custody.previous) ||
       rx_serial==UINT64_MAX || fetch_sequence==UINT64_MAX)return custody_error(LI2_FETCH_STALE);
    uintptr_t page=custody.original.address;
    if(pc<page || pc-page>=PAGE)return custody_error(LI2_FETCH_ARGUMENT);
    if((e=custody_phase(LI2_CUSTODY_ENTRY,LI2_CUSTODY_BUILDING)))return custody_error(e);
    size_t bytes=PAGE-(pc-page);if(bytes>15)bytes=15;
    rx_view=(struct li2_fetch_rx_view){.phase=LI2_RX_STAGING,.serial=++rx_serial,
        .before_sequence=ref->sequence,.pc=pc,.length=bytes};
    custody.owner.event=k->event;custody.serial=rx_view.serial;custody_receipt(LI2_CUSTODY_RETAINED);
    /* Preserve the same global phase boundaries. They do not publish rows. */
    li2_maps_phase_end();
    if((e=li2_maps_phase_begin()) || (e=custody_validate(ref)))return custody_error(e);
    rx_candidate=fetch;rx_candidate.pc=pc;rx_candidate.requested=bytes;
    rx_candidate.progress=(struct li2_fetch_progress){.identity_observed=1,.pages_copied=1};
    rx_candidate.pages[0]=custody.page;rx_candidate.backing[0]=fetch.last_backing;
    for(size_t i=0;i<sizeof rx_candidate.bytes;i++)rx_candidate.bytes[i]=0;
    const volatile unsigned char *source=(const void *)pc;
    for(size_t i=0;i<bytes;i++) {
        unsigned char byte=source[i];rx_candidate.bytes[i]=byte;rx_view.bytes[i]=byte;
        rx_candidate.progress.bytes_copied=i+1;
    }
    rx_candidate.progress.complete=1;rx_view.pid=fetch.pid;rx_view.tid=fetch.tid;
    rx_view.page=rx_candidate.pages[0];rx_view.backing=rx_candidate.backing[0];
    if((e=custody_increment(&custody_stats.retained_stages)) ||
       (e=custody_phase(LI2_CUSTODY_BUILDING,LI2_CUSTODY_STAGED)))return custody_error(e);
    rx_view.complete=1;__asm__ volatile("":::"memory");rx_view.phase=LI2_RX_STAGED;
    *out=&rx_view;return 0;
}
int li2_lifecycle_fetch_rx_commit_custody(const struct li2_fetch_ref *ref,
        const struct li2_fetch_rx_view *v,const struct li2_custody_owner *k,struct li2_fetch_ref *out) {
    if(!out){li2_page_custody_discard(LI2_CUSTODY_ERROR);return LI2_FETCH_ARGUMENT;}
    int e=custody_owner_live(k,ref,1);if(e)return custody_error(e);
    if(v==&rx_view && !v->custody.kind)return li2_lifecycle_fetch_rx_commit(ref,v,out);
    if((e=rx_binding(ref,v)))return custody_error(e);
    if(!custody_owner_same(k) || k->event!=custody.owner.event || custody.serial!=v->serial ||
       CUSTODY_LOAD(&custody_stats.phase)!=LI2_CUSTODY_STAGED ||
       !custody_equal(&k->owner->request,&custody.previous,sizeof custody.previous))return custody_error(LI2_FETCH_STALE);
    if(v->custody.kind==LI2_CUSTODY_FRESH) {
        e=li2_lifecycle_fetch_rx_commit(ref,v,out);if(e)return custody_error(e);
    } else if(v->custody.kind==LI2_CUSTODY_RETAINED) {
        if(fetch_sequence==UINT64_MAX)return custody_error(LI2_FETCH_STATE);
        if((e=custody_validate(ref)))return custody_error(e);
        const volatile unsigned char *source=(const void *)rx_candidate.pc;
        for(size_t i=0;i<rx_candidate.requested;i++)
            if(source[i]!=rx_candidate.bytes[i] || source[i]!=rx_view.bytes[i])
                return custody_error(fetch_error(LI2_FETCH_SOURCE,(long)i));
        rx_view.phase=LI2_RX_COMMITTING;__asm__ volatile("":::"memory");
        rx_candidate.progress.held=1;rx_candidate.progress.sequence=++fetch_sequence;
        fetch=rx_candidate;*out=(struct li2_fetch_ref){&fetch,fetch.progress.sequence};
        rx_view.after_sequence=fetch.progress.sequence;
        __asm__ volatile("":::"memory");rx_view.phase=LI2_RX_COMMITTED;
    } else return custody_error(LI2_FETCH_STATE);
    custody.sequence=out->sequence;
    if((e=custody_phase(LI2_CUSTODY_STAGED,LI2_CUSTODY_COMMITTED)))return custody_error(e);
    return 0;
}
int li2_lifecycle_fetch_rx_publish_custody(const struct li2_fetch_ref *ref,
        const struct li2_fetch_rx_view *v,const struct li2_custody_owner *k) {
    if(v==&rx_view && !v->custody.kind) {
        int e=fetch_ref(ref);
        if(e || v->phase!=LI2_RX_COMMITTED || !v->complete || v->result ||
           v->after_sequence!=ref->sequence)return custody_error(e?e:LI2_FETCH_STALE);
        return 0;
    }
    int e=custody_owner_live(k,ref,0);if(e)return custody_error(e);
    if(v!=&rx_view || v->phase!=LI2_RX_COMMITTED || !custody_owner_same(k) ||
       k->event!=custody.owner.event || custody.serial!=v->serial ||
       ref->sequence!=custody.sequence || v->after_sequence!=ref->sequence ||
       k->owner->request.page_count!=custody.opening.page_count ||
       !custody_equal(k->owner->request.pages,custody.opening.pages,sizeof custody.opening.pages))
        return custody_error(LI2_FETCH_STALE);
    custody.previous=k->owner->request;
    if(v->custody.kind==LI2_CUSTODY_FRESH && (e=custody_increment(&custody_stats.seeds)))return custody_error(e);
    if((e=custody_increment(&custody_stats.commits)) ||
       (e=custody_phase(LI2_CUSTODY_COMMITTED,LI2_CUSTODY_RETURN)))return custody_error(e);
    return 0;
}
int li2_page_custody_return(const void *chain) {
    unsigned phase=CUSTODY_LOAD(&custody_stats.phase);
    if(phase==LI2_CUSTODY_EMPTY)return 0;
    if(phase!=LI2_CUSTODY_RETURN || chain!=custody.owner.chain)return custody_error(LI2_FETCH_STATE);
    struct li2_fetch_ref ref={&fetch,custody.sequence};
    int e=custody_owner_live(&custody.owner,&ref,0);
    if(e || !custody_owner_same(&custody.owner) ||
       !custody_equal(&custody.owner.owner->request,&custody.previous,sizeof custody.previous))
        return custody_error(e?e:LI2_FETCH_STALE);
    e=custody_phase(LI2_CUSTODY_RETURN,LI2_CUSTODY_READY);return e?custody_error(e):0;
}
