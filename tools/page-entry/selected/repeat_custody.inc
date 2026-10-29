/* Included by lifecycle_loader.c after fetch_loader.inc. One fixed real REP
   owner, one unchanged fetch, and a consumed event ticket. Retained authority
   never publishes maps rows and cannot transfer to a successor instruction. */
#include "repeat_lease.h"
#include "register_run_publish.h"
static struct li2_repeat_custody_observation rep_custody_stats;
static struct {
    struct li2_repeat_lease_owner *owner;
    struct li2_step_session *session_pointer;
    struct li2_step_session session;
    struct li2_run_protection protection;
    struct li2_tf_hooks hooks;
    struct li2_step_request request;
    struct li2_fetch_ref ref;
    struct owned_page original;
    struct li2_fetch_page page;
    struct stat object_stat;
    uint64_t major,minor,inode,ticket;
    int retained_fd;
    uintptr_t pc;
    size_t length;
    unsigned char bytes[15];
} rep_custody;
#define REP_LOAD(p) __atomic_load_n((p),__ATOMIC_ACQUIRE)
#define REP_STORE(p,v) __atomic_store_n((p),(v),__ATOMIC_RELEASE)
_Static_assert(__atomic_always_lock_free(4,0),"REP signal-safe phases");
_Static_assert(__atomic_always_lock_free(8,0),"REP signal-safe epochs");
static int rep_equal(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;
    for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;
    return 1;
}
static int rep_zero(const void *a,size_t n) {
    const unsigned char *p=a;
    for(size_t i=0;i<n;i++)if(p[i])return 0;
    return 1;
}
static int rep_bad(unsigned code,long detail) {
    REP_STORE(&rep_custody_stats.ticket,0);
    REP_STORE(&rep_custody_stats.phase,LI2_REP_CUSTODY_FAILED);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    if(!rep_custody_stats.first_error) {
        rep_custody_stats.first_detail=detail;
        REP_STORE(&rep_custody_stats.first_error,code?code:LI2_FETCH_STATE);
    }
    return (int)REP_LOAD(&rep_custody_stats.first_error);
}
static int rep_increment(uint64_t *p) {
    uint64_t old=REP_LOAD(p);
    do {
        if(old==UINT64_MAX)return rep_bad(LI2_FETCH_STATE,1);
    } while(!__atomic_compare_exchange_n(p,&old,old+1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE));
    return 0;
}
static int rep_phase(unsigned before,unsigned after) {
    unsigned expected=before;
    if(REP_LOAD(&rep_custody_stats.first_error) ||
       !__atomic_compare_exchange_n(&rep_custody_stats.phase,&expected,after,0,
                                    __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        return rep_bad(LI2_FETCH_STATE,2);
    return 0;
}
static int rep_protected(uintptr_t first,size_t bytes) {
    const struct li2_run_protection *h=&rep_custody.protection;
    return first && bytes && first<=UINTPTR_MAX-bytes &&
        h->contains && h->contains(h->context,first,bytes)==1;
}
static int rep_registered(const struct li2_repeat_lease_owner *o) {
    return REP_LOAD(&rep_custody_stats.initialized) && o && o==rep_custody.owner &&
        !REP_LOAD(&rep_custody_stats.first_error) &&
        rep_protected((uintptr_t)o,sizeof(*o)) &&
        rep_protected((uintptr_t)rep_custody.session_pointer,sizeof(rep_custody.session)) &&
        rep_protected((uintptr_t)&rep_custody,sizeof(rep_custody)) &&
        rep_protected((uintptr_t)&rep_custody_stats,sizeof(rep_custody_stats));
}
int li2_repeat_custody_initialize(struct li2_repeat_lease_owner *o,
        struct li2_step_session *s,const struct li2_run_protection *h) {
    if(REP_LOAD(&rep_custody_stats.initialized) || rep_custody.owner ||
       rep_custody_stats.first_error || !o || !s || !h || !h->add || !h->contains ||
       !active || tx.guard || fetch.progress.held ||
       !s->initialized || !s->self_test_complete || s->pid<=0 || s->pid!=s->tid ||
       !rep_zero(o,sizeof(*o)))return rep_bad(LI2_FETCH_ARGUMENT,3);
    uintptr_t a=(uintptr_t)o,b=(uintptr_t)s;
    if(a>UINTPTR_MAX-sizeof(*o) || b>UINTPTR_MAX-sizeof(*s) ||
       overlaps(a,a+sizeof(*o),b,b+sizeof(*s)) ||
       overlaps(a,a+sizeof(*o),(uintptr_t)&rep_custody,(uintptr_t)&rep_custody+sizeof(rep_custody)) ||
       overlaps(a,a+sizeof(*o),(uintptr_t)&rep_custody_stats,(uintptr_t)&rep_custody_stats+sizeof(rep_custody_stats)) ||
       overlaps(b,b+sizeof(*s),(uintptr_t)&rep_custody,(uintptr_t)&rep_custody+sizeof(rep_custody)) ||
       overlaps(b,b+sizeof(*s),(uintptr_t)&rep_custody_stats,(uintptr_t)&rep_custody_stats+sizeof(rep_custody_stats)))
        return rep_bad(LI2_FETCH_ARGUMENT,4);
    rep_custody.owner=o;rep_custody.session_pointer=s;rep_custody.session=*s;
    rep_custody.protection=*h;
    const uintptr_t starts[]={a,b,(uintptr_t)&rep_custody,(uintptr_t)&rep_custody_stats};
    const size_t sizes[]={sizeof(*o),sizeof(*s),sizeof(rep_custody),sizeof(rep_custody_stats)};
    for(size_t i=0;i<4;i++) {
        int e=h->add(h->context,starts[i],sizes[i]);
        if(e || !rep_protected(starts[i],sizes[i]))return rep_bad(LI2_FETCH_STATE,e);
    }
    if(RAW(SYS_getpid,0,0,0,0,0,0)!=s->pid || RAW(SYS_gettid,0,0,0,0,0,0)!=s->tid)
        return rep_bad(LI2_FETCH_IDENTITY,5);
    REP_STORE(&rep_custody_stats.initialized,1);
    return 0;
}
static int rep_request(const struct li2_fetch_ref *ref,const struct li2_step_request *q) {
    int e=fetch_ref(ref);if(e)return e;
    if(!q || !li2_repeat_width(&q->decoded) ||
       q->decoded.pc!=fetch.pc || q->decoded.available!=fetch.requested ||
       q->decoded.length>fetch.requested ||
       !rep_equal(q->decoded.bytes,fetch.bytes,fetch.requested) ||
       (q->original_flags&(LI2_STEP_TF|LI2_STEP_RF)))return LI2_FETCH_ARGUMENT;
    size_t n=((q->decoded.next_pc-1)&~(PAGE-1))==(fetch.pc&~(PAGE-1))?1:2;
    if(q->page_count!=n || n>fetch.page_count)return LI2_FETCH_PAGE;
    for(size_t i=0;i<n;i++) {
        const struct li2_step_page *p=&q->pages[i];
        const struct owned_page *v=&fetch.original[i];
        if(p->address!=v->address || p->object!=v->allocation || p->generation!=v->generation ||
           p->offset!=v->offset || p->closed_prot!=PROT_READ ||
           p->open_prot!=(PROT_READ|PROT_EXEC))return LI2_FETCH_PAGE;
    }
    return 0;
}
int li2_repeat_custody_eligible(const struct li2_fetch_ref *ref,
        const struct li2_step_request *q,int *eligible) {
    if(!eligible)return LI2_FETCH_ARGUMENT;
    *eligible=0;
    if(!rep_registered(rep_custody.owner) || REP_LOAD(&rep_custody_stats.phase)!=LI2_REP_CUSTODY_EMPTY ||
       REP_LOAD(&rep_custody_stats.bound) || REP_LOAD(&rep_custody_stats.ticket))return LI2_FETCH_STATE;
    int e=rep_request(ref,q);if(e)return e;
    /* A stale/mutated source never becomes a fallback. Both pages of a valid
       unsupported window still receive the complete old R/NX validator. */
    for(size_t i=0;i<fetch.page_count;i++) {
        e=li2_lifecycle_fetch_validate(ref,i,PROT_READ);if(e)return e;
    }
    if(fetch.page_count!=1 || q->page_count!=1)return 0;
    const struct owned_page *p=&fetch.original[0];
    if(p->backing==ANONYMOUS)return 0;
    if(p->backing!=SEALED || p->object>=object_count)return LI2_FETCH_BACKING;
    *eligible=1;return 0;
}
int li2_repeat_custody_quiet(const struct li2_repeat_lease_owner *o) {
    if(!rep_registered(o) || REP_LOAD(&rep_custody_stats.phase)!=LI2_REP_CUSTODY_EMPTY ||
       REP_LOAD(&rep_custody_stats.bound) || REP_LOAD(&rep_custody_stats.ticket) ||
       rep_custody_stats.attempt!=rep_custody_stats.closed)return LI2_FETCH_STATE;
    if(!rep_custody_stats.attempt)return rep_zero(o,sizeof(*o))?0:LI2_FETCH_STATE;
    if(!li2_repeat_lease_closed(o) || o->attempts!=rep_custody_stats.attempt ||
       o->completed!=rep_custody_stats.closed || o->borrow_held ||
       o->borrow.owner!=rep_custody.ref.owner || o->borrow.sequence!=rep_custody.ref.sequence)
        return LI2_FETCH_STATE;
    const struct li2_repeat_owner *r=&o->repeat;
    const struct li2_step_owner *p=&r->step;
    if(p->phase!=LI2_STEP_COMPLETE || p->first_error || p->in_handler ||
       p->session!=rep_custody.session_pointer ||
       !rep_equal(p->session,&rep_custody.session,sizeof(rep_custody.session)) ||
       !rep_equal(&p->request,&rep_custody.request,sizeof(p->request)) ||
       !rep_equal(&o->repeat.hooks,&rep_custody.hooks,sizeof(rep_custody.hooks)) ||
       !rep_equal(&p->hooks,&rep_custody.hooks.step,sizeof(p->hooks)) ||
       !r->final || r->remaining || r->closed_cycles!=1 || r->reopened_cycles ||
       !r->continuation_complete || r->continuation_result ||
       !o->close_complete || !o->release_started || !o->release_complete ||
       o->release_result || o->return_pending || o->failure_started)return LI2_FETCH_STATE;
    return 0;
}
int li2_repeat_custody_reset_ready(const struct li2_repeat_lease_owner *o) {
    int e=li2_repeat_custody_quiet(o);if(e)return rep_bad((unsigned)e,6);
    if(REP_LOAD(&rep_custody_stats.reset_ready))return rep_bad(LI2_FETCH_STATE,7);
    REP_STORE(&rep_custody_stats.reset_ready,1);return 0;
}
int li2_repeat_custody_bind(struct li2_repeat_lease_owner *o,const struct li2_fetch_ref *ref) {
    if(!rep_registered(o) || REP_LOAD(&rep_custody_stats.phase)!=LI2_REP_CUSTODY_EMPTY ||
       !REP_LOAD(&rep_custody_stats.reset_ready) || REP_LOAD(&rep_custody_stats.bound) ||
       REP_LOAD(&rep_custody_stats.ticket))return rep_bad(LI2_FETCH_STATE,8);
    const struct li2_step_owner *p=&o->repeat.step;
    int e=rep_request(ref,&p->request);
    if(e)return rep_bad((unsigned)e,9);
    if(rep_custody_stats.attempt==UINT64_MAX || o->attempts!=rep_custody_stats.attempt+1 ||
       o->completed!=rep_custody_stats.closed || o->borrow_held!=1 ||
       fetch.page_count!=1 || p->request.page_count!=1 || fetch.original[0].backing!=SEALED ||
       p->phase!=LI2_STEP_ARMED || p->in_handler || p->first_error || p->self_test ||
       p->session!=rep_custody.session_pointer ||
       !rep_equal(p->session,&rep_custody.session,sizeof(rep_custody.session)) ||
       !p->hooks.context || !p->hooks.authenticate || !p->hooks.failure ||
       !o->repeat.hooks.continue_closed ||
       !rep_equal(&o->repeat.hooks.step,&p->hooks,sizeof(p->hooks)) ||
       o->borrow.owner!=ref->owner || o->borrow.sequence!=ref->sequence ||
       o->repeat.traces || o->repeat.closed_cycles || o->repeat.reopened_cycles ||
       p->trace_seen || p->revoke_sync_started ||
       !rep_zero(p->open_started,sizeof(p->open_started)) ||
       !rep_zero(p->opened,sizeof(p->opened)) || !rep_zero(p->open_result,sizeof(p->open_result)) ||
       !rep_zero(p->revoke_started,sizeof(p->revoke_started)) ||
       !rep_zero(p->revoked,sizeof(p->revoked)) || !rep_zero(p->revoke_result,sizeof(p->revoke_result)) ||
       p->open_sync || p->revoke_sync)return rep_bad(LI2_FETCH_STATE,10);
    REP_STORE(&rep_custody_stats.reset_ready,0);
    rep_custody.ref=*ref;rep_custody.request=p->request;rep_custody.hooks=o->repeat.hooks;
    rep_custody.original=fetch.original[0];rep_custody.page=fetch.pages[0];
    rep_custody.pc=fetch.pc;rep_custody.length=fetch.requested;
    for(size_t i=0;i<sizeof(rep_custody.bytes);i++)rep_custody.bytes[i]=fetch.bytes[i];
    rep_custody_stats.page=fetch.pages[0];rep_custody_stats.borrow_sequence=ref->sequence;
    rep_custody_stats.event=0;
    rep_custody_stats.seed_backing=(struct li2_fetch_backing){0};
    rep_custody_stats.last_backing=(struct li2_fetch_backing){0};
    rep_custody_stats.cold_maps=(struct li2_fetch_map_progress){0};
    if((e=rep_increment(&rep_custody_stats.attempt)))return e;
    REP_STORE(&rep_custody_stats.bound,1);
    return rep_phase(LI2_REP_CUSTODY_EMPTY,LI2_REP_CUSTODY_BOUND);
}
static int rep_bound(const struct li2_repeat_lease_owner *o,const struct li2_fetch_ref *ref) {
    if(!rep_registered(o) || !REP_LOAD(&rep_custody_stats.bound) || !ref ||
       ref->owner!=rep_custody.ref.owner || ref->sequence!=rep_custody.ref.sequence ||
       o->borrow.owner!=ref->owner || o->borrow.sequence!=ref->sequence ||
       o->borrow_held!=1 || o->attempts!=rep_custody_stats.attempt)return LI2_FETCH_STALE;
    int e=fetch_ref(ref);if(e)return e;
    const struct li2_step_owner *p=&o->repeat.step;
    if(p->first_error || p->self_test || p->session!=rep_custody.session_pointer ||
       !rep_equal(p->session,&rep_custody.session,sizeof(rep_custody.session)) ||
       !rep_equal(&p->request,&rep_custody.request,sizeof(p->request)) ||
       !rep_equal(&o->repeat.hooks,&rep_custody.hooks,sizeof(rep_custody.hooks)) ||
       !rep_equal(&p->hooks,&rep_custody.hooks.step,sizeof(p->hooks)) ||
       fetch.page_count!=1 || fetch.pc!=rep_custody.pc || fetch.requested!=rep_custody.length ||
       !rep_equal(fetch.bytes,rep_custody.bytes,sizeof(rep_custody.bytes)) ||
       !fetch_owned_equal(&fetch.original[0],&rep_custody.original) ||
       !rep_equal(&fetch.pages[0],&rep_custody.page,sizeof(rep_custody.page)))return LI2_FETCH_STALE;
    return 0;
}
int li2_repeat_custody_before_begin(struct li2_repeat_lease_owner *o,const struct li2_fetch_ref *ref) {
    int e=rep_bound(o,ref);if(e)return rep_bad((unsigned)e,11);
    if(REP_LOAD(&rep_custody_stats.phase)!=LI2_REP_CUSTODY_BOUND ||
       o->repeat.step.phase!=LI2_STEP_ARMED || o->repeat.step.in_handler)
        return rep_bad(LI2_FETCH_STATE,12);
    e=li2_lifecycle_fetch_validate(ref,0,PROT_READ);
    if(!e)e=rep_bound(o,ref);
    if(!e && REP_LOAD(&rep_custody_stats.phase)!=LI2_REP_CUSTODY_BOUND)e=LI2_FETCH_STATE;
    return e?rep_bad((unsigned)e,13):0;
}
static int rep_open(const struct li2_repeat_lease_owner *o,unsigned in_handler,unsigned closing) {
    const struct li2_step_owner *p=&o->repeat.step;
    return p->phase==LI2_STEP_RUNNING && p->in_handler==in_handler &&
        p->open_started[0]==1 && p->opened[0]==1 && !p->open_result[0] && !p->open_sync &&
        !p->open_started[1] && !p->opened[1] && !p->open_result[1] &&
        !p->revoke_started[0] && !p->revoke_started[1] && !p->revoked[0] && !p->revoked[1] &&
        !p->revoke_result[0] && !p->revoke_result[1] && !p->revoke_sync_started && !p->revoke_sync &&
        !o->repeat.closed_cycles && !o->repeat.reopened_cycles && o->close_started==closing && !o->release_started;
}
int li2_repeat_custody_seed(struct li2_repeat_lease_owner *o,const struct li2_fetch_ref *ref) {
    int e=rep_bound(o,ref);if(e)return rep_bad((unsigned)e,14);
    if(!rep_open(o,1,0) || o->repeat.traces || o->repeat.step.trace_seen ||
       REP_LOAD(&rep_custody_stats.event) || REP_LOAD(&rep_custody_stats.ticket))
        return rep_bad(LI2_FETCH_STATE,15);
    if((e=rep_phase(LI2_REP_CUSTODY_BOUND,LI2_REP_CUSTODY_SEEDING)))return e;
    /* A new actual RX acquisition, never a reused R/NX or historical receipt. */
    li2_maps_phase_end();
    if((e=li2_maps_phase_begin()) || (e=li2_lifecycle_fetch_validate(ref,0,PROT_READ|PROT_EXEC)))
        return rep_bad((unsigned)e,16);
    const struct owned_page *p=current(rep_custody.original.address);
    const struct map_row *m=mapping(rep_custody.original.address);
    const struct li2_fetch_map_progress *v=&fetch.progress.validation;
    if(!fetch_owned_equal(p,&rep_custody.original) || p->backing!=SEALED || p->object>=object_count ||
       !m || !m->private || m->prot!=(PROT_READ|PROT_EXEC) ||
       !v->opened || !v->closed || !v->close_started || v->close_result || v->last_read ||
       !v->rows || !v->bytes || v->observation.kind!=LI2_MAPS_FRESH ||
       v->observation.io_performed!=1 || !v->observation.acquisition_id ||
       !REP_LOAD(&maps_stats.active) || !REP_LOAD(&maps_stats.valid) || REP_LOAD(&maps_stats.poisoned) ||
       v->observation.handler_id!=REP_LOAD(&maps_stats.handler_id) ||
       v->observation.mutation_epoch!=REP_LOAD(&maps_stats.mutation_epoch))return rep_bad(LI2_FETCH_STATE,17);
    const struct object *ob=&objects[p->object];
    rep_custody.major=ob->major;rep_custody.minor=ob->minor;rep_custody.inode=ob->inode;
    rep_custody.retained_fd=ob->retained_fd;rep_custody.object_stat=ob->stat;
    rep_custody_stats.cold_maps=*v;rep_custody_stats.seed_backing=fetch.last_backing;
    rep_custody_stats.last_backing=fetch.last_backing;
    if((e=rep_bound(o,ref)) || !rep_open(o,1,0))return rep_bad(e?(unsigned)e:LI2_FETCH_STATE,30);
    if((e=rep_increment(&rep_custody_stats.epoch)) || (e=rep_increment(&rep_custody_stats.seeds)))return e;
    rep_custody.ticket=REP_LOAD(&rep_custody_stats.epoch);
    REP_STORE(&rep_custody_stats.ticket,1);
    return rep_phase(LI2_REP_CUSTODY_SEEDING,LI2_REP_CUSTODY_VALIDATED);
}
void li2_repeat_custody_boundary(void) {
    if(!REP_LOAD(&rep_custody_stats.initialized) || !REP_LOAD(&rep_custody_stats.bound))return;
    if(!REP_LOAD(&rep_custody_stats.ticket) ||
       REP_LOAD(&rep_custody_stats.epoch)!=rep_custody.ticket ||
       rep_phase(LI2_REP_CUSTODY_READY,LI2_REP_CUSTODY_ENTRY)) {
        (void)rep_bad(LI2_FETCH_STATE,18);return;
    }
    if(rep_increment(&rep_custody_stats.event) || rep_increment(&rep_custody_stats.entries))return;
}
static int rep_retained(const struct li2_repeat_lease_owner *o,const struct li2_fetch_ref *ref) {
    int e=rep_bound(o,ref);if(e)return e;
    if(!REP_LOAD(&rep_custody_stats.ticket) ||
       REP_LOAD(&rep_custody_stats.epoch)!=rep_custody.ticket)return LI2_FETCH_STALE;
    if((e=fetch_identity()))return e;
    const struct owned_page *p=current(rep_custody.original.address);
    if(!fetch_owned_equal(p,&rep_custody.original) || p->object>=object_count)return LI2_FETCH_STALE;
    const struct object *b=&objects[p->object];
    if(b->major!=rep_custody.major || b->minor!=rep_custody.minor || b->inode!=rep_custody.inode ||
       b->retained_fd!=rep_custody.retained_fd || b->stat.st_dev!=rep_custody.object_stat.st_dev ||
       b->stat.st_ino!=rep_custody.object_stat.st_ino || b->stat.st_size!=rep_custody.object_stat.st_size ||
       b->stat.st_mode!=rep_custody.object_stat.st_mode)return LI2_FETCH_BACKING;
    fetch.progress.last_backing_page=0;fetch.progress.last_backing_observed=1;
    e=fetch_backing_check(p,&fetch.last_backing);
    rep_custody_stats.last_backing=fetch.last_backing;
    if(e)return e;
    const struct li2_fetch_backing *seed=&rep_custody_stats.seed_backing,*now=&fetch.last_backing;
    if(now->retained_fd!=seed->retained_fd || now->seals!=seed->seals ||
       now->seals_observed!=1 || now->stat_observed!=1 || now->stat_result ||
       now->stat.st_dev!=seed->stat.st_dev || now->stat.st_ino!=seed->stat.st_ino ||
       now->stat.st_size!=seed->stat.st_size || now->stat.st_mode!=seed->stat.st_mode)return LI2_FETCH_BACKING;
    const volatile unsigned char *source=(const void *)fetch.pc;
    for(size_t i=0;i<fetch.requested;i++)if(source[i]!=rep_custody.bytes[i])return LI2_FETCH_SOURCE;
    if(REP_LOAD(&rep_custody_stats.epoch)!=rep_custody.ticket ||
       !REP_LOAD(&rep_custody_stats.ticket) || REP_LOAD(&rep_custody_stats.first_error))return LI2_FETCH_STALE;
    return rep_bound(o,ref);
}
int li2_repeat_custody_validate(struct li2_repeat_lease_owner *o,const struct li2_fetch_ref *ref) {
    if(!rep_registered(o) || REP_LOAD(&rep_custody_stats.phase)!=LI2_REP_CUSTODY_ENTRY ||
       !rep_open(o,1,0) || o->repeat.step.trace_seen!=1 || !o->repeat.traces ||
       o->repeat.traces!=REP_LOAD(&rep_custody_stats.event))return rep_bad(LI2_FETCH_STATE,19);
    int e=rep_retained(o,ref);if(e)return rep_bad((unsigned)e,20);
    if((e=rep_increment(&rep_custody_stats.validations)))return e;
    return rep_phase(LI2_REP_CUSTODY_ENTRY,LI2_REP_CUSTODY_VALIDATED);
}
int li2_repeat_custody_prepare_return(struct li2_repeat_lease_owner *o,const struct li2_fetch_ref *ref) {
    int e=rep_bound(o,ref);if(e)return rep_bad((unsigned)e,21);
    if(!rep_open(o,1,0) || o->repeat.final ||
       o->repeat.traces!=REP_LOAD(&rep_custody_stats.event) ||
       (o->repeat.traces && !o->repeat.remaining) ||
       !REP_LOAD(&rep_custody_stats.ticket) ||
       REP_LOAD(&rep_custody_stats.epoch)!=rep_custody.ticket)return rep_bad(LI2_FETCH_STATE,22);
    return rep_phase(LI2_REP_CUSTODY_VALIDATED,LI2_REP_CUSTODY_RETURN);
}
int li2_repeat_custody_handler_end(struct li2_repeat_lease_owner *o,const struct li2_fetch_ref *ref) {
    int e=rep_bound(o,ref);if(e)return rep_bad((unsigned)e,23);
    if(!rep_open(o,0,0) || !o->return_pending || o->repeat.final ||
       o->repeat.traces!=REP_LOAD(&rep_custody_stats.event) ||
       !REP_LOAD(&rep_custody_stats.ticket) ||
       REP_LOAD(&rep_custody_stats.epoch)!=rep_custody.ticket)return rep_bad(LI2_FETCH_STATE,24);
    if((e=rep_increment(&rep_custody_stats.returns)))return e;
    return rep_phase(LI2_REP_CUSTODY_RETURN,LI2_REP_CUSTODY_READY);
}
int li2_repeat_custody_close(struct li2_repeat_lease_owner *o,const struct li2_fetch_ref *ref) {
    int e=rep_bound(o,ref);if(e)return rep_bad((unsigned)e,25);
    if(!rep_open(o,1,1) || !o->repeat.final || o->repeat.remaining ||
       !o->repeat.traces || o->repeat.traces!=REP_LOAD(&rep_custody_stats.event) ||
       !REP_LOAD(&rep_custody_stats.ticket) ||
       REP_LOAD(&rep_custody_stats.epoch)!=rep_custody.ticket)return rep_bad(LI2_FETCH_STATE,26);
    if((e=rep_phase(LI2_REP_CUSTODY_VALIDATED,LI2_REP_CUSTODY_CLOSING)))return e;
    REP_STORE(&rep_custody_stats.ticket,0);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    return rep_increment(&rep_custody_stats.epoch);
}
int li2_repeat_custody_released(struct li2_repeat_lease_owner *o,const struct li2_fetch_ref *ref) {
    if(!rep_registered(o) || REP_LOAD(&rep_custody_stats.phase)!=LI2_REP_CUSTODY_CLOSING ||
       !REP_LOAD(&rep_custody_stats.bound) || REP_LOAD(&rep_custody_stats.ticket) ||
       !ref || ref->owner!=&fetch || ref->sequence!=rep_custody.ref.sequence ||
       fetch.progress.sequence!=ref->sequence || fetch.progress.held || fetch.progress.first_error ||
       o->borrow.owner!=ref->owner || o->borrow.sequence!=ref->sequence || o->borrow_held ||
       o->attempts!=rep_custody_stats.attempt || o->completed!=rep_custody_stats.closed)
        return rep_bad(LI2_FETCH_STATE,27);
    const struct li2_repeat_owner *r=&o->repeat;
    const struct li2_step_owner *p=&r->step;
    if(p->phase!=LI2_STEP_REVOKING || p->in_handler!=1 || p->first_error ||
       !rep_equal(&p->request,&rep_custody.request,sizeof(p->request)) ||
       p->session!=rep_custody.session_pointer ||
       !rep_equal(p->session,&rep_custody.session,sizeof(rep_custody.session)) ||
       !rep_equal(&p->hooks,&rep_custody.hooks.step,sizeof(p->hooks)) ||
       !r->final || r->remaining || !r->traces || r->traces!=rep_custody_stats.event ||
       r->closed_cycles!=1 || r->reopened_cycles || !r->continuation_started ||
       !r->continuation_complete || r->continuation_result ||
       p->open_started[0]!=1 || p->opened[0]!=1 || p->open_result[0] || p->open_sync ||
       p->revoke_started[0]!=1 || p->revoked[0]!=1 || p->revoke_result[0] ||
       !p->revoke_sync_started || p->revoke_sync ||
       p->open_started[1] || p->opened[1] || p->open_result[1] ||
       p->revoke_started[1] || p->revoked[1] || p->revoke_result[1] ||
       !o->close_complete || !o->release_started || !o->release_complete || o->release_result)
        return rep_bad(LI2_FETCH_STATE,28);
    if(rep_increment(&rep_custody_stats.closed))return (int)rep_custody_stats.first_error;
    REP_STORE(&rep_custody_stats.bound,0);
    return rep_phase(LI2_REP_CUSTODY_CLOSING,LI2_REP_CUSTODY_EMPTY);
}
void li2_repeat_custody_invalidate(unsigned reason) {
    if(!REP_LOAD(&rep_custody_stats.initialized) || !REP_LOAD(&rep_custody_stats.bound))return;
    rep_custody_stats.last_reason=reason;
    unsigned phase=REP_LOAD(&rep_custody_stats.phase);
    /* No retained ticket exists during the one initial open/acquisition or
       the one final close. Only those trusted protocols may perform RAW I/O.
       Event/error/lifecycle invalidation is never excused by this phase. */
    int expected=(reason==LI2_REP_CUSTODY_RAW &&
        (phase==LI2_REP_CUSTODY_BOUND || phase==LI2_REP_CUSTODY_SEEDING || phase==LI2_REP_CUSTODY_CLOSING)) ||
        (reason==LI2_REP_CUSTODY_RELEASE && phase==LI2_REP_CUSTODY_CLOSING);
    REP_STORE(&rep_custody_stats.ticket,0);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    if(rep_increment(&rep_custody_stats.invalidations) || rep_increment(&rep_custody_stats.epoch))return;
    if(!expected)(void)rep_bad(LI2_FETCH_STALE,(long)reason);
}
void li2_repeat_custody_fail(const struct li2_repeat_lease_owner *o,unsigned code,long detail) {
    if(!REP_LOAD(&rep_custody_stats.initialized))return;
    if(o!=rep_custody.owner) { (void)rep_bad(LI2_FETCH_ARGUMENT,29);return; }
    (void)rep_bad(code,detail);
}
const struct li2_repeat_custody_observation *li2_repeat_custody_progress(void) {
    return &rep_custody_stats;
}
#undef REP_LOAD
#undef REP_STORE
