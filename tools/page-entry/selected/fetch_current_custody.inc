/* Included after old physical custody and descriptive current-view stage.
   Old physical API bodies remain exact. This private stage/candidate/payload
   never alias rx_view/rx_candidate/custody. Phase/epoch invalidation is shared. */
#include "fetch_current_custody.h"
static struct li2_current_custody_stats cc_stats;
static uint64_t cc_serial;
static struct li2_fetch cc_candidate;
static struct {
    unsigned bound;
    struct li2_custody_owner owner;
    const struct li2_step_session *session_pointer;
    struct li2_step_session session;
    struct li2_step_hooks hooks;
    struct li2_step_request opening,previous;
    struct owned_page original;
    struct li2_fetch_page page;
    uint64_t ticket,sequence,serial,origin_sequence;
    uint64_t major,minor,inode;
    struct stat object_stat;
    int retained_fd;
    struct li2_current_custody_provenance proof;
} cc;
const struct li2_fetch_rx_view *li2_lifecycle_fetch_rx_current_progress(void) { return &rx_current.stage; }
const struct li2_current_custody_provenance *li2_current_custody_provenance(void) { return &cc.proof; }
void li2_current_custody_snapshot(struct li2_current_custody_stats *out) {
    if(!out)return;
#define CC_COPY(f) out->f=CUSTODY_LOAD(&cc_stats.f)
    CC_COPY(attempts);CC_COPY(current_stages);CC_COPY(current_seeds);CC_COPY(physical_fallbacks);
    CC_COPY(retained_stages);CC_COPY(retained_checks);CC_COPY(commits);CC_COPY(cancels);
    CC_COPY(first_error);CC_COPY(first_detail);
#undef CC_COPY
}
int li2_current_custody_owned(void) {
    /* Old discard intentionally owns the shared epoch, not this payload.
       Its stale bound bit must not select current hooks for a later physical
       lease. Epoch never wraps: the old increment poisons on overflow. */
    return CUSTODY_LOAD(&cc.bound) && CUSTODY_LOAD(&custody_stats.epoch)==cc.ticket &&
        CUSTODY_LOAD(&custody_stats.phase)!=LI2_CUSTODY_EMPTY;
}
static int cc_error(int error) {
    int first=fetch_error((unsigned)error,0);
    if(!CUSTODY_LOAD(&cc_stats.first_error)) {
        CUSTODY_STORE(&cc_stats.first_detail,fetch.progress.first_detail);
        CUSTODY_STORE(&cc_stats.first_error,(unsigned)first);
    }
    li2_page_custody_discard(LI2_CUSTODY_ERROR);
    if(rx_current.result==LI2_MAPS_CURRENT_UNAVAILABLE)rx_current.result=first;
    if(!rx_current.stage.result)rx_current.stage.result=first;
    (void)rx_current_error(first);return first;
}
static int cc_phase(unsigned before,unsigned after) {
    unsigned expected=before;
    if(CUSTODY_LOAD(&custody_stats.epoch)!=cc.ticket ||
       !__atomic_compare_exchange_n(&custody_stats.phase,&expected,after,0,
                                    __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return LI2_FETCH_STALE;
    return 0;
}
static int cc_owner_same(const struct li2_custody_owner *k) {
    const struct li2_step_owner *p=k->owner;
    return k->chain==cc.owner.chain && p==cc.owner.owner &&
        k->slot==cc.owner.slot && k->generation==cc.owner.generation &&
        p->session==cc.session_pointer &&
        custody_equal(p->session,&cc.session,sizeof cc.session) &&
        p->hooks.context==cc.hooks.context && p->hooks.authenticate==cc.hooks.authenticate &&
        p->hooks.failure==cc.hooks.failure;
}
static int cc_physical_entry(void) {
    /* This is only a route discriminator. The original stage still performs
       every owner/session/request/sequence/source check before it can pass.
       A stale current attempt alone never supplies this physical receipt. */
    const struct li2_page_custody_receipt *r=&rx_view.custody;
    return CUSTODY_LOAD(&custody_stats.phase)==LI2_CUSTODY_ENTRY &&
        CUSTODY_LOAD(&custody_stats.epoch)==custody.ticket &&
        (r->kind==LI2_CUSTODY_FRESH || r->kind==LI2_CUSTODY_RETAINED) &&
        r->provenance==LI2_CUSTODY_MANAGED_SEALED && r->epoch==custody.ticket &&
        r->origin_sequence==custody.origin_sequence && r->chain==(uintptr_t)custody.owner.chain &&
        r->owner==(uintptr_t)custody.owner.owner && r->session==(uintptr_t)custody.session_pointer &&
        r->slot==custody.owner.slot && r->owner_generation==custody.owner.generation &&
        r->event==custody.owner.event && custody_equal(&r->origin,&custody.origin,sizeof r->origin) &&
        rx_view.phase==LI2_RX_COMMITTED && rx_view.complete && !rx_view.result &&
        rx_view.serial==custody.serial && rx_view.after_sequence==custody.sequence;
}
static void cc_receipt(unsigned kind) {
    cc.proof.kind=kind;cc.proof.stage_serial=cc.serial;
    rx_current.stage.custody=(struct li2_page_custody_receipt){.kind=kind,
        .provenance=LI2_CUSTODY_CURRENT_MANAGED_SEALED,.epoch=cc.ticket,
        .origin_sequence=cc.origin_sequence,.chain=(uintptr_t)cc.owner.chain,
        .owner=(uintptr_t)cc.owner.owner,.session=(uintptr_t)cc.owner.owner->session,
        .slot=cc.owner.slot,.owner_generation=cc.owner.generation,
        .event=cc.owner.event,.origin=cc.proof.origin.physical};
}
static int cc_receipt_live(const struct li2_fetch_rx_view *v) {
    if(v!=&rx_current.stage || !CUSTODY_LOAD(&cc.bound))return 0;
    const struct li2_page_custody_receipt *r=&v->custody;
    return cc.proof.version==1 && cc.proof.complete==1 && cc.proof.consumed==1 &&
        cc.proof.epoch==cc.ticket && cc.proof.origin_sequence==cc.origin_sequence &&
        cc.proof.stage_serial==cc.serial &&
        (cc.proof.kind==LI2_CUSTODY_CURRENT_SEED || cc.proof.kind==LI2_CUSTODY_CURRENT_RETAINED) &&
        r->kind==cc.proof.kind && r->provenance==LI2_CUSTODY_CURRENT_MANAGED_SEALED &&
        r->epoch==cc.ticket && r->origin_sequence==cc.origin_sequence &&
        r->chain==(uintptr_t)cc.owner.chain && r->owner==(uintptr_t)cc.owner.owner &&
        r->session==(uintptr_t)cc.session_pointer && r->slot==cc.owner.slot &&
        r->owner_generation==cc.owner.generation && r->event==cc.owner.event &&
        custody_equal(&r->origin,&cc.proof.origin.physical,sizeof r->origin);
}
static int cc_seed(const struct li2_custody_owner *k,const struct li2_fetch_ref *ref) {
    int e=custody_owner_live(k,ref,1);if(e)return e;
    const struct owned_page *p=current(fetch.original[0].address);
    const struct map_row *r=p?mapping(p->address):0;
    const struct li2_fetch_rx_current_view *v=&rx_current;
    if((e=li2_maps_current_validate(&v->ticket,v->query)))return e;
    if(!v->complete || v->result || v->borrow.owner!=ref->owner || v->borrow.sequence!=ref->sequence ||
       v->stage.phase!=LI2_RX_STAGED || !v->stage.complete || v->stage.result ||
       !fetch_owned_equal(p,&fetch.original[0]) || p->backing!=SEALED || p->object>=object_count ||
       p->admitted || !p->live || p->actual!=PROT_READ || p->logical!=(PROT_READ|PROT_EXEC) ||
       !r || !r->private || r->prot!=(PROT_READ|PROT_EXEC) ||
       !custody_equal(&v->stage.maps,&v->query->query,sizeof v->stage.maps))return LI2_FETCH_STALE;
    uint64_t epoch=CUSTODY_LOAD(&custody_stats.epoch);
    /* All pointers below are exact protected objects. No RAW/callback between
       final ticket validation, copying evidence, consumption and phase CAS. */
    cc.proof=(struct li2_current_custody_provenance){.version=1,.epoch=epoch,
        .origin_sequence=ref->sequence,.origin=*v->query};
    if((e=li2_maps_current_release(&v->ticket)))return e;
    cc.proof.consumed=1;
    unsigned expected=LI2_CUSTODY_EMPTY;
    if(CUSTODY_LOAD(&custody_stats.epoch)!=epoch ||
       !__atomic_compare_exchange_n(&custody_stats.phase,&expected,LI2_CUSTODY_BUILDING,
           0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return LI2_FETCH_STALE;
    cc.ticket=epoch;CUSTODY_STORE(&cc.bound,1);
    cc.owner=*k;cc.session_pointer=k->owner->session;cc.session=*k->owner->session;cc.hooks=k->owner->hooks;
    cc.opening=k->owner->request;cc.previous=k->owner->request;cc.original=*p;cc.page=v->stage.page;
    cc.sequence=ref->sequence;cc.origin_sequence=ref->sequence;cc.serial=++cc_serial;
    rx_current.stage.serial=cc.serial;
    const struct object *o=&objects[p->object];
    cc.major=o->major;cc.minor=o->minor;cc.inode=o->inode;cc.retained_fd=o->retained_fd;cc.object_stat=o->stat;
    cc_candidate=fetch;cc_candidate.pc=v->stage.pc;cc_candidate.requested=v->stage.length;
    cc_candidate.progress=(struct li2_fetch_progress){.identity_observed=1,.pages_copied=1,
        .preparation=v->stage.maps,.bytes_copied=v->stage.length,.complete=1};
    cc_candidate.pages[0]=v->stage.page;cc_candidate.backing[0]=v->stage.backing;
    for(size_t i=0;i<sizeof cc_candidate.bytes;i++)cc_candidate.bytes[i]=i<v->stage.length?v->stage.bytes[i]:0;
    rx_current.stage.maps_observed=1;cc.proof.complete=1;cc_receipt(LI2_CUSTODY_CURRENT_SEED);
    if((e=custody_increment(&cc_stats.current_stages)))return e;
    return cc_phase(LI2_CUSTODY_BUILDING,LI2_CUSTODY_STAGED);
}
/* Same retained identity/backing/whole-byte predicates as physical custody;
   only the private payload and explicit current-provenance counters differ. */
static int cc_validate(const struct li2_fetch_ref *ref) {
    int e=fetch_ref(ref);if(e)return e;
    if(!cc_receipt_live(&rx_current.stage) || ref->sequence!=cc.sequence || fetch.page_count!=1 ||
       !fetch_owned_equal(&fetch.original[0],&cc.original))return LI2_FETCH_STALE;
    if((e=fetch_identity()))return e;
    const struct owned_page *p=current(cc.original.address);
    if(!fetch_owned_equal(p,&cc.original) || p->object>=object_count)return LI2_FETCH_STALE;
    const struct object *o=&objects[p->object];
    if(o->major!=cc.major || o->minor!=cc.minor || o->inode!=cc.inode ||
       o->retained_fd!=cc.retained_fd || o->stat.st_dev!=cc.object_stat.st_dev ||
       o->stat.st_ino!=cc.object_stat.st_ino || o->stat.st_size!=cc.object_stat.st_size ||
       o->stat.st_mode!=cc.object_stat.st_mode)return LI2_FETCH_BACKING;
    fetch.progress.validation=(struct li2_fetch_map_progress){0};
    fetch.progress.last_backing_page=0;fetch.progress.last_backing_observed=1;
    if((e=fetch_backing_check(p,&fetch.last_backing)))return e;
    const volatile unsigned char *source=(const void *)fetch.pc;
    for(size_t i=0;i<fetch.requested;i++)if(source[i]!=fetch.bytes[i])
        return fetch_error(LI2_FETCH_SOURCE,(long)i);
    if(CUSTODY_LOAD(&custody_stats.epoch)!=cc.ticket)return LI2_FETCH_STALE;
    if((e=custody_increment(&cc_stats.retained_checks)))return e;
    ++rx_current.stage.custody.checks;return 0;
}
int li2_lifecycle_fetch_rx_stage_current_custody(const struct li2_fetch_ref *ref,uintptr_t pc,
        const struct li2_custody_owner *k,const struct li2_fetch_rx_view **out) {
    if(!out)return cc_error(LI2_FETCH_ARGUMENT);
    *out=0;int e=custody_owner_live(k,ref,1);if(e)return cc_error(e);
    unsigned phase=CUSTODY_LOAD(&custody_stats.phase);
    if(phase==LI2_CUSTODY_EMPTY) {
        CUSTODY_STORE(&cc.bound,0);
        if((e=custody_increment(&cc_stats.attempts)))return cc_error(e);
        if(cc_serial==UINT64_MAX)return cc_error(LI2_FETCH_STATE);
        const struct li2_fetch_rx_current_view *v=0;
        e=li2_lifecycle_fetch_rx_current_stage(ref,pc,&v);
        if(e==LI2_MAPS_CURRENT_UNAVAILABLE) {
            if((e=custody_increment(&cc_stats.physical_fallbacks)))return cc_error(e);
            return LI2_MAPS_CURRENT_UNAVAILABLE;
        }
        if(e)return cc_error(e);
        if(v!=&rx_current || (e=cc_seed(k,ref)))return cc_error(e?e:LI2_FETCH_STALE);
        *out=&rx_current.stage;return 0;
    }
    if(!li2_current_custody_owned()) {
        /* A physical custody continuation is never converted to current kind. */
        if(cc_physical_entry())return LI2_MAPS_CURRENT_UNAVAILABLE;
        return cc_error(LI2_FETCH_STATE);
    }
    if(phase!=LI2_CUSTODY_ENTRY || !cc_owner_same(k) || cc.owner.event==UINT64_MAX ||
       k->event!=cc.owner.event+1 || ref->sequence!=cc.sequence ||
       rx_current.stage.phase!=LI2_RX_COMMITTED || rx_current.stage.after_sequence!=ref->sequence ||
       rx_current.stage.serial!=cc.serial ||
       !custody_equal(&k->owner->request,&cc.previous,sizeof cc.previous) ||
       rx_serial==UINT64_MAX || cc_serial==UINT64_MAX || fetch_sequence==UINT64_MAX)return cc_error(LI2_FETCH_STALE);
    uintptr_t page=cc.original.address;
    if(pc<page || pc-page>=PAGE)return cc_error(LI2_FETCH_ARGUMENT);
    if((e=cc_phase(LI2_CUSTODY_ENTRY,LI2_CUSTODY_BUILDING)))return cc_error(e);
    size_t bytes=PAGE-(pc-page);if(bytes>15)bytes=15;
    rx_current=(struct li2_fetch_rx_current_view){.version=1,.borrow=*ref,
        .stage={.phase=LI2_RX_STAGING,.serial=++cc_serial,.before_sequence=ref->sequence,.pc=pc,.length=bytes}};
    cc.owner.event=k->event;cc.serial=rx_current.stage.serial;cc_receipt(LI2_CUSTODY_CURRENT_RETAINED);
    li2_maps_phase_end();
    if((e=li2_maps_phase_begin()) || (e=cc_validate(ref)))return cc_error(e);
    cc_candidate=fetch;cc_candidate.pc=pc;cc_candidate.requested=bytes;
    cc_candidate.progress=(struct li2_fetch_progress){.identity_observed=1,.pages_copied=1};
    cc_candidate.pages[0]=cc.page;cc_candidate.backing[0]=fetch.last_backing;
    for(size_t i=0;i<sizeof cc_candidate.bytes;i++)cc_candidate.bytes[i]=0;
    const volatile unsigned char *source=(const void *)pc;
    for(size_t i=0;i<bytes;i++) {
        unsigned char byte=source[i];cc_candidate.bytes[i]=byte;rx_current.stage.bytes[i]=byte;
        cc_candidate.progress.bytes_copied=i+1;
    }
    cc_candidate.progress.complete=1;rx_current.stage.pid=fetch.pid;rx_current.stage.tid=fetch.tid;
    rx_current.stage.page=cc_candidate.pages[0];rx_current.stage.backing=cc_candidate.backing[0];
    if((e=custody_increment(&cc_stats.retained_stages)) ||
       (e=cc_phase(LI2_CUSTODY_BUILDING,LI2_CUSTODY_STAGED)))return cc_error(e);
    rx_current.complete=rx_current.stage.complete=1;__asm__ volatile("":::"memory");rx_current.stage.phase=LI2_RX_STAGED;
    *out=&rx_current.stage;return 0;
}
static int cc_binding(const struct li2_fetch_ref *ref,const struct li2_fetch_rx_view *v) {
    int e=fetch_ref(ref);if(e)return e;
    if(!cc_receipt_live(v) || v->phase!=LI2_RX_STAGED ||
       !rx_current.complete || rx_current.result || !v->complete || v->result ||
       v->before_sequence!=ref->sequence || cc_candidate.progress.held ||
       !cc_candidate.progress.complete || cc_candidate.page_count!=1 ||
       cc_candidate.pc!=v->pc || cc_candidate.requested!=v->length ||
       !fetch_owned_equal(&cc_candidate.original[0],&fetch.original[0]))return LI2_FETCH_STALE;
    return 0;
}
int li2_lifecycle_fetch_rx_cancel_current_custody(const struct li2_fetch_ref *ref,const struct li2_fetch_rx_view *v) {
    int e=cc_binding(ref,v);if(e)return cc_error(e);
    if(CUSTODY_LOAD(&custody_stats.phase)!=LI2_CUSTODY_EMPTY ||
       custody_stats.last_reason!=LI2_CUSTODY_MISS)return cc_error(LI2_FETCH_STATE);
    rx_current.stage.phase=LI2_RX_CANCELLED;CUSTODY_STORE(&cc.bound,0);
    if((e=custody_increment(&cc_stats.cancels)))return cc_error(e);
    return 0;
}
int li2_lifecycle_fetch_rx_commit_current_custody(const struct li2_fetch_ref *ref,
        const struct li2_fetch_rx_view *v,const struct li2_custody_owner *k,struct li2_fetch_ref *out) {
    if(!out)return cc_error(LI2_FETCH_ARGUMENT);
    int e=custody_owner_live(k,ref,1);if(e)return cc_error(e);
    if((e=cc_binding(ref,v)))return cc_error(e);
    if(!cc_owner_same(k) || k->event!=cc.owner.event || cc.serial!=v->serial ||
       CUSTODY_LOAD(&custody_stats.phase)!=LI2_CUSTODY_STAGED ||
       !custody_equal(&k->owner->request,&cc.previous,sizeof cc.previous))return cc_error(LI2_FETCH_STALE);
    if(fetch_sequence==UINT64_MAX)return cc_error(LI2_FETCH_STATE);
    if(v->custody.kind==LI2_CUSTODY_CURRENT_SEED) {
        /* Preserve the second complete original cold validation, including all
           backing/source/alias predicates; no physical-FRESH claim is added. */
        if((e=li2_lifecycle_fetch_validate(ref,0,PROT_READ|PROT_EXEC)))return cc_error(e);
    } else if(v->custody.kind==LI2_CUSTODY_CURRENT_RETAINED) {
        if((e=cc_validate(ref)))return cc_error(e);
    } else return cc_error(LI2_FETCH_STATE);
    const volatile unsigned char *source=(const void *)cc_candidate.pc;
    for(size_t i=0;i<cc_candidate.requested;i++)
        if(source[i]!=cc_candidate.bytes[i] || source[i]!=v->bytes[i])
            return cc_error(fetch_error(LI2_FETCH_SOURCE,(long)i));
    rx_current.stage.phase=LI2_RX_COMMITTING;__asm__ volatile("":::"memory");
    cc_candidate.progress.held=1;cc_candidate.progress.sequence=++fetch_sequence;
    fetch=cc_candidate;*out=(struct li2_fetch_ref){&fetch,fetch.progress.sequence};
    rx_current.stage.after_sequence=fetch.progress.sequence;
    __asm__ volatile("":::"memory");rx_current.stage.phase=LI2_RX_COMMITTED;
    cc.sequence=out->sequence;
    if((e=cc_phase(LI2_CUSTODY_STAGED,LI2_CUSTODY_COMMITTED)))return cc_error(e);
    return 0;
}
int li2_lifecycle_fetch_rx_publish_current_custody(const struct li2_fetch_ref *ref,
        const struct li2_fetch_rx_view *v,const struct li2_custody_owner *k) {
    int e=custody_owner_live(k,ref,0);if(e)return cc_error(e);
    if(!cc_receipt_live(v) || v->phase!=LI2_RX_COMMITTED || !cc_owner_same(k) ||
       k->event!=cc.owner.event || cc.serial!=v->serial || ref->sequence!=cc.sequence ||
       v->after_sequence!=ref->sequence || k->owner->request.page_count!=cc.opening.page_count ||
       !custody_equal(k->owner->request.pages,cc.opening.pages,sizeof cc.opening.pages))return cc_error(LI2_FETCH_STALE);
    cc.previous=k->owner->request;
    if(v->custody.kind==LI2_CUSTODY_CURRENT_SEED && (e=custody_increment(&cc_stats.current_seeds)))return cc_error(e);
    if((e=custody_increment(&cc_stats.commits)) || (e=cc_phase(LI2_CUSTODY_COMMITTED,LI2_CUSTODY_RETURN)))return cc_error(e);
    return 0;
}
int li2_current_custody_return(const void *chain) {
    if(!li2_current_custody_owned() || CUSTODY_LOAD(&custody_stats.phase)!=LI2_CUSTODY_RETURN ||
       chain!=cc.owner.chain || !cc_receipt_live(&rx_current.stage) ||
       rx_current.stage.phase!=LI2_RX_COMMITTED || !rx_current.stage.complete ||
       rx_current.result || rx_current.stage.result ||
       rx_current.stage.after_sequence!=cc.sequence)return cc_error(LI2_FETCH_STATE);
    struct li2_fetch_ref ref={&fetch,cc.sequence};
    int e=custody_owner_live(&cc.owner,&ref,0);
    if(e || !cc_owner_same(&cc.owner) ||
       !custody_equal(&cc.owner.owner->request,&cc.previous,sizeof cc.previous))return cc_error(e?e:LI2_FETCH_STALE);
    e=cc_phase(LI2_CUSTODY_RETURN,LI2_CUSTODY_READY);return e?cc_error(e):0;
}
