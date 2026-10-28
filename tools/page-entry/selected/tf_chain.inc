/* Included by step_owner.c only in LI2_TF_HANDOFF builds. Reuses unchanged
   frame/identity/revoke helpers and the complete existing generic owner. */
#include "tf_chain.h"
static struct li2_tf_chain *chain_registered;
static void chain_invalidate(struct li2_tf_chain *c) {
    __atomic_store_n(&c->entry.valid,0,__ATOMIC_RELEASE);
}
static int chain_registered_ok(const struct li2_tf_chain *c) {
    return c && c==chain_registered && c->initialized && c->active>=0 && c->active<2;
}
static struct li2_tf_chain_slot *chain_slot(struct li2_tf_chain *c) {
    return &c->slots[c->active];
}
static void chain_first(struct li2_tf_chain *c,unsigned code,long detail) {
    if(!c->first_error){c->first_error=code;c->first_detail=detail;}
}
static void chain_owner_failure(void *context,const struct li2_step_owner *owner) {
    struct li2_tf_chain_slot *s=context;struct li2_tf_chain *c=s->chain;
    chain_invalidate(c);chain_first(c,owner->first_error,owner->first_detail);
    s->phase=LI2_CHAIN_FAILED;
    if(c->failure)c->failure(c);
}
_Noreturn void li2_tf_chain_abort(struct li2_tf_chain *c,unsigned code,long detail) {
#ifdef LI2_MAPS_PHASE_REUSE
    li2_maps_phase_fail();
#endif
    if(chain_registered_ok(c)) {
        chain_invalidate(c);chain_first(c,code,detail);
        struct li2_tf_chain_slot *s=chain_slot(c);s->phase=LI2_CHAIN_FAILED;
        if(s->owner.step.session && s->owner.step.phase!=LI2_STEP_COMPLETE)
            li2_tf_abort(&s->owner,code,detail);
        /* Preparation may fail before arm installs a step owner. No source
           opens in that phase; retain its occupied fetch prefix and fail. */
        if(c->failure)c->failure(c);
    }
    (void)RAW(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static void chain_need(struct li2_tf_chain *c,int yes,unsigned code,long detail) {
    if(!yes)li2_tf_chain_abort(c,code,detail);
}
static void chain_count(struct li2_tf_chain *c,uint64_t *counter) {
    chain_need(c,*counter!=UINT64_MAX,LI2_CHAIN_OVERFLOW,0);++*counter;
}
static void chain_stats(struct li2_tf_chain *c) {
    struct li2_decoder_stats now;
    chain_need(c,!li2_decoder_stats(&now) && equal(&now,&c->initial_stats,sizeof now),LI2_CHAIN_STATS,0);
}
/* Copy before release/reprepare can replace any singleton payload. A partial
   failure remains a partial observation; it never receives complete status. */
static void chain_observe(struct li2_chain_fetch *o) {
    const struct li2_fetch_progress *p=li2_lifecycle_fetch_progress();
    struct li2_fetch_view v={0};li2_lifecycle_fetch_partial_view(&v);
    o->progress=*p;o->pc=v.pc;o->length=v.length;o->page_count=v.page_count;
    o->pid=v.pid;o->tid=v.tid;o->identity_observed=v.identity_observed;
    if(v.length<=15 && v.bytes)copy(o->bytes,v.bytes,v.length);
    if(v.page_count<=2 && v.pages && v.backing)for(size_t i=0;i<v.page_count;i++) {
        o->pages[i]=v.pages[i];o->backing[i]=v.backing[i];
    }
    if(v.last_backing)o->last_backing=*v.last_backing;
}
static int chain_authenticate(void *context,const struct li2_step_page *p,int prot) {
    struct li2_tf_chain_slot *s=context;struct li2_tf_chain *c=s?s->chain:0;
    if(!chain_registered_ok(c) || s!=chain_slot(c) || !c->pending ||
       s->fetch.ref.sequence!=s->fetch.progress.sequence)return LI2_FETCH_STALE;
    for(size_t i=0;i<s->fetch.page_count;i++) {
        const struct li2_fetch_page *q=&s->fetch.pages[i];
        if(p->address==q->address && p->object==q->allocation && p->generation==q->generation &&
           p->offset==q->offset && p->closed_prot==PROT_READ && p->open_prot==(PROT_READ|PROT_EXEC)) {
            int r=li2_lifecycle_fetch_validate(&s->fetch.ref,i,prot);chain_observe(&s->fetch);return r;
        }
    }
    return LI2_FETCH_STALE;
}
static int chain_continue(void *context,uintptr_t pc) {
    struct li2_tf_chain_slot *s=context;struct li2_tf_chain *c=s?s->chain:0;
    if(!chain_registered_ok(c) || s!=chain_slot(c) || !c->pending)return LI2_FETCH_STALE;
    int r=li2_lifecycle_tf_continuation(&s->fetch.ref,pc,&s->query);
    chain_observe(&s->fetch);return r;
}
static int chain_frame_equal(const struct li2_step_frame *saved,const ucontext_t *uc,int clear_tf) {
    if(!uc || !saved->fp_bytes || saved->initialized!=saved->fp_bytes ||
       saved->fp_bytes>LI2_STEP_FP_BYTES || (uintptr_t)uc->uc_mcontext.fpregs!=saved->fp_address)return 0;
    uint64_t mask=0;copy(&mask,&uc->uc_sigmask,sizeof mask);
    if(mask!=saved->mask)return 0;
    for(size_t i=0;i<NGREG;i++) {
        greg_t expected=saved->greg[i];
        if(clear_tf && i==REG_EFL)expected&=~(greg_t)LI2_STEP_TF;
        if(uc->uc_mcontext.gregs[i]!=expected)return 0;
    }
    return equal(uc->uc_mcontext.fpregs,saved->fp,saved->fp_bytes);
}
static int chain_trace_closed(const struct li2_tf_chain_slot *s) {
    const struct li2_tf_owner *o=&s->owner;const struct li2_step_owner *p=&o->step;
    if(p->phase!=LI2_STEP_COMPLETE || p->first_error ||
       !p->trace_seen || !p->revoke_sync_started || p->revoke_sync ||
       !o->continuation_started || !o->continuation_complete || o->continuation_result ||
       !s->query.attempted || !s->query.page_observed || !s->query.complete || s->query.result ||
       s->query.pc!=o->actual_post_pc || s->fetch.progress.first_error ||
       s->fetch.progress.sequence!=s->fetch.ref.sequence)return 0;
    for(size_t i=0;i<p->request.page_count;i++)
        if(!p->open_started[i] || !p->opened[i] || !p->revoke_started[i] || !p->revoked[i])return 0;
    return p->request.page_count && p->request.page_count<=2;
}
static int chain_closed(const struct li2_tf_chain_slot *s) {
    return s->phase==LI2_CHAIN_CLOSED && chain_trace_closed(s) &&
        s->release.started && s->release.complete && !s->release.result && !s->fetch.progress.held;
}
static struct li2_tf_chain_slot *chain_next(struct li2_tf_chain *c,unsigned index) {
    struct li2_tf_chain_slot *s=&c->slots[index];
    chain_need(c,s->phase==LI2_CHAIN_EMPTY || chain_closed(s) ||
        (s->phase==LI2_CHAIN_FALLBACK && s->release.complete && !s->release.result &&
         !s->fetch.progress.held && !s->fetch.progress.first_error),LI2_CHAIN_STATE,s->phase);
    uint64_t generation=s->generation;chain_count(c,&generation);
    *s=(struct li2_tf_chain_slot){.chain=c,.index=index,.generation=generation,.event_id=c->event_id};
    /* Install callback cleanup context and slot identity before publishing
       PREPARING. Arm itself will install the step session/request. */
    s->owner.step.hooks=(struct li2_step_hooks){s,chain_authenticate,chain_owner_failure};
    __asm__ volatile("":::"memory");c->active=index;c->pending=1;
    __asm__ volatile("":::"memory");s->phase=LI2_CHAIN_PREPARING;
    return s;
}
static void chain_release(struct li2_tf_chain *c,struct li2_tf_chain_slot *s,
                          struct li2_chain_release *r) {
    chain_need(c,!r->started && !r->complete,LI2_CHAIN_STATE,1);
    r->started=1;r->result=li2_lifecycle_fetch_release(&s->fetch.ref);
    chain_observe(&s->fetch);
    chain_need(c,!r->result,LI2_CHAIN_RELEASE,r->result);
    r->complete=1;chain_count(c,&c->releases);
}
static void chain_capture_borrow(struct li2_tf_chain *c,struct li2_tf_chain_slot *s) {
    struct li2_fetch_view v={0};int result=li2_lifecycle_fetch_view(&s->fetch.ref,&v);
    chain_observe(&s->fetch);
    chain_need(c,!result && s->fetch.progress.held && s->fetch.progress.complete &&
       !s->fetch.progress.first_error && s->fetch.progress.sequence==s->fetch.ref.sequence &&
       v.length && v.length<=15 && v.page_count && v.page_count<=2 &&
       v.pid==c->session->pid && v.tid==c->session->tid && v.identity_observed,
       LI2_CHAIN_PREPARE,result);
}
static void chain_decode(struct li2_tf_chain *c,struct li2_tf_chain_slot *s) {
    s->decode_attempted=1;
    s->decode_result=(int)li2_decoder_decode(s->fetch.pc,s->fetch.bytes,s->fetch.length,&s->decoded);
    chain_need(c,!s->decode_result,LI2_CHAIN_DECODE,s->decode_result);
    s->decode_complete=1;chain_stats(c);
    chain_need(c,s->decoded.abi_version==1 && !s->decoded.reserved &&
       s->decoded.pc==s->fetch.pc && s->decoded.available==s->fetch.length &&
       s->decoded.decode_status<=LI2_TRUNCATED,LI2_CHAIN_DECODE,1);
    if(s->decoded.decode_status==LI2_VALID)
        chain_need(c,s->decoded.length && s->decoded.length<=s->fetch.length &&
           s->decoded.pc<=UINTPTR_MAX-s->decoded.length &&
           s->decoded.next_pc==s->decoded.pc+s->decoded.length &&
           equal(s->decoded.bytes,s->fetch.bytes,s->decoded.length),LI2_CHAIN_DECODE,2);
}
static void chain_prepare(struct li2_tf_chain *c,struct li2_tf_chain_slot *s,uintptr_t pc) {
    size_t bytes=LI2_STEP_PAGE-(pc&(LI2_STEP_PAGE-1));if(bytes>15)bytes=15;
    s->prepare_attempted=1;chain_count(c,&c->prepare_attempts);
    s->prepare_result=li2_lifecycle_fetch_prepare(pc,bytes,&s->fetch.ref);
    chain_observe(&s->fetch);
    chain_need(c,!s->prepare_result,LI2_CHAIN_PREPARE,s->prepare_result);
    chain_capture_borrow(c,s);chain_decode(c,s);
    if(s->decoded.decode_status==LI2_TRUNCATED && bytes<15) {
        s->first_decoded=s->decoded;
        chain_release(c,s,&s->first_release);s->first_fetch=s->fetch;s->retry=1;
        s->fetch=(struct li2_chain_fetch){0};chain_count(c,&c->prepare_attempts);
        s->prepare_result=li2_lifecycle_fetch_prepare(pc,15,&s->fetch.ref);chain_observe(&s->fetch);
        chain_need(c,!s->prepare_result,LI2_CHAIN_PREPARE,s->prepare_result);
        chain_capture_borrow(c,s);chain_decode(c,s);
    }
    s->prepare_complete=1;
}
static void chain_arm(struct li2_tf_chain *c,struct li2_tf_chain_slot *s,uint64_t flags) {
    struct li2_step_request request={.decoded=s->decoded,.original_flags=flags};
    uintptr_t first_page=s->decoded.pc&~(LI2_STEP_PAGE-1),last=(s->decoded.next_pc-1)&~(LI2_STEP_PAGE-1);
    request.page_count=first_page==last?1:2;
    chain_need(c,request.page_count<=s->fetch.page_count,LI2_STEP_PAGE_BINDING,0);
    for(size_t i=0;i<request.page_count;i++) {
        const struct li2_fetch_page *p=&s->fetch.pages[i];
        request.pages[i]=(struct li2_step_page){p->address,p->allocation,p->generation,p->offset,PROT_READ,PROT_READ|PROT_EXEC};
    }
    struct li2_tf_hooks hooks={{s,chain_authenticate,chain_owner_failure},chain_continue};
    s->phase=LI2_CHAIN_ARMING;chain_count(c,&c->attempts);
    int result=li2_tf_arm(&s->owner,c->session,&hooks,&request);
    if(result)li2_tf_chain_abort(c,(unsigned)result,0);
    chain_stats(c);
}
int li2_tf_chain_init(struct li2_tf_chain *c,struct li2_step_session *session,
                      void (*failure)(const struct li2_tf_chain *)) {
    if(!c || !session || !failure || chain_registered || c->initialized ||
       !session->initialized || !identity(session))return LI2_CHAIN_ARGUMENT;
    if(li2_decoder_stats(&c->initial_stats) || c->initial_stats.phase!=2)return LI2_CHAIN_STATS;
    c->session=session;c->failure=failure;
    for(unsigned i=0;i<2;i++){c->slots[i].chain=c;c->slots[i].index=i;}
    chain_registered=c;__asm__ volatile("":::"memory");c->initialized=1;return 0;
}
void li2_tf_chain_event_boundary(struct li2_tf_chain *c) {
    if(!c || !c->initialized)return;
    chain_invalidate(c);chain_need(c,chain_registered_ok(c),LI2_CHAIN_ARGUMENT,0);
    chain_count(c,&c->event_id);
}
void li2_tf_chain_handler_end(struct li2_tf_chain *c) {
    if(!c || !c->initialized)return;
    chain_invalidate(c);chain_need(c,!c->in_handler,LI2_CHAIN_STATE,2);
}
void li2_tf_chain_begin_nx(struct li2_tf_chain *c,const struct li2_fetch_ref *ref,
                          const struct li2_decoded *d,uint64_t flags,int sig,siginfo_t *si,ucontext_t *uc) {
    chain_need(c,chain_registered_ok(c) && ref && d && !c->pending && !c->in_handler &&
       c->event_id && !c->first_error && c->session->self_test_complete,LI2_CHAIN_STATE,3);
    chain_invalidate(c);c->in_handler=1;
    unsigned old_phase=c->slots[c->active].phase;
    unsigned index=(old_phase==LI2_CHAIN_EMPTY || old_phase==LI2_CHAIN_FALLBACK)?c->active:c->active^1;
    struct li2_tf_chain_slot *s=chain_next(c,index);s->origin=1;s->fetch.ref=*ref;
    chain_capture_borrow(c,s);chain_decode(c,s);
    chain_need(c,equal(d,&s->decoded,sizeof *d),LI2_CHAIN_DECODE,3);
    s->prepare_complete=1;chain_count(c,&c->nx_entries);chain_arm(c,s,flags);
    li2_tf_begin_observed_shstk(&s->owner,sig,si,uc);
    chain_observe(&s->fetch);s->phase=LI2_CHAIN_EXECUTING;c->in_handler=0;
}
/* A proof exists only after the real old TRACE has completely closed and its
   actual borrow has released. Nothing can publish one from scalar flags. */
static void chain_produce(struct li2_tf_chain *c,unsigned previous,unsigned next,
                          int sig,const siginfo_t *si,const ucontext_t *uc) {
    const struct li2_tf_chain_slot *p=&c->slots[previous];
    chain_need(c,chain_closed(p) && sig==SIGTRAP && si && si->si_signo==SIGTRAP &&
       si->si_code==TRAP_TRACE && !si->si_errno && uc &&
       uc->uc_mcontext.gregs[REG_TRAPNO]==1 && !uc->uc_mcontext.gregs[REG_ERR] &&
       (uintptr_t)si->si_addr==p->owner.actual_post_pc &&
       chain_frame_equal(&p->owner.step.after,uc,1) && identity(c->session),LI2_CHAIN_ORIGIN,0);
    uint64_t flags=(uint64_t)uc->uc_mcontext.gregs[REG_EFL];
    chain_need(c,!(flags&(LI2_STEP_TF|LI2_STEP_RF)) &&
       flags==(p->owner.actual_post_flags&~LI2_STEP_TF),LI2_CHAIN_ORIGIN,1);
    chain_count(c,&c->sequence);
    c->entry.previous=previous;c->entry.next=next;c->entry.event_id=c->event_id;
    c->entry.sequence=c->sequence;c->entry.previous_generation=p->generation;
    c->entry.next_generation=c->slots[next].generation;c->entry.pc=p->owner.actual_post_pc;
    c->entry.flags=flags;c->entry.previous_borrow_sequence=p->fetch.ref.sequence;
    /* Every field and copied owner is installed before signal-visible valid. */
    __atomic_store_n(&c->entry.valid,1,__ATOMIC_RELEASE);
}
static void chain_begin_trace(struct li2_tf_chain *c,int sig,siginfo_t *si,ucontext_t *uc) {
    unsigned usable=__atomic_exchange_n(&c->entry.valid,0,__ATOMIC_ACQ_REL);
    struct li2_tf_trace_entry *e=&c->entry;
    chain_need(c,usable==1 && e->previous<2 && e->next==(unsigned)c->active && e->previous!=e->next &&
       e->event_id==c->event_id && e->sequence==c->sequence && c->in_handler && c->pending,
       LI2_CHAIN_ORIGIN,2);
    struct li2_tf_chain_slot *s=chain_slot(c);const struct li2_tf_chain_slot *p=&c->slots[e->previous];
    chain_need(c,chain_closed(p) && p->generation==e->previous_generation &&
       s->generation==e->next_generation && p->fetch.ref.sequence==e->previous_borrow_sequence &&
       s->decoded.pc==e->pc && s->owner.step.request.original_flags==e->flags &&
       li2_tf_entry_route(&s->decoded)==LI2_TF_ENTRY_PLAIN &&
       chain_frame_equal(&p->owner.step.after,uc,1),LI2_CHAIN_ORIGIN,3);
    struct li2_step_owner *o=&s->owner.step;
    enter(o,LI2_STEP_ARMED,sig,si,uc);
    require(o,sig==SIGTRAP && si->si_signo==SIGTRAP && si->si_code==TRAP_TRACE && !si->si_errno &&
       uc->uc_mcontext.gregs[REG_TRAPNO]==1 && !uc->uc_mcontext.gregs[REG_ERR] &&
       (uintptr_t)si->si_addr==e->pc && (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==e->pc &&
       ((uint64_t)uc->uc_mcontext.gregs[REG_CSGSFS]&0xffff)==0x33 &&
       (uint64_t)uc->uc_mcontext.gregs[REG_EFL]==e->flags,LI2_CHAIN_ORIGIN,4);
    frame(o,&o->before,uc);
    require(o,equal((const void *)e->pc,o->request.decoded.bytes,o->request.decoded.length),LI2_STEP_PAGE_BINDING,2);
    o->phase=LI2_STEP_OPENING;
    for(size_t i=0;i<o->request.page_count;i++) {
        const struct li2_step_page *page=&o->request.pages[i];
        require(o,!o->hooks.authenticate(o->hooks.context,page,page->closed_prot),LI2_STEP_PAGE_BINDING,(long)i);
        require(o,chain_frame_equal(&o->before,uc,0),LI2_CHAIN_FRAME,1);
        o->open_started[i]=1;
        o->open_result[i]=RAW(SYS_mprotect,page->address,LI2_STEP_PAGE,page->open_prot,0,0,0);
        require(o,!o->open_result[i],LI2_STEP_OPEN,o->open_result[i]);o->opened[i]=1;
        require(o,!o->hooks.authenticate(o->hooks.context,page,page->open_prot),LI2_STEP_PAGE_BINDING,(long)i);
        require(o,chain_frame_equal(&o->before,uc,0),LI2_CHAIN_FRAME,2);
    }
    o->open_sync=RAW(SYS_membarrier,32,0,0,0,0,0);
    require(o,!o->open_sync,LI2_STEP_SYNC_OPEN,o->open_sync);
    require(o,chain_frame_equal(&o->before,uc,0),LI2_CHAIN_FRAME,3);
    uc->uc_mcontext.gregs[REG_EFL]|=LI2_STEP_TF;
    o->phase=LI2_STEP_RUNNING;o->in_handler=0;s->phase=LI2_CHAIN_EXECUTING;
    chain_count(c,&c->trace_entries);c->in_handler=0;
}
enum li2_chain_result li2_tf_chain_trace(struct li2_tf_chain *c,int sig,siginfo_t *si,ucontext_t *uc) {
    chain_need(c,chain_registered_ok(c) && c->pending && !c->in_handler && !c->first_error,
               LI2_CHAIN_STATE,4);
    c->in_handler=1;unsigned previous=c->active;struct li2_tf_chain_slot *p=chain_slot(c);
    chain_need(c,p->phase==LI2_CHAIN_EXECUTING && c->event_id>p->event_id,LI2_CHAIN_ORIGIN,5);
    p->phase=LI2_CHAIN_CLOSING;li2_tf_trace(&p->owner,sig,si,uc);
    chain_observe(&p->fetch);
    chain_need(c,chain_trace_closed(p) && chain_frame_equal(&p->owner.step.after,uc,1),LI2_CHAIN_FRAME,4);
    chain_release(c,p,&p->release);p->phase=LI2_CHAIN_CLOSED;
    chain_need(c,chain_closed(p) && chain_frame_equal(&p->owner.step.after,uc,1),LI2_CHAIN_FRAME,4);
    chain_count(c,&c->steps);c->pending=0;
    struct li2_tf_chain_slot *s=chain_next(c,previous^1);s->origin=2;
    /* Predecessor has no singleton pointers. A new preparation can safely
       replace fetch storage; failures now belong to the installed successor. */
    chain_prepare(c,s,p->owner.actual_post_pc);
    chain_need(c,chain_frame_equal(&p->owner.step.after,uc,1),LI2_CHAIN_FRAME,5);
    if(s->decoded.decode_status==LI2_INVALID)s->fallback=LI2_CHAIN_DECODE_INVALID;
    else if(s->decoded.decode_status==LI2_TRUNCATED)s->fallback=LI2_CHAIN_DECODE_TRUNCATED;
    else if(s->decoded.kind!=LI2_NONE)s->fallback=LI2_CHAIN_SELECTED;
    else if(s->decoded.step_disposition==LI2_STEP_CANDIDATE &&
        !(s->decoded.length==2 && s->decoded.bytes[0]==0x66 && s->decoded.bytes[1]==0x90))
        s->fallback=LI2_CHAIN_OLD_STEP;
    else if(li2_tf_entry_route(&s->decoded)!=LI2_TF_ENTRY_PLAIN)s->fallback=LI2_CHAIN_NOT_PLAIN;
    else {
        s->classify_result=(int)li2_decoder_tf_classify(s->decoded.pc,s->decoded.bytes,
                                                     s->decoded.available,&s->descriptive_classification);
        chain_need(c,!s->classify_result,LI2_CHAIN_DECODE,s->classify_result);chain_stats(c);
        const struct li2_tf_classification *a=&s->descriptive_classification;
        chain_need(c,a->abi_version==1 && a->pc==s->decoded.pc && a->next_pc==s->decoded.next_pc &&
            a->code==s->decoded.code && a->length==s->decoded.length,LI2_CHAIN_DECODE,4);
        if(!a->policy)s->fallback=LI2_CHAIN_NOT_CLASSIFIED;
        else chain_need(c,a->policy==1,LI2_CHAIN_DECODE,5);
    }
    if(s->fallback) {
        chain_invalidate(c);chain_release(c,s,&s->release);
        chain_need(c,chain_frame_equal(&p->owner.step.after,uc,1),LI2_CHAIN_FRAME,6);
        s->phase=LI2_CHAIN_FALLBACK;chain_count(c,&c->fallbacks);c->pending=0;c->in_handler=0;
        return LI2_CHAIN_NX_FALLBACK;
    }
    uint64_t flags=(uint64_t)uc->uc_mcontext.gregs[REG_EFL];
    chain_arm(c,s,flags);chain_produce(c,previous,c->active,sig,si,uc);
    chain_begin_trace(c,sig,si,uc);return LI2_CHAIN_RUNNING;
}
_Noreturn void li2_tf_chain_unexpected(struct li2_tf_chain *c,int sig,siginfo_t *si,ucontext_t *uc) {
#ifdef LI2_MAPS_PHASE_REUSE
    li2_maps_phase_fail();
#endif
    chain_invalidate(c);chain_count(c,&c->unexpected_events);
    struct li2_tf_chain_slot *s=chain_slot(c);struct li2_step_owner *o=&s->owner.step;
    /* Capture the actual frame even during preparation/opening; it does not
       become a completed TRACE. Never overwrite predecessor's retained frame. */
    if(si){s->unexpected_signal=sig;s->unexpected_code=si->si_code;
        s->unexpected_errno=si->si_errno;s->unexpected_address=(uintptr_t)si->si_addr;}
    if(uc){frame(o,&s->unexpected,uc);s->unexpected_frame_observed=1;}
    li2_tf_chain_abort(c,LI2_STEP_FOREIGN_EVENT,sig);
}
