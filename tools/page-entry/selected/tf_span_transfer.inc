/* Distinct actual TRACE capability, included after the unchanged chain body.
   The bridge's complete strict PT_LOAD registration protects this storage. */
#include "tf_span_transfer.h"
struct li2_tf_span_transfer {
    struct li2_tf_chain *chain;
    struct li2_step_session *session;
    struct li2_step_session saved_session;
    volatile unsigned valid;
    struct li2_span_transfer_progress progress;
    siginfo_t signal;
    ucontext_t incoming,closed;
    struct li2_step_frame frame;
};
static struct li2_tf_span_transfer span_transfer;
static uint64_t span_transfer_serial;
static int span_error(unsigned code,long detail) {
    struct li2_span_transfer_progress *p=&span_transfer.progress;
    if(!p->first_error){p->first_error=code;p->first_detail=detail;}
    return (int)p->first_error;
}
static void span_event_boundary(void) {
    __atomic_store_n(&span_transfer.valid,0,__ATOMIC_RELEASE);
}
static void span_handler_end(struct li2_tf_chain *c) {
#ifdef LI2_LINKED_EPOCH
    const struct li2_span_transfer_progress *p=&span_transfer.progress;
    /* A later event can install another real owner. Check this consumed
       terminal only in the handler that issued it, before guest execution. */
    if(p->phase==LI2_ST_REFAULT && p->event==c->event_id)
        chain_need(c,span_transfer.chain==c && p->issued==1 &&
            p->refault_attempted==1 && p->refaulted==1 &&
            !p->consume_attempted && !p->consumed &&
            !p->resume_attempted && !p->resumed && !p->successor_installed &&
            !p->first_error && !c->pending && !c->in_handler &&
            !li2_lifecycle_fetch_interlock() &&
            p->fresh.complete && !p->fresh.progress.held &&
            p->fresh.ref.sequence==p->fresh_borrow &&
            p->fresh_borrow>p->previous_borrow,LI2_ST_STATE,2);
#endif
    chain_need(c,!__atomic_load_n(&span_transfer.valid,__ATOMIC_ACQUIRE) &&
        span_transfer.progress.phase!=LI2_ST_CLOSING &&
        span_transfer.progress.phase!=LI2_ST_CLOSED &&
        span_transfer.progress.phase!=LI2_ST_RESUMING,LI2_ST_STATE,1);
}
const struct li2_span_transfer_progress *li2_tf_chain_span_progress(void) {
    return &span_transfer.progress;
}
static int span_page_equal(const struct li2_fetch_page *a,const struct li2_fetch_page *b) {
    return a->address==b->address && a->allocation==b->allocation && a->generation==b->generation &&
        a->offset==b->offset && a->initial_extent==b->initial_extent && a->backing==b->backing &&
        a->object==b->object && a->logical==b->logical && a->closed_prot==b->closed_prot &&
        a->vma_first==b->vma_first && a->vma_end==b->vma_end && a->vma_major==b->vma_major &&
        a->vma_minor==b->vma_minor && a->vma_inode==b->vma_inode && a->vma_offset==b->vma_offset;
}
static int span_frame_equal(int sig,const siginfo_t *si,const ucontext_t *uc) {
    const struct li2_tf_span_transfer *t=&span_transfer;
    return sig==SIGTRAP && si && uc && si->si_signo==SIGTRAP &&
        si->si_code==TRAP_TRACE && !si->si_errno &&
        uc->uc_mcontext.gregs[REG_TRAPNO]==1 && !uc->uc_mcontext.gregs[REG_ERR] &&
        (uintptr_t)si->si_addr==t->progress.pc &&
        (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==t->progress.pc &&
        (uint64_t)uc->uc_mcontext.gregs[REG_EFL]==t->progress.flags &&
        equal(si,&t->signal,sizeof *si) && equal(uc,&t->closed,sizeof *uc) &&
        chain_frame_equal(&t->frame,uc,1);
}
static int span_origin(const struct li2_tf_span_transfer *t) {
    if(t!=&span_transfer || !t->chain || !t->session || t->progress.first_error ||
       t->progress.phase!=LI2_ST_CLOSED || t->progress.issued!=1 ||
       t->progress.consume_attempted || t->progress.consumed ||
       t->progress.resume_attempted || t->progress.resumed ||
       __atomic_load_n(&t->valid,__ATOMIC_ACQUIRE)!=1)return LI2_ST_ORIGIN;
#ifdef LI2_LINKED_EPOCH
    if(t->progress.refault_attempted || t->progress.refaulted)return LI2_ST_ORIGIN;
#endif
    const struct li2_tf_chain *c=t->chain;
    const struct li2_span_transfer_progress *e=&t->progress;
    if(e->previous>=2 || c->active!=(sig_atomic_t)e->previous ||
       c->session!=t->session || !equal(c->session,&t->saved_session,sizeof t->saved_session) ||
       !e->serial || e->serial!=span_transfer_serial || !e->event || e->event!=c->event_id ||
       c->pending || c->in_handler || c->first_error || !chain_registered_ok(c))return LI2_ST_ORIGIN;
    const struct li2_tf_chain_slot *p=&c->slots[e->previous];
    if(!chain_closed(p) || p->generation!=e->previous_generation ||
       p->fetch.ref.sequence!=e->previous_borrow || p->owner.actual_post_pc!=e->pc ||
       (p->owner.actual_post_flags&~LI2_STEP_TF)!=e->flags ||
       !equal(&p->owner.step.after,&t->frame,sizeof t->frame) ||
       !e->released.complete || e->released.progress.held ||
       e->released.ref.owner!=p->fetch.ref.owner ||
       e->released.ref.sequence!=p->fetch.ref.sequence)return LI2_ST_ORIGIN;
    return li2_tf_chain_run_reuse_quiet(c,0);
}
int li2_tf_chain_span_quiet(const struct li2_tf_span_transfer *t) {
    return span_origin(t);
}
int li2_tf_chain_span_close(struct li2_tf_chain *c,int sig,siginfo_t *si,ucontext_t *uc,
                           const struct li2_tf_span_transfer **out) {
    if(!out)return LI2_ST_ARGUMENT;
    *out=0;
    if(!chain_registered_ok(c) || !c->pending || c->in_handler || c->first_error ||
       !si || !uc || __atomic_load_n(&span_transfer.valid,__ATOMIC_ACQUIRE) ||
       (span_transfer.progress.phase!=LI2_ST_IDLE &&
        span_transfer.progress.phase!=LI2_ST_CONSUMED &&
#ifdef LI2_LINKED_EPOCH
        span_transfer.progress.phase!=LI2_ST_RESUMED &&
        span_transfer.progress.phase!=LI2_ST_REFAULT))return LI2_ST_STATE;
#else
        span_transfer.progress.phase!=LI2_ST_RESUMED))return LI2_ST_STATE;
#endif
    if(span_transfer_serial==UINT64_MAX)return LI2_ST_OVERFLOW;
    struct li2_tf_chain_slot *p=chain_slot(c);
    if(p->phase!=LI2_CHAIN_EXECUTING || c->event_id<=p->event_id ||
       p->owner.step.phase!=LI2_STEP_RUNNING || p->owner.step.in_handler ||
       p->owner.step.request.page_count!=1 || p->fetch.page_count!=1 ||
       !p->fetch.ref.owner || !p->fetch.ref.sequence ||
       sig!=SIGTRAP || si->si_signo!=SIGTRAP || si->si_code!=TRAP_TRACE || si->si_errno ||
       uc->uc_mcontext.gregs[REG_TRAPNO]!=1 || uc->uc_mcontext.gregs[REG_ERR] ||
       (uintptr_t)si->si_addr!=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP] ||
       ((uint64_t)uc->uc_mcontext.gregs[REG_EFL]&(LI2_STEP_TF|LI2_STEP_RF))!=LI2_STEP_TF)
        return LI2_ST_ORIGIN;
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    uintptr_t page=p->owner.step.request.pages[0].address;
    if(pc<page || pc-page>LI2_STEP_PAGE-15)return LI2_ST_ORIGIN;
    /* New caller's busy guard is already visible. From here all fallible old
       operations retain the actual old chain cleanup prefix and terminate. */
#ifdef LI2_SPAN_FAST_BYTES
    /* Valid remains zero and the caller's CLOSING prefix remains installed
       through the entire volatile assembly clear; no ticket is issued here. */
    li2_span_bytes_zero(&span_transfer,sizeof span_transfer);
#else
    volatile unsigned char *zero=(void *)&span_transfer;
    for(size_t i=0;i<sizeof span_transfer;i++)zero[i]=0;
#endif
    struct li2_tf_span_transfer *t=&span_transfer;
    t->chain=c;t->session=c->session;copy(&t->saved_session,c->session,sizeof t->saved_session);
    struct li2_span_transfer_progress *e=&t->progress;
    e->phase=LI2_ST_CLOSING;e->serial=++span_transfer_serial;e->event=c->event_id;
    e->previous=(unsigned)c->active;e->previous_generation=p->generation;
    e->previous_borrow=p->fetch.ref.sequence;e->pc=pc;
    copy(&t->signal,si,sizeof *si);copy(&t->incoming,uc,sizeof *uc);
    c->in_handler=1;
#ifdef LI2_TF_SEALED_CUSTODY
    li2_page_custody_discard(LI2_CUSTODY_MISS);
#endif
    p->phase=LI2_CHAIN_CLOSING;li2_tf_trace(&p->owner,sig,si,uc);
    chain_observe(&p->fetch);
    chain_need(c,chain_trace_closed(p) && chain_frame_equal(&p->owner.step.after,uc,1),LI2_CHAIN_FRAME,4);
    chain_release(c,p,&p->release);p->phase=LI2_CHAIN_CLOSED;
    chain_need(c,chain_closed(p) && chain_frame_equal(&p->owner.step.after,uc,1),LI2_CHAIN_FRAME,4);
#ifdef LI2_TF_SAME_PAGE_LEASE
    chain_same_page_closed(c,p);
#endif
    chain_count(c,&c->steps);c->pending=0;
    copy(&t->frame,&p->owner.step.after,sizeof t->frame);
    copy(&t->closed,uc,sizeof *uc);e->flags=(uint64_t)uc->uc_mcontext.gregs[REG_EFL];
    /* Compare the entire same-event raw UC, with only the old owner's exact
       TF edit in this local expectation; retain both actual copies above. */
    ucontext_t expected;copy(&expected,&t->incoming,sizeof expected);
    expected.uc_mcontext.gregs[REG_EFL]&=~LI2_STEP_TF;
    chain_need(c,equal(&expected,uc,sizeof expected) && equal(&t->signal,si,sizeof *si) &&
        !(e->flags&(LI2_STEP_TF|LI2_STEP_RF)),LI2_ST_FRAME,0);
    int error=li2_lifecycle_span_fetch_snapshot(&e->released);
    chain_need(c,!error && e->released.complete && !e->released.progress.held &&
        e->released.ref.owner==p->fetch.ref.owner &&
        e->released.ref.sequence==p->fetch.ref.sequence,LI2_ST_FETCH,error);
    c->in_handler=0;e->phase=LI2_ST_CLOSED;e->issued=1;
    __atomic_store_n(&t->valid,1,__ATOMIC_RELEASE);
    chain_need(c,!span_origin(t) && span_frame_equal(sig,si,uc),LI2_ST_ORIGIN,1);
    *out=t;return 0;
}
static int span_fresh(unsigned held,struct li2_span_fetch_observation *out) {
    int error=li2_lifecycle_span_fetch_snapshot(out);if(error)return error;
    const struct li2_tf_span_transfer *t=&span_transfer;
    const struct li2_tf_chain_slot *p=&t->chain->slots[t->progress.previous];
    if(!out->complete || out->progress.held!=held || out->length!=15 || out->page_count!=1 ||
       out->pc!=t->progress.pc || out->pid!=t->saved_session.pid || out->tid!=t->saved_session.tid ||
       out->ref.owner!=t->progress.released.ref.owner ||
       out->ref.sequence<=t->progress.previous_borrow ||
       !span_page_equal(&out->pages[0],&p->query.page))return LI2_ST_FETCH;
    if(!held && (!out->progress.validation_calls || !out->progress.last_backing_observed))
        return LI2_ST_FETCH;
    return 0;
}
int li2_tf_chain_span_consume(const struct li2_tf_span_transfer *ticket,
                            struct li2_step_session *session,const struct li2_fetch_ref *ref,
                            uintptr_t pc,int sig,const siginfo_t *si,const ucontext_t *uc) {
    int error=span_origin(ticket);if(error)return span_error((unsigned)error,0);
    struct li2_tf_span_transfer *t=&span_transfer;
    if(!session || session!=t->session || !ref || pc!=t->progress.pc ||
       !span_frame_equal(sig,si,uc) || !identity(session))return span_error(LI2_ST_FRAME,1);
    if((error=span_fresh(1,&t->progress.fresh)))return span_error((unsigned)error,1);
    if(ref->owner!=t->progress.fresh.ref.owner || ref->sequence!=t->progress.fresh.ref.sequence)
        return span_error(LI2_ST_FETCH,2);
    t->progress.consume_attempted=1;
    if(__atomic_exchange_n(&t->valid,0,__ATOMIC_ACQ_REL)!=1)return span_error(LI2_ST_ORIGIN,2);
    t->progress.fresh_borrow=ref->sequence;t->progress.consumed=1;
    t->progress.phase=LI2_ST_CONSUMED;return 0;
}
int li2_tf_chain_span_resume(const struct li2_tf_span_transfer *ticket,int sig,siginfo_t *si,
                           ucontext_t *uc,enum li2_chain_result *result) {
    int error=span_origin(ticket);if(error)return span_error((unsigned)error,3);
    struct li2_tf_span_transfer *t=&span_transfer;
    /* No returning RAW precedes the installed successor. The actual fresh
       released snapshot binds identity here; chain_prepare and the unchanged
       arm path perform their real identity observations after chain_next. */
    if(!result || !span_frame_equal(sig,si,uc))
        return span_error(LI2_ST_FRAME,2);
    if((error=span_fresh(0,&t->progress.fresh)))return span_error((unsigned)error,4);
    t->progress.resume_attempted=1;
    if(__atomic_exchange_n(&t->valid,0,__ATOMIC_ACQ_REL)!=1)return span_error(LI2_ST_ORIGIN,3);
    t->progress.fresh_borrow=t->progress.fresh.ref.sequence;t->progress.phase=LI2_ST_RESUMING;
    struct li2_tf_chain *c=t->chain;unsigned previous=t->progress.previous;
    const struct li2_tf_chain_slot *p=&c->slots[previous];c->in_handler=1;
    /* chain_next installs the real successor/failure callback before prepare.
       All code below is the old genuine CLOSED-to-new-TRACE tail, not reset. */
    struct li2_tf_chain_slot *s=chain_next(c,previous^1);s->origin=2;
    t->progress.next=c->active;t->progress.successor_installed=1;
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
#ifdef LI2_EVENT_PROFILE
        li2_event_site(&s->fetch.pages[0],s->decoded.pc,s->decoded.code,s->fallback);
#endif
        chain_invalidate(c);chain_release(c,s,&s->release);
        chain_need(c,chain_frame_equal(&p->owner.step.after,uc,1),LI2_CHAIN_FRAME,6);
        s->phase=LI2_CHAIN_FALLBACK;chain_count(c,&c->fallbacks);c->pending=0;c->in_handler=0;
#if defined(LI2_EFFECT_PROVIDER) && defined(LI2_TF_HANDOFF) && defined(LI2_REGISTER_RUN)
        if(s->fallback==LI2_CHAIN_OLD_STEP)chain_run_offer(c,previous,sig,si,uc);
#endif
        *result=LI2_CHAIN_NX_FALLBACK;
    } else {
        uint64_t flags=(uint64_t)uc->uc_mcontext.gregs[REG_EFL];
        chain_arm(c,s,flags);chain_produce(c,previous,c->active,sig,si,uc);
        chain_begin_trace(c,sig,si,uc);*result=LI2_CHAIN_RUNNING;
    }
    t->progress.phase=LI2_ST_RESUMED;t->progress.resumed=1;return 0;
}
#ifdef LI2_LINKED_EPOCH
int li2_tf_chain_span_refault(const struct li2_tf_span_transfer *ticket,uint64_t serial,int sig,
                             const siginfo_t *si,const ucontext_t *uc) {
    /* The singleton pointer alone cannot distinguish a retained old handle. */
    if(ticket!=&span_transfer || !serial || serial!=span_transfer_serial ||
       serial!=span_transfer.progress.serial)return span_error(LI2_ST_ORIGIN,5);
    int error=span_origin(ticket);if(error)return span_error((unsigned)error,5);
    struct li2_tf_span_transfer *t=&span_transfer;
    /* Pure owner/frame/fetch checks only. The actual release already performed
       identity/maps/backing/source validation with expected PROT_READ. This
       snapshot rechecks its current lifecycle epochs and exact newer ref. */
    if(!span_frame_equal(sig,si,uc))return span_error(LI2_ST_FRAME,3);
    if(t->progress.successor_installed || li2_lifecycle_fetch_interlock())
        return span_error(LI2_ST_STATE,3);
    if((error=span_fresh(0,&t->progress.fresh)))return span_error((unsigned)error,5);
    t->progress.refault_attempted=1;
    if(__atomic_exchange_n(&t->valid,0,__ATOMIC_ACQ_REL)!=1)
        return span_error(LI2_ST_ORIGIN,4);
    t->progress.fresh_borrow=t->progress.fresh.ref.sequence;
    t->progress.refaulted=1;t->progress.phase=LI2_ST_REFAULT;return 0;
}
#endif
