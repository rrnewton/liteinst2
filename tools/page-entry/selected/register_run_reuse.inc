/* Included in register_run_publish.c only. No externally writable permit or
   scalar authority constructor; old owner and publisher layouts stay exact. */
#ifdef LI2_RUN_REUSE_TYPES
enum reuse_lease_phase {
    REUSE_NO_LEASE,REUSE_CLAIMED,REUSE_ARMING,REUSE_ARMED,
    REUSE_ENTERING,REUSE_RUNNING,REUSE_EXITING,REUSE_EXIT_OBSERVED,
    REUSE_RESET_READY
};
struct reuse_permit {
    uint64_t generation,completion;
    struct li2_run_handle handle;
    unsigned valid;
};
struct reuse_private {
    unsigned enabled,lookup,reset_pending,retiring;
    enum reuse_lease_phase lease;
    struct li2_run_owner *owner;
    struct li2_run_completion_history *history;
    struct li2_fetch_ref borrow;
    struct li2_run_handle current;
    uint64_t flags,generation,completions,copied_instructions,retirements;
    uint64_t live[LI2_RUN_CACHE_PAGES];
    uint64_t attempts[LI2_RUN_CACHE_PAGES];
    struct reuse_permit permits[LI2_RUN_CACHE_PAGES];
    size_t cursor;
    struct li2_run_retirement retirement;
    /* Transient exact completion, erased after issuance. Historical frames
       never constrain a later retirement after legitimate intervening work. */
    struct li2_run_owner completed;
};
static int reuse_failure(struct li2_run_cache *,unsigned,long);
#else
static int reuse_zero(const void *p,size_t n) {
    const unsigned char *b=p;
    for(size_t i=0;i<n;i++)if(b[i])return 0;
    return 1;
}
static void reuse_copy(void *a,const void *b,size_t n) {
    unsigned char *x=a;const unsigned char *y=b;
    for(size_t i=0;i<n;i++)x[i]=y[i];
}
static void reuse_clear(void *p,size_t n) {
    unsigned char *b=p;for(size_t i=0;i<n;i++)b[i]=0;
}
int li2_run_reuse_enabled(void) {return cache.reuse.enabled!=0;}
static int reuse_bad(long detail) {return error(&cache,LI2_CACHE_REUSE,detail);}
static int reuse_runtime(enum li2_run_reuse_stage stage,const struct li2_fetch_ref *b) {
    int r=li2_run_reuse_runtime(stage,b);
    return r?reuse_bad(r):0;
}
static int reuse_budget(const struct li2_run_plan *plan) {
    const struct reuse_private *r=&cache.reuse;
    const struct li2_run_completion_history *h=r->history;
    if(!h || h->first_error || h->reset_started!=h->reset_complete ||
       h->completed_runs!=r->completions || h->copied_instructions!=r->copied_instructions ||
       r->completions==UINT64_MAX)return reuse_bad(25);
    if(plan && (plan->instruction_count<2 || plan->instruction_count>LI2_RUN_MAX_INSTRUCTIONS ||
       r->copied_instructions>UINT64_MAX-plan->instruction_count))return reuse_bad(26);
    return 0;
}
static struct li2_run_publication *reuse_resolve(struct li2_run_cache *c,
                                                struct li2_run_handle h) {
    if(c!=&cache || !c->reuse.enabled || h.opaque[0]!=1 ||
       h.opaque[1]>=c->diagnostic.slots_used || !h.opaque[2] || !h.opaque[3] ||
       h.opaque[3]>c->diagnostic.attempts)return 0;
    size_t i=(size_t)h.opaque[1];
    if(c->reuse.live[i]!=h.opaque[2] || c->slots[i].progress.generation!=h.opaque[2] ||
       c->reuse.attempts[i]!=h.opaque[3])return 0;
    return &c->slots[i];
}
static void reuse_owner_failure(void *,const struct li2_run_owner *);
static int reuse_owned(const struct li2_run_owner *o) {
    struct reuse_private *r=&cache.reuse;
    struct li2_run_publication *p=reuse_resolve(&cache,r->current);
    return o && o==r->owner && p && r->lease!=REUSE_NO_LEASE &&
        !r->lookup && !r->reset_pending && o->session==cache.session &&
        o->publication==p && o->publisher.context==&cache &&
        o->publisher.observe==li2_run_publication_observe && o->publisher.failure==reuse_owner_failure &&
        r->current.opaque[3]==cache.diagnostic.last_attempt.ordinal &&
        cache.diagnostic.last_attempt.complete==1 &&
        r->borrow.sequence==cache.diagnostic.last_attempt.borrow_sequence &&
        same(&o->borrow,&r->borrow,sizeof(r->borrow)) && o->logical_flags==r->flags &&
        same(&o->plan,&p->plan,sizeof(p->plan)) && !o->first_error;
}
static int reuse_failure(struct li2_run_cache *c,unsigned code,long detail) {
    struct reuse_private *r=&c->reuse;
    struct li2_run_retirement *t=&r->retirement;
    if(!r->retiring) {
        size_t i=c->diagnostic.last_attempt.slot;
        if(i<c->diagnostic.slots_used && c->slots[i].progress.phase==LI2_PUBLICATION_WRITING)
            return publication_error(c,&c->slots[i],code,detail);
        return attempt_error(c,code,detail);
    }
    if(!t->first_error){t->first_error=code;t->first_detail=detail;}
    t->phase=LI2_RETIRE_FAILED;(void)attempt_error(c,code,detail);
    struct li2_run_publication *p=&c->slots[c->diagnostic.last_attempt.slot];
    if(!p->progress.first_error){p->progress.first_error=code;p->progress.first_detail=detail;}
    p->progress.phase=LI2_PUBLICATION_FAILED;
    if(t->cleanup_started)return (int)c->diagnostic.first_error;
    t->cleanup_started=1;__asm__ volatile("" ::: "memory");
    t->cleanup_result=RAW(SYS_mprotect,t->entry,LI2_STEP_PAGE,PROT_READ,0,0,0);
    t->cleanup_sync_result=RAW(SYS_membarrier,MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE,0,0,0,0,0);
    int q=li2_lifecycle_private_code_query(t->entry,LI2_STEP_PAGE,PROT_READ,&t->cleanup);
    if(!t->cleanup_result && !t->cleanup_sync_result && !q &&
       t->cleanup.complete && t->cleanup.pages_checked==1)t->cleanup_complete=1;
    return (int)c->diagnostic.first_error;
}
int li2_run_reuse_initialize(struct li2_step_session *s,const struct li2_run_protection *h,
    struct li2_run_owner *o,struct li2_run_completion_history *history,struct li2_run_cache **out) {
    if(!out)return LI2_CACHE_ARGUMENT;
    *out=&cache;
    if(cache.diagnostic.phase!=LI2_CACHE_EMPTY || cache.reuse.enabled)return LI2_CACHE_REUSE;
    uintptr_t a=(uintptr_t)o,b=(uintptr_t)history;
    if(!o || !history || !h || !h->add || !h->contains ||
       a>UINTPTR_MAX-sizeof(*o) || b>UINTPTR_MAX-sizeof(*history) ||
       (a<b+sizeof(*history) && b<a+sizeof(*o)) ||
       !reuse_zero(o,sizeof(*o)) || !reuse_zero(history,sizeof(*history)))
        return error(&cache,LI2_CACHE_ARGUMENT,1);
    int e=h->add(h->context,a,sizeof(*o));
    if(e || h->contains(h->context,a,sizeof(*o))!=1)return error(&cache,LI2_CACHE_PROTECTION,e);
    e=h->add(h->context,b,sizeof(*history));
    if(e || h->contains(h->context,b,sizeof(*history))!=1)return error(&cache,LI2_CACHE_PROTECTION,e);
    e=li2_run_cache_initialize(s,h,out);if(e)return e;
    cache.reuse.owner=o;cache.reuse.history=history;
    __asm__ volatile("" ::: "memory");cache.reuse.enabled=1;return 0;
}
static int reuse_backing_same(const struct li2_fetch_backing *a,
                             const struct li2_fetch_backing *b) {
    /* Seals fix content and extent, not access/change timestamps. Join the
       retained identity that fetch_backing_check authenticates on every pass;
       source() still validates this current borrow and all source bytes. */
    return a->retained_fd==b->retained_fd && a->seals==b->seals &&
        a->seals_observed==b->seals_observed && a->stat_observed==b->stat_observed &&
        a->stat_result==b->stat_result && a->stat.st_dev==b->stat.st_dev &&
        a->stat.st_ino==b->stat.st_ino && a->stat.st_size==b->stat.st_size &&
        a->stat.st_mode==b->stat.st_mode;
}
static int reuse_source_again(struct li2_run_cache *c,struct li2_run_publication *p) {
    int e=source(c,&c->last_borrow,&p->plan);if(e)return e;
    if(c->page_count!=p->source_page_count)return reuse_bad(2);
    for(size_t i=0;i<c->page_count;i++)if(!page_same(&c->pages[i],&p->source_pages[i]) ||
       !reuse_backing_same(&c->backing[i],&p->source_backing[i]))return reuse_bad(3);
    return reuse_runtime(LI2_REUSE_REVALIDATE,&c->last_borrow);
}
static int reuse_write(struct li2_run_cache *c,struct li2_run_publication *p) {
    struct li2_run_publication_progress *q=&p->progress;
    __asm__ volatile("" ::: "memory");
    q->phase=LI2_PUBLICATION_WRITING;__asm__ volatile("" ::: "memory");
    int e=li2_lifecycle_private_code_query(q->entry,LI2_STEP_PAGE,PROT_READ|PROT_WRITE,&q->before);
    if(e || !q->before.complete || q->before.pages_checked!=1)return reuse_failure(c,LI2_CACHE_QUERY,e);
    q->rw_checked=1;volatile unsigned char *to=(void *)q->entry;
    for(size_t i=0;i<LI2_STEP_PAGE;i++){to[i]=0xcc;q->fill_bytes=i+1;}
    for(size_t i=0;i<p->plan.generated_length;i++){to[i]=p->plan.generated[i];q->code_bytes=i+1;}
    q->rx_started=1;q->rx_result=RAW(SYS_mprotect,q->entry,LI2_STEP_PAGE,PROT_READ|PROT_EXEC,0,0,0);
    if(q->rx_result)return reuse_failure(c,LI2_CACHE_RX,q->rx_result);
    q->rx_complete=1;q->sync_started=1;
    q->sync_result=RAW(SYS_membarrier,MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE,0,0,0,0,0);
    if(q->sync_result)return reuse_failure(c,LI2_CACHE_SYNC,q->sync_result);
    q->sync_complete=1;
    e=li2_lifecycle_private_code_query(q->entry,LI2_STEP_PAGE,PROT_READ|PROT_EXEC,&q->after);
    if(e || !q->after.complete || q->after.pages_checked!=1)return reuse_failure(c,LI2_CACHE_QUERY,e);
    e=verify_bytes(p,&q->verified_bytes);if(e)return reuse_failure(c,(unsigned)e,0);
    e=reuse_source_again(c,p);if(e)return reuse_failure(c,(unsigned)e,c->diagnostic.first_detail);
    q->phase=LI2_PUBLICATION_COMPLETE;++c->diagnostic.complete_slots;
    if(c->reuse.retiring) {
        c->reuse.retirement.phase=LI2_RETIRE_REPLACED;++c->reuse.retirements;
        __asm__ volatile("" ::: "memory");c->reuse.retiring=0;
    }
    return 0;
}
int li2_run_reuse_publish(struct li2_run_cache *c,const struct li2_fetch_ref *borrow,
    const struct li2_run_plan *plan,struct li2_run_handle *out) {
    if(!out)return LI2_CACHE_ARGUMENT;
    *out=(struct li2_run_handle){{0}};
    int e=usable(c);if(e)return e;
    struct reuse_private *r=&c->reuse;
    if(!r->enabled || c->busy || r->lookup || r->lease || r->reset_pending || r->retiring)
        return reuse_bad(4);
    e=reuse_budget(0);if(e)return e;
    if(!borrow || !plan || !borrow->sequence || borrow->sequence<=c->last_borrow.sequence ||
       c->diagnostic.attempts==UINT64_MAX)return reuse_bad(5);
    c->busy=1;c->last_borrow=*borrow;
    struct li2_run_publish_attempt *a=&c->diagnostic.last_attempt;
    *a=(struct li2_run_publish_attempt){.ordinal=++c->diagnostic.attempts,
        .borrow_sequence=borrow->sequence,.installed=1,.slot=LI2_RUN_CACHE_PAGES};
    e=source(c,borrow,plan);if(e)return e;
    e=reuse_budget(&c->rebuilt);if(e)return e;
    e=reuse_runtime(LI2_REUSE_PUBLISH,borrow);if(e)return e;
    size_t chosen=LI2_RUN_CACHE_PAGES;
    for(size_t i=0;i<c->diagnostic.slots_used;i++) {
        struct li2_run_publication *p=&c->slots[i];
        if(!same(&p->plan,&c->rebuilt,sizeof(p->plan)) || p->source_page_count!=c->page_count)continue;
        int equal=1;
        for(size_t j=0;j<c->page_count;j++)if(!page_same(&p->source_pages[j],&c->pages[j]))equal=0;
        if(!equal)continue;
        a->slot=i;a->hit=1;
        e=inspect(c,p);if(e)return attempt_error(c,(unsigned)e,c->diagnostic.first_detail);
        e=reuse_source_again(c,p);if(e)return e;
        if(c->diagnostic.hits==UINT64_MAX)return reuse_bad(6);
        ++c->diagnostic.hits;chosen=i;break;
    }
    if(chosen==LI2_RUN_CACHE_PAGES) {
        if(r->generation==UINT64_MAX)return reuse_bad(7);
        if(c->diagnostic.slots_used<LI2_RUN_CACHE_PAGES)chosen=c->diagnostic.slots_used++;
        else {
            for(size_t n=0;n<LI2_RUN_CACHE_PAGES;n++) {
                size_t i=(r->cursor+n)%LI2_RUN_CACHE_PAGES;
                struct reuse_permit *permit=&r->permits[i];
                if(!permit->valid)continue;
                if(permit->valid!=1 || !permit->completion || permit->completion>r->completions ||
                   permit->generation!=r->live[i] ||
                   reuse_resolve(c,permit->handle)!=&c->slots[i] || !receipt(c,&c->slots[i]))
                    return reuse_bad(8);
                chosen=i;break;
            }
            if(chosen==LI2_RUN_CACHE_PAGES) {
                if(c->diagnostic.full_misses==UINT64_MAX)return reuse_bad(9);
                ++c->diagnostic.full_misses;a->miss_before_publication=1;a->complete=1;c->busy=0;
                return LI2_RUN_SLOW;
            }
            if(r->retirements==UINT64_MAX || !c->diagnostic.complete_slots)return reuse_bad(10);
            struct li2_run_publication *p=&c->slots[chosen];
            e=inspect(c,p);if(e)return e;
            /* Refresh after selection/inspection. Only this actual new borrow
               and publisher route can be active; an old permit is insufficient. */
            e=reuse_runtime(LI2_REUSE_PUBLISH,borrow);if(e)return e;
            struct reuse_permit *permit=&r->permits[chosen];
            struct li2_run_retirement *t=&r->retirement;
            *t=(struct li2_run_retirement){.phase=LI2_RETIRE_INSTALLED,
                .old_handle=permit->handle,.old_publication=p->progress,
                .completion=permit->completion,.attempt=a->ordinal,.entry=p->progress.entry,
                .rx_checked=1,.verified_bytes=p->last_verified_bytes,.rx=p->last_inspection};
            a->slot=chosen;permit->valid=0;t->consumed=1;r->live[chosen]=0;
            --c->diagnostic.complete_slots;r->cursor=(chosen+1)%LI2_RUN_CACHE_PAGES;
            /* Install cleanup identity before permission work. Interrupted
               retirement is terminal even before the new progress exists. */
            __asm__ volatile("" ::: "memory");r->retiring=1;
            __asm__ volatile("" ::: "memory");
            t->revoke_started=1;t->revoke_result=RAW(SYS_mprotect,t->entry,LI2_STEP_PAGE,PROT_READ,0,0,0);
            if(t->revoke_result)return reuse_failure(c,LI2_CACHE_WRITE,t->revoke_result);
            t->sync_started=1;
            t->sync_result=RAW(SYS_membarrier,MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE,0,0,0,0,0);
            if(t->sync_result)return reuse_failure(c,LI2_CACHE_SYNC,t->sync_result);
            e=li2_lifecycle_private_code_query(t->entry,LI2_STEP_PAGE,PROT_READ,&t->revoked);
            if(e || !t->revoked.complete || t->revoked.pages_checked!=1)
                return reuse_failure(c,LI2_CACHE_QUERY,e);
            t->revoke_complete=1;t->phase=LI2_RETIRE_REVOKED;
            t->writable_started=1;
            t->writable_result=RAW(SYS_mprotect,t->entry,LI2_STEP_PAGE,PROT_READ|PROT_WRITE,0,0,0);
            if(t->writable_result)return reuse_failure(c,LI2_CACHE_WRITE,t->writable_result);
            e=li2_lifecycle_private_code_query(t->entry,LI2_STEP_PAGE,PROT_READ|PROT_WRITE,&t->writable);
            if(e || !t->writable.complete || t->writable.pages_checked!=1)
                return reuse_failure(c,LI2_CACHE_QUERY,e);
            t->writable_complete=1;t->phase=LI2_RETIRE_WRITABLE;
        }
        a->slot=chosen;
        struct li2_run_publication *p=&c->slots[chosen];
        reuse_clear(p,sizeof(*p));
        p->progress.allocation=1;p->progress.generation=++r->generation;
        r->live[chosen]=r->generation;p->progress.borrow_sequence=borrow->sequence;
        p->progress.entry=c->diagnostic.initialization.arena+chosen*LI2_STEP_PAGE;
        p->plan=c->rebuilt;p->source_page_count=c->page_count;
        for(size_t i=0;i<c->page_count;i++){p->source_pages[i]=c->pages[i];p->source_backing[i]=c->backing[i];}
        e=reuse_write(c,p);if(e)return e;
    }
    r->permits[chosen].valid=0;
    r->current=(struct li2_run_handle){{1,chosen,r->live[chosen],a->ordinal}};
    r->attempts[chosen]=a->ordinal;
    r->borrow=*borrow;r->lookup=1;a->complete=1;*out=r->current;c->busy=0;return 0;
}
static void reuse_owner_failure(void *context,const struct li2_run_owner *o) {
    (void)context;(void)reuse_bad(o?o->first_error:11);
    li2_run_reuse_runtime_failure(o);
}
int li2_run_reuse_arm(struct li2_run_cache *c,struct li2_run_handle h,
    struct li2_run_owner *o,const struct li2_fetch_ref *b,uint64_t flags) {
    int e=usable(c);if(e)return e;
    struct reuse_private *r=&c->reuse;
    struct li2_run_publication *p=reuse_resolve(c,h);
    if(!r->enabled || c->busy || r->lookup!=1 || r->lease || r->reset_pending ||
       !same(&h,&r->current,sizeof(h)) || !p || o!=r->owner || !b ||
       !same(b,&r->borrow,sizeof(*b)) || !reuse_zero(o,sizeof(*o)))return reuse_bad(12);
    e=reuse_budget(&p->plan);if(e)return e;
    r->permits[h.opaque[1]].valid=0;r->lookup=0;r->flags=flags;r->lease=REUSE_CLAIMED;
    const struct li2_run_publisher pub={c,li2_run_publication_observe,reuse_owner_failure};
    e=li2_run_arm(o,c->session,b,flags,&pub,p);
    return e?reuse_bad(e):0;
}
int li2_run_reuse_arm_check(struct li2_run_owner *o,struct li2_step_session *s,
    const struct li2_fetch_ref *b,uint64_t flags,const struct li2_run_publisher *pub,
    const struct li2_run_publication *p) {
    struct reuse_private *r=&cache.reuse;
    if(!r->enabled)return 0;
    if(usable(&cache) || cache.busy || r->lease!=REUSE_CLAIMED || o!=r->owner || s!=cache.session ||
       !b || !same(b,&r->borrow,sizeof(*b)) || flags!=r->flags ||
       p!=reuse_resolve(&cache,r->current) || !pub || pub->context!=&cache ||
       pub->observe!=li2_run_publication_observe || pub->failure!=reuse_owner_failure)
        return reuse_bad(13);
    r->lease=REUSE_ARMING;return 0;
}
int li2_run_reuse_enter_check(struct li2_run_owner *o,enum li2_run_phase phase) {
    struct reuse_private *r=&cache.reuse;
    if(!r->enabled)return 0;
    if(usable(&cache) || cache.busy || !reuse_owned(o) || o->phase!=phase || o->in_handler)
        return reuse_bad(14);
    if(phase==LI2_RUN_ARMED && r->lease==REUSE_ARMED)r->lease=REUSE_ENTERING;
    else if(phase==LI2_RUN_RUNNING && r->lease==REUSE_RUNNING)r->lease=REUSE_EXITING;
    else return reuse_bad(15);
    return 0;
}
int li2_run_reuse_observe_owner(struct li2_run_owner *o,struct li2_run_slot_observation *out) {
    if(!out || out->attempted)return reuse_bad(16);
    out->attempted=1;
    struct reuse_private *r=&cache.reuse;
    int e=usable(&cache);
    if(e || !r->enabled || cache.busy || !reuse_owned(o)) {
        out->result=e?e:reuse_bad(17);return out->result;
    }
    enum reuse_lease_phase next;
    if(r->lease==REUSE_ARMING && o->phase==LI2_RUN_PLANNING && out==&o->armed_slot)next=REUSE_ARMED;
    else if(r->lease==REUSE_ENTERING && o->phase==LI2_RUN_ENTERING && out==&o->entry_slot)next=REUSE_RUNNING;
    else if(r->lease==REUSE_EXITING && o->phase==LI2_RUN_EXIT_CHECKING && out==&o->exit_slot)next=REUSE_EXIT_OBSERVED;
    else {out->result=reuse_bad(18);return out->result;}
    cache.busy=1;
    struct li2_run_publication *p=reuse_resolve(&cache,r->current);
    out->owner_observed=1;out->entry=p->progress.entry;
    out->mapping_first=out->entry;out->mapping_end=out->entry+LI2_STEP_PAGE;
    out->allocation=p->progress.allocation;out->generation=p->progress.generation;
    out->length=p->plan.generated_length;
    e=inspect(&cache,p);
    if(p->last_inspection.complete){out->mapping_observed=1;out->actual_prot=p->last_inspection.actual_prot;}
    if(e){out->result=e;return e;}
    out->writable_aliases=0;
    const volatile unsigned char *bytes=(const void *)out->entry;
    for(size_t i=0;i<out->length;i++)out->bytes[i]=bytes[i];
    out->bytes_observed=1;out->complete=1;r->lease=next;cache.busy=0;return 0;
}
int li2_run_reuse_reset_ready(struct li2_run_owner *o,struct li2_run_completion_history *h) {
    struct reuse_private *r=&cache.reuse;
    if(!r->enabled)return 0;
    if(usable(&cache) || cache.busy || !reuse_owned(o) || h!=r->history ||
       r->lease!=REUSE_EXIT_OBSERVED || r->reset_pending ||
       o->phase!=LI2_RUN_COMPLETE || o->in_handler || h->completed_runs!=r->completions ||
       r->completions==UINT64_MAX)return reuse_bad(19);
    int e=reuse_budget(&o->plan);if(e)return e;
    reuse_copy(&r->completed,o,sizeof(*o));r->lease=REUSE_RESET_READY;return 0;
}
void li2_run_reuse_reset_committed(void) {
    struct reuse_private *r=&cache.reuse;
    if(!r->enabled)return;
    /* The caller has executed the unchanged infallible copy/clear block.
       An out-of-order direct call terminates; it cannot mint completion. */
    if(r->lease!=REUSE_RESET_READY || r->reset_pending || !r->history->reset_complete ||
       r->history->completed_runs!=r->completions+1 ||
       r->history->copied_instructions!=r->copied_instructions+r->completed.plan.instruction_count ||
       !reuse_zero(r->owner,sizeof(*r->owner)) ||
       !same(&r->history->last_complete,&r->completed,sizeof(r->completed))) {
        (void)reuse_bad(20);(void)RAW(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    ++r->completions;r->copied_instructions+=r->completed.plan.instruction_count;
    r->lease=REUSE_NO_LEASE;r->reset_pending=1;
}
static int reuse_endpoint(const struct li2_step_frame *f,const ucontext_t *uc) {
    if(!uc || !f->initialized || f->initialized!=f->fp_bytes ||
       f->fp_bytes<512 || f->fp_bytes>LI2_STEP_FP_BYTES)return 0;
    uint64_t mask=0;reuse_copy(&mask,&uc->uc_sigmask,sizeof(mask));
    return mask==f->mask && (uintptr_t)uc->uc_mcontext.fpregs==f->fp_address &&
        same(uc->uc_mcontext.gregs,f->greg,sizeof(f->greg)) &&
        same(uc->uc_mcontext.fpregs,f->fp,f->fp_bytes);
}
int li2_run_reuse_quiesce(struct li2_run_cache *c,struct li2_run_completion_history *h,
    const ucontext_t *uc) {
    int e=usable(c);if(e)return e;
    struct reuse_private *r=&c->reuse;
    struct li2_run_publication *p=reuse_resolve(c,r->current);
    if(!r->enabled || c->busy || r->lookup || r->lease || r->reset_pending!=1 ||
       h!=r->history || h->first_error || !h->reset_complete ||
       h->completed_runs!=r->completions || !reuse_zero(r->owner,sizeof(*r->owner)) ||
       !same(&h->last_complete,&r->completed,sizeof(r->completed)) || !p ||
       !reuse_endpoint(&r->completed.after,uc) || li2_lifecycle_fetch_interlock())return reuse_bad(21);
    const struct li2_fetch_progress *f=li2_lifecycle_fetch_progress();
    if(!f || !same(f,&r->completed.final_fetch,sizeof(*f)))return reuse_bad(22);
    e=reuse_runtime(LI2_REUSE_QUIESCE,0);if(e)return e;
    if(!reuse_endpoint(&r->completed.after,uc))return reuse_bad(23);
    size_t i=(size_t)r->current.opaque[1];
    if(r->permits[i].valid)return reuse_bad(24);
    r->permits[i]=(struct reuse_permit){.generation=r->live[i],.completion=r->completions,
        .handle=r->current,.valid=1};
    r->reset_pending=0;reuse_clear(&r->completed,sizeof(r->completed));return 0;
}
int li2_run_reuse_snapshot(const struct li2_run_cache *c,struct li2_run_reuse_observation *out) {
    if(c!=&cache || !out || !c->reuse.enabled)return LI2_CACHE_ARGUMENT;
    const struct reuse_private *r=&c->reuse;
    *out=(struct li2_run_reuse_observation){.generation=r->generation,.completions=r->completions,
        .copied_instructions=r->copied_instructions,
        .retirements=r->retirements,.cursor=r->cursor,.lookup=r->lookup,.lease=(unsigned)r->lease,
        .reset_pending=r->reset_pending,.current=r->current,.retirement=r->retirement};
    size_t i=c->diagnostic.last_attempt.slot;
    if(c->diagnostic.last_attempt.installed && i<c->diagnostic.slots_used) {
        out->publication_present=1;out->publication=c->slots[i].progress;
    }
    return 0;
}
int li2_run_reuse_publication(const struct li2_run_cache *c,struct li2_run_handle h,
    struct li2_run_publication_progress *out) {
    if(!out)return LI2_CACHE_ARGUMENT;
    struct li2_run_publication *p=reuse_resolve((struct li2_run_cache *)c,h);
    if(!p)return LI2_CACHE_REUSE;
    *out=p->progress;return 0;
}
#endif
