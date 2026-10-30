/* Distinct completed-generation reuse. Included after sp_entry. The existing
   register-run reuse contract is the model; no REGISTER_RUN permit is forged. */
#if LI2_SCALAR_SPAN_TRACE != 1
#error "literal scalar reuse profile only"
#endif
struct spr_permit { uint64_t generation,completion; unsigned valid; };
struct spr_retirement {
    unsigned started,consumed,old_verified,target_ready,replaced;
    size_t slot,verified_bytes;
    uint64_t old_generation,new_generation,completion,ordinal;
    uintptr_t old_entry,new_entry;
    struct sp_slot old_slot;
    struct li2_private_code_query old_idle;
    struct sp_permission revoked,target_closed,writable,cleanup;
};
static struct {
    unsigned initialized,registered,pending,retiring;
    size_t cursor,slot;
    uintptr_t target;
    uint64_t generation,retirement_attempts,retirements,permits_issued,claims;
    uint64_t live[SP_PAGES],predecessor[SP_PAGES];
    uintptr_t entry[SP_PAGES];
    struct spr_permit permits[SP_PAGES],claimed;
    struct spr_retirement retirement;
} spr;
static int spr_protected(void) {
    return spr.initialized==1 && spr.registered==1 && sp_protected() &&
        selected_run_protect_contains(0,(uintptr_t)&spr,sizeof spr)==1;
}
static int spr_address(size_t slot,uintptr_t entry) {
    return slot<SP_PAGES && (entry==selected_scalar_span.arena+slot*PAGE ||
        entry==selected_scalar_span.low_arena+slot*PAGE);
}
static int spr_identity(size_t slot,uint64_t generation) {
    if(!spr_protected() || slot>=selected_scalar_span.used || !generation ||
       generation>spr.generation || spr.live[slot]!=generation)return 0;
    const struct sp_slot *s=&selected_scalar_span.slots[slot];
    return s->installed==1 && s->complete==1 && s->identity==generation &&
        s->filled==PAGE && s->verified==PAGE && s->publication.complete==1 &&
        s->plan.generated==spr.entry[slot] && spr.entry[slot]==sp_entry(s->key.entry,slot);
}
static void spr_initialize(void) {
    sp_need(!spr.initialized && !spr.registered && selected_scalar_span_busy &&
        !selected_scalar_span_active,SP_STATE,300);
    sp_need(!selected_run_protect_add(0,(uintptr_t)&spr,sizeof spr),SP_STATE,301);
    spr.registered=1;spr.initialized=1;sp_need(spr_protected(),SP_STATE,302);
}
static void spr_begin(void) {
    sp_need(spr_protected() && !spr.pending && !spr.retiring &&
        !selected_scalar_span_active && selected_scalar_span_busy &&
        !selected_step_pending && selected_pending_route==SELECTED_NO_STEP,SP_STATE,303);
    sp_zero(&spr.claimed,sizeof spr.claimed);
}
static int spr_permitted(size_t slot) {
    const struct spr_permit *p=&spr.permits[slot];
    if(!p->valid)return 0;
    sp_need(p->valid==1 && p->completion && p->completion<=selected_scalar_span.completed &&
        spr_identity(slot,p->generation),SP_STATE,304);
    return 1;
}
static size_t spr_choose(void) {
    sp_need(selected_scalar_span.used==SP_PAGES && !spr.pending && !spr.retiring &&
        sp_quiet(&selected_borrow),SP_STATE,305);
    for(size_t n=0;n<SP_PAGES;n++) {
        size_t slot=(spr.cursor+n)%SP_PAGES;
        if(spr_permitted(slot))return slot;
    }
    return SP_PAGES; /* No completed generation: original clean capacity MISS. */
}
static int spr_permission(uintptr_t entry,int prot,struct sp_permission *p) {
    if(p->started)return SP_STATE;
    p->prot=prot;p->started=1;__asm__ volatile("":::"memory");
    p->result=raw(SYS_mprotect,entry,PAGE,prot,0,0,0);p->returned=1;
    p->sync_started=1;__asm__ volatile("":::"memory");
    p->sync_result=raw(SYS_membarrier,32,0,0,0,0,0);p->sync_returned=1;
    int q=sp_query(entry,prot,&p->query);
    if(p->result || p->sync_result || q)return SP_PUBLICATION;
    p->complete=1;return 0;
}
static void spr_prepare(size_t slot,uintptr_t target,const siginfo_t *si,const ucontext_t *uc) {
    struct sp_record *r=&selected_scalar_span.current;
    sp_need(spr_protected() && !spr.pending && !spr.retiring && slot<SP_PAGES &&
        slot<=selected_scalar_span.used && spr_address(slot,target) &&
        target==sp_entry(r->source.key.entry,slot) && selected_scalar_span_busy &&
        !selected_scalar_span_active && !selected_step_pending &&
        selected_pending_route==SELECTED_NO_STEP && sp_quiet(&selected_borrow) &&
        sp_identity() && r->build_started && r->build_returned && !r->build_result &&
        selected_scalar_span.scratch.ready==1 &&
        selected_scalar_span.scratch.generated==target,SP_STATE,306);
    sp_need(spr.generation!=UINT64_MAX,SP_OVERFLOW,300);
    struct sp_slot *s=&selected_scalar_span.slots[slot];
    /* Install stable cleanup addresses before inspection, retirement or clearing
       mutable slot bytes. A nested event never closes a partially copied plan. */
    spr.pending=1;spr.slot=slot;spr.target=target;r->slot=(unsigned)slot;r->slot_present=1;
    selected_pending_route=SELECTED_SCALAR_SPAN;selected_step_pending=1;__asm__ volatile("":::"memory");
    if(slot<selected_scalar_span.used) {
        sp_need(spr_permitted(slot),SP_STATE,307);
        struct spr_retirement *t=&spr.retirement;
        sp_zero(t,sizeof *t);t->started=1;t->slot=slot;t->old_entry=s->plan.generated;t->new_entry=target;
        t->old_generation=spr.live[slot];t->new_generation=spr.generation+1;
        t->completion=spr.permits[slot].completion;sp_count(&spr.retirement_attempts);
        t->ordinal=spr.retirement_attempts;copy(&t->old_slot,s,sizeof *s);
        copy(&spr.claimed,&spr.permits[slot],sizeof spr.claimed);
        spr.permits[slot].valid=0;t->consumed=1;spr.retiring=1;__asm__ volatile("":::"memory");
        /* A fresh full reconstruction detects stale/corrupted metadata before
           it is retired; every byte of its actual closed image still matches. */
        sp_need(!sp_plan(&s->plan) && !sp_query(t->old_entry,PROT_READ,&t->old_idle) &&
            !sp_bytes(s,&t->verified_bytes),SP_PUBLICATION,300);t->old_verified=1;
        spr.live[slot]=0;
        sp_need(!spr_permission(t->old_entry,PROT_READ,&t->revoked),SP_PUBLICATION,301);
        /* Low/high placement can switch. Revoke the actual target too, even
           when it is virgin RW; no retained opposite-arena page stays RX. */
        sp_need(!spr_permission(target,PROT_READ,&t->target_closed),SP_PUBLICATION,302);
        sp_need(!spr_permission(target,PROT_READ|PROT_WRITE,&t->writable),SP_PUBLICATION,303);
        sp_need(!li2_lifecycle_span_validate(&selected_borrow,&r->source,&selected_scalar_span.scratch) &&
            sp_quiet(&selected_borrow) && sp_unchanged(&r->before,si,uc),SP_SOURCE,300);
        t->target_ready=1;spr.predecessor[slot]=t->old_generation;
        sp_zero(s,sizeof *s);
    } else {
        sp_need(!s->installed && !s->complete && !s->identity && !spr.live[slot] &&
            !spr.permits[slot].valid,SP_STATE,308);
    }
    ++spr.generation;spr.live[slot]=spr.generation;spr.entry[slot]=target;
    r->publication_generation=spr.generation;
}
static void spr_published(size_t slot) {
    sp_need(spr.pending && spr.slot==slot && spr_identity(slot,spr.generation),SP_STATE,309);
    if(spr.retiring) {
        struct spr_retirement *t=&spr.retirement;
        sp_need(t->started && t->consumed && t->target_ready && !t->replaced &&
            t->slot==slot && t->new_generation==spr.generation,SP_STATE,310);
        t->replaced=1;sp_count(&spr.retirements);spr.cursor=(slot+1)%SP_PAGES;spr.retiring=0;
    }
}
static void spr_claim(size_t slot,int hit) {
    struct sp_record *r=&selected_scalar_span.current;
    sp_need(slot<selected_scalar_span.used && spr_protected() && !spr.retiring,SP_STATE,311);
    if(hit) {
        sp_need(!spr.pending && spr_address(slot,spr.entry[slot]),SP_STATE,312);
        spr.pending=1;spr.slot=slot;spr.target=spr.entry[slot];
        r->publication_generation=spr.live[slot];
        sp_need(spr_permitted(slot),SP_STATE,312);
        copy(&spr.claimed,&spr.permits[slot],sizeof spr.claimed);spr.permits[slot].valid=0;
    } else sp_need(spr.pending && spr.slot==slot && r->publication_generation==spr.live[slot],SP_STATE,313);
    sp_need(spr_identity(slot,r->publication_generation),SP_STATE,311);
    sp_count(&spr.claims);
}
static int spr_claimed(void) {
    const struct sp_record *r=&selected_scalar_span.current;
    return spr.pending==1 && !spr.retiring && r->slot_present && r->slot==spr.slot && r->slot<SP_PAGES &&
        !spr.permits[r->slot].valid && spr_identity(r->slot,r->publication_generation) &&
        spr.target==selected_scalar_span.slots[r->slot].plan.generated;
}
static void spr_quiesce(int sig,const siginfo_t *si,const ucontext_t *uc) {
    const struct sp_record *r=&selected_scalar_span.current;
    const struct li2_fetch_progress *f=li2_lifecycle_fetch_progress();
    sp_need(spr_claimed() && !spr.retiring && selected_scalar_span_busy &&
        !selected_scalar_span_active && !selected_step_pending &&
        selected_pending_route==SELECTED_NO_STEP && !li2_lifecycle_fetch_interlock() &&
        selected_scalar_span.entries==selected_scalar_span.completed && r->completed==1 &&
        r->release_complete==1 && !r->release_result && r->close.complete==1 &&
        r->closed_bytes==PAGE && f && !f->held && f->complete && !f->first_error &&
        equal(f,&r->final_fetch,sizeof *f) && equal(r,&selected_scalar_span.last,sizeof *r) &&
        sig==r->after.sig && sp_identity() && sp_quiet(0) && sp_unchanged(&r->after,si,uc),SP_STATE,314);
    struct spr_permit *p=&spr.permits[r->slot];sp_need(!p->valid,SP_STATE,315);
    p->generation=r->publication_generation;p->completion=selected_scalar_span.completed;
    p->valid=1;sp_count(&spr.permits_issued);spr.pending=0;
}
static void spr_abort(void) {
    struct sp_record *r=&selected_scalar_span.current;
    if(!spr.pending || r->cleanup_started)return;
    r->cleanup_started=1;
    if(!spr_protected() || !r->slot_present || r->slot!=spr.slot ||
       !spr_address(spr.slot,spr.target))return;
    int error=spr_permission(spr.target,PROT_READ,&r->cleanup);
    struct spr_retirement *t=&spr.retirement;
    if(spr.retiring && t->started && t->slot==spr.slot && t->old_entry!=spr.target) {
        if(!spr_address(t->slot,t->old_entry))return;
        int old_error=spr_permission(t->old_entry,PROT_READ,&t->cleanup);
        if(old_error)return;
    }
    if(!error)r->cleanup_complete=1;
    /* First error and permit consumption survive. No failed generation can
       receive a completion permit or be dispatched/recycled. */
}
static void spr_report(unsigned status,unsigned code,long detail) {
    struct writer w={.used=0};text(&w,"LI2_SCALAR_SPAN_REUSE {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",detail<0?0ULL-(uint64_t)detail:(uint64_t)detail);
    field(&w,",\"detail_negative\":",detail<0);
    field(&w,",\"generation\":",spr.generation);field(&w,",\"retirement_attempts\":",spr.retirement_attempts);
    field(&w,",\"retirements\":",spr.retirements);field(&w,",\"claims\":",spr.claims);
    field(&w,",\"permits_issued\":",spr.permits_issued);field(&w,",\"pending\":",spr.pending);
    field(&w,",\"retiring\":",spr.retiring);field(&w,",\"cursor\":",spr.cursor);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
_Static_assert(14*21+256<=sizeof(((struct writer *)0)->bytes),"bounded reuse report");
