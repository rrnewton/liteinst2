/* Distinct completed-generation reuse. Included after sr_entry. The existing
   register-run reuse contract is the model; no REGISTER_RUN permit is forged. */
#if LI2_SCALAR_REGION_REUSE != 1
#error "literal scalar reuse profile only"
#endif
#ifdef LI2_SCALAR_REGION_CERTIFICATE
#error "certificate lifetime and generation reuse require a separate composition"
#endif
struct srr_permit { uint64_t generation,completion; unsigned valid; };
struct srr_retirement {
    unsigned started,consumed,old_verified,target_ready,replaced;
    size_t slot,verified_bytes;
    uint64_t old_generation,new_generation,completion,ordinal;
    uintptr_t old_entry,new_entry;
    struct sr_slot old_slot;
    struct li2_private_code_query old_idle;
    struct sr_permission revoked,target_closed,writable,cleanup;
};
static struct {
    unsigned initialized,registered,pending,retiring;
    size_t cursor,slot;
    uintptr_t target;
    uint64_t generation,retirement_attempts,retirements,permits_issued,claims;
    uint64_t live[SR_PAGES],predecessor[SR_PAGES];
    uintptr_t entry[SR_PAGES];
    struct srr_permit permits[SR_PAGES],claimed;
    struct srr_retirement retirement;
} srr;
static int srr_protected(void) {
    return srr.initialized==1 && srr.registered==1 && sr_protected() &&
        selected_run_protect_contains(0,(uintptr_t)&srr,sizeof srr)==1;
}
static int srr_address(size_t slot,uintptr_t entry) {
    return slot<SR_PAGES && (entry==selected_scalar_region.arena+slot*PAGE ||
        entry==selected_scalar_region.low_arena+slot*PAGE);
}
static int srr_identity(size_t slot,uint64_t generation) {
    if(!srr_protected() || slot>=selected_scalar_region.used || !generation ||
       generation>srr.generation || srr.live[slot]!=generation)return 0;
    const struct sr_slot *s=&selected_scalar_region.slots[slot];
    return s->installed==1 && s->complete==1 && s->identity==generation &&
        s->filled==PAGE && s->verified==PAGE && s->publication.complete==1 &&
        s->plan.generated==srr.entry[slot] && srr.entry[slot]==sr_entry(s->key.entry,slot);
}
static void srr_initialize(void) {
    sr_need(!srr.initialized && !srr.registered && selected_scalar_region_busy &&
        !selected_scalar_region_active,SR_STATE,300);
    sr_need(!selected_run_protect_add(0,(uintptr_t)&srr,sizeof srr),SR_STATE,301);
    srr.registered=1;srr.initialized=1;sr_need(srr_protected(),SR_STATE,302);
}
static void srr_begin(void) {
    sr_need(srr_protected() && !srr.pending && !srr.retiring &&
        !selected_scalar_region_active && selected_scalar_region_busy &&
        !selected_step_pending && selected_pending_route==SELECTED_NO_STEP,SR_STATE,303);
    sr_zero(&srr.claimed,sizeof srr.claimed);
}
static int srr_permitted(size_t slot) {
    const struct srr_permit *p=&srr.permits[slot];
    if(!p->valid)return 0;
    sr_need(p->valid==1 && p->completion && p->completion<=selected_scalar_region.completed &&
        srr_identity(slot,p->generation),SR_STATE,304);
    return 1;
}
static size_t srr_choose(void) {
    sr_need(selected_scalar_region.used==SR_PAGES && !srr.pending && !srr.retiring &&
        sr_quiet(&selected_borrow),SR_STATE,305);
    for(size_t n=0;n<SR_PAGES;n++) {
        size_t slot=(srr.cursor+n)%SR_PAGES;
        if(srr_permitted(slot))return slot;
    }
    return SR_PAGES; /* No completed generation: original clean capacity MISS. */
}
static int srr_permission(uintptr_t entry,int prot,struct sr_permission *p) {
    if(p->started)return SR_STATE;
    p->prot=prot;p->started=1;__asm__ volatile("":::"memory");
    p->result=raw(SYS_mprotect,entry,PAGE,prot,0,0,0);p->returned=1;
    p->sync_started=1;__asm__ volatile("":::"memory");
    p->sync_result=raw(SYS_membarrier,32,0,0,0,0,0);p->sync_returned=1;
    int q=sr_query(entry,prot,&p->query);
    if(p->result || p->sync_result || q)return SR_PUBLICATION;
    p->complete=1;return 0;
}
static void srr_prepare(size_t slot,uintptr_t target,const siginfo_t *si,const ucontext_t *uc) {
    struct sr_record *r=&selected_scalar_region.current;
    sr_need(srr_protected() && !srr.pending && !srr.retiring && slot<SR_PAGES &&
        slot<=selected_scalar_region.used && srr_address(slot,target) &&
        target==sr_entry(r->source.key.entry,slot) && selected_scalar_region_busy &&
        !selected_scalar_region_active && !selected_step_pending &&
        selected_pending_route==SELECTED_NO_STEP && sr_quiet(&selected_borrow) &&
        sr_identity() && r->build_started && r->build_returned && !r->build_result &&
        selected_scalar_region.scratch.ready==1 &&
        selected_scalar_region.scratch.generated==target,SR_STATE,306);
    sr_need(srr.generation!=UINT64_MAX,SR_OVERFLOW,300);
    struct sr_slot *s=&selected_scalar_region.slots[slot];
    /* Install stable cleanup addresses before inspection, retirement or clearing
       mutable slot bytes. A nested event never closes a partially copied plan. */
    srr.pending=1;srr.slot=slot;srr.target=target;r->slot=(unsigned)slot;r->slot_present=1;
    selected_pending_route=SELECTED_SCALAR_REGION;selected_step_pending=1;__asm__ volatile("":::"memory");
    if(slot<selected_scalar_region.used) {
        sr_need(srr_permitted(slot),SR_STATE,307);
        struct srr_retirement *t=&srr.retirement;
        sr_zero(t,sizeof *t);t->started=1;t->slot=slot;t->old_entry=s->plan.generated;t->new_entry=target;
        t->old_generation=srr.live[slot];t->new_generation=srr.generation+1;
        t->completion=srr.permits[slot].completion;sr_count(&srr.retirement_attempts);
        t->ordinal=srr.retirement_attempts;copy(&t->old_slot,s,sizeof *s);
        copy(&srr.claimed,&srr.permits[slot],sizeof srr.claimed);
        srr.permits[slot].valid=0;t->consumed=1;srr.retiring=1;__asm__ volatile("":::"memory");
        /* A fresh full reconstruction detects stale/corrupted metadata before
           it is retired; every byte of its actual closed image still matches. */
        sr_need(!sr_plan(&s->plan) && !sr_query(t->old_entry,PROT_READ,&t->old_idle) &&
            !sr_bytes(s,&t->verified_bytes),SR_PUBLICATION,300);t->old_verified=1;
        srr.live[slot]=0;
        sr_need(!srr_permission(t->old_entry,PROT_READ,&t->revoked),SR_PUBLICATION,301);
        /* Low/high placement can switch. Revoke the actual target too, even
           when it is virgin RW; no retained opposite-arena page stays RX. */
        sr_need(!srr_permission(target,PROT_READ,&t->target_closed),SR_PUBLICATION,302);
        sr_need(!srr_permission(target,PROT_READ|PROT_WRITE,&t->writable),SR_PUBLICATION,303);
        sr_need(!li2_lifecycle_region_validate(&selected_borrow,&r->source,&selected_scalar_region.scratch) &&
            sr_quiet(&selected_borrow) && sr_unchanged(&r->before,si,uc),SR_SOURCE,300);
        t->target_ready=1;srr.predecessor[slot]=t->old_generation;
        sr_zero(s,sizeof *s);
    } else {
        sr_need(!s->installed && !s->complete && !s->identity && !srr.live[slot] &&
            !srr.permits[slot].valid,SR_STATE,308);
    }
    ++srr.generation;srr.live[slot]=srr.generation;srr.entry[slot]=target;
    r->publication_generation=srr.generation;
}
static void srr_published(size_t slot) {
    sr_need(srr.pending && srr.slot==slot && srr_identity(slot,srr.generation),SR_STATE,309);
    if(srr.retiring) {
        struct srr_retirement *t=&srr.retirement;
        sr_need(t->started && t->consumed && t->target_ready && !t->replaced &&
            t->slot==slot && t->new_generation==srr.generation,SR_STATE,310);
        t->replaced=1;sr_count(&srr.retirements);srr.cursor=(slot+1)%SR_PAGES;srr.retiring=0;
    }
}
static void srr_claim(size_t slot,int hit) {
    struct sr_record *r=&selected_scalar_region.current;
    sr_need(slot<selected_scalar_region.used && srr_protected() && !srr.retiring,SR_STATE,311);
    if(hit) {
        sr_need(!srr.pending && srr_address(slot,srr.entry[slot]),SR_STATE,312);
        srr.pending=1;srr.slot=slot;srr.target=srr.entry[slot];
        r->publication_generation=srr.live[slot];
        sr_need(srr_permitted(slot),SR_STATE,312);
        copy(&srr.claimed,&srr.permits[slot],sizeof srr.claimed);srr.permits[slot].valid=0;
    } else sr_need(srr.pending && srr.slot==slot && r->publication_generation==srr.live[slot],SR_STATE,313);
    sr_need(srr_identity(slot,r->publication_generation),SR_STATE,311);
    sr_count(&srr.claims);
}
static int srr_claimed(void) {
    const struct sr_record *r=&selected_scalar_region.current;
    return srr.pending==1 && !srr.retiring && r->slot_present && r->slot==srr.slot && r->slot<SR_PAGES &&
        !srr.permits[r->slot].valid && srr_identity(r->slot,r->publication_generation) &&
        srr.target==selected_scalar_region.slots[r->slot].plan.generated;
}
static void srr_quiesce(int sig,const siginfo_t *si,const ucontext_t *uc) {
    const struct sr_record *r=&selected_scalar_region.current;
    const struct li2_fetch_progress *f=li2_lifecycle_fetch_progress();
    sr_need(srr_claimed() && !srr.retiring && selected_scalar_region_busy &&
        !selected_scalar_region_active && !selected_step_pending &&
        selected_pending_route==SELECTED_NO_STEP && !li2_lifecycle_fetch_interlock() &&
        selected_scalar_region.entries==selected_scalar_region.completed && r->completed==1 &&
        r->release_complete==1 && !r->release_result && r->close.complete==1 &&
        r->closed_bytes==PAGE && f && !f->held && f->complete && !f->first_error &&
        equal(f,&r->final_fetch,sizeof *f) && equal(r,&selected_scalar_region.last,sizeof *r) &&
        sig==r->after.sig && sr_identity() && sr_quiet(0) && sr_unchanged(&r->after,si,uc),SR_STATE,314);
    struct srr_permit *p=&srr.permits[r->slot];sr_need(!p->valid,SR_STATE,315);
    p->generation=r->publication_generation;p->completion=selected_scalar_region.completed;
    p->valid=1;sr_count(&srr.permits_issued);srr.pending=0;
}
static void srr_abort(void) {
    struct sr_record *r=&selected_scalar_region.current;
    if(!srr.pending || r->cleanup_started)return;
    r->cleanup_started=1;
    if(!srr_protected() || !r->slot_present || r->slot!=srr.slot ||
       !srr_address(srr.slot,srr.target))return;
    int error=srr_permission(srr.target,PROT_READ,&r->cleanup);
    struct srr_retirement *t=&srr.retirement;
    if(srr.retiring && t->started && t->slot==srr.slot && t->old_entry!=srr.target) {
        if(!srr_address(t->slot,t->old_entry))return;
        int old_error=srr_permission(t->old_entry,PROT_READ,&t->cleanup);
        if(old_error)return;
    }
    if(!error)r->cleanup_complete=1;
    /* First error and permit consumption survive. No failed generation can
       receive a completion permit or be dispatched/recycled. */
}
static void srr_report(unsigned status,unsigned code,long detail) {
    struct writer w={.used=0};text(&w,"LI2_SCALAR_REUSE {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",detail<0?0ULL-(uint64_t)detail:(uint64_t)detail);
    field(&w,",\"detail_negative\":",detail<0);
    field(&w,",\"generation\":",srr.generation);field(&w,",\"retirement_attempts\":",srr.retirement_attempts);
    field(&w,",\"retirements\":",srr.retirements);field(&w,",\"claims\":",srr.claims);
    field(&w,",\"permits_issued\":",srr.permits_issued);field(&w,",\"pending\":",srr.pending);
    field(&w,",\"retiring\":",srr.retiring);field(&w,",\"cursor\":",srr.cursor);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
_Static_assert(14*21+256<=sizeof(((struct writer *)0)->bytes),"bounded reuse report");
