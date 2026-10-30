/* Distinct completed-generation reuse. Included after le_entry. The existing
   register-run reuse contract is the model; no REGISTER_RUN permit is forged. */
#if LI2_SCALAR_SPAN_TRACE != 1
#error "literal scalar reuse profile only"
#endif
struct ler_permit { uint64_t generation,completion; unsigned valid; };
struct ler_retirement {
    unsigned started,consumed,old_verified,target_ready,replaced;
    size_t slot,verified_bytes;
    uint64_t old_generation,new_generation,completion,ordinal;
    uintptr_t old_entry,new_entry;
    struct le_slot old_slot;
    unsigned char old_payload[LI2_LINK_PROOF_BYTES];
    struct li2_private_code_query old_idle;
    struct le_permission revoked,target_closed,writable,cleanup;
};
static struct {
    unsigned initialized,registered,pending,retiring;
    size_t cursor,slot;
    uintptr_t target;
    uint64_t generation,retirement_attempts,retirements,permits_issued,claims;
    uint64_t live[LE_PAGES],predecessor[LE_PAGES];
    uintptr_t entry[LE_PAGES];
    struct ler_permit permits[LE_PAGES],claimed;
    struct ler_retirement retirement;
} ler;
static int ler_protected(void) {
    return ler.initialized==1 && ler.registered==1 && le_protected() &&
        selected_run_protect_contains(0,(uintptr_t)&ler,sizeof ler)==1;
}
static int ler_address(size_t slot,uintptr_t entry) {
    return slot<LE_PAGES && (entry==selected_linked_epoch.arena+slot*PAGE ||
        entry==selected_linked_epoch.low_arena+slot*PAGE);
}
static int ler_identity(size_t slot,uint64_t generation) {
    if(!ler_protected() || slot>=selected_linked_epoch.used || !generation ||
       generation>ler.generation || ler.live[slot]!=generation)return 0;
    const struct le_slot *s=&selected_linked_epoch.slots[slot];
    return s->installed==1 && s->complete==1 && s->identity==generation &&
        s->filled==PAGE && s->verified==PAGE && s->publication.complete==1 && le_proof_ready(s) &&
        le_plan(s)->generated==ler.entry[slot] && ler.entry[slot]==le_entry(le_key(s)->entry,slot);
}
static void ler_initialize(void) {
    le_need(!ler.initialized && !ler.registered && selected_linked_epoch_busy &&
        !selected_linked_epoch_active,LE_STATE,300);
    le_need(!selected_run_protect_add(0,(uintptr_t)&ler,sizeof ler),LE_STATE,301);
    ler.registered=1;ler.initialized=1;le_need(ler_protected(),LE_STATE,302);
}
static void ler_begin(void) {
    le_need(ler_protected() && !ler.pending && !ler.retiring &&
        !selected_linked_epoch_active && selected_linked_epoch_busy &&
        !selected_step_pending && selected_pending_route==SELECTED_NO_STEP,LE_STATE,303);
    le_zero(&ler.claimed,sizeof ler.claimed);
}
static int ler_permitted(size_t slot) {
    const struct ler_permit *p=&ler.permits[slot];
    if(!p->valid)return 0;
    le_need(p->valid==1 && p->completion && p->completion<=selected_linked_epoch.completed &&
        ler_identity(slot,p->generation),LE_STATE,304);
    return 1;
}
static size_t ler_choose(void) {
    le_need(selected_linked_epoch.used==LE_PAGES && !ler.pending && !ler.retiring &&
        le_quiet(&selected_borrow),LE_STATE,305);
    for(size_t n=0;n<LE_PAGES;n++) {
        size_t slot=(ler.cursor+n)%LE_PAGES;
        if(ler_permitted(slot))return slot;
    }
    return LE_PAGES; /* No completed generation: original clean capacity MISS. */
}
static int ler_permission(uintptr_t entry,int prot,struct le_permission *p) {
    if(p->started)return LE_STATE;
    p->prot=prot;p->started=1;__asm__ volatile("":::"memory");
    p->result=raw(SYS_mprotect,entry,PAGE,prot,0,0,0);p->returned=1;
    p->sync_started=1;__asm__ volatile("":::"memory");
    p->sync_result=raw(SYS_membarrier,32,0,0,0,0,0);p->sync_returned=1;
    int q=le_query(entry,prot,&p->query);
    if(p->result || p->sync_result || q)return LE_PUBLICATION;
    p->complete=1;return 0;
}
static void ler_prepare(size_t slot,uintptr_t target,const siginfo_t *si,const ucontext_t *uc) {
    struct le_record *r=&selected_linked_epoch.current;
    le_need(ler_protected() && !ler.pending && !ler.retiring && slot<LE_PAGES &&
        slot<=selected_linked_epoch.used && ler_address(slot,target) &&
        target==le_entry(r->source.key.entry,slot) && selected_linked_epoch_busy &&
        !selected_linked_epoch_active && !selected_step_pending &&
        selected_pending_route==SELECTED_NO_STEP && le_quiet(&selected_borrow) &&
        le_identity() && r->build_started && r->build_returned && !r->build_result &&
        selected_linked_epoch.scratch.ready==1 &&
        selected_linked_epoch.scratch.generated==target,LE_STATE,306);
    le_need(ler.generation!=UINT64_MAX,LE_OVERFLOW,300);
    struct le_slot *s=&selected_linked_epoch.slots[slot];
    /* Install stable cleanup addresses before inspection, retirement or clearing
       mutable slot bytes. A nested event never closes a partially copied plan. */
    ler.pending=1;ler.slot=slot;ler.target=target;r->slot=(unsigned)slot;r->slot_present=1;
    selected_pending_route=SELECTED_LINKED_EPOCH;selected_step_pending=1;__asm__ volatile("":::"memory");
    if(slot<selected_linked_epoch.used) {
        le_need(ler_permitted(slot),LE_STATE,307);
        struct ler_retirement *t=&ler.retirement;
        le_zero(t,sizeof *t);t->started=1;t->slot=slot;t->old_entry=le_plan(s)->generated;t->new_entry=target;
        t->old_generation=ler.live[slot];t->new_generation=ler.generation+1;
        t->completion=ler.permits[slot].completion;le_count(&ler.retirement_attempts);
        t->ordinal=ler.retirement_attempts;copy(&t->old_slot,s,sizeof *s);
        copy(&ler.claimed,&ler.permits[slot],sizeof ler.claimed);
        ler.permits[slot].valid=0;t->consumed=1;ler.retiring=1;__asm__ volatile("":::"memory");
        /* A fresh full reconstruction detects stale/corrupted metadata before
           it is retired; every byte of its actual closed image still matches. */
        le_need(!le_rebuild(le_plan(s)) && !le_query(t->old_entry,PROT_READ,&t->old_idle) &&
            !le_bytes(s,&t->verified_bytes),LE_PUBLICATION,300);t->old_verified=1;
        copy(t->old_payload,(const void *)s->proof,sizeof t->old_payload);
        ler.live[slot]=0;lep.ready_generation[slot]=0;
        le_need(!ler_permission(t->old_entry,PROT_READ,&t->revoked),LE_PUBLICATION,301);
        /* Low/high placement can switch. Revoke the actual target too, even
           when it is virgin RW; no retained opposite-arena page stays RX. */
        le_need(!ler_permission(target,PROT_READ,&t->target_closed),LE_PUBLICATION,302);
        le_need(!ler_permission(target,PROT_READ|PROT_WRITE,&t->writable),LE_PUBLICATION,303);
#ifdef LI2_LINKED_PREEDGE
        le_need(!li2_lifecycle_preedge_validate(&selected_borrow,&r->source,&selected_linked_epoch.scratch) &&
#else
        le_need(!li2_lifecycle_link_validate(&selected_borrow,&r->source,&selected_linked_epoch.scratch) &&
#endif
            le_quiet(&selected_borrow) && le_unchanged(&r->before,si,uc),LE_SOURCE,300);
        t->target_ready=1;ler.predecessor[slot]=t->old_generation;
        le_proof_writable(slot);le_zero(s,sizeof *s);
    } else {
        le_need(!s->installed && !s->complete && !s->identity && !ler.live[slot] &&
            !ler.permits[slot].valid,LE_STATE,308);
    }
    if(slot==selected_linked_epoch.used)le_proof_writable(slot);
    ++ler.generation;ler.live[slot]=ler.generation;ler.entry[slot]=target;
    r->publication_generation=ler.generation;
}
static void ler_published(size_t slot) {
    le_need(ler.pending && ler.slot==slot && ler_identity(slot,ler.generation),LE_STATE,309);
    if(ler.retiring) {
        struct ler_retirement *t=&ler.retirement;
        le_need(t->started && t->consumed && t->target_ready && !t->replaced &&
            t->slot==slot && t->new_generation==ler.generation,LE_STATE,310);
        t->replaced=1;le_count(&ler.retirements);ler.cursor=(slot+1)%LE_PAGES;ler.retiring=0;
    }
}
static void ler_claim(size_t slot,int hit) {
    struct le_record *r=&selected_linked_epoch.current;
    le_need(slot<selected_linked_epoch.used && ler_protected() && !ler.retiring,LE_STATE,311);
    if(hit) {
        le_need(!ler.pending && ler_address(slot,ler.entry[slot]),LE_STATE,312);
        ler.pending=1;ler.slot=slot;ler.target=ler.entry[slot];
        r->publication_generation=ler.live[slot];
        le_need(ler_permitted(slot),LE_STATE,312);
        copy(&ler.claimed,&ler.permits[slot],sizeof ler.claimed);ler.permits[slot].valid=0;
    } else le_need(ler.pending && ler.slot==slot && r->publication_generation==ler.live[slot],LE_STATE,313);
    le_need(ler_identity(slot,r->publication_generation),LE_STATE,311);
    le_count(&ler.claims);
}
static int ler_claimed(void) {
    const struct le_record *r=&selected_linked_epoch.current;
    return ler.pending==1 && !ler.retiring && r->slot_present && r->slot==ler.slot && r->slot<LE_PAGES &&
        !ler.permits[r->slot].valid && ler_identity(r->slot,r->publication_generation) &&
        ler.target==selected_linked_epoch.slots[r->slot].generated;
}
static void ler_quiesce(int sig,const siginfo_t *si,const ucontext_t *uc) {
    const struct le_record *r=&selected_linked_epoch.current;
    const struct li2_fetch_progress *f=li2_lifecycle_fetch_progress();
    le_need(ler_claimed() && !ler.retiring && selected_linked_epoch_busy &&
        !selected_linked_epoch_active && !selected_step_pending &&
        selected_pending_route==SELECTED_NO_STEP && !li2_lifecycle_fetch_interlock() &&
        selected_linked_epoch.entries==selected_linked_epoch.completed && r->completed==1 &&
        r->release_complete==1 && !r->release_result && r->close.complete==1 &&
#ifdef LI2_LINKED_PREEDGE
        r->closed_bytes==PAGE && r->epoch_final.phase==LI2_PREEDGE_RELEASED &&
#else
        r->closed_bytes==PAGE && r->epoch_final.phase==LI2_LINK_RELEASED &&
#endif
        r->epoch_final.release_complete==1 && !li2_lifecycle_link_interlock() && f && !f->held && f->complete && !f->first_error &&
        equal(f,&r->final_fetch,sizeof *f) && equal(r,&selected_linked_epoch.last,sizeof *r) &&
        sig==r->after.sig && le_identity() && le_quiet(0) && le_unchanged(&r->after,si,uc),LE_STATE,314);
    struct ler_permit *p=&ler.permits[r->slot];le_need(!p->valid,LE_STATE,315);
    p->generation=r->publication_generation;p->completion=selected_linked_epoch.completed;
    p->valid=1;le_count(&ler.permits_issued);ler.pending=0;
}
static void ler_abort(void) {
    struct le_record *r=&selected_linked_epoch.current;
    if(!ler.pending || r->cleanup_started)return;
    r->cleanup_started=1;
    if(!ler_protected() || !r->slot_present || r->slot!=ler.slot ||
       !ler_address(ler.slot,ler.target))return;
    int error=ler_permission(ler.target,PROT_READ,&r->cleanup);
    struct ler_retirement *t=&ler.retirement;
    if(ler.retiring && t->started && t->slot==ler.slot && t->old_entry!=ler.target) {
        if(!ler_address(t->slot,t->old_entry))return;
        int old_error=ler_permission(t->old_entry,PROT_READ,&t->cleanup);
        if(old_error)return;
    }
    if(!error)r->cleanup_complete=1;
    /* First error and permit consumption survive. No failed generation can
       receive a completion permit or be dispatched/recycled. */
}
static void ler_report(unsigned status,unsigned code,long detail) {
#ifdef LI2_LINKED_PREEDGE
    struct writer w={.used=0};text(&w,"LI2_LINKED_PREEDGE_REUSE {\"version\":2");
#else
    struct writer w={.used=0};text(&w,"LI2_LINKED_EPOCH_REUSE {\"version\":1");
#endif
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",detail<0?0ULL-(uint64_t)detail:(uint64_t)detail);
    field(&w,",\"detail_negative\":",detail<0);
    field(&w,",\"generation\":",ler.generation);field(&w,",\"retirement_attempts\":",ler.retirement_attempts);
    field(&w,",\"retirements\":",ler.retirements);field(&w,",\"claims\":",ler.claims);
    field(&w,",\"permits_issued\":",ler.permits_issued);field(&w,",\"pending\":",ler.pending);
    field(&w,",\"retiring\":",ler.retiring);field(&w,",\"cursor\":",ler.cursor);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
_Static_assert(14*21+256<=sizeof(((struct writer *)0)->bytes),"bounded reuse report");
