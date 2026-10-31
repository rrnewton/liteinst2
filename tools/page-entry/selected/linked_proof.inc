/* Immutable payload is the plan itself, not a claimed hash of a mutable BSS
   mirror. Only this publication/retirement path writes it. All guest effects
   retain the existing strict whole protected-range guards. */
#include "linked_epoch_config.h"
#ifdef LI2_LINKED_PREEDGE
#if LI2_LINK_PREEDGE_BINDING_VERSION != 2
#error "exact v2 pre-edge policy binding required"
#endif
#endif
#if LI2_LINKED_EPOCH != 1 || LI2_LINK_BINDING_VERSION != 1
#error "exact linked archive and policy binding required"
#endif
static const unsigned char le_archive[32]=LI2_LINK_ARCHIVE_SHA256;
static const unsigned char le_policy[32]=LI2_LINK_POLICY_SHA256;
#define LE_PROOF_TOTAL (LE_PAGES*LI2_LINK_PROOF_BYTES)
static int le_proof_protected(void) {
    return lep.initialized==1 && lep.registered==1 && lep.allocated==1 && lep.arena_registered==1 &&
        selected_run_protect_contains(0,(uintptr_t)&lep,sizeof lep)==1 &&
        selected_run_protect_contains(0,lep.arena,LE_PROOF_TOTAL)==1 && le_protected();
}
static int le_proof_query(uintptr_t address,int prot,struct li2_private_code_query *q) {
    int e=li2_lifecycle_private_code_query(address,LI2_LINK_PROOF_BYTES,prot,q);
    return e || q->attempted!=1 || q->complete!=1 || q->result || q->first!=address ||
        q->end!=address+LI2_LINK_PROOF_BYTES || q->pages_checked!=16 ||
        q->expected_prot!=prot || q->actual_prot!=prot?LE_PUBLICATION:0;
}
static int le_proof_permission(uintptr_t address,int prot,struct le_permission *p) {
    if(p->started || (prot!=PROT_READ && prot!=(PROT_READ|PROT_WRITE)))return LE_STATE;
    p->started=1;p->prot=prot;
    p->result=raw(SYS_mprotect,address,LI2_LINK_PROOF_BYTES,prot,0,0,0);p->returned=1;
    p->sync_started=1;p->sync_result=raw(SYS_membarrier,32,0,0,0,0,0);p->sync_returned=1;
    int e=le_proof_query(address,prot,&p->query);
    if(p->result || p->sync_result || e)return LE_PUBLICATION;
    p->complete=1;return 0;
}
static void le_proof_initialize(void) {
    le_need(!lep.initialized && !lep.allocated && selected_linked_epoch_busy &&
        !selected_linked_epoch_active && ler_protected(),LE_STATE,420);
    unsigned archive=0,policy=0;
    for(unsigned i=0;i<32;i++){archive|=le_archive[i];policy|=le_policy[i];}
    le_need(archive && policy,LE_STATE,421);
    le_need(!selected_run_protect_add(0,(uintptr_t)&lep,sizeof lep),LE_STATE,422);lep.registered=1;
    lep.allocation_result=raw(SYS_mmap,0,LE_PROOF_TOTAL,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    long a=lep.allocation_result;
    le_need(!(a<0 && a>=-4095) && a>0 && !((uintptr_t)a&(PAGE-1)) &&
        (uintptr_t)a<(UINT64_C(1)<<47)-LE_PROOF_TOTAL,LE_PUBLICATION,a);
    lep.arena=(uintptr_t)a;lep.allocated=1;
    le_need((lep.arena+LE_PROOF_TOTAL<=selected_linked_epoch.arena ||
             lep.arena>=selected_linked_epoch.arena+LE_BYTES) &&
            (lep.arena+LE_PROOF_TOTAL<=selected_linked_epoch.low_arena ||
             lep.arena>=selected_linked_epoch.low_arena+LE_BYTES),LE_PUBLICATION,423);
    le_need(!selected_run_protect_add(0,lep.arena,LE_PROOF_TOTAL),LE_STATE,423);lep.arena_registered=1;
    for(unsigned i=0;i<16;i++) {
        struct li2_private_code_query *q=&lep.initial[i];uintptr_t first=lep.arena+i*64U*PAGE;
        int e=li2_lifecycle_private_code_query(first,64U*PAGE,PROT_READ|PROT_WRITE,q);
        le_need(!e && q->attempted==1 && q->complete==1 && !q->result && q->first==first &&
            q->end==first+64U*PAGE && q->pages_checked==64 && q->actual_prot==(PROT_READ|PROT_WRITE),
            LE_PUBLICATION,424);
    }
    lep.initialized=1;le_need(le_proof_protected(),LE_STATE,424);
}
static int le_proof_ready(const struct le_slot *s) {
    uintptr_t first=(uintptr_t)&selected_linked_epoch.slots[0],address=(uintptr_t)s;
    if(!le_proof_protected() || lep.pending || address<first || address-first>=sizeof selected_linked_epoch.slots ||
       (address-first)%sizeof(*s))return 0;
    size_t slot=(address-first)/sizeof(*s);
    if(!s->identity || lep.ready_generation[slot]!=s->identity ||
       s->proof!=lep.arena+slot*LI2_LINK_PROOF_BYTES || s->generated!=ler.entry[slot] ||
       ler.live[slot]!=s->identity || !ler_address(slot,s->generated))return 0;
    const struct le_proof_publication *q=&lep.slot_publication[slot];
#ifdef LI2_LINKED_PREEDGE
    const struct li2_preedge_proof_header *h=&q->header;
#else
    const struct li2_link_proof_header *h=&q->header;
#endif
    if(q->started!=1 || q->complete!=1 || q->zeroed!=LI2_LINK_PROOF_BYTES ||
#ifdef LI2_LINKED_PREEDGE
       q->copied!=sizeof(struct li2_preedge_proof) || q->verified!=LI2_LINK_PROOF_BYTES ||
#else
       q->copied!=sizeof(struct li2_link_proof) || q->verified!=LI2_LINK_PROOF_BYTES ||
#endif
       q->writable.attempted!=1 || q->writable.complete!=1 || q->writable.result ||
       q->writable.first!=s->proof || q->writable.end!=s->proof+LI2_LINK_PROOF_BYTES ||
       q->writable.pages_checked!=16 || q->writable.expected_prot!=(PROT_READ|PROT_WRITE) ||
       q->writable.actual_prot!=(PROT_READ|PROT_WRITE) ||
       q->sealed.started!=1 || q->sealed.returned!=1 || q->sealed.sync_started!=1 ||
       q->sealed.sync_returned!=1 || q->sealed.complete!=1 || q->sealed.prot!=PROT_READ ||
       q->sealed.result || q->sealed.sync_result || q->sealed.query.attempted!=1 ||
       q->sealed.query.complete!=1 || q->sealed.query.result ||
       q->sealed.query.expected_prot!=PROT_READ || q->sealed.query.actual_prot!=PROT_READ ||
       q->sealed.query.first!=s->proof || q->sealed.query.end!=s->proof+LI2_LINK_PROOF_BYTES ||
#ifdef LI2_LINKED_PREEDGE
       q->sealed.query.pages_checked!=16 || h->version!=2 || h->bytes!=LI2_LINK_PROOF_BYTES ||
#else
       q->sealed.query.pages_checked!=16 || h->version!=1 || h->bytes!=LI2_LINK_PROOF_BYTES ||
#endif
       h->registry!=(uintptr_t)&lep || h->slot!=slot || h->generation!=s->identity ||
       h->generated!=s->generated || !h->plan_proof || !h->none_proof ||
       h->plan_proof>selected_linked_epoch.plan_checks || h->none_proof>selected_linked_epoch.rseq_checks ||
       h->reserved[0] || h->reserved[1] || h->reserved[2] || h->reserved[3] ||
       !equal(h->archive,le_archive,32) || !equal(h->policy,le_policy,32))return 0;
#ifdef LI2_LINKED_PREEDGE
    const struct li2_preedge_proof *p=le_payload(s);
#else
    const struct li2_link_proof *p=le_payload(s);
#endif
#ifdef LI2_LINKED_PREEDGE
    return equal(&p->header,h,sizeof(*h)) && p->plan.version==LI2_PREEDGE_VERSION && p->plan.ready==1 &&
        p->plan.bytes==sizeof(p->plan) && !p->plan.reserved &&
#else
    return equal(&p->header,h,sizeof(*h)) && p->plan.version==LI2_LINK_VERSION && p->plan.ready==1 &&
#endif
        p->plan.generated==s->generated && p->plan.page==p->key.page.address && p->plan.entry==p->key.entry;
}
static int le_proof_check(const struct le_slot *s,struct li2_private_code_query *q) {
    /* Validate the fixed protected address before dereferencing its anchor.
       Pure readiness is also used for fail-stop nested exact-PC association. */
    if(!le_proof_ready(s))return LE_PLAN;
    int e=le_proof_query(s->proof,PROT_READ,q);
    if(e || !le_proof_ready(s))return LE_PUBLICATION;
    le_count(&selected_linked_epoch.proof_checks);return 0;
}
static void le_proof_writable(size_t slot) {
    le_need(le_proof_protected() && !lep.pending && slot<LE_PAGES &&
        !lep.ready_generation[slot] && selected_linked_epoch_busy && !selected_linked_epoch_active &&
        ler.pending && ler.slot==slot && !li2_lifecycle_link_interlock(),LE_STATE,425);
    /* The actual old and target code pages were revoked before this call.
       No live generation or completion permit can survive into proof writes. */
    lep.pending=1;lep.slot=slot;lep.target=lep.arena+slot*LI2_LINK_PROOF_BYTES;
    le_zero(&lep.close,sizeof lep.close);le_zero(&lep.writable,sizeof lep.writable);
    le_zero(&lep.cleanup,sizeof lep.cleanup);
    le_need(!le_proof_permission(lep.target,PROT_READ,&lep.close),LE_PUBLICATION,425);
    le_need(!le_proof_permission(lep.target,PROT_READ|PROT_WRITE,&lep.writable),LE_PUBLICATION,426);
    le_zero(&lep.slot_publication[slot],sizeof lep.slot_publication[slot]);
}
static void le_proof_publish(struct le_slot *s) {
    size_t slot=lep.slot;
    le_need(slot<LE_PAGES,LE_STATE,431);
    struct le_proof_publication *p=&lep.slot_publication[slot];
    le_need(lep.pending==1 && slot<LE_PAGES && s==&selected_linked_epoch.slots[slot] &&
        s->proof==lep.target && s->identity==ler.live[slot] && !lep.ready_generation[slot] &&
        s->publication.complete==1 && s->publication.prot==PROT_READ &&
        s->filled==PAGE && s->verified==PAGE && selected_linked_epoch_busy && !selected_linked_epoch_active,
        LE_STATE,427);
#ifdef LI2_LINKED_PREEDGE
    p->started=1;p->header.version=2;p->header.bytes=LI2_LINK_PROOF_BYTES;
#else
    p->started=1;p->header.version=1;p->header.bytes=LI2_LINK_PROOF_BYTES;
#endif
    p->header.registry=(uintptr_t)&lep;p->header.slot=slot;p->header.generation=s->identity;
    p->header.generated=s->generated;
    p->header.plan_proof=selected_linked_epoch.current.cold_plan_proof;
    p->header.none_proof=selected_linked_epoch.current.cold_none_proof;
    copy(p->header.archive,le_archive,32);copy(p->header.policy,le_policy,32);
    copy(&lep.scratch.header,&p->header,sizeof p->header);
    le_need(!le_proof_query(s->proof,PROT_READ|PROT_WRITE,&p->writable),LE_PUBLICATION,427);
    volatile unsigned char *dst=(void *)s->proof;const unsigned char *src=(const void *)&lep.scratch;
    for(size_t i=0;i<LI2_LINK_PROOF_BYTES;i++){dst[i]=0;p->zeroed=i+1;}
    for(size_t i=0;i<sizeof lep.scratch;i++){dst[i]=src[i];p->copied=i+1;}
    le_need(!le_proof_permission(s->proof,PROT_READ,&p->sealed),LE_PUBLICATION,428);
    for(size_t i=0;i<LI2_LINK_PROOF_BYTES;i++) {
        unsigned char expected=i<sizeof lep.scratch?src[i]:0;
        le_need(dst[i]==expected,LE_PUBLICATION,429);p->verified=i+1;
    }
    p->complete=1;__asm__ volatile("":::"memory");lep.ready_generation[slot]=s->identity;
    lep.pending=0;le_need(le_proof_ready(s),LE_PLAN,430);
}
static void le_proof_abort(void) {
    if(!lep.pending || lep.cleanup.started)return;
    if(!le_proof_protected() || lep.slot>=LE_PAGES ||
       lep.target!=lep.arena+lep.slot*LI2_LINK_PROOF_BYTES)return;
    lep.ready_generation[lep.slot]=0;
    (void)le_proof_permission(lep.target,PROT_READ,&lep.cleanup);
}
