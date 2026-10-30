/* Distinct generation-bound certificate composition. Include after the full
   unchanged reuse helper. No current source ticket or live rseq check is cached. */
#include "scalar_reuse_certificate_config.h"
#if LI2_SCALAR_REGION_REUSE_CERTIFICATE != 1 || LI2_SCALAR_REGION_REUSE != 1 || \
    !defined(LI2_REUSE_CERTIFICATE_BINDING_VERSION) || LI2_REUSE_CERTIFICATE_BINDING_VERSION != 1
#error "literal reuse-certificate profile and actual build identity required"
#endif
static const unsigned char srcg_archive[32]=LI2_REUSE_CERTIFICATE_ARCHIVE_SHA256;
static const unsigned char srcg_policy_digest[32]=LI2_REUSE_CERTIFICATE_POLICY_SHA256;
#define SRCG_BYTES LI2_REUSE_CERTIFICATE_BYTES
#define SRCG_TOTAL (SR_PAGES*SRCG_BYTES)
struct srcg_publication {
    unsigned started,complete;
    size_t zeroed,copied,verified;
    struct li2_reuse_certificate_header header;
    struct li2_private_code_query writable;
    struct sr_permission sealed;
};
struct srcg_current {
    unsigned pending,constructing,committed;
    size_t slot;
    uintptr_t address,generated;
    uint64_t old_generation,generation,plan_proof,rseq_proof;
    struct li2_private_code_query virgin;
    struct sr_permission cleanup;
};
struct srcg_retirement {
    unsigned started,consumed,old_verified,authority_revoked,writable_complete;
    size_t slot,compared,copied;
    uintptr_t address,old_entry,new_entry;
    uint64_t old_generation,new_generation,completion;
    struct srcg_publication old_publication;
    struct li2_private_code_query old_idle;
    struct sr_permission closed,writable;
    unsigned char old_bytes[SRCG_BYTES];
};
static struct {
    unsigned initialized,metadata_registered,allocated,arena_registered;
    long allocation_result;
    uintptr_t arena;
    uint64_t publications,retirements,checks,live_checks,terminal_matches;
    uint64_t ready_generation[SR_PAGES];
    struct li2_private_code_query initial[SRCG_TOTAL/(64U*PAGE)];
    struct srcg_publication slot[SR_PAGES];
    struct srcg_current current;
    struct srcg_retirement retirement;
} srcg_store;

static int srcg_protected(void) {
    return sr_protected() && srcg_store.metadata_registered==1 &&
        srcg_store.arena_registered==1 && srcg_store.allocated==1 &&
        selected_run_protect_contains(0,(uintptr_t)&srcg_store,sizeof srcg_store)==1 &&
        selected_run_protect_contains(0,srcg_store.arena,SRCG_TOTAL)==1;
}
static uintptr_t srcg_address(size_t slot) {
    if(srcg_store.initialized!=1 || slot>=SR_PAGES || !srcg_store.arena ||
       (srcg_store.arena&(PAGE-1)) || srcg_store.arena>=(UINT64_C(1)<<47)-SRCG_TOTAL ||
       !srcg_protected())return 0;
    return srcg_store.arena+slot*SRCG_BYTES;
}
static int srcg_query(uintptr_t address,int prot,struct li2_private_code_query *q) {
    if(!address)return SR_STATE;
    int e=li2_lifecycle_private_code_query(address,SRCG_BYTES,prot,q);
    return e || q->attempted!=1 || q->complete!=1 || q->result ||
        q->first!=address || q->end!=address+SRCG_BYTES ||
        q->pages_checked!=LI2_REUSE_CERTIFICATE_PAGES ||
        q->expected_prot!=prot || q->actual_prot!=prot?SR_PUBLICATION:0;
}
static int srcg_permission(uintptr_t address,int prot,struct sr_permission *p) {
    if(!address || p->started || (prot!=PROT_READ && prot!=(PROT_READ|PROT_WRITE)))return SR_STATE;
    p->prot=prot;p->started=1;__asm__ volatile("":::"memory");
    p->result=raw(SYS_mprotect,address,SRCG_BYTES,prot,0,0,0);p->returned=1;
    p->sync_started=1;__asm__ volatile("":::"memory");
    p->sync_result=raw(SYS_membarrier,32,0,0,0,0,0);p->sync_returned=1;
    int e=srcg_query(address,prot,&p->query);
    if(p->result || p->sync_result || e)return SR_PUBLICATION;
    p->complete=1;return 0;
}
static void srcg_initialize(void) {
    sr_need(!srcg_store.initialized && !srcg_store.allocated && srr_protected() &&
        selected_scalar_region_busy && !selected_scalar_region_active,SR_STATE,400);
    unsigned archive=0,policy=0;
    for(size_t i=0;i<32;i++){archive|=srcg_archive[i];policy|=srcg_policy_digest[i];}
    sr_need(archive && policy,SR_STATE,401);
    sr_need(!selected_run_protect_add(0,(uintptr_t)&srcg_store,sizeof srcg_store),SR_STATE,402);
    srcg_store.metadata_registered=1;
    srcg_store.allocation_result=raw(SYS_mmap,0,SRCG_TOTAL,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    long a=srcg_store.allocation_result;
    sr_need(!(a<0 && a>=-4095) && a>0 && !((uintptr_t)a&(PAGE-1)) &&
        (uintptr_t)a<(UINT64_C(1)<<47)-SRCG_TOTAL,SR_PUBLICATION,a);
    srcg_store.arena=(uintptr_t)a;srcg_store.allocated=1;
    sr_need(((uintptr_t)a+SRCG_TOTAL<=selected_scalar_region.arena ||
             (uintptr_t)a>=selected_scalar_region.arena+SR_BYTES) &&
            ((uintptr_t)a+SRCG_TOTAL<=selected_scalar_region.low_arena ||
             (uintptr_t)a>=selected_scalar_region.low_arena+SR_BYTES),SR_PUBLICATION,400);
    sr_need(!selected_run_protect_add(0,(uintptr_t)a,SRCG_TOTAL),SR_STATE,403);
    srcg_store.arena_registered=1;sr_need(srcg_protected(),SR_STATE,404);
    /* Preserve the original private query's maximum 64 pages per call. */
    for(size_t i=0;i<sizeof(srcg_store.initial)/sizeof(srcg_store.initial[0]);i++) {
        struct li2_private_code_query *q=&srcg_store.initial[i];
        uintptr_t first=(uintptr_t)a+i*64U*PAGE;
        int e=li2_lifecycle_private_code_query(first,64U*PAGE,PROT_READ|PROT_WRITE,q);
        sr_need(!e && q->complete==1 && q->pages_checked==64 && q->first==first &&
            q->end==first+64U*PAGE && q->actual_prot==(PROT_READ|PROT_WRITE),SR_PUBLICATION,401);
    }
    srcg_store.initialized=1;
}
/* Pure small readiness check for reuse identity. It never calls srr_identity:
   srr_identity uses this additional, separately published authority. */
static int srcg_ready(size_t slot,uint64_t generation) {
    if(!generation || !srcg_address(slot) || srcg_store.ready_generation[slot]!=generation)return 0;
    const struct srcg_publication *p=&srcg_store.slot[slot];
    return p->started==1 && p->complete==1 && p->header.slot==slot &&
        p->header.generation==generation && p->header.generated==srr.entry[slot] &&
        p->sealed.complete==1 && p->zeroed==SRCG_BYTES &&
        p->copied==sizeof(struct li2_reuse_certificate) && p->verified==SRCG_BYTES;
}
/* Exact full payload comparison; no decoder, RAW, guest load operand, or
   caller-supplied address. This is also safe for terminal-only PC association. */
static int srcg_equal(size_t slot,uint64_t generation,const struct sr_slot *s,size_t *compared) {
    if(!srcg_ready(slot,generation) || slot>=selected_scalar_region.used ||
       s!=&selected_scalar_region.slots[slot] || s->identity!=generation ||
       s->plan.generated!=srr.entry[slot])return SR_STATE;
    const struct srcg_publication *p=&srcg_store.slot[slot];
    const struct li2_reuse_certificate_header *h=&p->header;
    uintptr_t address=srcg_address(slot);
    const struct li2_reuse_certificate *c=(const void *)address;
    if(h->version!=1 || h->bytes!=SRCG_BYTES || h->registry!=(uintptr_t)&srcg_store ||
       !h->plan_proof || h->plan_proof>selected_scalar_region.plan_checks ||
       !h->rseq_proof || h->rseq_proof>selected_scalar_region.rseq_checks ||
       h->reserved[0] || h->reserved[1] || h->reserved[2] || h->reserved[3] ||
       !equal(h->archive,srcg_archive,32) || !equal(h->policy,srcg_policy_digest,32) ||
       p->writable.attempted!=1 || p->writable.complete!=1 || p->writable.first!=address ||
       p->writable.end!=address+SRCG_BYTES || p->writable.pages_checked!=LI2_REUSE_CERTIFICATE_PAGES ||
       p->writable.expected_prot!=(PROT_READ|PROT_WRITE) ||
       p->writable.actual_prot!=(PROT_READ|PROT_WRITE) || p->writable.result ||
       p->sealed.started!=1 || p->sealed.returned!=1 || p->sealed.sync_started!=1 ||
       p->sealed.sync_returned!=1 || p->sealed.result || p->sealed.sync_result ||
       p->sealed.prot!=PROT_READ || p->sealed.query.attempted!=1 || p->sealed.query.complete!=1 ||
       p->sealed.query.first!=address || p->sealed.query.end!=address+SRCG_BYTES ||
       p->sealed.query.pages_checked!=LI2_REUSE_CERTIFICATE_PAGES ||
       p->sealed.query.expected_prot!=PROT_READ || p->sealed.query.actual_prot!=PROT_READ || p->sealed.query.result ||
       !equal(&c->header,h,sizeof *h) || !equal(&c->key,&s->key,sizeof c->key) ||
       !equal(&c->plan,&s->plan,sizeof c->plan))return SR_PLAN;
    *compared=sizeof(*c);
    const volatile unsigned char *b=(const void *)address;
    for(size_t i=sizeof(*c);i<SRCG_BYTES;i++){if(b[i])return SR_PLAN;*compared=i+1;}
    return 0;
}
static void srcg_begin(void) {
    sr_need(srcg_store.initialized==1 && !srcg_store.current.pending,SR_STATE,405);
    sr_zero(&srcg_store.current,sizeof srcg_store.current);
}
static void srcg_anchor(size_t slot,uintptr_t generated,uint64_t generation) {
    struct srcg_current *a=&srcg_store.current;
    sr_need(!a->pending && slot<SR_PAGES && srr_address(slot,generated),SR_STATE,406);
    /* Install the stable numeric extent before any further certificate/slot
       inspection. Abort does not depend on used, installed, ready or payload. */
    a->slot=slot;a->address=srcg_address(slot);a->generated=generated;
    a->generation=generation;a->pending=1;__asm__ volatile("":::"memory");
    sr_need(a->address && generation,SR_STATE,407);
}
/* Explicit unchanged 47-Code policy: future decoder extensions do not acquire
   certificate authority automatically. Numeric IDs are locked iced 1.21; full
   actual plan and per-head NONE validators already ran before this guard. */
static int srcg_policy(const struct li2_region_plan *p) {
    if(p->ready!=1 || !p->heads || p->heads>LI2_REGION_HEADS)return 0;
    for(size_t i=0;i<p->heads;i++) {
        const struct li2_region_decoded *d=&p->original[i];
        switch(d->decoded.code) {
        case 281: /* Mov_rm32_r32 */
        case 282: /* Mov_rm64_r64 */
        case 285: /* Mov_r32_rm32 */
        case 286: /* Mov_r64_rm64 */
        case 2090: /* Movzx_r32_rm8 */
        case 2091: /* Movzx_r64_rm8 */
        case 260: /* And_rm32_imm8 */
        case 261: /* And_rm64_imm8 */
        case 96: /* Xor_rm32_r32 */
        case 97: /* Xor_rm64_r64 */
        case 273: /* Test_rm32_r32 */
        case 274: /* Test_rm64_r64 */
        case 115: /* Cmp_AL_imm8 */
        case 161: /* Jo_rel8_64 */
        case 1856: /* Jo_rel32_64 */
        case 164: /* Jno_rel8_64 */
        case 1859: /* Jno_rel32_64 */
        case 167: /* Jb_rel8_64 */
        case 1862: /* Jb_rel32_64 */
        case 170: /* Jae_rel8_64 */
        case 1865: /* Jae_rel32_64 */
        case 173: /* Je_rel8_64 */
        case 1868: /* Je_rel32_64 */
        case 176: /* Jne_rel8_64 */
        case 1871: /* Jne_rel32_64 */
        case 179: /* Jbe_rel8_64 */
        case 1874: /* Jbe_rel32_64 */
        case 182: /* Ja_rel8_64 */
        case 1877: /* Ja_rel32_64 */
        case 185: /* Js_rel8_64 */
        case 1880: /* Js_rel32_64 */
        case 188: /* Jns_rel8_64 */
        case 1883: /* Jns_rel32_64 */
        case 191: /* Jp_rel8_64 */
        case 1886: /* Jp_rel32_64 */
        case 194: /* Jnp_rel8_64 */
        case 1889: /* Jnp_rel32_64 */
        case 197: /* Jl_rel8_64 */
        case 1892: /* Jl_rel32_64 */
        case 200: /* Jge_rel8_64 */
        case 1895: /* Jge_rel32_64 */
        case 203: /* Jle_rel8_64 */
        case 1898: /* Jle_rel32_64 */
        case 206: /* Jg_rel8_64 */
        case 1901: /* Jg_rel32_64 */
        case 701: /* Jmp_rel8_64 */
        case 696: /* Jmp_rel32_64 */
            break;
        default:return 0;
        }
        if(d->version!=1 || d->ready!=1 || d->refusal || d->memory_count>1 ||
           (d->memory_count && d->memory.access!=LI2_REGION_READ) ||
           d->operand_count>2 || (d->gpr_write&(1U<<4)))return 0;
        for(size_t j=0;j<d->operand_count;j++)
            if((d->operands[j].access&LI2_REGION_WRITE) &&
               d->operands[j].kind!=LI2_REGION_REGISTER)return 0;
    }
    return 1;
}

static void srcg_prepare(size_t slot,uintptr_t generated) {
    srcg_anchor(slot,generated,srr.generation+1);
    struct sr_record *r=&selected_scalar_region.current;
    sr_need(srr.pending && srr.slot==slot && srr.target==generated && !srr.retiring &&
        srr.generation!=UINT64_MAX && r->build_started && r->build_returned && !r->build_result &&
        selected_scalar_region.scratch.ready==1 && srcg_policy(&selected_scalar_region.scratch) &&
        selected_scalar_region.plan_checks &&
        selected_scalar_region.rseq_checks && r->source.ready==1 &&
        selected_scalar_region.scratch.page==r->source.key.page.address &&
        selected_scalar_region.scratch.entry==r->source.key.entry &&
        equal(selected_scalar_region.scratch.source,r->source.key.bytes,PAGE),SR_STATE,408);
    struct srcg_current *a=&srcg_store.current;
    a->constructing=1;a->old_generation=srr.live[slot];
    /* Capture the actual successful NEW cold proofs before old retirement's
       additional full reconstruction changes the plan counter. */
    a->plan_proof=selected_scalar_region.plan_checks;a->rseq_proof=selected_scalar_region.rseq_checks;
    sr_need(a->address+SRCG_BYTES<=r->source.key.page.address ||
        a->address>=r->source.key.page.address+PAGE,SR_SOURCE,400);
    if(slot==selected_scalar_region.used) {
        sr_need(!a->old_generation && !srcg_store.ready_generation[slot] &&
            !srcg_store.slot[slot].started,SR_STATE,409);
        sr_need(!srcg_query(a->address,PROT_READ|PROT_WRITE,&a->virgin),SR_PUBLICATION,402);
    }
}
static void srcg_retire_verify(size_t slot) {
    struct srcg_current *a=&srcg_store.current;
    const struct srr_retirement *old=&srr.retirement;
    sr_need(a->pending && a->constructing && a->slot==slot && srr.retiring &&
        old->started && old->consumed && !srr.permits[slot].valid &&
        srr.claimed.valid==1 && srr.claimed.generation==a->old_generation &&
        srr.claimed.completion==old->completion && old->old_generation==a->old_generation &&
        old->new_generation==a->generation && old->slot==slot,SR_STATE,410);
    struct srcg_retirement *t=&srcg_store.retirement;sr_zero(t,sizeof *t);
    t->started=1;t->consumed=1;t->slot=slot;t->address=a->address;
    t->old_generation=a->old_generation;t->new_generation=a->generation;
    t->old_entry=old->old_entry;t->new_entry=old->new_entry;t->completion=old->completion;
    sr_need(!srcg_query(t->address,PROT_READ,&t->old_idle) &&
        !srcg_equal(slot,t->old_generation,&selected_scalar_region.slots[slot],&t->compared),SR_PUBLICATION,403);
    copy(&t->old_publication,&srcg_store.slot[slot],sizeof t->old_publication);
    const volatile unsigned char *b=(const void *)t->address;
    for(size_t i=0;i<SRCG_BYTES;i++){t->old_bytes[i]=b[i];t->copied=i+1;}
    t->old_verified=1;
}
static void srcg_revoke(size_t slot) {
    struct srcg_retirement *t=&srcg_store.retirement;
    sr_need(t->started && t->consumed && t->old_verified && t->slot==slot &&
        t->compared==SRCG_BYTES && t->copied==SRCG_BYTES && !srr.live[slot] &&
        srr.retirement.old_verified && srr.retirement.old_generation==t->old_generation &&
        srcg_store.ready_generation[slot]==t->old_generation,SR_STATE,411);
    srcg_store.ready_generation[slot]=0;t->authority_revoked=1;__asm__ volatile("":::"memory");
}
static void srcg_writable(size_t slot) {
    struct srcg_retirement *t=&srcg_store.retirement;
    const struct srr_retirement *old=&srr.retirement;
    sr_need(t->authority_revoked && t->slot==slot && !t->writable_complete &&
        !srcg_store.ready_generation[slot] && !srr.live[slot] && !srr.permits[slot].valid &&
        old->consumed && old->revoked.complete && old->target_closed.complete &&
        old->slot==slot && old->old_generation==t->old_generation &&
        old->new_generation==t->new_generation && old->old_entry==t->old_entry &&
        old->new_entry==t->new_entry,SR_STATE,412);
    sr_need(!srcg_permission(t->address,PROT_READ,&t->closed),SR_PUBLICATION,404);
    sr_need(!srcg_permission(t->address,PROT_READ|PROT_WRITE,&t->writable),SR_PUBLICATION,405);
    t->writable_complete=1;
}
static void srcg_publish(size_t slot) {
    sr_need(slot<SR_PAGES,SR_STATE,421);
    struct srcg_current *a=&srcg_store.current;struct sr_record *r=&selected_scalar_region.current;
    struct sr_slot *s=&selected_scalar_region.slots[slot];
    sr_need(a->pending && a->constructing && !a->committed && a->slot==slot &&
        a->address==srcg_address(slot) && a->generation==srr.generation &&
        a->generation==srr.live[slot] && a->generation==r->publication_generation &&
        srr.pending && srr.slot==slot && srr.target==a->generated &&
        !srcg_store.ready_generation[slot] && s->installed==1 && !s->complete &&
        s->identity==a->generation && s->plan.generated==a->generated &&
        s->publication.complete==1 && s->filled==PAGE && s->verified==PAGE &&
        li2_region_source_key_equal(&s->key,&r->source.key) &&
        equal(&s->plan,&selected_scalar_region.scratch,sizeof s->plan) &&
        selected_scalar_region_busy && !selected_scalar_region_active &&
        selected_pending_route==SELECTED_SCALAR_REGION && selected_step_pending==1,SR_STATE,413);
    if(a->old_generation) {
        const struct srcg_retirement *t=&srcg_store.retirement;
        sr_need(srr.retiring && t->slot==slot && t->new_generation==a->generation &&
            t->authority_revoked && t->writable_complete && srr.retirement.target_ready &&
            !srr.permits[slot].valid,SR_STATE,414);
    } else sr_need(a->virgin.complete==1 && !srr.retiring,SR_STATE,415);
    struct srcg_publication *p=&srcg_store.slot[slot];sr_zero(p,sizeof *p);p->started=1;
    sr_need(!srcg_query(a->address,PROT_READ|PROT_WRITE,&p->writable),SR_PUBLICATION,406);
    struct li2_reuse_certificate_header *h=&p->header;
    h->version=1;h->bytes=SRCG_BYTES;h->registry=(uintptr_t)&srcg_store;h->slot=slot;
    h->generation=a->generation;h->generated=a->generated;h->plan_proof=a->plan_proof;h->rseq_proof=a->rseq_proof;
    copy(h->archive,srcg_archive,32);copy(h->policy,srcg_policy_digest,32);
    volatile unsigned char *b=(void *)a->address;
    for(size_t i=0;i<SRCG_BYTES;i++){b[i]=0;p->zeroed=i+1;}
    struct li2_reuse_certificate *c=(void *)a->address;
    copy(&c->header,h,sizeof *h);copy(&c->key,&s->key,sizeof c->key);copy(&c->plan,&s->plan,sizeof c->plan);
    p->copied=sizeof(*c);
    sr_need(!srcg_permission(a->address,PROT_READ,&p->sealed),SR_PUBLICATION,407);
    sr_need(equal(&c->header,h,sizeof *h) && equal(&c->key,&s->key,sizeof c->key) &&
        equal(&c->plan,&s->plan,sizeof c->plan),SR_PLAN,400);
    p->verified=sizeof(*c);
    for(size_t i=sizeof(*c);i<SRCG_BYTES;i++){sr_need(!b[i],SR_PLAN,401);p->verified=i+1;}
    p->complete=1; /* Not dispatch readiness: both publications must commit. */
}
static void srcg_commit(size_t slot) {
    sr_need(slot<SR_PAGES,SR_STATE,422);
    struct srcg_current *a=&srcg_store.current;const struct sr_slot *s=&selected_scalar_region.slots[slot];
    const struct srcg_publication *p=&srcg_store.slot[slot];
    sr_need(a->pending && a->constructing && !a->committed && a->slot==slot &&
        a->generation==srr.generation && a->generation==srr.live[slot] &&
        !srcg_store.ready_generation[slot] && s->installed==1 && s->complete==1 &&
        s->identity==a->generation && s->plan.generated==a->generated && s->publication.complete==1 &&
        s->filled==PAGE && s->verified==PAGE && p->complete==1 && p->sealed.complete==1 &&
        p->verified==SRCG_BYTES && p->header.generation==a->generation &&
        p->header.plan_proof==a->plan_proof && p->header.rseq_proof==a->rseq_proof,SR_STATE,416);
    __asm__ volatile("":::"memory");srcg_store.ready_generation[slot]=a->generation;a->committed=1;
    sr_count(&srcg_store.publications);if(a->old_generation)sr_count(&srcg_store.retirements);
}
static void srcg_hit(size_t slot) {
    sr_need(slot<SR_PAGES,SR_STATE,423);
    srcg_anchor(slot,srr.entry[slot],srr.live[slot]);
    srcg_store.current.committed=1;
}
static int srcg_current_slot(const struct sr_slot *s) {
    const struct sr_record *r=&selected_scalar_region.current;const struct srcg_current *a=&srcg_store.current;
    return a->pending==1 && a->committed==1 && r->slot_present && r->slot<SR_PAGES &&
        r->slot==a->slot && s==&selected_scalar_region.slots[r->slot] && srr_claimed() &&
        a->address==srcg_address(r->slot) && a->generation==r->publication_generation &&
        a->generated==s->plan.generated && li2_region_source_key_equal(&s->key,&r->source.key);
}
static int srcg_check(struct sr_slot *s,unsigned stage) {
    struct sr_record *r=&selected_scalar_region.current;
    if(stage>=2 || !srcg_current_slot(s))return SR_STATE;
    struct li2_reuse_certificate_observation *o=&r->certificate[stage];
    if(o->match.attempted)return SR_STATE;
    o->match.attempted=1;o->match.generation=r->publication_generation;
    int e=srcg_query(srcg_address(r->slot),PROT_READ,&o->mapping);
    if(!e)e=srcg_equal(r->slot,r->publication_generation,s,&o->match.compared);
    o->match.result=e;selected_initialized();if(e)return e;
    o->match.complete=1;sr_count(&srcg_store.checks);return 0;
}
static int srcg_live(struct sr_slot *s,const ucontext_t *uc,unsigned stage) {
    struct sr_record *r=&selected_scalar_region.current;
    if(stage>=3 || !srcg_current_slot(s) || !r->certificate[stage==2].match.complete)return SR_STATE;
    struct li2_reuse_certificate_match *m=&r->certificate_live[stage];
    if(m->attempted)return SR_STATE;
    m->attempted=1;m->generation=r->publication_generation;
    int e=srcg_equal(r->slot,r->publication_generation,s,&m->compared);
    if(!e)e=li2_rseq_region_live(uc,&r->live_rseq[stage]);
    m->result=e;selected_initialized();if(e)return e;
    m->complete=1;sr_count(&srcg_store.live_checks);return 0;
}
static int srcg_terminal(const struct sr_slot *s) {
    struct sr_record *r=&selected_scalar_region.current;
    struct li2_reuse_certificate_match *m=&r->certificate_terminal;
    if(m->attempted || !selected_scalar_region_active || !r->redirected || r->completed ||
       !r->open.complete || !r->certificate[0].match.complete ||
       !r->certificate_live[0].complete || !r->certificate_live[1].complete ||
       !srcg_current_slot(s))return SR_STATE;
    m->attempted=1;m->generation=r->publication_generation;
    m->result=srcg_equal(r->slot,r->publication_generation,s,&m->compared);
    if(m->result)return m->result;
    if(srcg_store.terminal_matches==UINT64_MAX)return m->result=SR_OVERFLOW;
    m->complete=1;++srcg_store.terminal_matches;return 0;
}
static void srcg_quiesce(void) {
    const struct sr_record *r=&selected_scalar_region.current;
    sr_need(r->slot_present && r->slot<SR_PAGES &&
        srcg_current_slot(&selected_scalar_region.slots[r->slot]),SR_STATE,417);
    for(size_t i=0;i<2;i++)sr_need(r->certificate[i].match.complete==1 &&
        !r->certificate[i].match.result && r->certificate[i].match.compared==SRCG_BYTES &&
        r->certificate[i].match.generation==r->publication_generation,SR_STATE,418);
    for(size_t i=0;i<3;i++)sr_need(r->certificate_live[i].complete==1 &&
        !r->certificate_live[i].result && r->certificate_live[i].compared==SRCG_BYTES &&
        r->certificate_live[i].generation==r->publication_generation &&
        r->live_rseq[i].complete==1 && !r->live_rseq[i].result,SR_STATE,419);
}
static void srcg_released(void) {
    const struct sr_record *r=&selected_scalar_region.current;
    sr_need(r->slot_present && r->slot<SR_PAGES && srcg_store.current.pending==1 && !srr.pending &&
        srr.permits[r->slot].valid==1 && srr.permits[r->slot].generation==r->publication_generation &&
        srr.permits[r->slot].completion==selected_scalar_region.completed,SR_STATE,420);
    srcg_store.current.pending=0;
}
static void srcg_abort(void) {
    struct srcg_current *a=&srcg_store.current;
    if(!a->pending || a->cleanup.started)return;
    if(a->slot>=SR_PAGES || !a->address || a->address!=srcg_address(a->slot))return;
    /* Independently close the certificate even when code cleanup returned
       early. Revocation and consumed permit survive any partial syscall. */
    srcg_store.ready_generation[a->slot]=0;__asm__ volatile("":::"memory");
    (void)srcg_permission(a->address,PROT_READ,&a->cleanup);
}
static void srcg_report(unsigned status,unsigned code,long detail) {
    struct writer w={.used=0};text(&w,"LI2_SCALAR_REUSE_CERTIFICATE {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",detail<0?0ULL-(uint64_t)detail:(uint64_t)detail);
    field(&w,",\"detail_negative\":",detail<0);field(&w,",\"initialized\":",srcg_store.initialized);
    field(&w,",\"publications\":",srcg_store.publications);field(&w,",\"retirements\":",srcg_store.retirements);
    field(&w,",\"certificate_checks\":",srcg_store.checks);field(&w,",\"live_rseq_checks\":",srcg_store.live_checks);
    field(&w,",\"terminal_matches\":",srcg_store.terminal_matches);
    field(&w,",\"pending\":",srcg_store.current.pending);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
_Static_assert(SRCG_TOTAL/(64U*PAGE)==16,"old per-query bound retained");
_Static_assert(12*21+256<=sizeof(((struct writer *)0)->bytes),"bounded certificate report");
