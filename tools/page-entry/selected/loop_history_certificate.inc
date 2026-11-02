/* Included after pda_receipt. The complete old common receipt predicates and
   original source-only reconstructors remain the first-proof authority. */
#include "loop_history_certificate.h"
#define LHC_ROUND(n) (((n)+PAGE-1U)&~(size_t)(PAGE-1U))
enum { LHC_LOOP=1U,LHC_EFFECTS=2U,LHC_REBUILD=4U };
struct lhc_certificate {
    unsigned valid,policy,mask,reserved;
    uint64_t epoch,id,serial;
    const struct li2_pg_epoch *owner;
    const struct pda_completion *completion;
    uintptr_t capsule;
    struct li2_step_session session;
    unsigned char archive[32],policy_hash[32];
};
struct lhc_root {
    unsigned initialized,poisoned,writer,reserved;
    uint64_t epoch[LI2_PGD_RECEIPTS];
    struct lhc_certificate cell[LI2_PGD_RECEIPTS];
};
union lhc_root_page { struct lhc_root value; unsigned char page[PAGE]; };
struct lhc_witnesses { struct li2_le_witness loop,effects; };
union lhc_capsule {
    struct lhc_witnesses value;
    unsigned char pages[LHC_ROUND(sizeof(struct lhc_witnesses))];
};
struct lhc_counts {
    uint64_t decisions,hits,misses,full_calls,differential_checks,disagreements;
    uint64_t issues,invalidations,abort_invalidations,errors,restored_bytes;
};
#ifdef LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL
struct lhc_scratch {
    struct plr_state before_loop,expected_loop;
    struct ple_state before_effects,expected_effects;
    struct li2_pg_plan before_rebuild;
};
#endif
struct lhc_storage {
    union lhc_root_page root;
    union lhc_capsule capsule[LI2_PGD_RECEIPTS];
    struct lhc_counts counts;
#ifdef LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL
    struct lhc_scratch scratch;
#endif
} __attribute__((aligned(PAGE)));
static struct lhc_storage lhc;
_Static_assert(LI2_PGD_RECEIPTS==3 && LI2_PGD_MEMBERS==2,
    "the original two active members and three completion cells");
_Static_assert(sizeof(struct lhc_root)<=PAGE && sizeof(union lhc_root_page)==PAGE &&
    sizeof(union lhc_capsule)%PAGE==0 && offsetof(struct lhc_storage,capsule)%PAGE==0 &&
    offsetof(struct lhc_storage,counts)%PAGE==0 && sizeof lhc%PAGE==0,
    "root and each witness capsule have isolated pages");
_Static_assert(_Alignof(struct pda_completion)==PAGE && sizeof(struct pda_completion)%PAGE==0 &&
    offsetof(struct pda_state,completion)%PAGE==0 &&
    offsetof(struct pda_state,claimed)>=offsetof(struct pda_state,completion)+
        sizeof(((struct pda_state *)0)->completion),
    "completion pages contain no mutable claim masks or adjacent owner state");

static int lhc_add(uint64_t *value,uint64_t n) {
    if(*value>UINT64_MAX-n)return PE_OVERFLOW;
    *value+=n;return 0;
}
static int lhc_permission(uintptr_t first,size_t bytes,int prot) {
    return raw(SYS_mprotect,first,bytes,prot,0,0,0)?PE_PUBLICATION:0;
}
static unsigned lhc_index(const struct pda_completion *c) {
    for(unsigned i=0;i<LI2_PGD_RECEIPTS;i++)if(c==&pe.domain.completion[i])return i;
    return LI2_PGD_RECEIPTS;
}
static unsigned lhc_mask(const struct pda_completion *c) {
    if(c->direct_exit.complete!=1 || c->direct_exit.member>=c->count ||
       c->direct_exit.member>=LI2_PGD_MEMBERS)return 0;
    unsigned p=(unsigned)c->member[c->direct_exit.member].header.plan_policy;
    return p==LI2_PF_VERSION?LHC_LOOP|LHC_EFFECTS|LHC_REBUILD:
        p==LI2_LP_VERSION?LHC_LOOP:p==LI2_LPE_VERSION?LHC_LOOP|LHC_EFFECTS:0;
}
static int lhc_root_live(void) {
    return lhc.root.value.initialized==1 && !lhc.root.value.poisoned &&
        !lhc.root.value.reserved && handling==1 && !pe_failing && !pe.resuming &&
        pe.initialized==1 && pe.registered==1 && pe_identity() &&
        selected_run_protect_contains(0,(uintptr_t)&lhc,sizeof lhc)==1 &&
        !lrc_readonly((uintptr_t)&lhc.root,sizeof lhc.root);
}
static int lhc_initialize(void) {
    if(pe.initialized || !pe_busy || pe_active || pe.resuming ||
       lhc.root.value.initialized || protected_count>=RANGES ||
       selected_run_protect_contains(0,(uintptr_t)&pe,sizeof pe)!=1)return PE_STATE;
    long result=raw(SYS_mmap,(long)&lhc,sizeof lhc,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
    if((uintptr_t)result!=(uintptr_t)&lhc ||
       selected_run_protect_add(0,(uintptr_t)&lhc,sizeof lhc))return PE_PUBLICATION;
    for(unsigned i=0;i<LI2_PGD_RECEIPTS;i++) {
        struct pda_completion *c=&pe.domain.completion[i];
        if(!pda_zero(c,sizeof *c) || pe.domain.claimed[i])return PE_STATE;
        result=raw(SYS_mmap,(long)c,sizeof *c,PROT_READ,
            MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
        if((uintptr_t)result!=(uintptr_t)c || lrc_readonly((uintptr_t)c,sizeof *c) ||
           lhc_permission((uintptr_t)&lhc.capsule[i],sizeof lhc.capsule[i],PROT_READ) ||
           lrc_readonly((uintptr_t)&lhc.capsule[i],sizeof lhc.capsule[i]))return PE_PUBLICATION;
    }
    lhc.root.value.initialized=1;
    return lhc_permission((uintptr_t)&lhc.root,sizeof lhc.root,PROT_READ);
}
/* Called only after the original whole old-cell/claims-drained assertion,
   immediately before the original zero-and-fill of that exact cell. */
static int lhc_begin(struct pda_completion *c) {
    unsigned i=lhc_index(c);
    if(i>=LI2_PGD_RECEIPTS || !lhc_root_live() || lhc.root.value.writer ||
       !pe_busy || pe.p.phase!=LI2_PG_CLOSED || pe.domain.work.receipt!=i ||
       !pe.domain.work.bound || pe.domain.work.completion ||
       lhc.root.value.epoch[i]==UINT64_MAX ||
       lhc.counts.invalidations==UINT64_MAX)return PE_STATE;
    const struct lhc_certificate *old=&lhc.root.value.cell[i];
    if(c->id) {
        if(old->valid!=1 || !old->epoch || old->epoch!=lhc.root.value.epoch[i] ||
           old->completion!=c || old->id!=c->id || old->serial!=c->serial ||
           !c->count || c->count>LI2_PGD_MEMBERS ||
           pe.domain.claimed[i]!=(1U<<c->count)-1U)return PE_STATE;
    } else if(old->valid || !pda_zero(c,sizeof *c) || pe.domain.claimed[i])return PE_STATE;
    if(lhc_permission((uintptr_t)&lhc.root,sizeof lhc.root,PROT_READ|PROT_WRITE))return PE_PUBLICATION;
    ++lhc.root.value.epoch[i];
    le_zero(&lhc.root.value.cell[i],sizeof lhc.root.value.cell[i]);
    lhc.root.value.writer=i+1;
    __asm__ volatile("":::"memory");
    if(lhc_permission((uintptr_t)&lhc.root,sizeof lhc.root,PROT_READ))return PE_PUBLICATION;
    ++lhc.counts.invalidations;
    if(lhc_permission((uintptr_t)c,sizeof *c,PROT_READ|PROT_WRITE) ||
       lhc_permission((uintptr_t)&lhc.capsule[i],sizeof lhc.capsule[i],PROT_READ|PROT_WRITE))
        return PE_PUBLICATION;
    le_zero(&lhc.capsule[i],sizeof lhc.capsule[i]);return 0;
}
/* The immediately preceding, unchanged pda_receipt succeeded. Its canonical
   witnesses are copied once; no failed or partial theorem is certified. */
static int lhc_issue(const struct pda_completion *c) {
    unsigned i=lhc_index(c),mask=lhc_mask(c);
    if(i>=LI2_PGD_RECEIPTS || !lhc_root_live() || lhc.root.value.writer!=i+1 ||
       lhc.root.value.cell[i].valid || !lhc.root.value.epoch[i] ||
       !pe_busy || pe.p.phase!=LI2_PG_CLOSED || pe.domain.work.receipt!=i ||
       pe.domain.work.completion || c->complete!=1 || c->id!=pe.domain.next_id ||
       c->serial!=pe.p.serial || pe.domain.claimed[i] || pe.loop.scope || pe_decoding ||
       lhc.counts.issues==UINT64_MAX)return PE_STATE;
    if(c->direct_exit.complete && !mask)return PE_STATE;
    if(mask) {
        if(!equal(&pe.loop.check,&pe.loop.historical,sizeof pe.loop.check) ||
           !pda_zero(&pe.loop.direct,sizeof pe.loop.direct) ||
           ((mask&LHC_REBUILD) && !pda_zero(&pe.rebuild,sizeof pe.rebuild)))return PE_STATE;
        copy(&lhc.capsule[i].value.loop,&pe.loop.historical,sizeof pe.loop.historical);
        if(mask&LHC_EFFECTS) {
            if(!equal(&pe.effects.check,&pe.effects.historical,sizeof pe.effects.check))return PE_STATE;
            copy(&lhc.capsule[i].value.effects,&pe.effects.historical,sizeof pe.effects.historical);
        }
    }
    if(lhc_permission((uintptr_t)c,sizeof *c,PROT_READ) ||
       lhc_permission((uintptr_t)&lhc.capsule[i],sizeof lhc.capsule[i],PROT_READ) ||
       lrc_readonly((uintptr_t)c,sizeof *c) ||
       lrc_readonly((uintptr_t)&lhc.capsule[i],sizeof lhc.capsule[i]))return PE_PUBLICATION;
    if(lhc_permission((uintptr_t)&lhc.root,sizeof lhc.root,PROT_READ|PROT_WRITE))return PE_PUBLICATION;
    uint64_t epoch=lhc.root.value.epoch[i];
    struct lhc_certificate *v=&lhc.root.value.cell[i];
    *v=(struct lhc_certificate){.policy=mask?(unsigned)c->member[c->direct_exit.member].header.plan_policy:0,
        .mask=mask,.epoch=epoch,.id=c->id,.serial=c->serial,.owner=&pe,.completion=c,
        .capsule=(uintptr_t)&lhc.capsule[i],.session=pe.session};
    copy(v->archive,pe_archive,32);copy(v->policy_hash,pe_policy,32);
    lhc.root.value.writer=0;__asm__ volatile("":::"memory");v->valid=1;
    if(lhc_permission((uintptr_t)&lhc.root,sizeof lhc.root,PROT_READ))return PE_PUBLICATION;
    ++lhc.counts.issues;return 0;
}
static int lhc_match(const struct pda_completion *c,unsigned i) {
    if(i>=LI2_PGD_RECEIPTS || !lhc_root_live() || lhc.root.value.writer)return 0;
    const struct lhc_certificate *v=&lhc.root.value.cell[i];
    return v->valid==1 && !v->reserved && v->epoch && v->epoch==lhc.root.value.epoch[i] &&
        v->id==c->id && v->serial==c->serial &&
        v->owner==&pe && v->completion==c && v->capsule==(uintptr_t)&lhc.capsule[i] &&
        equal(&v->session,&pe.session,sizeof pe.session) && equal(v->archive,pe_archive,32) &&
        equal(v->policy_hash,pe_policy,32) && v->mask==lhc_mask(c) &&
        v->policy==(v->mask?(unsigned)c->member[c->direct_exit.member].header.plan_policy:0) &&
        !lrc_readonly((uintptr_t)c,sizeof *c) &&
        !lrc_readonly((uintptr_t)&lhc.capsule[i],sizeof lhc.capsule[i]);
}
static int lhc_restore(const struct pda_completion *c,unsigned i) {
    const struct lhc_certificate *v=&lhc.root.value.cell[i];
    const struct lhc_witnesses *w=&lhc.capsule[i].value;
    if(!v->mask || !plr_scope_enter(PLR_HISTORY))return 0;
    plr_source(&c->member[c->direct_exit.member].source);
    copy(&pe.loop.historical,&w->loop,sizeof w->loop);copy(&pe.loop.check,&w->loop,sizeof w->loop);
    if(v->mask&LHC_EFFECTS) {
        copy(&pe.effects.historical,&w->effects,sizeof w->effects);
        copy(&pe.effects.check,&w->effects,sizeof w->effects);
    }
    if(v->mask&LHC_REBUILD)le_zero(&pe.rebuild,sizeof pe.rebuild);
    le_zero(&pe.loop.direct,sizeof pe.loop.direct);
    plr_scope_leave(PLR_HISTORY);return 1;
}
static int lhc_full(const struct pda_completion *c) {
    if(lhc_add(&lhc.counts.full_calls,1))return 0;
    return pda_direct_exit_value(c);
}
static int lhc_direct_value(const struct pda_completion *c) {
    unsigned i=lhc_index(c);
    if(lhc_add(&lhc.counts.decisions,1) || i>=LI2_PGD_RECEIPTS || !lhc_root_live())return 0;
    /* First completion proof runs with this sole invalidated cell writable. */
    if(lhc.root.value.writer==i+1 && !lhc.root.value.cell[i].valid && lhc.root.value.epoch[i] &&
       pe_busy && pe.p.phase==LI2_PG_CLOSED && pe.domain.work.receipt==i &&
       c->id==pe.domain.next_id && c->serial==pe.p.serial) {
        if(lhc_add(&lhc.counts.misses,1))return 0;
        return lhc_full(c);
    }
    if(!lhc_match(c,i)) { (void)lhc_add(&lhc.counts.errors,1);return 0; }
    if(!lhc.root.value.cell[i].mask) {
        if(lhc_add(&lhc.counts.misses,1))return 0;
        return lhc_full(c); /* the original whole-zero direct-exit predicate */
    }
    if(lhc_add(&lhc.counts.hits,1))return 0;
#ifdef LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL
    struct lhc_scratch *s=&lhc.scratch;
    copy(&s->before_loop,&pe.loop,sizeof pe.loop);
    copy(&s->before_effects,&pe.effects,sizeof pe.effects);
    copy(&s->before_rebuild,&pe.rebuild,sizeof pe.rebuild);
#endif
    int cached=lhc_restore(c,i);
#ifdef LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL
    copy(&s->expected_loop,&pe.loop,sizeof pe.loop);
    copy(&s->expected_effects,&pe.effects,sizeof pe.effects);
    /* Restore the complete pre-call state before the unchanged comparator,
       so an extra write in either path cannot hide behind the other path. */
    copy(&pe.loop,&s->before_loop,sizeof pe.loop);
    copy(&pe.effects,&s->before_effects,sizeof pe.effects);
    copy(&pe.rebuild,&s->before_rebuild,sizeof pe.rebuild);
    if(lhc_add(&lhc.counts.differential_checks,1))return 0;
    int actual=lhc_full(c);
    if(actual) {
        uint64_t *n=lhc.root.value.cell[i].policy==LI2_LPE_VERSION?
            &s->expected_effects.counts.historical_reconstructions:
            &s->expected_loop.counts.historical_reconstructions;
        if(*n==UINT64_MAX)return 0;
        ++*n; /* the original function really executed this reconstruction */
    }
    int same=cached==actual && equal(&pe.loop,&s->expected_loop,sizeof pe.loop) &&
        equal(&pe.effects,&s->expected_effects,sizeof pe.effects) &&
        ((cached && (lhc.root.value.cell[i].mask&LHC_REBUILD))?pda_zero(&pe.rebuild,sizeof pe.rebuild):
            equal(&pe.rebuild,&s->before_rebuild,sizeof pe.rebuild));
    if(!same) { (void)lhc_add(&lhc.counts.disagreements,1);return 0; }
#endif
    if(!cached)return 0;
    uint64_t bytes=2U*PAGE+sizeof pe.loop.pages+2U*sizeof pe.loop.historical+sizeof pe.loop.direct;
    if(lhc.root.value.cell[i].mask&LHC_EFFECTS)bytes+=2U*sizeof pe.effects.historical;
    if(lhc.root.value.cell[i].mask&LHC_REBUILD)bytes+=sizeof pe.rebuild;
    return !lhc_add(&lhc.counts.restored_bytes,bytes);
}
static void lhc_abort(void) {
    if(lhc.root.value.initialized!=1)return;
    if(!lhc_permission((uintptr_t)&lhc.root,sizeof lhc.root,PROT_READ|PROT_WRITE)) {
        lhc.root.value.poisoned=1;
        for(unsigned i=0;i<LI2_PGD_RECEIPTS;i++)lhc.root.value.cell[i].valid=0;
        __asm__ volatile("":::"memory");
        (void)lhc_permission((uintptr_t)&lhc.root,sizeof lhc.root,PROT_READ);
    }
    for(unsigned i=0;i<LI2_PGD_RECEIPTS;i++) {
        (void)lhc_permission((uintptr_t)&pe.domain.completion[i],sizeof pe.domain.completion[i],PROT_READ);
        (void)lhc_permission((uintptr_t)&lhc.capsule[i],sizeof lhc.capsule[i],PROT_READ);
    }
    (void)lhc_add(&lhc.counts.abort_invalidations,1);
}
static void lhc_report(unsigned status,unsigned code) {
    struct writer w={.used=0};text(&w,"LI2_LOOP_HISTORY {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
#ifdef LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL
    field(&w,",\"differential\":",1);
#else
    field(&w,",\"differential\":",0);
#endif
#define LHC_FIELD(n) field(&w,",\"" #n "\":",lhc.counts.n)
    LHC_FIELD(decisions);LHC_FIELD(hits);LHC_FIELD(misses);LHC_FIELD(full_calls);
    LHC_FIELD(differential_checks);LHC_FIELD(disagreements);LHC_FIELD(issues);
    LHC_FIELD(invalidations);LHC_FIELD(abort_invalidations);LHC_FIELD(errors);LHC_FIELD(restored_bytes);
#undef LHC_FIELD
    text(&w,"}\n");
    if(raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0)!=(long)w.used) {
        (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
}
#undef LHC_ROUND
