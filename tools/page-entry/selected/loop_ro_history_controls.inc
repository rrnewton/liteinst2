#if LI2_LOOP_RO_CONTROL == 2
/* Test-only controls, reached after a genuine issued lhc_match. Every
   decision below calls the complete pda_receipt, including its common and
   live-scope checks. Only this test hook is suppressed recursively. */
struct lro_history_saved {
    struct pda_completion completion;
    union lhc_capsule capsule;
    unsigned claimed[LI2_PGD_RECEIPTS];
    unsigned policy,mask;
};
static struct lro_history_saved lro_history_saved;
static int lro_history_initialize(void) {
    if(protected_count>=RANGES || selected_run_protect_add(0,
        (uintptr_t)&lro_history_saved,sizeof lro_history_saved))return PE_STATE;
    return 0;
}
enum lro_history_path { LRO_H_COMMON,LRO_H_ROOT,LRO_H_MATCH,LRO_H_HIT,
    LRO_H_SCOPE,LRO_H_DIFFERENCE };
static uint64_t lro_history_reconstructions(unsigned policy) {
    return policy==LI2_LPE_VERSION?pe.effects.counts.historical_reconstructions:
        pe.loop.counts.historical_reconstructions;
}
static int lro_history_decision(const struct pda_completion *c,unsigned i,
                               enum lro_history_path path) {
    struct lhc_counts expected=lhc.counts;
    lro_need(i<LI2_PGD_RECEIPTS,44);
    uint64_t reconstructions=lro_history_reconstructions(lro_history_saved.policy);
    if(path!=LRO_H_COMMON)++expected.decisions;
    if(path==LRO_H_MATCH)++expected.errors;
    if(path==LRO_H_HIT || path==LRO_H_SCOPE || path==LRO_H_DIFFERENCE) {
        ++expected.hits;++expected.full_calls;++expected.differential_checks;
        if(path!=LRO_H_SCOPE)++reconstructions;
    }
    if(path==LRO_H_DIFFERENCE)++expected.disagreements;
    if(path==LRO_H_HIT) {
        uint64_t bytes=2U*PAGE+sizeof pe.loop.pages+2U*sizeof pe.loop.historical+sizeof pe.loop.direct;
        if(lro_history_saved.mask&LHC_EFFECTS)bytes+=2U*sizeof pe.effects.historical;
        if(lro_history_saved.mask&LHC_REBUILD)bytes+=sizeof pe.rebuild;
        expected.restored_bytes+=bytes;
    }
    int actual=pda_receipt(c);
    lro_need(actual==(path==LRO_H_HIT) && equal(&lhc.counts,&expected,sizeof expected) &&
        lro_history_reconstructions(lro_history_saved.policy)==reconstructions,40);
    return actual;
}
static void lro_history_restored(const struct pda_completion *c,unsigned i) {
    lro_need(equal(&lhc.root,lro.root,PAGE) &&
        equal(c,&lro_history_saved.completion,sizeof *c) &&
        equal(&lhc.capsule[i],&lro_history_saved.capsule,sizeof lhc.capsule[i]) &&
        equal(pe.domain.claimed,lro_history_saved.claimed,sizeof pe.domain.claimed) &&
        !pe.loop.scope && !pe_decoding &&
        !lrc_readonly((uintptr_t)&lhc.root,sizeof lhc.root) &&
        !lrc_readonly((uintptr_t)c,sizeof *c) &&
        !lrc_readonly((uintptr_t)&lhc.capsule[i],sizeof lhc.capsule[i]) &&
        lhc_match(c,i),41);
    (void)lro_history_decision(c,i,LRO_H_HIT);++lro.restorations;
}
static void lro_history_root_restore(void) {
    lro_prot((uintptr_t)&lhc.root,PAGE,PROT_READ|PROT_WRITE);
    copy(&lhc.root,lro.root,PAGE);lro_prot((uintptr_t)&lhc.root,PAGE,PROT_READ);
}
static void lro_history_hook(const struct pda_completion *c,unsigned i) {
    /* This is a separately bound test selector, never production authority. */
    if(lro.busy || lro.started || i>=LI2_PGD_RECEIPTS || !lhc_match(c,i) ||
       !lhc.root.value.cell[i].mask || c->direct_exit.member>=c->count ||
       c->member[c->direct_exit.member].source.entry!=UINT64_C(0x4000200))return;
    lro_need(lro.initialized==1 && !pe.loop.scope && !pe_decoding,42);
    lro.busy=lro.started=1;
    const struct lhc_certificate *issued=&lhc.root.value.cell[i];
    lro.root_serial=issued->serial;lro.epoch=issued->epoch;
    lro_history_saved.policy=issued->policy;lro_history_saved.mask=issued->mask;
    lro.generation=c->member[c->direct_exit.member].generation.generation;
    lro.source_entry=c->member[c->direct_exit.member].source.entry;
    copy(lro.root,&lhc.root,PAGE);
    copy(&lro_history_saved.completion,c,sizeof *c);
    copy(&lro_history_saved.capsule,&lhc.capsule[i],sizeof lhc.capsule[i]);
    copy(lro_history_saved.claimed,pe.domain.claimed,sizeof pe.domain.claimed);
    lro_history_restored(c,i);
    uintptr_t root=(uintptr_t)&lhc.root,cell=(uintptr_t)c,capsule=(uintptr_t)&lhc.capsule[i];
    unsigned number=0;int result;
    /* Each altered coordinate keeps the complete original receipt checks. */
    for(unsigned kind=0;kind<18;kind++) {
        lro_prot(root,PAGE,PROT_READ|PROT_WRITE);
        struct lhc_root *r=&lhc.root.value;struct lhc_certificate *v=&r->cell[i];
        switch(kind) {
        case 0:r->initialized=0;break;
        case 1:r->poisoned=1;break;
        case 2:r->reserved=1;break;
        case 3:r->writer=LI2_PGD_RECEIPTS+1;break;
        case 4:r->epoch[i]^=1;break;
        case 5:v->valid=0;break;
        case 6:v->reserved=1;break;
        case 7:v->epoch^=1;break;
        case 8:v->id^=1;break;
        case 9:v->serial^=1;break;
        case 10:v->owner=0;break;
        case 11:v->completion=0;break;
        case 12:v->capsule+=PAGE;break;
        case 13:((unsigned char *)&v->session)[0]^=1;break;
        case 14:v->archive[0]^=1;break;
        case 15:v->policy_hash[0]^=1;break;
        case 16:v->mask^=LHC_EFFECTS;break;
        default:v->policy^=1;break;
        }
        lro_prot(root,PAGE,PROT_READ);
        result=lro_history_decision(c,i,kind<3?LRO_H_ROOT:LRO_H_MATCH);
        lro_result(number,LRO_REJECT,0,(unsigned)result);
        lro_history_root_restore();lro_history_restored(c,i);lro_mark(number++);
    }
    /* Whole common predicates must still reject before a cache decision. */
    for(unsigned kind=0;kind<3;kind++) {
        lro_prot(cell,sizeof *c,PROT_READ|PROT_WRITE);
        struct pda_completion *changed=(void *)cell;
        if(kind==0)changed->complete=0;
        else if(kind==1)changed->member[0].generation.ready_generation^=1;
        else changed->rseq.word_after=1;
        lro_prot(cell,sizeof *c,PROT_READ);
        result=lro_history_decision(c,i,LRO_H_COMMON);lro_result(number,LRO_REJECT,0,(unsigned)result);
        lro_prot(cell,sizeof *c,PROT_READ|PROT_WRITE);
        copy((void *)cell,&lro_history_saved.completion,sizeof *c);lro_prot(cell,sizeof *c,PROT_READ);
        lro_history_restored(c,i);lro_mark(number++);
    }
    const uintptr_t addresses[4]={root,cell,capsule,capsule};
    const size_t sizes[4]={PAGE,sizeof *c,sizeof lhc.capsule[i],sizeof lhc.capsule[i]};
    for(unsigned kind=0;kind<4;kind++) {
        lro_prot(addresses[kind],sizes[kind],kind==3?PROT_READ|PROT_EXEC:PROT_READ|PROT_WRITE);
        result=lro_history_decision(c,i,kind?LRO_H_MATCH:LRO_H_ROOT);
        lro_result(number,LRO_REJECT,0,(unsigned)result);
        lro_prot(addresses[kind],sizes[kind],PROT_READ);lro_history_restored(c,i);lro_mark(number++);
    }
    const void *copies[3]={lro.root,&lro_history_saved.completion,&lro_history_saved.capsule};
    for(unsigned kind=0;kind<3;kind++) {
        int fd=lro_file_mapping(addresses[kind],sizes[kind],copies[kind]);
        result=lro_history_decision(c,i,kind?LRO_H_MATCH:LRO_H_ROOT);
        lro_result(number,LRO_REJECT,0,(unsigned)result);
        lro_anonymous_restore(addresses[kind],sizes[kind],copies[kind],fd);
        lro_history_restored(c,i);lro_mark(number++);
    }
    /* A byte-identical copied completion is not the actual issued cell. */
    result=lro_history_decision(&lro_history_saved.completion,i,LRO_H_ROOT);
    lro_result(number,LRO_REJECT,0,(unsigned)result);lro_history_restored(c,i);lro_mark(number++);
    for(unsigned kind=0;kind<4;kind++) {
        uintptr_t at=kind==0?root:kind==1?cell:capsule;
        long observed=lro_kernel_write(at,kind==3);
        lro_result(number,kind==3?LRO_KERNEL_PARTIAL:LRO_KERNEL_EFAULT,kind==3?1:EFAULT,
            (unsigned)(observed<0?-observed:observed));
        lro_history_restored(c,i);lro_mark(number++);
    }
    /* A valid capsule does not bypass the actual serialized HISTORY scope. */
    pe.loop.scope=PLR_HISTORY;
    result=lro_history_decision(c,i,LRO_H_SCOPE);lro_result(number,LRO_REJECT,0,(unsigned)result);
    pe.loop.scope=0;lro_history_restored(c,i);lro_mark(number++);
    /* Last: keep every key valid, alter the immutable witness then restore R.
       The actual uncached path must run, disagree, and retain its increment. */
    lro_prot(capsule,sizeof lhc.capsule[i],PROT_READ|PROT_WRITE);
    lhc.capsule[i].value.loop.version^=1;
    lro_prot(capsule,sizeof lhc.capsule[i],PROT_READ);
    result=lro_history_decision(c,i,LRO_H_DIFFERENCE);lro_result(number,LRO_DIFF_REJECT,0,(unsigned)result);
    lro_prot(capsule,sizeof lhc.capsule[i],PROT_READ|PROT_WRITE);
    copy((void *)capsule,&lro_history_saved.capsule,sizeof lhc.capsule[i]);
    lro_prot(capsule,sizeof lhc.capsule[i],PROT_READ);lro_history_restored(c,i);lro_mark(number++);
    lro_need(number==35 && lro.checks==35 && lro.restorations==36 &&
        lro.passed==(UINT64_C(1)<<35)-1,43);
    lro.complete=1;selected_persistent_abort(PE_PUBLICATION,LRO_STOP_HISTORY);
}
#else
static void lro_history_hook(const struct pda_completion *c,unsigned i) {(void)c;(void)i;}
#endif
