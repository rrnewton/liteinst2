/* Passive observations only. No helper result participates in admission;
   even observation overflow/state failure leaves the original decision intact. */
#include "loop_ro_reasons.h"
#ifdef LI2_LOOP_RO_RETIRED
#include "loop_ro_retired.h"
#endif
_Static_assert(LI2_PTR_SLOTS==2,"observe the unchanged two-slot policy");
static struct { unsigned stage,kind,occupied,bank,slot,installed,failed;uint64_t seen,passed; } lrr_state;
static struct li2_lrr_counts *lrr_counts(void) {
    const struct li2_pgc_record *p=li2_pgc_current;
#ifdef LI2_LOOP_RO_RETIRED
    if(!p || p->header[1]!=LI2_LRX_VERSION || p->header[2]!=LI2_LRX_BYTES || !p->header[15])return 0;
    return &((struct li2_lrx_record *)(void *)li2_pgc_current)->base.reasons;
#else
    if(!p || p->header[1]!=LI2_LRR_VERSION || p->header[2]!=LI2_LRR_BYTES || !p->header[15])return 0;
    return &((struct li2_lrr_record *)(void *)li2_pgc_current)->reasons;
#endif
}
static void lrr_bad(struct li2_lrr_counts *c,unsigned code) {
    if(c && !c->error)__atomic_store_n(&c->error,code,__ATOMIC_RELEASE);
}
static int lrr_count(struct li2_lrr_counts *c,uint64_t *p) {
    if(!c || c->error)return 0;
    uint64_t n=__atomic_load_n(p,__ATOMIC_RELAXED);
    if(n==UINT64_MAX){lrr_bad(c,1);return 0;}
    __atomic_store_n(p,n+1,__ATOMIC_RELEASE);return 1;
}
static void lrr_begin(uintptr_t pc) {
    struct li2_lrr_counts *c=lrr_counts();if(!c || c->error)return;
    if(lrr_state.stage || pe.selected_slot>=2 || pe.selected_bank>=2){lrr_bad(c,2);return;}
    const struct li2_ptr_slot *s=&pe.retained[pe.selected_slot];
    unsigned kind=pe.subentry_selected?2U:(s->generation.installed && s->publication.source.entry==pc)?1U:0U;
    unsigned occupied=!!pe.retained[0].generation.installed+!!pe.retained[1].generation.installed;
    lrr_state.stage=1;lrr_state.kind=kind;lrr_state.occupied=occupied;lrr_state.bank=pe.selected_bank;
    lrr_state.slot=pe.selected_slot;lrr_state.installed=!!s->generation.installed;
    lrr_state.failed=0;lrr_state.seen=0;lrr_state.passed=0;
    __atomic_store_n(&c->in_flight,1,__ATOMIC_RELEASE);
    lrr_count(c,&c->attempts);lrr_count(c,&c->selection[kind][occupied][pe.selected_bank]);
}
static void lrr_evaluate(void) {
    struct li2_lrr_counts *c=lrr_counts();if(!c || c->error)return;
    if(lrr_state.stage!=1){lrr_bad(c,3);return;}
    lrr_state.stage=2;
}
static int lrr_test(unsigned bit,int value) {
    struct li2_lrr_counts *c=lrr_counts();if(!c || c->error)return value;
    /* Observe only the original expression's evaluated terms. No later
       predicate is called to explain an earlier false result. */
    if(lrr_state.stage!=2 || bit>=10 || lrr_state.failed ||
       lrr_state.seen!=((UINT64_C(1)<<bit)-1)){lrr_bad(c,4);return value;}
    lrr_state.seen|=UINT64_C(1)<<bit;lrr_count(c,&c->seen[bit]);
    if(value){lrr_state.passed|=UINT64_C(1)<<bit;lrr_count(c,&c->passed[bit]);}
    else {lrr_state.failed=1;lrr_count(c,&c->first_failure[lrr_state.kind][bit]);}
    return value;
}
static void lrr_plan(unsigned kind) {
    struct li2_lrr_counts *c=lrr_counts();if(!c || c->error)return;
    if(lrr_state.stage!=2 || kind<1 || kind>4 ||
       (kind<=2?(lrr_state.seen!=1023 || lrr_state.passed!=1023 ||
                  lrr_state.kind!=kind):!lrr_state.failed)){lrr_bad(c,5);return;}
    lrr_count(c,&c->outcome[lrr_state.kind][kind<=2?0:kind==3?1:2]);
    lrr_state.stage=kind==3?3:4;
}
static void lrr_bound(void) {
    struct li2_lrr_counts *c=lrr_counts();if(!c || c->error)return;
    if(lrr_state.stage!=4 || pe.selected_slot!=lrr_state.slot || pe.selected_bank!=lrr_state.bank){lrr_bad(c,6);return;}
    unsigned outcome;
    if(pe.warm) {
        if(lrr_state.failed || !lrr_state.kind){lrr_bad(c,7);return;}
        outcome=3;
        lrr_count(c,pe.entry.target.pc!=pe.entry.target.root?&c->subentry_hits:&c->root_hits);
    } else {
        if(!lrr_state.failed){lrr_bad(c,8);return;}
        outcome=lrr_state.installed?5:4;
    }
    lrr_count(c,&c->outcome[lrr_state.kind][outcome]);lrr_state.stage=5;
}
static void lrr_finish(unsigned outcome) {
    struct li2_lrr_counts *c=lrr_counts();if(!c || c->error)return;
    if((outcome!=1 && outcome!=2) || lrr_state.stage!=(outcome==1?3U:5U)){lrr_bad(c,9);return;}
    lrr_count(c,&c->outcome[lrr_state.kind][outcome==1?6:7]);lrr_count(c,&c->finished);
    lrr_state.stage=0;__atomic_store_n(&c->in_flight,0,__ATOMIC_RELEASE);
}
