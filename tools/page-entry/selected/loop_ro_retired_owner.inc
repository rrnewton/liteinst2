/* Observation only: no saved key or result participates in admission. */
#include "loop_ro_retired.h"
struct lrx_retired {
    unsigned valid,bank;size_t registry_count;
    uint64_t generation,build_serial,completed_serial,retirement,offer;
    uint64_t lifetime_version,lifetime_mode,registration_epoch,address,length,signature;
    struct li2_pg_source_key source;
    struct li2_fork_range registry[RANGES];
};
static struct {
    unsigned initialized,busy,next,count;
    uint64_t serial;
    const struct li2_pg_sources *source;
    const struct li2_pg_rseq_progress *rseq;
    struct lrx_retired ring[LI2_LRX_SLOTS];
} lrx_state;
static struct li2_lrx_counts *lrx_counts(void) {
    const struct li2_pgc_record *p=li2_pgc_current;
    if(!p || p->header[1]!=LI2_LRX_VERSION || p->header[2]!=LI2_LRX_BYTES || !p->header[15])return 0;
    return &((struct li2_lrx_record *)(void *)li2_pgc_current)->retired;
}
static void lrx_bad(struct li2_lrx_counts *c,unsigned code) {
    if(c && !c->error)__atomic_store_n(&c->error,code,__ATOMIC_RELEASE);
}
static void lrx_count(struct li2_lrx_counts *c,uint64_t *p) {
    if(!c || c->error)return;
    uint64_t n=__atomic_load_n(p,__ATOMIC_RELAXED);
    if(n==UINT64_MAX){lrx_bad(c,1);return;}
    __atomic_store_n(p,n+1,__ATOMIC_RELEASE);
}
static void lrx_initialize(void) {
    struct li2_lrx_counts *c=lrx_counts();if(!c || c->error)return;
    if(lrx_state.initialized || selected_run_protect_contains(0,(uintptr_t)&lrx_state,sizeof lrx_state)!=1) {
        lrx_bad(c,2);return;
    }
    lrx_state.initialized=1;
}
static void lrx_source(const struct li2_pg_sources *s,const struct li2_pg_rseq_progress *r) {
    struct li2_lrx_counts *c=lrx_counts();if(!c || c->error)return;
    if(!lrx_state.initialized || lrx_state.busy || !s || s->complete!=1 || !r ||
       !pe_busy || !pe.p.serial || s->serial!=pe.p.serial || !r->active || !r->seed_complete) {
        lrx_bad(c,3);return;
    }
    lrx_state.source=s;lrx_state.rseq=r;lrx_state.serial=pe.p.serial;
}
static unsigned lrx_age(uint64_t age) {
    const uint64_t bounds[7]={1,2,4,8,16,64,256};
    unsigned i=0;while(i<7 && age>bounds[i])i++;return i;
}
static int lrx_test(unsigned bit,int value) {
    struct li2_lrx_counts *c=lrx_counts();if(!c || c->error || bit!=4 || value)return value;
    lrx_count(c,&c->gate4);
    const struct li2_pg_sources *s=lrx_state.source;const struct li2_pg_rseq_progress *r=lrx_state.rseq;
    if(!lrx_state.initialized || lrx_state.busy || !s || !r || !pe_busy ||
       lrx_state.serial!=pe.p.serial || s->serial!=pe.p.serial || s->complete!=1 ||
       pe.selected_bank>1 || pe.candidate_registry_count>RANGES || lrx_state.count>LI2_LRX_SLOTS ||
       lrx_state.next>=LI2_LRX_SLOTS || lrr_state.stage!=2 || !lrr_state.failed ||
       lrr_state.seen!=31 || lrr_state.passed!=15) {lrx_bad(c,4);return value;}
    lrx_state.busy=1;
    unsigned root=0,source=0,exact=0,bank_diff=0,registry_diff=0,lifetime_diff=0;
    unsigned exact_rank=0,exact_age=0;
    for(unsigned rank=0;rank<lrx_state.count;rank++) {
        unsigned at=(lrx_state.next+LI2_LRX_SLOTS-1-rank)%LI2_LRX_SLOTS;
        const struct lrx_retired *old=&lrx_state.ring[at];
        if(old->valid!=1 || !old->generation || !old->build_serial ||
           old->completed_serial<old->build_serial || !old->retirement || old->retirement>c->saves ||
           old->offer>=PGC_VALUE(offers) || old->bank>1 || old->registry_count>RANGES) {
            lrx_bad(c,5);break;
        }
        if(old->source.entry!=s->key.entry)continue;
        root=1;
        if(!li2_pg_source_key_equal(&old->source,&s->key))continue;
        unsigned bd=old->bank!=pe.selected_bank;
        unsigned rd=old->registry_count!=pe.candidate_registry_count ||
            !equal(old->registry,pe.candidate_registry,old->registry_count*sizeof old->registry[0]);
        unsigned ld=old->lifetime_version!=1 || old->lifetime_mode!=r->lifetime_mode ||
            old->registration_epoch!=r->registration_epoch || old->address!=r->address ||
            old->length!=r->length || old->signature!=r->signature;
        if(!source){bank_diff=bd;registry_diff=rd;lifetime_diff=ld;}source=1;
        if(!bd && !rd && !ld) {
            exact=1;exact_rank=rank;exact_age=lrx_age(PGC_VALUE(offers)-old->offer);break;
        }
    }
    if(!c->error) {
        if(root)lrx_count(c,&c->root_seen);
        if(source)lrx_count(c,&c->source_seen);
        if(exact) {
            lrx_count(c,&c->exact_seen);lrx_count(c,&c->retirement_rank[exact_rank]);lrx_count(c,&c->offer_age[exact_age]);
        } else if(!root)lrx_count(c,&c->no_root);
        else if(!source)lrx_count(c,&c->source_changed);
        else {
            lrx_count(c,&c->context_changed);
            if(bank_diff)lrx_count(c,&c->bank_changed);
            if(registry_diff)lrx_count(c,&c->registry_changed);
            if(lifetime_diff)lrx_count(c,&c->lifetime_changed);
        }
        lrx_count(c,&c->search_done);
    }
    lrx_state.busy=0;return value;
}
static void lrx_retire(void) {
    struct li2_lrx_counts *c=lrx_counts();if(!c || c->error)return;
    if(!lrx_state.initialized || lrx_state.busy || pe.selected_slot>=2 ||
       lrx_state.next>=LI2_LRX_SLOTS || lrx_state.count>LI2_LRX_SLOTS || c->saves==UINT64_MAX) {
        lrx_bad(c,6);return;
    }
    /* Called only after actual ped_claim() and the real retirement event,
       before generation/source/registry overwrite. The claim was completed. */
    const struct li2_ptr_slot *slot=&pe.retained[pe.selected_slot];
    const struct li2_pg_generation *g=&slot->generation;const struct pe_header *h=&slot->publication.header;
    unsigned bank=2;
    for(unsigned i=0;i<2;i++)if(slot->banks[i].generated==g->generated) {
        if(bank!=2){lrx_bad(c,7);return;}bank=i;
    }
    if(!pe_busy || pe.warm || g->installed!=1 || g->complete!=1 || g->proof_complete!=1 ||
       g->ready_generation || !g->generation || !g->build_serial || slot->last_completed<g->build_serial ||
       h->generation!=g->generation || h->serial!=g->build_serial || bank>1 ||
       slot->registry_count>RANGES || slot->claim.valid || !slot->publication.source.entry ||
       PGC_VALUE(retirements)!=c->saves+1 || !PGC_VALUE(offers)) {lrx_bad(c,7);return;}
    lrx_state.busy=1;struct lrx_retired *out=&lrx_state.ring[lrx_state.next];
    out->valid=0;__asm__ volatile("":::"memory");
    out->bank=bank;out->registry_count=slot->registry_count;
    out->generation=g->generation;out->build_serial=g->build_serial;out->completed_serial=slot->last_completed;
    out->retirement=c->saves+1;out->offer=PGC_VALUE(offers);
    out->lifetime_version=h->lifetime_version;out->lifetime_mode=h->lifetime_mode;
    out->registration_epoch=h->registered_epoch;out->address=h->rseq_address;out->length=h->rseq_length;out->signature=h->rseq_signature;
    copy(&out->source,&slot->publication.source,sizeof out->source);
    copy(out->registry,slot->registry,out->registry_count*sizeof out->registry[0]);
    __asm__ volatile("":::"memory");out->valid=1;
    lrx_state.next=(lrx_state.next+1)%LI2_LRX_SLOTS;
    if(lrx_state.count==LI2_LRX_SLOTS)lrx_count(c,&c->overwrites);else lrx_state.count++;
    lrx_count(c,&c->saves);lrx_state.busy=0;
}
