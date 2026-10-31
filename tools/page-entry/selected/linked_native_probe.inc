/* Included in the real lifecycle TU after span_source and linked_source.
   These bridge-BSS cells are protected with the bridge itself. Record slots
   are never recycled, but one-shot renewal can advance a generation in place.
   A negative names the exact record AND generation, survives unrelated
   mappings, and cannot suppress a renewed or replacement lifetime. */
#include "linked_native_probe.h"
static struct li2_link_native_probe_progress lnp;
static uint64_t lnp_refused_generation[RECORDS];
static struct owned_page lnp_original;
const struct li2_link_native_probe_progress *li2_lifecycle_link_native_probe_progress(void) { return &lnp; }

static int lnp_current(const struct li2_span_source *s) {
    if(!s || __atomic_load_n(&s->ready,__ATOMIC_ACQUIRE)!=1 ||
       s->borrow.owner!=&fetch || !s->borrow.sequence || s->borrow.sequence!=fetch.progress.sequence ||
       fetch.progress.held || !fetch.progress.complete || fetch.progress.first_error ||
       fetch.progress.first_detail || !fetch.progress.identity_observed ||
       !active || tx.guard || allocation_id!=fetch.allocation_epoch || generation!=fetch.generation_epoch ||
       used!=fetch.records_epoch || counts.transactions!=fetch.transactions_epoch || tx.phase!=fetch.phase_epoch ||
       fetch.pid<=0 || fetch.pid!=fetch.tid || !span_source_geometry() ||
       s->key.entry!=fetch.pc || !span_source_page_equal(&s->key.page,&fetch.pages[0]) ||
       !span_source_backing_equal(&s->key.backing,&fetch.last_backing) ||
       li2_lifecycle_run_reuse_quiet(0) || li2_lifecycle_link_interlock() || !li2_native_pair_quiet())return 0;
    const struct owned_page *p=current(s->key.page.address);
    if(!fetch_owned_equal(p,&fetch.original[0]) || p->actual!=PROT_READ || p->admitted)return 0;
    size_t at=s->key.entry-s->key.page.address;
    return equal(s->key.bytes+at,fetch.bytes,15);
}
int li2_lifecycle_link_native_probe_choose(const struct li2_span_source *s,uint64_t serial) {
    if(!serial || lnp.pending || lnp.reserved || used>RECORDS ||
       lnp.chosen!=lnp.refaults || lnp.refaults!=lnp.next_nx)DIE(LI2_NP_STATE,90);
    native_increment(&lnp.lookups);
    if(!lnp_current(s) || s->key.page.address<NATIVE_LOW_LIMIT) {
        native_increment(&lnp.current_declines);return 0;
    }
    const struct owned_page *p=current(s->key.page.address);
    size_t index=(size_t)(p-records);
    if(index>=used || !p->generation)DIE(LI2_NP_STATE,91);
    if(lnp_refused_generation[index]==p->generation) {
        native_increment(&lnp.negative_hits);return 0;
    }
    /* Reusable one-shot publication legitimately renews this same slot.
       Current source/backing/epochs were already rechecked above; its new
       lifetime must pass the full-page policy again and get its own real NX. */
    lnp_refused_generation[index]=0;
    native_increment(&lnp.policy_checks);
    /* This is intentionally just the actual complete source page. A policy
       zero cannot admit it: a denied executable halo is left for real NX. */
    if(li2_native_policy(s->key.bytes,LI2_REGION_PAGE)) {
        native_increment(&lnp.policy_blocked);return 0;
    }
    const struct li2_native_pair_progress *n=li2_native_pair_progress();
    if(!n || !n->initialized || n->phase!=LI2_NP_IDLE || n->first_error ||
       n->in_handler || n->entry_pending || n->live || n->pid!=fetch.pid || n->tid!=fetch.tid)
        DIE(LI2_NP_STATE,92);
    if(n->events==UINT64_MAX || n->seeds==UINT64_MAX || np_life.published==UINT64_MAX)
        DIE(LI2_NP_OVERFLOW,90);
    lnp_original=*p;lnp.selected_record=index+1;lnp.selected_generation=p->generation;
    lnp.selected_serial=serial;lnp.selected_pc=s->key.entry;
    lnp.selected_event=n->events;lnp.selected_seeds=n->seeds;lnp.selected_published=np_life.published;
    lnp.outcome_complete=0;lnp.outcome_result=0;native_increment(&lnp.chosen);
    __asm__ volatile("":::"memory");lnp.pending=1;return 1;
}
int li2_lifecycle_link_native_probe_refault(uint64_t serial) {
    if(!lnp.pending || !serial || serial!=lnp.selected_serial ||
       lnp.refaults==UINT64_MAX || lnp.chosen!=lnp.refaults+1 || lnp.refaults!=lnp.next_nx)
        return LI2_NP_STATE;
    native_increment(&lnp.refaults);return 0;
}
int li2_lifecycle_link_native_probe_outcome(int result) {
    if(!lnp.pending)return 0;
    const struct li2_native_pair_progress *n=li2_native_pair_progress();
    lnp.outcome_result=result;
    if(lnp.pending!=1 || lnp.reserved || lnp.outcome_complete || !lnp.selected_record ||
       lnp.selected_record>used || used>RECORDS || lnp.selected_record>RECORDS ||
       !lnp.selected_serial || lnp.chosen!=lnp.refaults || lnp.next_nx==UINT64_MAX ||
       lnp.refaults!=lnp.next_nx+1 || lnp.selected_event==UINT64_MAX ||
       !n || n->events!=lnp.selected_event+1 || n->pc!=lnp.selected_pc ||
       n->signal_number!=SIGSEGV || n->signal_code!=SEGV_ACCERR || n->signal_errno ||
       n->signal_address!=n->pc || !n->first_observed)return LI2_NP_STATE;
    size_t index=(size_t)lnp.selected_record-1;
    const struct owned_page *p=&records[index];
    if(current(lnp_original.address)!=p || p->generation!=lnp.selected_generation ||
       lnp_original.generation!=lnp.selected_generation || lnp_refused_generation[index])return LI2_NP_STALE;
    struct owned_page expected=lnp_original;
    if(result==LI2_NP_RESUME) {
        expected.actual=PROT_READ|PROT_EXEC;expected.admitted=1;
        if(!fetch_owned_equal(p,&expected) || n->first_error || n->phase!=LI2_NP_EXECUTING_ONE ||
           n->live!=1 || n->in_handler || n->entry_pending ||
           lnp.selected_seeds==UINT64_MAX || n->seeds!=lnp.selected_seeds+1 ||
           lnp.selected_published==UINT64_MAX || np_life.published!=lnp.selected_published+1 ||
           np_life.first_error || !np_life.post_verified || np_life.busy || np_life.opening ||
           np_life.live!=1 || np_life.slots[0].pc!=n->pc ||
           np_life.slots[0].published!=1 || np_life.slots[0].policy)return LI2_NP_STATE;
        native_increment(&lnp.admitted);
    } else if(result==LI2_NP_FALLBACK) {
        if(!fetch_owned_equal(p,&expected) || !li2_native_pair_quiet() || n->first_error ||
           n->seeds!=lnp.selected_seeds || np_life.published!=lnp.selected_published)return LI2_NP_STATE;
        /* Only a genuine clean refusal writes the lifetime negative. */
        lnp_refused_generation[index]=lnp.selected_generation;native_increment(&lnp.refused);
    } else {
        /* Actual fatal rseq/identity/mapping outcomes stay fatal. They are
           never counted as a clean refusal or used to populate the cache. */
        if(result<=LI2_NP_REFAULT || !n->first_error || result!=(int)n->first_error)return LI2_NP_STATE;
        native_increment(&lnp.errors);
    }
    native_increment(&lnp.next_nx);lnp.outcome_complete=1;
    __asm__ volatile("":::"memory");lnp.pending=0;return 0;
}
