/* Independent binding for the opt-in pair owner. No old one-page state or
   pages==1 predicate is changed, and no supplied snapshot grants a pin. */
#include "native_pair.h"
static struct li2_rseq_pair_progress np_rseq;
static unsigned np_rseq_wait;
static uint64_t np_rseq_closed_fs,np_rseq_closed_gs;
static uint16_t np_rseq_closed_fs_selector,np_rseq_closed_gs_selector;
const struct li2_rseq_pair_progress *li2_rseq_pair_progress(void) { return &np_rseq; }
static int np_rseq_bad(unsigned code,long detail) {
    if(!np_rseq.first_error){np_rseq.first_error=code;np_rseq.first_detail=detail;}
    return (int)np_rseq.first_error;
}
static _Noreturn void np_rseq_unsafe(unsigned code,long detail) {
    (void)np_rseq_bad(code,detail);np_rseq.unsafe_terminal=1;
    __asm__ volatile("":::"memory");
    (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static int np_rseq_owner(const struct li2_native_pair_owner *o,unsigned phase) {
    return np_rseq.initialized && o && o==np_rseq.owner && !np_rseq.first_error &&
        li2_native_pair_owner_check(o,phase);
}
static int np_rseq_binding(void) {
    if(!state.initialized || state.first_error || state.pid!=np_rseq.pid || state.tid!=np_rseq.tid ||
       state.registered!=np_rseq.registered || state.epoch!=np_rseq.registration_epoch)return 0;
    if(!np_rseq.registered)return !state.held && state.phase==LI2_RSEQ_IDLE;
    return native_pin() && state.address==np_rseq.address && state.page==np_rseq.page &&
        state.length==np_rseq.length && state.signature==np_rseq.signature &&
        same_data(&state.data,&np_rseq.before);
}
/* Pure binding/word inspection before returning raw, even on nested/error
   ingress. An unsafe registered descriptor cannot authorize cleanup syscalls. */
static void np_rseq_zero(uint64_t *out) {
    if(np_rseq.checking)np_rseq_unsafe(LI2_RN_REENTRY,40);
    np_rseq.checking=1;__asm__ volatile("":::"memory");
    if(!np_rseq_binding())np_rseq_unsafe(LI2_RN_PIN,40);
    if(np_rseq.registered) {
        *out=*(const volatile uint64_t *)(np_rseq.address+8);
        if(*out)np_rseq_unsafe(LI2_RN_WORD,40);
    } else *out=0;
    __asm__ volatile("":::"memory");np_rseq.checking=0;
}
int li2_rseq_pair_initialize(const struct li2_native_pair_owner *o) {
    if(np_rseq.initialized || np_rseq.owner || !o ||
       !li2_native_pair_owner_check(o,LI2_NP_INITIALIZING) || !state.initialized || state.first_error ||
       native_rseq.phase!=LI2_RN_IDLE || native_boundary.phase!=LI2_RNB_IDLE)
        return np_rseq_bad(LI2_RN_STATE,40);
    np_rseq.owner=o;np_rseq.initialized=1;return 0;
}
int li2_rseq_pair_seed(const struct li2_native_pair_owner *o) {
    if(!np_rseq_owner(o,LI2_NP_SEEDING) || np_rseq.active || np_rseq_wait ||
       np_rseq.attempts!=np_rseq.closed || np_rseq.attempts==UINT64_MAX ||
       !state.initialized || state.first_error || state.registered>1 ||
       (state.registered?!native_pin():(state.held || state.phase!=LI2_RSEQ_IDLE)))
        return np_rseq_bad(LI2_RN_STATE,41);
    const struct li2_native_pair_lifecycle *l=li2_lifecycle_pair_progress();
    if(l->owner!=o || l->live || l->first_error || l->busy!=1 || l->candidate_eligible!=1)
        return np_rseq_bad(LI2_RN_STATE,42);
    np_rseq.registered=state.registered;np_rseq.pid=state.pid;np_rseq.tid=state.tid;
    np_rseq.registration_epoch=state.epoch;
    np_rseq.address=state.registered?state.address:0;np_rseq.page=state.registered?state.page:0;
    np_rseq.length=state.registered?state.length:0;np_rseq.signature=state.registered?state.signature:0;
    np_rseq.before=state.registered?state.data:(struct li2_rseq_data){0};
    np_rseq.after=(struct li2_rseq_data){0};np_rseq.word_before=0;np_rseq.word_entry=0;np_rseq.word_after=0;
    np_rseq.entry_checked=0;++np_rseq.attempts;np_rseq.active=1;
    __asm__ volatile("":::"memory");np_rseq_zero(&np_rseq.word_before);
    if(np_rseq.registered) {
        li2_maps_phase_end();struct li2_rseq_data observed={0};
        int e=li2_lifecycle_rseq_data(state.address,&observed);
        if(e || !same_data(&state.data,&observed))return np_rseq_bad(LI2_RN_PIN,e?e:41);
        np_rseq.before=observed;np_rseq_zero(&np_rseq.word_before);
    }
    if(tls_observe())return np_rseq_bad(LI2_RN_TLS,state.first_detail);
    np_rseq.fs_before=state.fs_base;np_rseq.gs_before=state.gs_base;
    np_rseq_zero(&np_rseq.word_before);return 0;
}
int li2_rseq_pair_published(const struct li2_native_pair_owner *o) {
    if((!np_rseq_owner(o,LI2_NP_SEEDING) && !np_rseq_owner(o,LI2_NP_EXTENDING)) ||
       np_rseq.active!=1 || np_rseq_wait || np_rseq.published==UINT64_MAX)
        return np_rseq_bad(LI2_RN_STATE,43);
    const struct li2_native_pair_lifecycle *l=li2_lifecycle_pair_progress();
    if(l->owner!=o || l->first_error || l->busy || l->opening || l->post_verified!=1 ||
       !l->live || l->live>2 || l->published!=np_rseq.published+1)
        return np_rseq_bad(LI2_RN_STATE,44);
    np_rseq_zero(&np_rseq.word_after);++np_rseq.published;np_rseq.entry_checked=0;return 0;
}
void li2_rseq_pair_preentry(const struct li2_native_pair_owner *o) {
    if(!np_rseq.active) {
        /* Cold routing also performs raw queries before eligibility is known.
           Authenticate the actual current registration without constructing a
           pair pin, seed or close obligation. No cached zero authorizes this. */
        if(!np_rseq.initialized || o!=np_rseq.owner || !state.initialized || state.first_error ||
           state.registered>1 || (state.registered?!native_pin():(state.held || state.phase!=LI2_RSEQ_IDLE)))
            np_rseq_unsafe(LI2_RN_PIN,44);
        if(state.registered) {
            if(np_rseq.checking)np_rseq_unsafe(LI2_RN_REENTRY,42);
            np_rseq.checking=1;__asm__ volatile("":::"memory");
            uint64_t word=*(const volatile uint64_t *)(state.address+8);
            if(word)np_rseq_unsafe(LI2_RN_WORD,41);
            __asm__ volatile("":::"memory");np_rseq.checking=0;
        }
        return;
    }
    np_rseq_zero(&np_rseq.word_entry);
    if(o!=np_rseq.owner || np_rseq.first_error || np_rseq.entry_checked ||
       (!li2_native_pair_owner_check(o,LI2_NP_EXECUTING_ONE) &&
        !li2_native_pair_owner_check(o,LI2_NP_EXECUTING_TWO) &&
        !li2_native_pair_owner_check(o,LI2_NP_WAIT_REFAULT)) ||
       np_rseq.preentries==UINT64_MAX) {
        /* The actual pin/word just passed. A stage/reentry contradiction is
           terminal with original cleanup, not an unsafe descriptor claim.
           Only a failed pure binding/word/checking guard bypasses cleanup. */
        (void)np_rseq_bad(LI2_RN_REENTRY,41);return;
    }
    ++np_rseq.preentries;
    __asm__ volatile("mov %%fs,%0; mov %%gs,%1":"=r"(np_rseq.fs_selector_entry),
                     "=r"(np_rseq.gs_selector_entry)::"memory");
    np_rseq.entry_checked=1;
}
int li2_rseq_pair_enter(const struct li2_native_pair_owner *o) {
    if(!np_rseq_owner(o,LI2_NP_ENTERING) || np_rseq.active!=1 || np_rseq_wait ||
       np_rseq.entry_checked!=1 || np_rseq.entries==UINT64_MAX ||
       np_rseq.preentries!=np_rseq.entries+1)return np_rseq_bad(LI2_RN_STATE,45);
    np_rseq_zero(&np_rseq.word_entry);++np_rseq.entries;return 0;
}
/* Native code may legitimately change its TLS bases. Refresh actual bases at
   the real boundary, retaining equal selectors across the helper itself. */
int li2_rseq_pair_refresh(const struct li2_native_pair_owner *o,int closing) {
    if((closing!=0 && closing!=1) || np_rseq.active!=1 || np_rseq.entry_checked!=1 ||
       np_rseq.refreshes==UINT64_MAX ||
       (closing?!np_rseq_owner(o,LI2_NP_CLOSING):!np_rseq_owner(o,LI2_NP_ENTERING)))
        return np_rseq_bad(LI2_RN_STATE,46);
    np_rseq_zero(&np_rseq.word_after);
    if(np_rseq.registered) {
        li2_maps_phase_end();int e=li2_lifecycle_rseq_data(state.address,&np_rseq.after);
        if(e || !same_data(&np_rseq.before,&np_rseq.after))return np_rseq_bad(LI2_RN_PIN,e?e:42);
        np_rseq_zero(&np_rseq.word_after);
    }
    if(tls_observe())return np_rseq_bad(LI2_RN_TLS,state.first_detail);
    np_rseq.fs_after=state.fs_base;np_rseq.gs_after=state.gs_base;
    __asm__ volatile("mov %%fs,%0; mov %%gs,%1":"=r"(np_rseq.fs_selector_after),
                     "=r"(np_rseq.gs_selector_after)::"memory");
    if(np_rseq.fs_selector_entry!=np_rseq.fs_selector_after ||
       np_rseq.gs_selector_entry!=np_rseq.gs_selector_after)return np_rseq_bad(LI2_RN_TLS,40);
    np_rseq_zero(&np_rseq.word_after);++np_rseq.refreshes;return 0;
}
int li2_rseq_pair_closed(const struct li2_native_pair_owner *o,int wait_refault) {
    if(!np_rseq_owner(o,LI2_NP_CLOSING) || np_rseq.active!=1 || np_rseq.entry_checked!=1 ||
       np_rseq_wait || (wait_refault!=0 && wait_refault!=1) || np_rseq.closed==UINT64_MAX)
        return np_rseq_bad(LI2_RN_STATE,47);
    const struct li2_native_pair_lifecycle *l=li2_lifecycle_pair_progress();
    const struct li2_native_close *c=&l->close;
    if(l->owner!=o || l->first_error || l->busy || l->opening || l->live ||
       l->published!=l->closed_pages || !c->complete || c->busy || c->first_error ||
       !c->pages || c->pages>2 || c->pages!=c->verified || c->pid!=np_rseq.pid || c->tid!=np_rseq.tid)
        return np_rseq_bad(LI2_RN_CLOSE,40);
    int e=li2_rseq_pair_refresh(o,1);if(e)return e;
    if(wait_refault) {
        np_rseq_wait=1;np_rseq.entry_checked=0;
        np_rseq_closed_fs=np_rseq.fs_after;np_rseq_closed_gs=np_rseq.gs_after;
        np_rseq_closed_fs_selector=np_rseq.fs_selector_after;
        np_rseq_closed_gs_selector=np_rseq.gs_selector_after;
    } else {++np_rseq.closed;np_rseq.entry_checked=0;np_rseq.active=0;}
    return 0;
}
int li2_rseq_pair_refault(const struct li2_native_pair_owner *o) {
    if(!np_rseq_owner(o,LI2_NP_REFAULTING) || np_rseq.active!=1 || np_rseq_wait!=1 ||
       np_rseq.entry_checked!=1 || np_rseq.entries==UINT64_MAX || np_rseq.refreshes==UINT64_MAX ||
       np_rseq.closed==UINT64_MAX || np_rseq.preentries!=np_rseq.entries+1)
        return np_rseq_bad(LI2_RN_STATE,48);
    np_rseq_zero(&np_rseq.word_entry);
    const struct li2_native_pair_lifecycle *l=li2_lifecycle_pair_progress();
    if(l->owner!=o || l->first_error || l->live || l->busy || !l->close.complete ||
       l->close.pages || l->close.first_error)return np_rseq_bad(LI2_RN_CLOSE,41);
    if(np_rseq.registered) {
        li2_maps_phase_end();int e=li2_lifecycle_rseq_data(state.address,&np_rseq.after);
        if(e || !same_data(&np_rseq.before,&np_rseq.after))return np_rseq_bad(LI2_RN_PIN,e?e:43);
        np_rseq_zero(&np_rseq.word_after);
    }
    if(tls_observe())return np_rseq_bad(LI2_RN_TLS,state.first_detail);
    np_rseq.fs_after=state.fs_base;np_rseq.gs_after=state.gs_base;
    __asm__ volatile("mov %%fs,%0; mov %%gs,%1":"=r"(np_rseq.fs_selector_after),
                     "=r"(np_rseq.gs_selector_after)::"memory");
    if(np_rseq.fs_after!=np_rseq_closed_fs || np_rseq.gs_after!=np_rseq_closed_gs ||
       np_rseq.fs_selector_entry!=np_rseq_closed_fs_selector ||
       np_rseq.gs_selector_entry!=np_rseq_closed_gs_selector ||
       np_rseq.fs_selector_entry!=np_rseq.fs_selector_after ||
       np_rseq.gs_selector_entry!=np_rseq.gs_selector_after)return np_rseq_bad(LI2_RN_TLS,41);
    np_rseq_zero(&np_rseq.word_after);++np_rseq.entries;++np_rseq.refreshes;++np_rseq.closed;
    np_rseq_wait=0;np_rseq.entry_checked=0;np_rseq.active=0;return 0;
}
int li2_rseq_pair_quiet(const struct li2_native_pair_owner *o) {
    return np_rseq_owner(o,LI2_NP_IDLE) && !np_rseq.active && !np_rseq.checking && !np_rseq_wait &&
        !np_rseq.entry_checked && np_rseq.attempts==np_rseq.closed &&
        np_rseq.preentries==np_rseq.entries;
}
