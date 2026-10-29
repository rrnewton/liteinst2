/* Distinct E9->UD2 owner. It never invokes the native-page epoch transition
   or claims that UD2 is a native SIGSEGV close. Included after native helpers. */
#include "rseq_publication.h"
#if LI2_ONESHOT_REUSABLE != 1 || !defined(LI2_EFFECT_PROVIDER) || LI2_EFFECT_PROVIDER != 1 || \
    !defined(LI2_RSEQ_NATIVE) || !defined(LI2_ONESHOT_PUBLICATION)
#error "publication rseq owner requires its complete reusable effect profile"
#endif
static struct li2_rseq_publication_state publication_rseq;
static struct li2_rseq_publication_state publication_last_complete,publication_last_refused;
const struct li2_rseq_publication_state *li2_rseq_publication_snapshot(void) {
    return &publication_rseq;
}
const struct li2_rseq_publication_state *li2_rseq_publication_last_complete(void) { return &publication_last_complete; }
const struct li2_rseq_publication_state *li2_rseq_publication_last_refused(void) { return &publication_last_refused; }
static int publication_bad(unsigned code,long detail) {
    if(!publication_rseq.first_error) {
        publication_rseq.first_detail=detail;__asm__ volatile("":::"memory");
        publication_rseq.first_error=code;
    }
    publication_rseq.phase=LI2_RP_FAILED;return (int)publication_rseq.first_error;
}
static _Noreturn void publication_unsafe(unsigned code,long detail) {
    (void)publication_bad(code,detail);publication_rseq.unsafe_terminal=1;
    __asm__ volatile("":::"memory");
    (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static int publication_binding(void) {
    const struct li2_rseq_publication_state *p=&publication_rseq;
    if(!state.initialized || state.first_error || state.pid!=p->pid || state.tid!=p->tid ||
       state.registered!=p->registered)return 0;
    if(!p->registered)return !state.held && state.phase==LI2_RSEQ_IDLE;
    return native_pin() && state.address==p->address && state.page==p->page &&
        state.length==p->length && state.signature==p->signature &&
        state.epoch==p->registration_epoch && same_data(&state.data,&p->before) &&
        state.fs_base==p->fs_before && state.gs_base==p->gs_before;
}
static void publication_zero(uint64_t *word) {
    if(publication_rseq.checking)publication_unsafe(LI2_RN_REENTRY,20);
    publication_rseq.checking=1;__asm__ volatile("":::"memory");
    if(!publication_binding())publication_unsafe(LI2_RN_PIN,20);
    *word=publication_rseq.registered?
        *(const volatile uint64_t *)(publication_rseq.address+8):0;
    if(*word)publication_unsafe(LI2_RN_WORD,20);
    __asm__ volatile("":::"memory");publication_rseq.checking=0;
}
int li2_rseq_publication_prepare(uintptr_t pc) {
    struct li2_rseq_publication_state *p=&publication_rseq;
    if(p->phase!=LI2_RP_IDLE || p->first_error || p->checking ||
       p->retired>p->attempts || p->attempts-p->retired!=p->cancelled || p->attempts==UINT64_MAX ||
       !state.initialized || state.first_error || state.pid<=0 || state.pid!=state.tid ||
       state.registered>1 || pc<LI2_ONESHOT_MIN_EXEC || pc>UINTPTR_MAX-5 ||
       li2_lifecycle_fetch_interlock() || native_rseq.phase!=LI2_RN_IDLE ||
       native_rseq.first_error)return publication_bad(LI2_RN_STATE,20);
    if(state.registered) { if(!native_pin())publication_unsafe(LI2_RN_PIN,21); }
    else if(state.held || state.phase!=LI2_RSEQ_IDLE)return publication_bad(LI2_RN_STATE,21);
    const struct li2_native_counts *n=li2_lifecycle_native_counts();
    if(n->admissions!=n->closed)return publication_bad(LI2_RN_STATE,22);
    *p=(struct li2_rseq_publication_state){.attempts=p->attempts+1,.retired=p->retired,.cancelled=p->cancelled,
        .last_closed_sequence=p->last_closed_sequence,.registered=state.registered,
        .pc=pc,.pid=state.pid,.tid=state.tid,.address=state.address,.page=state.page,
        .registration_epoch=state.epoch,.length=state.length,.signature=state.signature,
        .fs_before=state.fs_base,.gs_before=state.gs_base,.before=state.data};
    __asm__ volatile("":::"memory");p->phase=LI2_RP_PREPARING;
    publication_zero(&p->word_before);
    if(CALL(SYS_getpid,0,0,0,0,0,0)!=p->pid || CALL(SYS_gettid,0,0,0,0,0,0)!=p->tid)
        return publication_bad(LI2_RN_PIN,22);
    if(p->registered) {
        li2_maps_phase_end();
        struct li2_rseq_data observed={0};
        int e=li2_lifecycle_rseq_data(p->address,&observed);
        if(e || !same_data(&p->before,&observed))return publication_bad(LI2_RN_PIN,e?e:23);
        p->before=observed;
        if(tls_observe() || state.fs_base!=p->fs_before || state.gs_base!=p->gs_before)
            return publication_bad(LI2_RN_TLS,20);
        publication_zero(&p->word_before);
    }
    __asm__ volatile("":::"memory");p->phase=LI2_RP_PREPARED;return 0;
}
int li2_rseq_publication_bind(const struct li2_oneshot_plan *plan) {
    struct li2_rseq_publication_state *p=&publication_rseq;
    if(!plan || p->phase!=LI2_RP_PREPARED || p->first_error ||
       plan->pc!=p->pc || !plan->sequence || plan->sequence<=p->last_closed_sequence ||
       plan->next_pc!=plan->pc+2 || !plan->landing ||
       (plan->kind!=LI2_ONESHOT_SYSCALL && plan->kind!=LI2_ONESHOT_RDTSC && plan->kind!=3))
        return publication_bad(LI2_RN_STATE,23);
    publication_zero(&p->word_before);
    p->sequence=plan->sequence;p->landing=plan->landing;
    __asm__ volatile("":::"memory");p->phase=LI2_RP_BOUND;return 0;
}
int li2_rseq_publication_check(uint64_t sequence,uintptr_t pc) {
    struct li2_rseq_publication_state *p=&publication_rseq;
    if((p->phase!=LI2_RP_BOUND && p->phase!=LI2_RP_LANDED) || p->first_error ||
       sequence!=p->sequence || pc!=p->pc)return publication_bad(LI2_RN_STATE,24);
    publication_zero(p->phase==LI2_RP_BOUND?&p->word_before:&p->word_entry);return 0;
}
static int publication_owner(const struct li2_oneshot_owner *o,unsigned phase) {
    return o && o->initialized==1 && !o->in_handler && !o->state.first_error &&
        o->session && o->session->initialized==1 && o->session->self_test_complete==1 &&
        o->session->pid==publication_rseq.pid && o->session->tid==publication_rseq.tid &&
        o->session->application_mask==LI2_ONESHOT_MASK && !o->session->sync_register &&
        o->session->sync_query>=0 && (o->session->sync_query&96)==96 &&
        o->state.phase==phase && o->state.sequence==publication_rseq.sequence &&
        o->plan.sequence==publication_rseq.sequence && o->plan.pc==publication_rseq.pc &&
        o->plan.landing==publication_rseq.landing && o->state.published==1 &&
        o->write_attempted_mask==31 && o->write_completed_mask==31;
}
int li2_rseq_publication_publish(const struct li2_oneshot_owner *o) {
    struct li2_rseq_publication_state *p=&publication_rseq;
    if(p->phase!=LI2_RP_BOUND || p->first_error || !publication_owner(o,LI2_ONESHOT_PUBLISHED))
        return publication_bad(LI2_RN_STATE,25);
    publication_zero(&p->word_before);p->entry_checked=0;
    __asm__ volatile("":::"memory");p->phase=LI2_RP_PUBLISHED;return 0;
}
void li2_rseq_publication_preentry(void) {
    struct li2_rseq_publication_state *p=&publication_rseq;
    if(p->phase==LI2_RP_IDLE && !p->checking)return;
    if(p->checking || p->phase!=LI2_RP_PUBLISHED || p->entry_checked)
        publication_unsafe(LI2_RN_REENTRY,21);
    publication_zero(&p->word_entry);
    __asm__ volatile("mov %%fs,%0; mov %%gs,%1":"=r"(p->fs_entry),"=r"(p->gs_entry)::"memory");
    __asm__ volatile("":::"memory");p->entry_checked=1;
}
int li2_rseq_publication_landed(const struct li2_oneshot_owner *o,int sig,
                               const siginfo_t *si,const ucontext_t *uc) {
    struct li2_rseq_publication_state *p=&publication_rseq;
    if(p->phase!=LI2_RP_PUBLISHED || p->first_error || !p->entry_checked ||
       !publication_owner(o,LI2_ONESHOT_PUBLISHED) || !si || !uc ||
       sig!=SIGILL || si->si_signo!=SIGILL || si->si_code!=ILL_ILLOPN || si->si_errno ||
       (uintptr_t)si->si_addr!=p->landing ||
       (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]!=p->landing ||
       uc->uc_mcontext.gregs[REG_TRAPNO]!=6 || uc->uc_mcontext.gregs[REG_ERR])
        return publication_bad(LI2_RN_ENTRY,20);
    publication_zero(&p->word_entry);
    __asm__ volatile("":::"memory");p->phase=LI2_RP_LANDED;return 0;
}
int li2_rseq_publication_restored(const struct li2_oneshot_owner *o) {
    struct li2_rseq_publication_state *p=&publication_rseq;
    if(p->phase!=LI2_RP_LANDED || p->first_error || !publication_owner(o,LI2_ONESHOT_RESTORED) ||
       o->state.restored!=1 || o->restore_attempted_mask!=31 || o->restore_completed_mask!=31 ||
       o->release.call.started!=1 || o->release.call.returned!=1 ||
       o->release.call.verified!=1 || o->release.call.result || o->release.transaction_live ||
       li2_lifecycle_fetch_interlock())return publication_bad(LI2_RN_CLOSE,20);
    publication_zero(&p->word_restored);
    if(p->registered) {
        li2_maps_phase_end();
        int e=li2_lifecycle_rseq_data(p->address,&p->after);
        if(e || !same_data(&p->before,&p->after))return publication_bad(LI2_RN_PIN,e?e:24);
        if(tls_observe() || state.fs_base!=p->fs_before || state.gs_base!=p->gs_before)
            return publication_bad(LI2_RN_TLS,21);
        p->fs_after=state.fs_base;p->gs_after=state.gs_base;
        publication_zero(&p->word_restored);
    }
    __asm__ volatile("mov %%fs,%0; mov %%gs,%1":"=r"(p->fs_restored),"=r"(p->gs_restored)::"memory");
    if(p->fs_restored!=p->fs_entry || p->gs_restored!=p->gs_entry)
        return publication_bad(LI2_RN_TLS,22);
    __asm__ volatile("":::"memory");p->phase=LI2_RP_RESTORED;return 0;
}
int li2_rseq_publication_retire(const struct li2_oneshot_owner *o) {
    struct li2_rseq_publication_state *p=&publication_rseq;
    if(p->phase!=LI2_RP_RESTORED || p->first_error || p->checking ||
       !publication_owner(o,LI2_ONESHOT_COMPLETED) || o->state.restored!=1 ||
       p->retired==UINT64_MAX || p->retired>=p->attempts ||
       p->attempts-p->retired-1!=p->cancelled)
        return publication_bad(LI2_RN_STATE,26);
    publication_last_complete=*p;
    ++p->retired;p->last_closed_sequence=p->sequence;
    __asm__ volatile("":::"memory");p->phase=LI2_RP_IDLE;return 0;
}
static int publication_cancel(uint64_t sequence,uintptr_t pc,int phase) {
    struct li2_rseq_publication_state *p=&publication_rseq;
    if(p->phase!=phase || p->first_error || p->checking || p->entry_checked ||
       p->sequence!=sequence || p->pc!=pc || li2_lifecycle_fetch_interlock() ||
       p->cancelled==UINT64_MAX || p->retired>=p->attempts ||
       p->attempts-p->retired-1!=p->cancelled)return publication_bad(LI2_RN_STATE,27);
    publication_zero(&p->word_before);
    publication_last_refused=*p;
    ++p->cancelled;if(sequence)p->last_closed_sequence=sequence;
    __asm__ volatile("":::"memory");p->phase=LI2_RP_IDLE;return 0;
}
int li2_rseq_publication_cancel_unbound(uintptr_t pc) {
    return publication_cancel(0,pc,LI2_RP_PREPARED);
}
int li2_rseq_publication_cancel_bound(uint64_t sequence,uintptr_t pc) {
    if(!sequence)return publication_bad(LI2_RN_STATE,28);
    return publication_cancel(sequence,pc,LI2_RP_BOUND);
}
