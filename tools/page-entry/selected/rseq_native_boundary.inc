/* Included after native_zero. The original registered profile and original
   unregistered retry owner remain separate, with their old predicates. */
static struct li2_rseq_native_boundary_state native_boundary;
const struct li2_rseq_native_boundary_state *li2_rseq_native_boundary_snapshot(void) {
    return &native_boundary;
}
static int boundary_bad(unsigned code,long detail) {
    if(!native_boundary.first_error) {
        native_boundary.first_error=code;native_boundary.first_detail=detail;
    }
    native_boundary.phase=LI2_RNB_FAILED;
    return native_bad(code,detail);
}
static int boundary_binding(void) {
    return native_binding() && native_boundary.pid==state.pid && native_boundary.tid==state.tid &&
        native_boundary.address==state.address && native_boundary.page==state.page &&
        native_boundary.length==state.length && native_boundary.signature==state.signature &&
        native_boundary.registration_epoch==state.epoch &&
        same_data(&native_boundary.first_data,&state.data);
}
static int boundary_balanced(void) {
    return native_boundary.attempts==native_boundary.completed &&
        native_boundary.preentries==native_boundary.completed &&
        native_boundary.entries==native_boundary.completed &&
        native_boundary.observations==native_boundary.completed &&
        native_boundary.tls_refreshes==native_boundary.completed;
}
static int boundary_preentry(void) {
    if(native_boundary.phase==LI2_RNB_IDLE || native_boundary.phase==LI2_RNB_FIRST)return 0;
    /* First handler statement still proves zero before any returning raw
       call. A malformed or reentered pending token has no cleanup permit. */
    native_zero(&native_boundary.word_entry);
    if(!boundary_binding())native_unsafe(LI2_RN_PIN,20);
    if(native_boundary.phase!=LI2_RNB_WAIT_REFAULT || native_rseq.phase!=LI2_RN_CLOSING ||
       native_boundary.first_error || native_boundary.entry_checked ||
       native_boundary.preentries!=native_boundary.completed ||
       native_boundary.attempts!=native_boundary.completed+1)
        native_unsafe(LI2_RN_REENTRY,20);
    if(native_boundary.preentries==UINT64_MAX)native_unsafe(LI2_RN_OVERFLOW,20);
    ++native_boundary.preentries;
    __asm__ volatile("mov %%fs,%0; mov %%gs,%1":"=r"(native_boundary.fs_selector_entry),
                     "=r"(native_boundary.gs_selector_entry)::"memory");
    native_boundary.entry_checked=1;return 1;
}
int li2_rseq_native_boundary_enter(int sig,siginfo_t *si,const ucontext_t *uc,unsigned retry) {
    if(retry) {
        if(native_boundary.phase==LI2_RNB_IDLE && !state.registered && native_rseq.phase==LI2_RN_IDLE)
            return li2_rseq_native_enter(sig,si,uc); /* exact old unregistered route */
        if(retry!=1 || native_boundary.phase!=LI2_RNB_WAIT_REFAULT ||
           native_rseq.phase!=LI2_RN_CLOSING || native_rseq.first_error ||
           native_boundary.first_error || !native_boundary.entry_checked || !boundary_binding() ||
           native_boundary.preentries!=native_boundary.attempts ||
           native_boundary.entries!=native_boundary.completed)
            return boundary_bad(LI2_RN_STATE,20);
        if(!si || !uc || sig!=SIGSEGV || si->si_signo!=SIGSEGV || si->si_code!=SEGV_ACCERR ||
           si->si_errno || uc->uc_mcontext.gregs[REG_TRAPNO]!=14 || uc->uc_mcontext.gregs[REG_ERR]!=21 ||
           (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]!=native_boundary.pc ||
           (uintptr_t)si->si_addr!=native_boundary.pc ||
           (uintptr_t)uc->uc_mcontext.gregs[REG_CR2]!=native_boundary.pc)
            return boundary_bad(LI2_RN_ENTRY,20);
        native_zero(&native_boundary.word_entry);++native_boundary.entries;
        native_boundary.phase=LI2_RNB_ENTERING;return 0;
    }
    if(native_boundary.phase!=LI2_RNB_IDLE || native_boundary.first_error)
        return boundary_bad(LI2_RN_STATE,21);
    if(!state.registered || (si && uc &&
       (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==(uintptr_t)si->si_addr))
        return li2_rseq_native_enter(sig,si,uc); /* exact first-byte registered predicate */
    if(native_rseq.phase!=LI2_RN_EXECUTING || native_rseq.first_error ||
       !native_rseq.entry_checked || !native_binding())return boundary_bad(LI2_RN_STATE,22);
    if(!si || !uc || sig!=SIGSEGV || si->si_signo!=SIGSEGV || si->si_code!=SEGV_ACCERR ||
       si->si_errno || uc->uc_mcontext.gregs[REG_TRAPNO]!=14 || uc->uc_mcontext.gregs[REG_ERR]!=21 ||
       (uintptr_t)uc->uc_mcontext.gregs[REG_CR2]!=(uintptr_t)si->si_addr)
        return boundary_bad(LI2_RN_ENTRY,21);
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP],address=(uintptr_t)si->si_addr;
    uintptr_t page=pc&~(RSEQ_PAGE-1);
    if(page>UINTPTR_MAX-RSEQ_PAGE || address!=page+RSEQ_PAGE || address<=pc || address-pc>14 ||
       page!=(native_rseq.pc&~(RSEQ_PAGE-1)))return boundary_bad(LI2_RN_ENTRY,22);
    if(!boundary_balanced() || native_boundary.attempts==UINT64_MAX)
        return boundary_bad(LI2_RN_OVERFLOW,21);
    native_boundary=(struct li2_rseq_native_boundary_state){
        .attempts=native_boundary.attempts+1,.preentries=native_boundary.preentries,
        .entries=native_boundary.entries,.observations=native_boundary.observations,
        .tls_refreshes=native_boundary.tls_refreshes,.completed=native_boundary.completed,
        .pc=pc,.fault_address=address,.admitted_page=page,
        .address=state.address,.page=state.page,.pid=state.pid,.tid=state.tid,
        .registration_epoch=state.epoch,.length=state.length,.signature=state.signature,
        .first_data=native_rseq.before};
    native_boundary.phase=LI2_RNB_FIRST;
    native_zero(&native_boundary.word_first);++native_rseq.entries;
    native_rseq.phase=LI2_RN_CLOSING;return 0;
}
static int boundary_arm(const struct li2_native_close *c,const struct li2_native_counts *n) {
    if(native_boundary.phase!=LI2_RNB_FIRST || native_boundary.first_error || !boundary_binding() ||
       c->pages!=1 || c->attempted!=1 || c->returned!=1 || c->closed!=1 || c->verified!=1 ||
       c->last_address!=native_boundary.admitted_page || c->last_result || c->sync_result ||
       c->sync_started!=1 || c->sync_returned!=1 || c->cleanup_started || c->cleanup_complete ||
       c->sequence==UINT64_MAX || native_boundary.attempts!=native_boundary.completed+1)
        return boundary_bad(LI2_RN_CLOSE,20);
    native_boundary.first_close=*c;native_boundary.first_data=native_rseq.after;
    native_boundary.native_admissions=n->admissions;native_boundary.native_closed=n->closed;
    native_boundary.fs_first=native_rseq.fs_after;native_boundary.gs_first=native_rseq.gs_after;
    native_boundary.fs_selector_first=native_rseq.fs_selector_after;
    native_boundary.gs_selector_first=native_rseq.gs_selector_after;
    native_zero(&native_boundary.word_first);
    /* Keep the original owner CLOSING: there is no unguarded IDLE interval
       between verified one-page closure and the second genuine signal. */
    __asm__ volatile("":::"memory");native_boundary.phase=LI2_RNB_WAIT_REFAULT;return 0;
}
static int boundary_observe(void) {
    const struct li2_native_close *c=li2_lifecycle_native_close_progress();
    const struct li2_native_close *first=&native_boundary.first_close;
    const struct li2_native_counts *n=li2_lifecycle_native_counts();
    if(native_boundary.phase!=LI2_RNB_ENTERING || native_rseq.phase!=LI2_RN_CLOSING ||
       native_boundary.first_error || native_rseq.first_error || !native_boundary.entry_checked ||
       !boundary_binding() || !c->complete || c->busy || c->first_error ||
       c->sequence!=first->sequence+1 || c->pages || c->attempted || c->returned || c->closed ||
       c->verified || c->last_address || c->last_result || c->sync_started || c->sync_returned ||
       c->sync_result || c->cleanup_started || c->cleanup_complete ||
       c->pid!=native_boundary.pid || c->tid!=native_boundary.tid ||
       c->allocation_epoch!=first->allocation_epoch || c->generation_epoch!=first->generation_epoch ||
       c->transactions_epoch!=first->transactions_epoch || c->records_epoch!=first->records_epoch ||
       n->admissions!=native_boundary.native_admissions || n->closed!=native_boundary.native_closed ||
       n->admissions!=n->closed || native_boundary.entries!=native_boundary.attempts ||
       native_boundary.observations!=native_boundary.completed ||
       native_boundary.tls_refreshes!=native_boundary.completed)
        return boundary_bad(LI2_RN_CLOSE,21);
    native_boundary.second_close=*c;
    native_zero(&native_boundary.word_after);li2_maps_phase_end();
    int e=li2_lifecycle_rseq_data(state.address,&native_boundary.second_data);
    if(e || !same_data(&native_boundary.first_data,&native_boundary.second_data))
        return boundary_bad(LI2_RN_PIN,e?e:20);
    native_zero(&native_boundary.word_after);
    if(tls_observe())return boundary_bad(LI2_RN_TLS,state.first_detail);
    native_boundary.fs_second=state.fs_base;native_boundary.gs_second=state.gs_base;
    __asm__ volatile("mov %%fs,%0; mov %%gs,%1":"=r"(native_boundary.fs_selector_after),
                     "=r"(native_boundary.gs_selector_after)::"memory");
    if(native_boundary.fs_first!=native_boundary.fs_second || native_boundary.gs_first!=native_boundary.gs_second ||
       native_boundary.fs_selector_first!=native_boundary.fs_selector_entry ||
       native_boundary.gs_selector_first!=native_boundary.gs_selector_entry ||
       native_boundary.fs_selector_entry!=native_boundary.fs_selector_after ||
       native_boundary.gs_selector_entry!=native_boundary.gs_selector_after)
        return boundary_bad(LI2_RN_TLS,20);
    native_zero(&native_boundary.word_after);
    ++native_boundary.observations;++native_boundary.tls_refreshes;
    native_boundary.phase=LI2_RNB_OBSERVED;return 0;
}
int li2_rseq_native_boundary_complete(void) {
    if(native_boundary.phase==LI2_RNB_IDLE && !state.registered && native_rseq.phase==LI2_RN_IDLE)return 0;
    if(native_boundary.phase!=LI2_RNB_OBSERVED || native_boundary.first_error ||
       native_rseq.phase!=LI2_RN_CLOSING || native_rseq.first_error || !boundary_binding() ||
       native_boundary.attempts!=native_boundary.completed+1 ||
       native_boundary.preentries!=native_boundary.attempts || native_boundary.entries!=native_boundary.attempts ||
       native_boundary.observations!=native_boundary.attempts || native_boundary.tls_refreshes!=native_boundary.attempts)
        return boundary_bad(LI2_RN_STATE,23);
    native_zero(&native_boundary.word_after);++native_boundary.completed;
    __asm__ volatile("":::"memory");native_rseq.phase=LI2_RN_IDLE;
    __asm__ volatile("":::"memory");native_boundary.phase=LI2_RNB_IDLE;return 0;
}
