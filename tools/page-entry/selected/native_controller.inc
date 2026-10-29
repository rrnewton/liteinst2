#ifdef LI2_NATIVE_PAIR
#include "native_pair_controller.inc"
#else
/* A separate ingress for real execution epochs. Old instruction owners retain
   their exact known-flags and genuine-fault predicates. */
static void selected_native_count(uintptr_t pc) {
    if(!first_target_pc)first_target_pc=pc;
    ++faults;if(pc==original_interpreter.entry)++first_interpreter;
    if(image_code(&original_main,pc))++main_faults;
    else if(image_code(&original_interpreter,pc))++interpreter_faults;
    else ++dependency_faults;
}
static int selected_native_fetch(int sig,siginfo_t *si,ucontext_t *uc) {
    if(selected_selftesting)return 0;
    checked(!selected_step_pending && selected_pending_route==SELECTED_NO_STEP &&
            !li2_lifecycle_fetch_interlock(),1432,0);
    unsigned retry=li2_native_epoch_progress()->phase==LI2_NATIVE_RETRY;
    if(!selected_flags_known || retry) {
        int result=li2_native_epoch_nx(sig,si,uc,&selected_logical_flags);
        checked(result==LI2_NATIVE_READY || result==LI2_NATIVE_REFAULT,
                (unsigned)result,li2_native_epoch_progress()->first_detail);
        if(result==LI2_NATIVE_REFAULT) {
            if(image_code(&original_main,(uintptr_t)uc->uc_mcontext.gregs[REG_RIP])) {
                checked(native_main_refaults!=UINT64_MAX,1436,0);++native_main_refaults;
            }
            selected_native_count((uintptr_t)uc->uc_mcontext.gregs[REG_RIP]);
            return 1; /* Same real frame, now all pages NX. No fabricated event. */
        }
#ifdef LI2_MAPS_PHASE_REUSE
        /* Closing the epoch invalidated and ended the routing phase. Start a
           fresh phase only after the genuine NX owner verified full closure;
           no prior rows or query result survive. Syscall/fatal close callers
           keep their original direct-observation contract. */
        checked(!li2_maps_phase_begin(),770,0);
#endif
        selected_flags_known=1;
        if(retry)return 0; /* Force the old owner; readmission would refault forever. */
    }
    greg_t *g=uc->uc_mcontext.gregs;
    uint64_t mask=0;copy(&mask,&uc->uc_sigmask,8);
    checked(sig==SIGSEGV && si->si_signo==SIGSEGV && si->si_code==SEGV_ACCERR &&
            !si->si_errno && g[REG_TRAPNO]==14 && g[REG_ERR]==21 &&
            ((uint64_t)g[REG_CSGSFS]&0xffff)==0x33 && mask==SELECTED_MASK &&
            (uint64_t)g[REG_EFL]==(selected_logical_flags|SELECTED_RF),1433,0);
    uintptr_t pc=(uintptr_t)g[REG_RIP];
    /* First admission starts at a genuine first-byte fault. The separately
       owned straddler retry above preserves the qualified boundary CALL rule. */
    if((uintptr_t)si->si_addr!=pc)return 0;
    const struct li2_rseq_state *rseq=li2_rseq_snapshot();
    checked(rseq->initialized && !rseq->first_error,1434,0);
#ifdef LI2_RSEQ_NATIVE
    if(rseq->registered) {
        checked(rseq->registered==1 && rseq->held==1 && rseq->phase==LI2_RSEQ_ACTIVE,1434,1);
    } else checked(!rseq->held && rseq->phase==LI2_RSEQ_IDLE,1434,1);
#else
    if(rseq->registered)return 0;
    checked(!rseq->held && rseq->phase==LI2_RSEQ_IDLE,1434,1);
#endif
    if(!li2_lifecycle_native_admit(pc))return 0;
    if(image_code(&original_main,pc)) {
        checked(native_main_admissions!=UINT64_MAX,1436,1);++native_main_admissions;
    }
    selected_flags_known=0;
    selected_native_count(pc);
    return 1;
}
#endif
