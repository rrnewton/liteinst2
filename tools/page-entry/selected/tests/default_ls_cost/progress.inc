/* Private diagnostic only: observe real handler boundaries, never authorize. */
#if !defined(LI2_NATIVE_PAGES) || !defined(LI2_TF_HANDOFF) || !defined(LI2_RSEQ_INACTIVE) || !defined(LI2_MAPS_PHASE_REUSE)
#error "default-ls progress requires the complete native-page/TF/rseq profile"
#endif
static uint64_t diag_handlers,diag_samples;
static unsigned diag_active,diag_registered;
static uintptr_t diag_entry_pc;
static unsigned diag_signal;

static uint64_t diag_clock(long clock) {
    struct { long sec,nsec; } t;
    long result=raw(SYS_clock_gettime,clock,(long)&t,0,0,0,0);
    if(result || t.sec<0 || t.nsec<0 || t.nsec>=1000000000L ||
       (uint64_t)t.sec>(UINT64_MAX-999999999)/1000000000) {
        (void)raw(SYS_exit_group,126,0,0,0,0,0);__builtin_trap();
    }
    return (uint64_t)t.sec*1000000000+(uint64_t)t.nsec;
}
static void diag_emit(unsigned boundary,const ucontext_t *uc) {
    uint64_t cpu=diag_clock(2),wall=diag_clock(4); /* PROCESS_CPUTIME / MONOTONIC_RAW */
    struct writer w={.used=0};struct li2_lifecycle_counts lc;
    li2_lifecycle_snapshot(&lc);
    const struct li2_native_counts *nc=li2_lifecycle_native_counts();
    const struct li2_rseq_state *rs=li2_rseq_snapshot();
    struct li2_maps_stats ms;li2_maps_stats_read(&ms);
    text(&w,"LI2_DIAG {\"version\":3,\"prefix\":1");
    field(&w,",\"sample\":",diag_samples);field(&w,",\"boundary\":",boundary);
    field(&w,",\"handlers\":",diag_handlers);field(&w,",\"signal\":",diag_signal);
    field(&w,",\"entry_pc\":",diag_entry_pc);
    field(&w,",\"pc\":",(uintptr_t)uc->uc_mcontext.gregs[REG_RIP]);
    field(&w,",\"cpu_ns\":",cpu);field(&w,",\"wall_ns\":",wall);
    field(&w,",\"route\":",selected_pending_route);
    field(&w,",\"step_pending\":",selected_step_pending);
    field(&w,",\"nx\":",faults);field(&w,",\"chain_steps\":",selected_chain.steps);
    field(&w,",\"trace_entries\":",selected_chain.trace_entries);
    field(&w,",\"admissions\":",nc->admissions);field(&w,",\"closed\":",nc->closed);
    field(&w,",\"retained_records\":",lc.retained_records);field(&w,",\"live_pages\":",lc.live_pages);
    field(&w,",\"rseq_registered\":",rs->registered);field(&w,",\"rseq_phase\":",rs->phase);
    field(&w,",\"rseq_registrations\":",rs->registrations);
    field(&w,",\"rseq_instruction_checks\":",rs->instruction_checks);
    field(&w,",\"rseq_range_checks\":",rs->range_checks);
    field(&w,",\"rseq_run_checks\":",rs->run_checks);
    field(&w,",\"rseq_syscall_checks\":",rs->syscall_checks);
    field(&w,",\"rseq_last_pc\":",rs->last_pc);field(&w,",\"rseq_last_code\":",rs->last_code);
    field(&w,",\"maps_fresh_calls\":",ms.fresh_calls);
    field(&w,",\"maps_acquisitions\":",ms.acquisitions);
    field(&w,",\"maps_reuses\":",ms.reuses);
    field(&w,",\"maps_invalidations\":",ms.invalidations);
    field(&w,",\"maps_handler_id\":",ms.handler_id);
    field(&w,",\"maps_mutation_epoch\":",ms.mutation_epoch);
    field(&w,",\"maps_active\":",ms.active);
    field(&w,",\"maps_valid\":",ms.valid);
    field(&w,",\"maps_poisoned\":",ms.poisoned);
    text(&w,"}\n");
    if(w.used>2048 || raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0)!=(long)w.used) {
        (void)raw(SYS_exit_group,126,0,0,0,0,0);__builtin_trap();
    }
}
static void diag_begin(unsigned sig,const ucontext_t *uc) {
    diag_active=0;
    if(diag_samples==128)return;
    ++diag_handlers;
    unsigned registered=li2_rseq_snapshot()->registered;
    unsigned transition=registered!=diag_registered;diag_registered=registered;
    if(diag_handlers!=1 && diag_handlers%4096 && !transition)return;
    ++diag_samples;diag_active=1;diag_signal=sig;
    diag_entry_pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];diag_emit(1,uc);
}
static void diag_end(const ucontext_t *uc) {
    if(!diag_active)return;
    diag_emit(2,uc);diag_active=0;
}
