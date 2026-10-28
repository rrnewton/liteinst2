/* Admission-owned fixed one-shot route. No old quiescence/publication receipt is
   synthesized. A dormant return address may name any restored source byte. */
static int selected_oneshot_frame_range(void *unused,const void *p,size_t n) {
    (void)unused;uintptr_t a=(uintptr_t)p,first=(uintptr_t)fork_gate_stack.ss_sp;
    return !p || !n || first>UINTPTR_MAX-fork_gate_stack.ss_size ||
        a<first || a>first+fork_gate_stack.ss_size || n>first+fork_gate_stack.ss_size-a;
}
static void selected_oneshot_clear_route(void) {
    selected_step_pending=0;selected_pending_route=SELECTED_NO_STEP;
}
static _Noreturn void selected_oneshot_abort(unsigned code,long detail) {
    /* Nested cleanup never resumes the interrupted publication or C/Rust call. */
    if(!selected_oneshot_failing) {
        selected_oneshot_failing=1;
#ifdef LI2_MAPS_PHASE_REUSE
        li2_maps_phase_fail();
#endif
        struct li2_oneshot_owner *o=selected_oneshot_active;
        if(o && o->state.phase!=LI2_ONESHOT_RESTORED && o->state.phase!=LI2_ONESHOT_COMPLETED) {
            li2_admission_oneshot_fail(&o->state,code,detail);
            li2_oneshot_abort_close(o);
        }
        li2_lifecycle_abort();report(125,code,detail);
    }
    (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static unsigned selected_oneshot_kind(void) {
    if(selected_decoded.length!=2 || selected_decoded.bytes[0]!=0x0f)return 0;
    if(selected_decoded.kind==LI2_SYSCALL && selected_decoded.bytes[1]==0x05)return LI2_ONESHOT_SYSCALL;
    if(selected_decoded.kind==LI2_RDTSC && selected_decoded.bytes[1]==0x31)return LI2_ONESHOT_RDTSC;
    return 0;
}
static int selected_oneshot_try(int sig,siginfo_t *si,ucontext_t *uc) {
    unsigned kind=selected_oneshot_kind();
    if(!kind || selected_oneshot_used==LI2_ONESHOT_LIFECYCLE_SLOTS ||
       (uintptr_t)si->si_addr!=selected_decoded.pc)return 0;
    checked(selected_oneshot_used<LI2_ONESHOT_LIFECYCLE_SLOTS && !selected_oneshot_active &&
        !selected_step_pending && selected_pending_route==SELECTED_NO_STEP &&
        li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,1562,0);
#ifdef LI2_RSEQ_INACTIVE
    const struct li2_rseq_state *rs=li2_rseq_snapshot();
    checked(rs->initialized && !rs->first_error && !rs->held,1563,0);
    if(rs->registered) {checked(rs->phase==LI2_RSEQ_ACTIVE,1563,1);return 0;}
    checked(rs->phase==LI2_RSEQ_IDLE,1563,2);
#endif
    uintptr_t original_pc=selected_decoded.pc,original_next=selected_decoded.next_pc;
    selected_pending_route=SELECTED_ONESHOT;selected_step_pending=1;
#ifdef LI2_MAPS_PHASE_REUSE
    li2_maps_phase_end(); /* Every following observation is owned and fresh. */
#endif
    struct li2_oneshot_lifecycle *backend=0;
    int e=li2_lifecycle_oneshot_prepare(&selected_borrow,kind,&selected_oneshot_request,&backend);
    if(e==LI2_ONESHOT_REFUSED_UNTOUCHED) {
        checked(!backend && li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,1564,e);
        selected_oneshot_clear_route();return 0;
    }
    checked(e==LI2_ONESHOT_OK && backend,1565,e);
    struct li2_oneshot_owner *o=&selected_oneshot_owners[selected_oneshot_used++];
    selected_oneshot_active=o;
    const struct li2_oneshot_hooks hooks={backend,raw,selected_oneshot_frame_range,
        li2_lifecycle_oneshot_transfer,li2_lifecycle_oneshot_advance,
        li2_lifecycle_oneshot_observe,li2_lifecycle_oneshot_release};
    e=li2_oneshot_initialize(o,&selected_session,&hooks);checked(!e,1566,e);
    e=li2_oneshot_nx(o,&selected_oneshot_request,sig,si,uc);
    if(e==LI2_ONESHOT_REFUSED_UNTOUCHED || e==LI2_ONESHOT_REFUSED_RELEASED) {
        checked(!o->transferred && !o->state.mutation_started && !o->state.published,1567,e);
        if(e==LI2_ONESHOT_REFUSED_UNTOUCHED) {
            checked(li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,1568,0);
            for(size_t i=0;i<selected_view.page_count;i++)
                checked(!li2_lifecycle_fetch_validate(&selected_borrow,i,PROT_READ),1568,(long)i);
            selected_release();
        } else checked(!li2_lifecycle_fetch_interlock(),1569,0);
        selected_oneshot_active=0;selected_oneshot_clear_route();
        selected_prepare(original_pc);
        checked(selected_oneshot_kind()==kind && selected_decoded.next_pc==original_next,1570,0);
        return 0;
    }
    checked(e==LI2_ONESHOT_OK && o->state.phase==LI2_ONESHOT_PUBLISHED &&
        o->state.published && !o->state.first_error && !o->in_handler &&
        o->write_attempted_mask==31 && o->write_completed_mask==31 &&
        (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==original_pc,1571,e);
    /* Real original NX frame returns unchanged, executes the published E9 and
       reaches the registered literal UD2. No application-selected effect yet. */
    return 1;
}
static void selected_oneshot_landed(int sig,siginfo_t *si,ucontext_t *uc) {
    struct li2_oneshot_owner *o=selected_oneshot_active;
    checked(o && selected_step_pending && selected_pending_route==SELECTED_ONESHOT,1572,0);
    int e=li2_oneshot_ud(o,sig,si,uc,&selected_oneshot_handoff);
    checked(e==LI2_ONESHOT_OK && o->state.phase==LI2_ONESHOT_RESTORED &&
        o->state.restored && !o->state.first_error && !o->in_handler &&
        o->restore_attempted_mask==31 && o->restore_completed_mask==31 &&
        !li2_lifecycle_fetch_interlock(),1573,e);
    const struct li2_oneshot_handoff *h=&selected_oneshot_handoff;
    checked(h->actual_landing_frame==uc && h->sequence==o->plan.sequence &&
        h->kind==o->plan.kind && !h->reserved && h->original_pc==o->plan.pc &&
        h->original_next_pc==o->plan.next_pc && selected_flags_known &&
        h->logical_flags==selected_logical_flags,1574,0);
    selected_prepare(h->original_pc);
    checked(selected_oneshot_kind()==h->kind && selected_decoded.pc==h->original_pc &&
        selected_decoded.next_pc==h->original_next_pc &&
        equal(selected_decoded.bytes,o->plan.original,2),1575,0);
    /* All source bytes/permissions/generations are restored and a fresh borrow
       is now held. Keep active across dispatch: a nested reserved signal still
       terminates, while old selected effect interlocks retain their exact gate. */
    selected_oneshot_clear_route();
    unsigned index=(unsigned)(o-selected_oneshot_owners);
    checked(index<selected_oneshot_used && !selected_oneshot_effect_started[index],1576,0);
    selected_oneshot_effect_started[index]=1;
    if(h->kind==LI2_ONESHOT_RDTSC) {selected_builtin(uc);selected_release();}
    else selected_owned_syscall(uc,h->logical_flags);
    selected_oneshot_effect_returned[index]=1;
    checked((uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==h->original_next_pc &&
        !li2_lifecycle_fetch_interlock() && !selected_step_pending,1577,0);
    e=li2_admission_oneshot_transition(&o->state,LI2_ONESHOT_RESTORED,LI2_ONESHOT_COMPLETED);
    checked(!e,1578,e);selected_oneshot_active=0;
}
static void selected_oneshot_report(unsigned status,unsigned code,long detail) {
    struct writer w={.used=0};
    text(&w,"LI2_ONESHOT {\"version\":1,\"scope\":\"singleton_initial_main_temporary_e9\"");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",detail<0?0ULL-(uint64_t)detail:(uint64_t)detail);
    field(&w,",\"detail_negative\":",detail<0);field(&w,",\"owners\":",selected_oneshot_used);
    uint64_t published=0,restored=0,completed=0,syscall=0,rdtsc=0,started=0,returned=0;
    for(unsigned i=0;i<selected_oneshot_used;i++) {
        const struct li2_oneshot_owner *o=&selected_oneshot_owners[i];
        published+=o->state.published==1;restored+=o->state.restored==1;
        completed+=o->state.phase==LI2_ONESHOT_COMPLETED;
        syscall+=o->state.published==1 && o->plan.kind==LI2_ONESHOT_SYSCALL;
        rdtsc+=o->state.published==1 && o->plan.kind==LI2_ONESHOT_RDTSC;
        started+=selected_oneshot_effect_started[i]==1;returned+=selected_oneshot_effect_returned[i]==1;
    }
    field(&w,",\"published\":",published);field(&w,",\"restored\":",restored);
    field(&w,",\"completed\":",completed);field(&w,",\"syscall_patches\":",syscall);
    field(&w,",\"rdtsc_patches\":",rdtsc);field(&w,",\"effect_started\":",started);
    field(&w,",\"effect_returned\":",returned);
    field(&w,",\"active_phase\":",selected_oneshot_active?selected_oneshot_active->state.phase:0);
    text(&w,"}\n");checked(raw(SYS_write,report_fd,(long)w.bytes,w.used,0,0,0)==(long)w.used,1579,0);
}
static void selected_oneshot_stage(void) {
    /* Prefault fixed controller storage before any application frame is live. */
    volatile unsigned char *storage=(void *)selected_oneshot_owners;
    for(size_t i=0;i<sizeof(selected_oneshot_owners);i++)storage[i]=0;
    uintptr_t base=original_main.entry&~(PAGE-1),landing=0;
    if(base<LI2_ONESHOT_MIN_EXEC || base>UINTPTR_MAX-PAGE)return;
    for(unsigned i=1;i<=16 && !landing;i++) {
        uint64_t distance=(uint64_t)((i+1)/2)*UINT64_C(0x4000000);
        uintptr_t wanted=0;
        if(i&1) {if(base<=UINTPTR_MAX-distance-PAGE)wanted=base+distance;}
        else if(base>=LI2_ONESHOT_MIN_EXEC+distance)wanted=base-distance;
        if(wanted<LI2_ONESHOT_MIN_EXEC || wanted>UINTPTR_MAX-PAGE)continue;
        long result=raw(SYS_mmap,wanted,PAGE,PROT_READ|PROT_WRITE,
            MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
        if(result<0)continue;
        if((uintptr_t)result!=wanted) {
            checked(!raw(SYS_munmap,result,PAGE,0,0,0,0),1580,result);continue;
        }
        landing=wanted;
    }
    if(!landing)return; /* Clean capacity/reach fallback; no patch success. */
    protect(landing,PAGE);
    volatile unsigned char *bytes=(void *)landing;
    for(size_t i=0;i<PAGE;i++)bytes[i]=0xcc;
    bytes[0]=0x0f;bytes[1]=0x0b;
    checked(!raw(SYS_mprotect,landing,PAGE,PROT_READ|PROT_EXEC,0,0,0),1581,0);
    checked(!raw(SYS_membarrier,32,0,0,0,0,0),1582,0);
    checked(!li2_lifecycle_oneshot_register_landing(1,landing),1583,0);
}
