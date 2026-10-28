/* Included only by the explicit deterministic-builtins profile. The authentic
   NX/UD2 ingress and fresh original-source borrow belong to the old callers. */
static struct {
    volatile sig_atomic_t busy;
    unsigned first_error;
    long first_detail;
    uint64_t attempts,clock_completed[2],syscall_replaced,syscall_forwarded;
    struct {
        volatile sig_atomic_t entered,returned,committed;
        int status;
        struct li2_selected_clock_input input;
        struct li2_selected_clock_result result;
    } clock;
    struct {
        volatile sig_atomic_t prepared,entered,returned,pre_dispatch_guards_complete;
        volatile sig_atomic_t native_dispatch_entered,raw_entered,raw_returned;
        volatile sig_atomic_t replacement_selected,dispatch_returned,committed,exit_selected;
        int status;
        uint64_t actual_result;
        struct li2_selected_syscall_input input;
        struct li2_selected_syscall_result result;
    } syscall;
} selected_builtin_policy;
static void selected_builtin_policy_check(int ok,unsigned code,long detail) {
    if(!ok && !selected_builtin_policy.first_error) {
        selected_builtin_policy.first_error=code;selected_builtin_policy.first_detail=detail;
    }
    checked(ok,code,detail);
}
static void selected_builtin_policy_begin(void) {
    selected_builtin_policy_check(selected_provider_state.initialized &&
        selected_provider_state.mode==1 && selected_provider_builtins_enabled &&
        !selected_provider_state.busy && !selected_builtin_policy.busy &&
        !selected_builtin_policy.first_error && selected_builtin_policy.attempts!=UINT64_MAX,1610,0);
    selected_builtin_policy.busy=1;++selected_builtin_policy.attempts;
}
static void selected_provider_clock(ucontext_t *context) {
    selected_builtin_policy_begin();
    uint32_t kind=selected_decoded.kind;
    uint64_t count=selected_builtin_policy.clock_completed[0]+selected_builtin_policy.clock_completed[1];
    selected_builtin_policy_check((kind==LI2_RDTSC || kind==LI2_RDTSCP) &&
        count<LI2_POLICY_CLOCK_LAST && !selected_step_pending &&
        li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,1611,0);
    __typeof__(selected_builtin_policy.clock) *p=&selected_builtin_policy.clock;
    *p=(__typeof__(*p)){.input={1,kind,selected_decoded.pc,selected_decoded.next_pc,
        selected_logical_flags,count+1}};
    __asm__ volatile("":::"memory");p->entered=1;
    __asm__ volatile("":::"memory");
    p->status=selected_provider_binding.clock(&p->input,&p->result);
    __asm__ volatile("":::"memory");p->returned=1;
    __asm__ volatile("":::"memory");
    selected_builtin_policy_check(!p->status && !p->result.reserved &&
        (kind==LI2_RDTSCP || !p->result.aux),1612,p->status);
    greg_t *g=context->uc_mcontext.gregs;
    g[REG_RAX]=(greg_t)(uint32_t)p->result.value;
    g[REG_RDX]=(greg_t)(uint32_t)(p->result.value>>32);
    if(kind==LI2_RDTSCP) {g[REG_RCX]=(greg_t)p->result.aux;++tscp_count;}else ++tsc_count;
    g[REG_EFL]=(greg_t)p->input.logical_flags;g[REG_RIP]=(greg_t)p->input.next_pc;
    __asm__ volatile("":::"memory");p->committed=1;
    ++selected_builtin_policy.clock_completed[kind==LI2_RDTSCP];
    selected_builtin_policy.busy=0;
}
static void selected_provider_syscall_prepare(ucontext_t *context,uint64_t flags) {
    selected_builtin_policy_begin();
    selected_builtin_policy_check(selected_decoded.kind==LI2_SYSCALL && !selected_step_pending &&
        li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,1613,0);
    greg_t *g=context->uc_mcontext.gregs;
    __typeof__(selected_builtin_policy.syscall) *p=&selected_builtin_policy.syscall;
    *p=(__typeof__(*p)){.input={1,0,selected_decoded.pc,selected_decoded.next_pc,flags,
        (uint64_t)g[REG_RAX],{(uint64_t)g[REG_RDI],(uint64_t)g[REG_RSI],(uint64_t)g[REG_RDX],
        (uint64_t)g[REG_R10],(uint64_t)g[REG_R8],(uint64_t)g[REG_R9]},
        (uint64_t)g[REG_RCX],(uint64_t)g[REG_R11]}};
    __asm__ volatile("":::"memory");p->prepared=1;
}
static void selected_provider_syscall_decide(long n,const long args[6],ucontext_t *context) {
    __typeof__(selected_builtin_policy.syscall) *p=&selected_builtin_policy.syscall;
    greg_t *g=context->uc_mcontext.gregs;
    selected_builtin_policy_check(selected_builtin_policy.busy && p->prepared && !p->entered &&
        p->input.number==(uint64_t)n && p->input.next_pc==(uint64_t)g[REG_RIP] &&
        p->input.next_pc==(uint64_t)g[REG_RCX] && p->input.logical_flags==(uint64_t)g[REG_R11] &&
        p->input.logical_flags==(uint64_t)g[REG_EFL] && !li2_lifecycle_fetch_interlock() &&
        !selected_step_pending,1614,0);
    for(unsigned i=0;i<6;i++)selected_builtin_policy_check(p->input.args[i]==(uint64_t)args[i],1614,i+1);
    __asm__ volatile("":::"memory");p->entered=1;
    __asm__ volatile("":::"memory");
    p->status=selected_provider_binding.syscall(&p->input,&p->result);
    __asm__ volatile("":::"memory");p->returned=1;
    __asm__ volatile("":::"memory");
    selected_builtin_policy_check(!p->status && !p->result.reserved &&
        ((p->result.action==LI2_SYSCALL_NATIVE && !p->result.value) ||
         (p->result.action==LI2_SYSCALL_REPLACE &&
          ((n==SYS_getpid && p->result.value==LI2_POLICY_PID) ||
           (n==SYS_gettid && p->result.value==LI2_POLICY_TID)))),1615,p->status);
}
static void selected_provider_syscall_exit(void) {
    __typeof__(selected_builtin_policy.syscall) *p=&selected_builtin_policy.syscall;
    selected_builtin_policy_check(selected_builtin_policy.busy && p->returned &&
        p->result.action==LI2_SYSCALL_NATIVE &&
        (p->input.number==SYS_exit || p->input.number==SYS_exit_group),1616,0);
    /* The old report precedes raw exit. Do not report raw_entered or a returned
       dispatch here: neither event has happened at that report boundary. */
    p->exit_selected=1;
}
static void selected_provider_syscall_guarded(void) {
    __typeof__(selected_builtin_policy.syscall) *p=&selected_builtin_policy.syscall;
    selected_builtin_policy_check(selected_builtin_policy.busy && p->returned &&
        !p->pre_dispatch_guards_complete && !p->exit_selected,1616,1);
    /* Only the preceding shared guards are complete. Owner dispatch and
       syscall-specific permission checks still follow before any raw effect. */
    p->pre_dispatch_guards_complete=1;
    if(p->result.action==LI2_SYSCALL_NATIVE)p->native_dispatch_entered=1;
}
static int selected_provider_syscall_replace(long *result) {
    __typeof__(selected_builtin_policy.syscall) *p=&selected_builtin_policy.syscall;
    selected_builtin_policy_check(selected_builtin_policy.busy && p->pre_dispatch_guards_complete && result &&
        !p->raw_entered && !p->replacement_selected,1616,2);
    if(p->result.action==LI2_SYSCALL_NATIVE)return 0;
    selected_builtin_policy_check(!p->native_dispatch_entered &&
        (p->input.number==SYS_getpid || p->input.number==SYS_gettid),1616,3);
    *result=(long)p->result.value;p->actual_result=(uint64_t)*result;
    __asm__ volatile("":::"memory");p->replacement_selected=1;
    return 1;
}
static void selected_provider_syscall_raw_enter(void) {
    __typeof__(selected_builtin_policy.syscall) *p=&selected_builtin_policy.syscall;
    selected_builtin_policy_check(selected_builtin_policy.busy && p->pre_dispatch_guards_complete &&
        p->native_dispatch_entered && p->result.action==LI2_SYSCALL_NATIVE &&
        !p->replacement_selected && !p->raw_entered,1616,4);
    __asm__ volatile("":::"memory");p->raw_entered=1;
    __asm__ volatile("":::"memory");
}
static void selected_provider_syscall_raw_return(long result) {
    __typeof__(selected_builtin_policy.syscall) *p=&selected_builtin_policy.syscall;
    selected_builtin_policy_check(p->raw_entered && !p->raw_returned,1616,5);
    p->actual_result=(uint64_t)result;
    __asm__ volatile("":::"memory");p->raw_returned=1;
}
static int selected_provider_syscall_replaced(void) {
    return selected_builtin_policy.syscall.replacement_selected!=0;
}
static void selected_provider_syscall_commit(ucontext_t *context,long result) {
    __typeof__(selected_builtin_policy.syscall) *p=&selected_builtin_policy.syscall;
    greg_t *g=context->uc_mcontext.gregs;
    selected_builtin_policy_check(selected_builtin_policy.busy && p->returned && p->pre_dispatch_guards_complete &&
        !p->committed && p->input.next_pc==(uint64_t)g[REG_RIP] &&
        p->input.next_pc==(uint64_t)g[REG_RCX] && p->input.logical_flags==(uint64_t)g[REG_R11] &&
        p->input.logical_flags==(uint64_t)g[REG_EFL] && (uint64_t)result==(uint64_t)g[REG_RAX],1617,0);
    selected_builtin_policy_check(p->replacement_selected?
        (!p->native_dispatch_entered && !p->raw_entered && !p->raw_returned &&
         (uint64_t)result==p->result.value):
        (p->native_dispatch_entered && p->result.action==LI2_SYSCALL_NATIVE &&
         (!p->raw_entered || p->raw_returned)),1617,1);
    uint64_t *counter=p->replacement_selected?&selected_builtin_policy.syscall_replaced:
        &selected_builtin_policy.syscall_forwarded;
    selected_builtin_policy_check(*counter!=UINT64_MAX,1617,2);
    p->actual_result=(uint64_t)result;p->dispatch_returned=1;
    __asm__ volatile("":::"memory");p->committed=1;
    ++*counter;selected_builtin_policy.busy=0;
}
static void selected_provider_builtins_report(unsigned status,unsigned code) {
    if(!selected_provider_builtins_enabled)return;
    struct writer w={.used=0};
    text(&w,"LI2_PROVIDER_BUILTINS {\"version\":1,\"policy\":\"deterministic-builtins-v1\"");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"first_error\":",selected_builtin_policy.first_error);
    field(&w,",\"busy\":",selected_builtin_policy.busy);field(&w,",\"attempts\":",selected_builtin_policy.attempts);
    field(&w,",\"rdtsc_completed\":",selected_builtin_policy.clock_completed[0]);
    field(&w,",\"rdtscp_completed\":",selected_builtin_policy.clock_completed[1]);
    field(&w,",\"syscall_replaced\":",selected_builtin_policy.syscall_replaced);
    field(&w,",\"syscall_forwarded_returned\":",selected_builtin_policy.syscall_forwarded);
    field(&w,",\"clock_entered\":",selected_builtin_policy.clock.entered);
    field(&w,",\"clock_returned\":",selected_builtin_policy.clock.returned);
    field(&w,",\"clock_committed\":",selected_builtin_policy.clock.committed);
    field(&w,",\"syscall_prepared\":",selected_builtin_policy.syscall.prepared);
    field(&w,",\"syscall_entered\":",selected_builtin_policy.syscall.entered);
    field(&w,",\"syscall_returned\":",selected_builtin_policy.syscall.returned);
    field(&w,",\"syscall_pre_dispatch_guards_complete\":",selected_builtin_policy.syscall.pre_dispatch_guards_complete);
    field(&w,",\"native_dispatch_entered\":",selected_builtin_policy.syscall.native_dispatch_entered);
    field(&w,",\"raw_entered\":",selected_builtin_policy.syscall.raw_entered);
    field(&w,",\"raw_returned\":",selected_builtin_policy.syscall.raw_returned);
    field(&w,",\"replacement_selected\":",selected_builtin_policy.syscall.replacement_selected);
    field(&w,",\"dispatch_returned\":",selected_builtin_policy.syscall.dispatch_returned);
    field(&w,",\"syscall_committed\":",selected_builtin_policy.syscall.committed);
    field(&w,",\"exit_selected\":",selected_builtin_policy.syscall.exit_selected);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
_Static_assert(SYS_getpid==39 && SYS_gettid==186,"exact x86-64 tagged policy calls");
