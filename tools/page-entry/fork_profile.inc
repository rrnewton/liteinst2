/* Included only by runtime_loader.c: shares its real private gateway, frame,
   handlers, counters and protected ranges. It creates no alternate authority. */
#include <linux/membarrier.h>
#include <limits.h>
#include <sys/wait.h>

static const char *fork_env(const char *name) {
    const char *result=0; const char *const *env=bridge_environment();
    for(size_t i=0;env[i];i++) {
        size_t j=0;while(name[j] && name[j]==env[i][j])++j;
        if(!name[j] && env[i][j]=='=') { checked(!result,260,0);result=env[i]+j+1; }
    }
    return result;
}
static unsigned fork_decimal(const char **at) {
    unsigned n=0,digits=0;
    while(**at>='0' && **at<='9') { checked(n<=(65535U-(**at-'0'))/10,260,0);n=n*10+*(*at)++-'0';++digits; }
    checked(digits,260,0);return n;
}
static int fork_reserved_fd(long n) {
    return fork_profile.enabled && ((unsigned int)n==(unsigned int)fork_profile.sinks[0] ||
        (unsigned int)n==(unsigned int)fork_profile.sinks[1]);
}
static int fork_sink_alias(long fd) {
    if(!fork_profile.enabled)return 0;
    struct stat actual;
    if(raw(SYS_fstat,fd,(long)&actual,0,0,0,0))return 0;
    for(unsigned i=0;i<2;i++)if(actual.st_dev==fork_profile.sink_identity[i].st_dev &&
        actual.st_ino==fork_profile.sink_identity[i].st_ino && S_ISFIFO(actual.st_mode))return 1;
    return 0;
}
static void fork_sink_check(void) {
    for(unsigned i=0;i<2;i++) {
        struct stat actual;const struct stat *saved=&fork_profile.sink_identity[i];
        long flags=raw(SYS_fcntl,fork_profile.sinks[i],F_GETFL,0,0,0,0);
        checked(!raw(SYS_fstat,fork_profile.sinks[i],(long)&actual,0,0,0,0) &&
            actual.st_dev==saved->st_dev && actual.st_ino==saved->st_ino && actual.st_mode==saved->st_mode &&
            flags>=0 && (flags&O_ACCMODE)==O_WRONLY && !(flags&O_NONBLOCK),261,i);
    }
}
static void fork_configure(void) {
    const char *mode=fork_env("LI2_RAW_FORK"),*value=fork_env("LI2_FORK_REPORT_FDS"),*injection=fork_env("LI2_FORK_CHILD_FAILURE");
    if(!mode) { checked(!value && !injection,260,0);return; }
    checked(mode[0]=='1' && !mode[1] && value,260,0);
    unsigned a=fork_decimal(&value);checked(*value++==',',260,0);
    unsigned b=fork_decimal(&value);checked(!*value && a>2 && b>2 && a!=b,260,0);
    struct stat first,second;
    checked(!raw(SYS_fstat,a,(long)&first,0,0,0,0) && !raw(SYS_fstat,b,(long)&second,0,0,0,0) &&
        S_ISFIFO(first.st_mode) && S_ISFIFO(second.st_mode) &&
        (first.st_dev!=second.st_dev || first.st_ino!=second.st_ino),261,0);
    long fa=raw(SYS_fcntl,a,F_GETFL,0,0,0,0),fb=raw(SYS_fcntl,b,F_GETFL,0,0,0,0);
    checked(fa>=0 && fb>=0 && (fa&O_ACCMODE)==O_WRONLY && (fb&O_ACCMODE)==O_WRONLY &&
        !(fa&O_NONBLOCK) && !(fb&O_NONBLOCK),261,0);
    fork_profile.sinks[0]=(int)a;fork_profile.sinks[1]=(int)b;
    fork_profile.sink_identity[0]=first;fork_profile.sink_identity[1]=second;
    if(injection) { fork_profile.fail_step=fork_decimal(&injection);checked(!*injection && fork_profile.fail_step>=1 && fork_profile.fail_step<=4,260,0); }
    fork_profile.enabled=1;
    fork_profile.self_pid=raw(SYS_getpid,0,0,0,0,0,0);
}
static void fork_counter_snapshot(uint64_t out[FORK_COUNTERS]) {
    const uint64_t actual[FORK_COUNTERS]={faults,cpuid_count,tsc_count,tscp_count,syscall_count,forwarded,
        first_interpreter,main_faults,interpreter_faults,dependency_faults,tls_changes,tid_sets,robust_sets,rseq_calls,vdso_selected};
    for(size_t i=0;i<FORK_COUNTERS;i++)out[i]=actual[i];
}
static void fork_signal_check(void) {
    stack_t stack; struct action action;
    checked(!raw(SYS_sigaltstack,0,(long)&stack,0,0,0,0) && stack.ss_sp==fork_gate_stack.ss_sp &&
        stack.ss_size==fork_gate_stack.ss_size && stack.ss_flags==SS_ONSTACK,264,0);
    uintptr_t sp;__asm__ volatile("mov %%rsp,%0":"=r"(sp));
    checked(sp>=(uintptr_t)stack.ss_sp && sp-(uintptr_t)stack.ss_sp<stack.ss_size,264,1);
    for(unsigned i=0;i<2;i++) {
        int sig=i?SIGSYS:SIGSEGV;
        checked(!raw(SYS_rt_sigaction,sig,0,(long)&action,8,0,0) && action.handler==fork_gate_action.handler &&
            action.flags==fork_gate_action.flags && action.restorer==fork_gate_action.restorer &&
            action.mask==(fork_gate_action.mask&~(1ULL<<(SIGKILL-1))&~(1ULL<<(SIGSTOP-1))),264,sig);
    }
}
static void fork_child_step(unsigned step) {
    fork_profile.setup_started=step;
    if(fork_profile.fail_step==step)fail(273,step);
}
static void fork_child_rearm(void) {
    fork_profile.role=1;fork_profile.parent_pid=fork_profile.before_pid;
    /* role selects the distinct inherited sink before any fallible child work. */
    fork_profile.child_pid_result=raw(SYS_getpid,0,0,0,0,0,0);fork_profile.gate_observed|=1ULL<<0;
    fork_profile.child_tid_result=raw(SYS_gettid,0,0,0,0,0,0);fork_profile.gate_observed|=1ULL<<1;
    fork_profile.self_pid=fork_profile.child_pid_result;
    checked(fork_profile.self_pid>0 && fork_profile.self_pid!=fork_profile.before_pid &&
        fork_profile.self_pid==fork_profile.child_tid_result,263,0);
    fork_child_step(1);
    fork_sink_check();fork_signal_check();li2_lifecycle_fork_verify();
    li2_lifecycle_verify_kernel_code(vdso_first,vdso_end-vdso_first);
    fork_profile.setup_complete=1;
    fork_child_step(2);
    fork_profile.cpuid_before=raw(SYS_arch_prctl,ARCH_GET_CPUID,0,0,0,0,0);fork_profile.gate_observed|=1ULL<<2;
    checked(fork_profile.cpuid_before==0,266,fork_profile.cpuid_before);
    fork_profile.tsc_query=raw(SYS_prctl,PR_GET_TSC,(long)&fork_profile.tsc_before,0,0,0,0);fork_profile.gate_observed|=1ULL<<5;
    if(!fork_profile.tsc_query)fork_profile.gate_observed|=1ULL<<6;
    checked(!fork_profile.tsc_query && fork_profile.tsc_before==PR_TSC_SIGSEGV,267,fork_profile.tsc_query);
    fork_profile.cpuid_set=raw(SYS_arch_prctl,ARCH_SET_CPUID,0,0,0,0,0);fork_profile.gate_observed|=1ULL<<3;
    checked(!fork_profile.cpuid_set,268,fork_profile.cpuid_set);
    fork_profile.tsc_set=raw(SYS_prctl,PR_SET_TSC,PR_TSC_SIGSEGV,0,0,0,0);fork_profile.gate_observed|=1ULL<<7;
    checked(!fork_profile.tsc_set,268,fork_profile.tsc_set);
    fork_profile.cpuid_after=raw(SYS_arch_prctl,ARCH_GET_CPUID,0,0,0,0,0);fork_profile.gate_observed|=1ULL<<4;
    checked(!fork_profile.cpuid_after,268,fork_profile.cpuid_after);
    fork_profile.tsc_after_query=raw(SYS_prctl,PR_GET_TSC,(long)&fork_profile.tsc_after,0,0,0,0);fork_profile.gate_observed|=1ULL<<8;
    if(!fork_profile.tsc_after_query)fork_profile.gate_observed|=1ULL<<9;
    checked(!fork_profile.tsc_after_query && fork_profile.tsc_after==PR_TSC_SIGSEGV,268,fork_profile.tsc_after_query);
    fork_profile.setup_complete=2;
    fork_child_step(3);
    fork_profile.membarrier_register=raw(SYS_membarrier,MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,0,0,0,0,0);fork_profile.gate_observed|=1ULL<<10;
    checked(!fork_profile.membarrier_register,269,fork_profile.membarrier_register);
    fork_profile.membarrier_query=raw(SYS_membarrier,MEMBARRIER_CMD_GET_REGISTRATIONS,0,0,0,0,0);fork_profile.gate_observed|=1ULL<<11;
    checked(fork_profile.membarrier_query>=0 &&
        (fork_profile.membarrier_query&MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE),269,0);
    fork_profile.setup_complete=3;
    fork_child_step(4);
    fork_profile.sud_set=raw(SYS_prctl,PR_SET_SYSCALL_USER_DISPATCH,PR_SYS_DISPATCH_ON,
        (long)li2_gateway_start,li2_gateway_end-li2_gateway_start,0,0);
    fork_profile.gate_observed|=1ULL<<12;
    checked(!fork_profile.sud_set,270,fork_profile.sud_set);
    fork_profile.setup_complete=4;fork_profile.child_ready=1;
}
static int fork_dispatch(long n,const long a[6],ucontext_t *context,long *result) {
    if(!fork_profile.enabled || (n!=SYS_fork && n!=SYS_wait4))return 0;
    if(n==SYS_fork) {
        checked(!fork_profile.role && !fork_profile.attempted,262,0);
        long pid=raw(SYS_getpid,0,0,0,0,0,0),tid=raw(SYS_gettid,0,0,0,0,0,0);
        checked(pid>0 && pid==tid && pid==fork_profile.self_pid,263,0);
        struct action action;
        checked(!raw(SYS_rt_sigaction,SIGCHLD,0,(long)&action,8,0,0) && !action.handler &&
            !(action.flags&SA_NOCLDWAIT),264,SIGCHLD);
        fork_sink_check();fork_signal_check();li2_lifecycle_fork_capture(protected,protected_count);
        fork_profile.before_pid=pid;
        fork_profile.application_pc=(uintptr_t)context->uc_mcontext.gregs[REG_RIP];
        fork_profile.application_sp=(uintptr_t)context->uc_mcontext.gregs[REG_RSP];
        fork_counter_snapshot(fork_profile.inherited);
        li2_lifecycle_snapshot(&fork_profile.inherited_lifecycle);
        fork_profile.attempted=1;
        /* Genuine fork occurs on the private handler stack. Both returned
           copies retain the original ucontext and complete signal frame. */
        long actual=raw(n,a[0],a[1],a[2],a[3],a[4],a[5]);
        fork_profile.fork_result=actual;fork_profile.returned=1;
        if(!actual)fork_child_rearm();
        else if(actual>0)fork_profile.child_pid=actual;
        checked((uintptr_t)context->uc_mcontext.gregs[REG_RIP]==fork_profile.application_pc &&
            (uintptr_t)context->uc_mcontext.gregs[REG_RSP]==fork_profile.application_sp,275,0);
        *result=actual;return 1;
    }
    checked(!fork_profile.role && fork_profile.returned && fork_profile.child_pid>0 &&
        (int)a[0]==fork_profile.child_pid && ((int)a[2]==0 || (int)a[2]==WNOHANG),271,n);
    checked(fork_profile.wait_used<FORK_WAIT_RECORDS,272,n);
    struct fork_wait_record *record=&fork_profile.waits[fork_profile.wait_used++];
    for(size_t i=0;i<6;i++)record->args[i]=a[i];
    record->result=raw(n,a[0],a[1],a[2],a[3],a[4],a[5]);record->completed=1;
    /* Never infer non-reaping from -EFAULT; do not retry or consume a status. */
    *result=record->result;return 1;
}
struct fork_writer { char bytes[4096];size_t used; };
_Static_assert(sizeof(long)==8 && sizeof(int)==4,"Linux x86-64 syscall widths");
_Static_assert(sizeof(((struct fork_writer *)0)->bytes)<=PIPE_BUF,"single pipe report extent");
static void fork_text(struct fork_writer *w,const char *s) {
    while(*s) { if(w->used==sizeof(w->bytes))li2_fail("fork report overflow");w->bytes[w->used++]=*s++; }
}
static void fork_number(struct fork_writer *w,uint64_t n) {
    char b[20];size_t used=0;do { b[used++]=(char)('0'+n%10);n/=10; }while(n);
    while(used) { if(w->used==sizeof(w->bytes))li2_fail("fork report overflow");w->bytes[w->used++]=b[--used]; }
}
static void fork_signed(struct fork_writer *w,long n) {
    if(n<0)fork_text(w,"-");
    fork_number(w,n<0?0ULL-(uint64_t)n:(uint64_t)n);
}
static void fork_field(struct fork_writer *w,const char *key,long n) { fork_text(w,key);fork_signed(w,n); }
static void fork_array(struct fork_writer *w,const uint64_t *v,size_t n) {
    fork_text(w,"[");for(size_t i=0;i<n;i++){if(i)fork_text(w,",");fork_number(w,v[i]);}fork_text(w,"]");
}
static void fork_lifecycle_array(struct fork_writer *w,const struct li2_lifecycle_counts *c) {
    const uint64_t v[]={c->enabled,c->transactions,c->mappings,c->generations,c->retired,c->admissions,
        c->reconciliations,c->kernel_errors,c->partial_errors,c->materialized,c->sync_core,c->live_pages,
        c->retained_records,c->last_operation,c->last_syscall,c->last_result_abs,c->last_result_negative,c->last_phase};
    fork_array(w,v,sizeof(v)/sizeof(v[0]));
}
static void fork_report(unsigned status,unsigned code,long detail) {
    struct fork_writer w={.used=0};uint64_t counters[FORK_COUNTERS];struct li2_lifecycle_counts lifecycle;
    fork_counter_snapshot(counters);li2_lifecycle_snapshot(&lifecycle);
    fork_text(&w,"LI2_FORK {\"version\":1,\"scope\":\"sealed_namespace_raw_fork\",\"source_patches\":0");
    fork_field(&w,",\"status\":",status);fork_field(&w,",\"failure_code\":",code);fork_field(&w,",\"detail\":",detail);
    fork_field(&w,",\"role\":",fork_profile.role);fork_field(&w,",\"self_pid\":",fork_profile.self_pid);
    fork_field(&w,",\"before_pid\":",fork_profile.before_pid);fork_field(&w,",\"child_pid\":",fork_profile.child_pid);
    fork_field(&w,",\"attempted\":",fork_profile.attempted);fork_field(&w,",\"returned\":",fork_profile.returned);
    fork_field(&w,",\"fork_result\":",fork_profile.fork_result);fork_field(&w,",\"child_ready\":",fork_profile.child_ready);
    fork_field(&w,",\"setup_started\":",fork_profile.setup_started);fork_field(&w,",\"setup_complete\":",fork_profile.setup_complete);
    fork_field(&w,",\"gate_observed\":",fork_profile.gate_observed);
    fork_text(&w,",\"gate_results\":[");
    const long results[]={fork_profile.child_pid_result,fork_profile.child_tid_result,fork_profile.cpuid_before,
        fork_profile.cpuid_set,fork_profile.cpuid_after,fork_profile.tsc_query,fork_profile.tsc_before,
        fork_profile.tsc_set,fork_profile.tsc_after_query,fork_profile.tsc_after,fork_profile.membarrier_register,
        fork_profile.membarrier_query,fork_profile.sud_set};
    for(size_t i=0;i<sizeof(results)/sizeof(results[0]);i++){if(i)fork_text(&w,",");fork_signed(&w,results[i]);}
    fork_text(&w,"],\"inherited\":");fork_array(&w,fork_profile.inherited,FORK_COUNTERS);
    fork_text(&w,",\"current\":");fork_array(&w,counters,FORK_COUNTERS);
    fork_text(&w,",\"inherited_lifecycle\":");fork_lifecycle_array(&w,&fork_profile.inherited_lifecycle);
    fork_text(&w,",\"current_lifecycle\":");fork_lifecycle_array(&w,&lifecycle);
    fork_text(&w,",\"waits\":[");
    for(size_t i=0;i<fork_profile.wait_used;i++) {
        if(i)fork_text(&w,",");
        const struct fork_wait_record *r=&fork_profile.waits[i];
        fork_text(&w,"[");fork_number(&w,r->completed);fork_text(&w,",");fork_signed(&w,r->result);fork_text(&w,"]");
    }
    fork_text(&w,"]}\n");
    /* Distinct blocking FIFO owners; one <=PIPE_BUF write, no hidden retry. */
    long n=raw(SYS_write,fork_profile.sinks[fork_profile.role],(long)w.bytes,w.used,0,0,0);
    if(n!=(long)w.used) { (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap(); }
}
