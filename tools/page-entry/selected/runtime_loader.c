/* Freestanding singleton loader runtime. Kernel traps, not source patches.
   The real ld.so runs against an explicit namespace of inherited sealed DSOs. */
#include "bridge.h"
#include "lifecycle_loader.h"
#include "provider.h"
#include "step_owner.h"
#include "tf_owner.h"
#include "repeat_owner.h"
#include "tf_continuation.h"
#include "selected_globals.inc"
#include <linux/audit.h>
#include <fcntl.h>

#define RANGES 128
#define ALT_BYTES (512UL*1024)
struct action { void (*handler)(int,siginfo_t *,void *); unsigned long flags; void (*restorer)(void); uint64_t mask; };
static struct li2_fork_range protected[RANGES];
static size_t protected_count,dependency_count;
static struct image original_main,original_interpreter;
static volatile sig_atomic_t handling,reported;
static unsigned long faults,cpuid_count,tsc_count,tscp_count,syscall_count,forwarded;
static unsigned long first_interpreter,main_faults,interpreter_faults,dependency_faults;
static unsigned long tls_changes,tid_sets,robust_sets,rseq_calls;
static int report_fd=-1;
static uintptr_t first_target_pc;
static long last_syscall=-1;
static uintptr_t vdso_first,vdso_end;
static unsigned long vdso_selected;
static void fail(unsigned,long) __attribute__((noreturn));
#ifdef LI2_TF_HANDOFF
static void selected_chain_failure(const struct li2_tf_chain *);
static void selected_chain_report(unsigned,unsigned,long);
#endif
#ifdef LI2_REGISTER_RUN
static void selected_run_initialize(void);
static void selected_run_report(unsigned,unsigned,long);
#ifdef LI2_RUN_TIMING
static void selected_run_time_report(unsigned,unsigned,long);
#endif
static int selected_run_try(int,siginfo_t *,ucontext_t *,uint64_t);
static void selected_run_exit(int,siginfo_t *,ucontext_t *);
static void selected_run_before_syscall(long,const long[6]);
static _Noreturn void selected_run_abort(unsigned,long);
static _Noreturn void selected_run_unexpected(int,siginfo_t *,ucontext_t *);
#endif

#include "fork_profile.h"

/* All 99 numeric fields use at most 3,872 bytes at uint64 width;
   the fixed prefix/suffix adds 97 bytes (3,969 total <= 4,096).
   The unchanged bounded writer fits the existing 512 KiB guarded stack. */
struct writer { char bytes[4096]; size_t used; };
static void text(struct writer *w,const char *s) {
    while (*s) { if (w->used==sizeof(w->bytes)) li2_fail("loader report overflow"); w->bytes[w->used++]=*s++; }
}
static void number(struct writer *w,uint64_t n) {
    char b[20]; size_t used=0; do { b[used++]=(char)('0'+n%10); n/=10; } while(n);
    while (used) { if(w->used==sizeof(w->bytes)) li2_fail("loader report overflow"); w->bytes[w->used++]=b[--used]; }
}
static void field(struct writer *w,const char *name,uint64_t n) { text(w,name); number(w,n); }
#ifdef LI2_TF_HANDOFF
static void selected_report(struct writer *,unsigned,unsigned,long);
#else
static void selected_report(struct writer *);
#endif
static void selected_repeat_report(unsigned,unsigned,long);
static void report(unsigned status,unsigned code,long detail) {
    if(reported) return;
    reported=1;
    if(fork_profile.enabled) { fork_report(status,code,detail); return; }
    struct writer w={.used=0}; struct li2_lifecycle_counts lc; li2_lifecycle_snapshot(&lc);
#ifdef LI2_REGISTER_RUN
    text(&w,"LI2_LOADER {\"version\":1,\"scope\":\"partial_selected_register_run\",\"source_patches\":0");
#else
    text(&w,"LI2_LOADER {\"version\":1,\"scope\":\"partial_selected_generic_tf_original_entry\",\"source_patches\":0");
#endif
    field(&w,",\"status\":",status); field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",detail<0?0ULL-(uint64_t)detail:(uint64_t)detail);
    field(&w,",\"detail_negative\":",detail<0); field(&w,",\"dependency_objects\":",dependency_count);
    field(&w,",\"first_target_is_interpreter_entry\":",first_target_pc==original_interpreter.entry && first_target_pc!=0);
    field(&w,",\"interpreter_entry_faults\":",first_interpreter);
    field(&w,",\"nx_faults\":",faults); field(&w,",\"main_faults\":",main_faults);
    field(&w,",\"interpreter_faults\":",interpreter_faults); field(&w,",\"dependency_faults\":",dependency_faults);
    field(&w,",\"vdso_selected\":",vdso_selected);
    field(&w,",\"cpuid\":",cpuid_count); field(&w,",\"rdtsc\":",tsc_count); field(&w,",\"rdtscp\":",tscp_count);
    field(&w,",\"syscalls\":",syscall_count); field(&w,",\"forwarded\":",forwarded);
    field(&w,",\"tls_changes\":",tls_changes); field(&w,",\"set_tid_address\":",tid_sets);
    field(&w,",\"set_robust_list\":",robust_sets); field(&w,",\"rseq\":",rseq_calls);
    field(&w,",\"mappings\":",lc.mappings); field(&w,",\"generations\":",lc.generations);
    field(&w,",\"retired\":",lc.retired); field(&w,",\"admissions\":",lc.admissions);
    field(&w,",\"sync_core\":",lc.sync_core); field(&w,",\"kernel_errors\":",lc.kernel_errors);
    field(&w,",\"partial_errors\":",lc.partial_errors); field(&w,",\"live_pages\":",lc.live_pages);
    field(&w,",\"last_syscall\":",last_syscall<0?0:(uint64_t)last_syscall);
    field(&w,",\"last_mapping_syscall\":",lc.last_syscall); field(&w,",\"last_phase\":",lc.last_phase);
#ifdef LI2_TF_HANDOFF
    selected_report(&w,status,code,detail);
#else
    selected_report(&w);
#endif
    text(&w,"}\n"); (void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
    if(selected_repeat_attempts)selected_repeat_report(status,code,detail);
#ifdef LI2_TF_HANDOFF
    if(selected_chain.initialized)selected_chain_report(status,code,detail);
#endif
#ifdef LI2_REGISTER_RUN
    selected_run_report(status,code,detail);
#ifdef LI2_RUN_TIMING
    selected_run_time_report(status,code,detail);
#endif
#endif
}
static void fail(unsigned code,long detail) {
#ifdef LI2_MAPS_PHASE_REUSE
    li2_maps_phase_fail();
#endif

#ifdef LI2_REGISTER_RUN
    if(selected_pending_route==SELECTED_REGISTER_RUN)selected_run_abort(code,detail);
#endif
    if(selected_pending_route==SELECTED_REPEAT) li2_repeat_abort(&selected_repeat,code,detail);
#ifdef LI2_TF_HANDOFF
    if(selected_pending_route==SELECTED_GENERIC_TF) li2_tf_chain_abort(&selected_chain,code,detail);
#else
    if(selected_pending_route==SELECTED_GENERIC_TF) li2_tf_abort(&selected_tf,code,detail);
#endif
    if(selected_step_pending) li2_step_abort(&selected_step,code,detail);
    li2_lifecycle_abort(); report(125,code,detail);
    (void)raw(SYS_exit_group,125,0,0,0,0,0); __builtin_trap();
}
static void checked(int yes,unsigned code,long detail) { if(!yes) fail(code,detail); }
static void protect(uintptr_t first,size_t bytes) {
    checked(bytes && first<=UINTPTR_MAX-bytes && protected_count<RANGES,201,0);
    protected[protected_count++]=(struct li2_fork_range){first,first+bytes};
}
static int intersects(uintptr_t first,size_t bytes) {
    if (!bytes || first>UINTPTR_MAX-bytes) return 1;
    for(size_t i=0;i<protected_count;i++) if(first<protected[i].end && protected[i].first<first+bytes) return 1;
    return 0;
}
static int image_code(const struct image *image,uintptr_t pc) {
    for(size_t i=0;i<image->n;i++) {
        const Elf64_Phdr *p=&image->ph[i];
        if(p->p_type==PT_LOAD && (p->p_flags&PF_X) && pc>=image->bias+p->p_vaddr && pc-image->bias-p->p_vaddr<p->p_memsz) return 1;
    }
    return 0;
}
static void protect_image(const struct image *image,int whole) {
    for(size_t i=0;i<image->n;i++) {
        const Elf64_Phdr *p=&image->ph[i];
        if(p->p_type!=PT_LOAD || !p->p_memsz || (!whole && !(p->p_flags&PF_X))) continue;
        uintptr_t a=(image->bias+p->p_vaddr)&~(PAGE-1),b=(image->bias+p->p_vaddr+p->p_memsz+PAGE-1)&~(PAGE-1);
        protect(a,b-a);
    }
    if(image->source) protect((uintptr_t)image->source,(image->source_size+PAGE-1)&~(PAGE-1));
}
static void register_vdso(void) {
    const char *const *env=bridge_environment(); size_t n=0;while(env[n])++n;
    const Elf64_auxv_t *aux=(const void *)(env+n+1);uintptr_t address=0;
    for(size_t i=0;i<128 && aux[i].a_type;i++) if(aux[i].a_type==AT_SYSINFO_EHDR) { checked(!address,241,0);address=aux[i].a_un.a_val; }
    checked(address && !(address&(PAGE-1)),242,0);
    const Elf64_Ehdr *h=(const void *)address;
    checked(equal(h->e_ident,"\177ELF\2\1\1",7) && h->e_type==ET_DYN && h->e_machine==EM_X86_64 && h->e_phentsize==sizeof(Elf64_Phdr) && h->e_phnum && h->e_phnum<=16 && h->e_phoff<=PAGE && h->e_phnum*sizeof(Elf64_Phdr)<=PAGE-h->e_phoff,243,0);
    const Elf64_Phdr *ph=(const void *)(address+h->e_phoff);size_t loads=0;
    for(size_t i=0;i<h->e_phnum;i++) if(ph[i].p_type==PT_LOAD) {
        checked(!loads++ && ph[i].p_vaddr==0 && ph[i].p_offset==0 && ph[i].p_flags==(PF_R|PF_X) && ph[i].p_memsz && ph[i].p_memsz<=16*PAGE && ph[i].p_filesz==ph[i].p_memsz,244,0);
        vdso_first=address;vdso_end=address+((ph[i].p_memsz+PAGE-1)&~(PAGE-1));
    }
    checked(loads==1,245,0);li2_lifecycle_verify_kernel_code(vdso_first,vdso_end-vdso_first);protect(vdso_first,vdso_end-vdso_first);
}
#include "fork_profile.inc"

static int ordinary(long n) {
    switch(n) {
    case SYS_read: case SYS_write: case SYS_readv: case SYS_writev:
    case SYS_openat: case SYS_close: case SYS_fstat: case SYS_newfstatat:
    case SYS_statx: case SYS_statfs: case SYS_fstatfs: case SYS_lseek: case SYS_pread64: case SYS_getdents64:
    case SYS_access: case SYS_faccessat: case SYS_faccessat2:
    case SYS_readlink: case SYS_readlinkat: case SYS_getcwd:
    case SYS_getuid: case SYS_geteuid: case SYS_getgid: case SYS_getegid:
    case SYS_getpid: case SYS_gettid: case SYS_uname: case SYS_sysinfo:
    case SYS_getrandom: case SYS_clock_gettime: case SYS_gettimeofday:
    case SYS_getxattr: case SYS_lgetxattr: case SYS_fgetxattr:
    case SYS_listxattr: case SYS_llistxattr: case SYS_flistxattr:
    case SYS_brk: case SYS_futex: case SYS_fcntl: case SYS_prlimit64:
    case SYS_set_tid_address: case SYS_set_robust_list: case SYS_rseq:
        return 1;
    default: return 0;
    }
}
static void dispatch_operation(long n,ucontext_t *context) {
#ifdef LI2_MAPS_PHASE_REUSE
    li2_maps_phase_end(); /* Even a query syscall crosses the application boundary. */
#endif
    greg_t *g=context->uc_mcontext.gregs;
    uintptr_t pc=(uintptr_t)g[REG_RIP];
    checked(!li2_lifecycle_fetch_interlock() && !selected_step_pending,600,n);
    checked(n!=SYS_rseq && n!=SYS_fork && n!=SYS_clone && n!=SYS_vfork,601,n);
    ++syscall_count; last_syscall=n;
    long a[6]={g[REG_RDI],g[REG_RSI],g[REG_RDX],g[REG_R10],g[REG_R8],g[REG_R9]},result;
    if(n==SYS_exit || n==SYS_exit_group) {
        ++forwarded; report((unsigned)a[0],0,0); (void)raw(n,a[0],a[1],a[2],a[3],a[4],a[5]); fail(203,n);
    }
    checked(n!=SYS_close || ((unsigned int)a[0]!=(unsigned int)report_fd && !fork_reserved_fd(a[0])),204,n);
    checked(n!=SYS_fcntl || a[1]==F_GETFD || a[1]==F_GETFL || !fork_sink_alias(a[0]),274,n);

#ifdef LI2_REGISTER_RUN
    selected_run_before_syscall(n,a);
#endif
    li2_lifecycle_before_other(n,a);
    if(!fork_dispatch(n,a,context,&result) && !li2_lifecycle_dispatch(n,a,&result)) {
        if(n==SYS_arch_prctl) checked(a[0]==ARCH_SET_FS || a[0]==ARCH_SET_GS || a[0]==ARCH_GET_FS || a[0]==ARCH_GET_GS || a[0]==0x3001 || a[0]==ARCH_SHSTK_STATUS,205,a[0]);
        /* Queries execute in our handler context. Do not expose its blocked
           mask, SS_ONSTACK state or reserved private signal dispositions. */
        else if(n==SYS_rt_sigaction) checked(!a[1] && (int)a[0]!=SIGSEGV && (int)a[0]!=SIGSYS && (int)a[0]!=SIGTRAP,206,n);
        else if(n==SYS_rt_sigprocmask) fail(206,n);
        else if(n==SYS_sigaltstack) fail(207,n);
        else if(n==SYS_prctl) checked(a[0]==PR_CAPBSET_READ,240,a[0]);
        else if(n==SYS_ioctl) checked(a[1]==0x5401 || a[1]==0x5413 || a[1]==0x541b,208,a[1]);
        else if(n==SYS_madvise) checked(!intersects((uintptr_t)a[0],(size_t)a[1]),209,n);
        else checked(ordinary(n),210,n);
        result=raw(n,a[0],a[1],a[2],a[3],a[4],a[5]);
    }
    ++forwarded;
    if(n==SYS_arch_prctl && !result && (a[0]==ARCH_SET_FS || a[0]==ARCH_SET_GS)) ++tls_changes;
    if(n==SYS_set_tid_address && result>=0) ++tid_sets;
    if(n==SYS_set_robust_list && !result) ++robust_sets;
    if(n==SYS_rseq) ++rseq_calls;
    g[REG_RAX]=result; g[REG_RCX]=pc; g[REG_R11]=g[REG_EFL];
}
static void dispatch(siginfo_t *si,ucontext_t *context) {
    (void)si;(void)context;fail(602,0);
}
#include "selected_controller.inc"
#ifdef LI2_REGISTER_RUN
#include "selected_register_run.inc"
#endif

static void handler(int sig,siginfo_t *si,void *ptr) {
#ifdef LI2_MAPS_PHASE_REUSE
    li2_maps_event_boundary(); /* First action, including nested/foreign events. */
#endif
#ifdef LI2_TF_HANDOFF
    li2_tf_chain_event_boundary(&selected_chain);
#endif
#ifdef LI2_REGISTER_RUN
    if(selected_pending_route==SELECTED_REGISTER_RUN &&
       (handling || !selected_step_pending || !si || !ptr ||
        selected_run_owner.phase!=LI2_RUN_RUNNING))
        selected_run_unexpected(sig,si,ptr);
#endif
    if(selected_pending_route==SELECTED_REPEAT) {
        /* Preserve a real running REP fault before any generic guard. Nested
           or invalid frames remain refused by the installed owner's enter. */
        ucontext_t *uc=ptr;
        if(handling || !selected_step_pending || !si || !uc || sig!=SIGTRAP ||
           si->si_signo!=SIGTRAP || si->si_code!=TRAP_TRACE || si->si_errno ||
           uc->uc_mcontext.gregs[REG_TRAPNO]!=1 || uc->uc_mcontext.gregs[REG_ERR] ||
           (uintptr_t)si->si_addr!=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP])
            li2_repeat_unexpected(&selected_repeat,sig,si,uc);
    }
    if(selected_pending_route==SELECTED_GENERIC_TF) {
        /* Route real unexpected reserved events to the owner before the old
           controller guard can lose their actual running signal frame. The
           owner still refuses nested/inconsistent state with first-error
           cleanup; this does not invent a valid frame for such a state. */
        ucontext_t *uc=ptr;
        if(handling || !selected_step_pending || !si || !uc || sig!=SIGTRAP ||
           si->si_signo!=SIGTRAP || si->si_code!=TRAP_TRACE || si->si_errno ||
           uc->uc_mcontext.gregs[REG_TRAPNO]!=1 || uc->uc_mcontext.gregs[REG_ERR] ||
           (uintptr_t)si->si_addr!=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP])
#ifdef LI2_TF_HANDOFF
            li2_tf_chain_unexpected(&selected_chain,sig,si,uc);
#else
            li2_tf_unexpected(&selected_tf,sig,si,uc);
#endif
    }
    checked(!handling && si && ptr,218,sig); handling=1;
#ifdef LI2_MAPS_PHASE_REUSE
    /* This scopes routing only. The route still authenticates its actual frame,
       session and query ownership before using any observations. */
    if(!selected_selftesting && selected_session.self_test_complete)
        checked(!li2_maps_phase_begin(),770,0);
#endif
#ifdef LI2_REGISTER_RUN
    if(selected_pending_route==SELECTED_REGISTER_RUN) {
        selected_run_exit(sig,si,ptr);
    } else
#endif
    if(selected_pending_route==SELECTED_REPEAT) {
        selected_repeat_trace(sig,si,ptr);
    } else if(selected_pending_route==SELECTED_GENERIC_TF) {
        selected_generic_trace(sig,si,ptr);
    } else if(selected_step_pending) {
        checked(selected_pending_route==SELECTED_OLD_STEP,657,0);
        if(sig!=SIGTRAP) li2_step_abort(&selected_step,603,sig);
        selected_trace(sig,si,ptr);
        selected_pending_route=SELECTED_NO_STEP;
    } else if(sig==SIGSEGV) {
        checked(selected_pending_route==SELECTED_NO_STEP,658,0);
        selected_fetch(sig,si,ptr);
    }
    else if(sig==SIGSYS) dispatch(si,ptr);
    else fail(219,sig);
#ifdef LI2_TF_HANDOFF
    li2_tf_chain_handler_end(&selected_chain);
#endif
#ifdef LI2_MAPS_PHASE_REUSE
    li2_maps_phase_end(); /* Before sigreturn, hence before generated/app execution. */
#endif
    handling=0;
}

static size_t parse_fds(int fds[32]) {
    const char *const *env=bridge_environment(); const char *value=0; const char key[]="LI2_DEPENDENCY_FDS=";
    for(size_t i=0;env[i];i++) {
        size_t j=0;while(j<sizeof(key)-1 && env[i][j]==key[j])j++;
        if(j==sizeof(key)-1) { checked(!value,220,0);value=env[i]+j; }
    }
    checked(value && *value,221,0);size_t count=0;
    for(;;) {
        checked(count<32,222,0);unsigned fd=0,digits=0;
        while(*value && *value!=',') { checked(*value>='0' && *value<='9' && fd<=100000,223,0);fd=fd*10+(unsigned)(*value++-'0');++digits; }
        checked(digits,224,0);fds[count++]=(int)fd;
        if(!*value)break;
        ++value;checked(*value,225,0);
    }
    return count;
}
void runtime_arm(const struct image *main,const struct image *interp,size_t minimum) {
    checked(minimum && minimum<ALT_BYTES-16384,226,0); original_main=*main;original_interpreter=*interp;
    checked(raw(SYS_getpid,0,0,0,0,0,0)==raw(SYS_gettid,0,0,0,0,0,0),227,0);
    long fd=raw(SYS_fcntl,2,F_DUPFD_CLOEXEC,100,0,0,0);checked(fd>=0,228,fd);report_fd=(int)fd;
    fork_configure(); checked(!fork_profile.enabled,604,0);
    protect_image(bridge_runtime_image(),1);protect_image(main,0);protect_image(interp,0);
    unsigned long cet=0;long result=raw(SYS_arch_prctl,0x5005,(long)&cet,0,0,0,0);
    checked((!result && !cet)||result==-22||result==-38,229,result);
    uint64_t mask=0;checked(!raw(SYS_rt_sigprocmask,0,0,(long)&mask,8,0,0) && !(mask&((1ULL<<(SIGSEGV-1))|(1ULL<<(SIGSYS-1)))),230,0);
    struct action old;
    for(int sig=1;sig<=64;sig++) { if(sig==SIGKILL || sig==SIGSTOP)continue;checked(!raw(SYS_rt_sigaction,sig,0,(long)&old,8,0,0) && (uintptr_t)old.handler<=1 && ((sig!=SIGSEGV && sig!=SIGSYS && sig!=SIGTRAP) || !old.handler),231,sig); }
    size_t total=ALT_BYTES+2*PAGE;void *area=memory(total,PROT_NONE);protect((uintptr_t)area,total);
    checked(!raw(SYS_mprotect,(long)area+PAGE,ALT_BYTES,PROT_READ|PROT_WRITE,0,0,0),232,0);
    stack_t stack={.ss_sp=(char *)area+PAGE,.ss_size=ALT_BYTES}; fork_gate_stack=stack;checked(!raw(SYS_sigaltstack,(long)&stack,0,0,0,0,0),233,0);
    int fds[32];dependency_count=parse_fds(fds);
    const struct li2_lifecycle_hooks hooks={raw,fail,intersects};li2_lifecycle_initialize(fds,dependency_count,&hooks);
    li2_lifecycle_register_initial(main);li2_lifecycle_register_initial(interp);register_vdso();
    /* Closed in this partial profile. No vDSO execution/ownership claim. */
    selected_vdso_close_attempted=1;
    selected_vdso_close_result=raw(SYS_mprotect,vdso_first,vdso_end-vdso_first,PROT_READ,0,0,0);
    selected_vdso_close_observed=1;
    checked(!selected_vdso_close_result,605,selected_vdso_close_result);
    selected_vdso_closed=1;
    selected_initialize();
    checked(li2_lifecycle_known_code(main->entry,1) && li2_lifecycle_known_code(interp->entry,1),234,0);
    struct action action={handler,SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL,li2_restorer,SELECTED_MASK};
    fork_gate_action=action;
    checked(!raw(SYS_rt_sigaction,SIGSEGV,(long)&action,0,8,0,0) && !raw(SYS_rt_sigaction,SIGSYS,(long)&action,0,8,0,0) && !raw(SYS_rt_sigaction,SIGTRAP,(long)&action,0,8,0,0),235,0);
    checked(raw(SYS_arch_prctl,ARCH_GET_CPUID,0,0,0,0,0)==1,236,0);int tsc=0;
    checked(!raw(SYS_prctl,PR_GET_TSC,(long)&tsc,0,0,0,0) && tsc==PR_TSC_ENABLE,237,0);
    checked(!raw(SYS_arch_prctl,ARCH_SET_CPUID,0,0,0,0,0) && !raw(SYS_prctl,PR_SET_TSC,PR_TSC_SIGSEGV,0,0,0,0),238,0);
    checked(!raw(SYS_prctl,PR_SET_SYSCALL_USER_DISPATCH,PR_SYS_DISPATCH_ON,(long)li2_gateway_start,li2_gateway_end-li2_gateway_start,0,0),239,0);
    selected_selftest();
}
