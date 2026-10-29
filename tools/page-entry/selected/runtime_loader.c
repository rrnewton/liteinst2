/* Freestanding singleton loader runtime. Kernel traps, not source patches.
   The real ld.so runs against an explicit namespace of inherited sealed DSOs. */
#include "bridge.h"
#include "lifecycle_loader.h"
#ifdef LI2_NATIVE_PAGES
#include "native_pages.h"
#include "native_epoch.h"
#ifdef LI2_NATIVE_PAIR
#include "native_pair.h"
#endif
#include "native_seccomp.h"
#endif
#ifdef LI2_RSEQ_INACTIVE
#include "rseq_guard.h"
#if !defined(LI2_TF_HANDOFF) || !defined(LI2_REGISTER_RUN)
#error "The inactive-rseq runtime prototype requires the complete chain/register route composition"
#endif
#endif
#include "provider.h"
#include "step_owner.h"
#include "tf_owner.h"
#include "repeat_owner.h"
#include "tf_continuation.h"
#include "selected_globals.inc"
#ifdef LI2_ENTRY_TIMING
#include "entry_timing.h"
#endif
#ifdef LI2_EFFECT_PROVIDER
#include "selected_effect.h"
#include "readonly_query.h"
#if LI2_EFFECT_PROVIDER != 1 || LI2_ONESHOT_REUSABLE != 1 || LI2_ONESHOT_PUBLICATION != 1 || \
    LI2_CPUID_NX_ONLY != 1 || LI2_RSEQ_NATIVE != 1 || LI2_RSEQ_NATIVE_BOUNDARY != 1 || \
    LI2_RSEQ_TCGETS_BTRFS != 1 || LI2_RSEQ_TIOCGWINSZ_BTRFS != 1
#error "linked effects require the complete reusable/default-rseq composition"
#endif
#if defined(LI2_SELECTED_PROVIDER) || defined(LI2_SELECTED_PROVIDER_BUILTINS)
#error "linked effects retain their own immutable binding, separate from finite fixed policies"
#endif
static void selected_effect_begin(ucontext_t *,uintptr_t,uint64_t);
static void selected_effect_guarded(void);
static int selected_effect_is_native(void);
static void selected_effect_native_enter(void);
static void selected_effect_native_return(const struct li2_effect_result *);
static void selected_effect_native_outcome(void);
static void selected_effect_scripted_outcome(void);
static void selected_effect_apply_and_commit(ucontext_t *);
static void selected_effect_finish(void);
static int selected_effect_complete(siginfo_t *,ucontext_t *,uint64_t);
static void selected_effect_report(unsigned,unsigned,long);
struct selected_effect_raw_prefix {
    volatile sig_atomic_t entered,returned;
    long number,result;
};
static struct selected_effect_raw_prefix selected_effect_raw;
#endif
#ifdef LI2_ONESHOT_CPUID_NX
#if LI2_ONESHOT_CPUID_NX != 1 || LI2_CPUID_NX_ONLY != 1 || \
    LI2_ONESHOT_PUBLICATION != 1 || LI2_ONESHOT_INITIAL_INTERPRETER != 1
#error "one-shot CPUID-NX requires its fixed initial-image composition"
#endif
#if defined(LI2_SELECTED_PROVIDER) || defined(LI2_SELECTED_PROVIDER_BUILTINS)
#error "one-shot CPUID-NX uses the native selected effects"
#endif
#endif
#ifdef LI2_CPUID_NX_ONLY
#if LI2_CPUID_NX_ONLY != 1 || !defined(LI2_NATIVE_PAGES) || !defined(LI2_TF_HANDOFF) || \
    !defined(LI2_REGISTER_RUN) || !defined(LI2_MAPS_PHASE_REUSE) || !defined(LI2_RSEQ_INACTIVE)
#error "CPUID NX-only requires the complete native-page/TF/register/maps/rseq composition"
#endif
#if defined(LI2_ONESHOT_PUBLICATION) && !defined(LI2_ONESHOT_CPUID_NX) && !defined(LI2_EFFECT_PROVIDER)
#error "CPUID NX-only is a distinct native-page profile, not a one-shot profile"
#endif
static void selected_cpuid_nx_report(unsigned,unsigned);
#endif
#ifdef LI2_TF_SAME_PAGE_LEASE
#if LI2_TF_SAME_PAGE_LEASE != 1 || LI2_RSEQ_TIOCGWINSZ_BTRFS != 1 || LI2_RSEQ_NATIVE_BOUNDARY != 1
#error "same-page lease is a fixed boundary/winsz profile"
#endif
#if (defined(LI2_ONESHOT_PUBLICATION) && !defined(LI2_EFFECT_PROVIDER)) || defined(LI2_SELECTED_PROVIDER)
#error "same-page lease does not compose with one-shot/configured callbacks"
#endif
#endif
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
#ifdef LI2_NATIVE_PAGES
static uint64_t native_main_admissions,native_main_refaults;
#endif
static long last_syscall=-1;
#ifdef LI2_SELECTED_PROVIDER_BUILTINS
#ifndef LI2_SELECTED_PROVIDER
#error "Configured builtins require the configured provider profile"
#endif
static unsigned selected_provider_builtins_enabled;
static void selected_provider_syscall_decide(long,const long[6],ucontext_t *);
static void selected_provider_syscall_exit(void);
static void selected_provider_syscall_guarded(void);
static int selected_provider_syscall_replace(long *);
static void selected_provider_syscall_raw_enter(void);
static void selected_provider_syscall_raw_return(long);
static int selected_provider_syscall_replaced(void);
static void selected_provider_syscall_commit(ucontext_t *,long);
static void selected_provider_builtins_report(unsigned,unsigned);
#endif
static uintptr_t vdso_first,vdso_end;
static unsigned long vdso_selected;
static void fail(unsigned,long) __attribute__((noreturn));
#ifdef LI2_SELECTED_PROVIDER
static void selected_provider_report(unsigned,unsigned);
#endif
#ifdef LI2_ONESHOT_PUBLICATION
static void selected_oneshot_report(unsigned,unsigned,long);
static _Noreturn void selected_oneshot_abort(unsigned,long);
static void selected_oneshot_stage(void);
#endif
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
#if defined(LI2_EFFECT_PROVIDER) && defined(LI2_TF_HANDOFF) && defined(LI2_REGISTER_RUN)
static void selected_run_trace_try(int,siginfo_t *,ucontext_t *,uint64_t);
static void selected_run_trace_report(unsigned,unsigned,long);
#endif
static void selected_run_exit(int,siginfo_t *,ucontext_t *);
static void selected_run_before_syscall(long,const long[6]);
static _Noreturn void selected_run_abort(unsigned,long);
static _Noreturn void selected_run_unexpected(int,siginfo_t *,ucontext_t *);
#endif

#include "fork_profile.h"
#ifdef LI2_NATIVE_PAIR
static void selected_native_pair_report(unsigned,unsigned,long);
#endif

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
#ifdef LI2_RSEQ_INACTIVE
#include "rseq_report.inc"
#endif
#ifdef LI2_RSEQ_NATIVE
#include "rseq_native_report.inc"
#ifdef LI2_RSEQ_NATIVE_BOUNDARY
#include "rseq_native_boundary_report.inc"
#ifdef LI2_RSEQ_TCGETS_BTRFS
#include "rseq_tcgets_btrfs_report.inc"
#endif
#endif
#endif
#ifdef LI2_TF_HANDOFF
static void selected_report(struct writer *,unsigned,unsigned,long);
#else
static void selected_report(struct writer *);
#endif
#ifdef LI2_REPEAT_RX_LEASE
static void selected_repeat_lease_report(unsigned,unsigned,long);
static void selected_repeat_lease_initialize(void);
static void selected_repeat_lease_boundary(void);
static void selected_repeat_lease_end(const ucontext_t *);
static const struct li2_run_protection selected_run_protection;
#endif
static void selected_repeat_report(unsigned,unsigned,long);
#ifdef LI2_NATIVE_PAIR
#include "native_pair_report.inc"
#endif
static void report(unsigned status,unsigned code,long detail) {
    if(reported) return;
    reported=1;
    if(fork_profile.enabled) { fork_report(status,code,detail); return; }
    struct writer w={.used=0}; struct li2_lifecycle_counts lc; li2_lifecycle_snapshot(&lc);
#if defined(LI2_ONESHOT_PUBLICATION)
#ifdef LI2_ONESHOT_REUSABLE
    text(&w,"LI2_LOADER {\"version\":1,\"scope\":\"partial_selected_reusable_effects\"");
#elif defined(LI2_ONESHOT_CPUID_NX)
    text(&w,"LI2_LOADER {\"version\":1,\"scope\":\"partial_selected_oneshot_cpuid_nx\"");
#else
    text(&w,"LI2_LOADER {\"version\":1,\"scope\":\"partial_selected_oneshot\"");
#endif
#ifdef LI2_ONESHOT_REUSABLE
    uint64_t patches=selected_oneshot_counts.published;
#else
    uint64_t patches=0;
    for(unsigned i=0;i<selected_oneshot_used;i++)patches+=selected_oneshot_owners[i].state.published==1;
#endif
    field(&w,",\"source_patches\":",patches);
#elif defined(LI2_TF_SEALED_CUSTODY)
    text(&w,"LI2_LOADER {\"version\":1,\"scope\":\"partial_selected_sealed_page_custody\",\"source_patches\":0");
#elif defined(LI2_TF_SAME_PAGE_LEASE)
    text(&w,"LI2_LOADER {\"version\":1,\"scope\":\"partial_selected_same_page_tf_lease\",\"source_patches\":0");
#elif defined(LI2_CPUID_NX_ONLY)
    text(&w,"LI2_LOADER {\"version\":1,\"scope\":\"partial_selected_native_pages_cpuid_nx\",\"source_patches\":0");
#elif defined(LI2_NATIVE_PAGES)
    text(&w,"LI2_LOADER {\"version\":1,\"scope\":\"partial_selected_native_pages\",\"source_patches\":0");
#elif defined(LI2_REGISTER_RUN)
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
#ifdef LI2_NATIVE_PAGES
#ifdef LI2_NATIVE_PAIR
    selected_native_pair_report(status,code,detail);
#endif
    const struct li2_native_counts *nc=li2_lifecycle_native_counts();
    const struct li2_native_epoch *ne=li2_native_epoch_progress();
    const struct li2_native_close *cl=li2_lifecycle_native_close_progress();
    w.used=0;text(&w,"LI2_NATIVE {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"attempts\":",nc->attempts);field(&w,",\"admissions\":",nc->admissions);
    field(&w,",\"closed\":",nc->closed);field(&w,",\"blocked\":",nc->blocked);
    field(&w,",\"low_address_refusals\":",nc->low_address_refusals);
    field(&w,",\"epoch_exits\":",ne->ready);field(&w,",\"refaults\":",ne->retries);
    field(&w,",\"main_admissions\":",native_main_admissions);field(&w,",\"main_refaults\":",native_main_refaults);
    field(&w,",\"epoch_error\":",ne->first_error);field(&w,",\"close_error\":",cl->first_error);
    field(&w,",\"close_complete\":",cl->complete);field(&w,",\"close_busy\":",cl->busy);
    field(&w,",\"first_admission_ns\":",nc->first_admission_ns);
    field(&w,",\"first_source_offset\":",nc->first_source_offset);
    field(&w,",\"revisit_count\":",nc->revisit_count);
    text(&w,",\"revisit_ns\":[");
    for(size_t i=0;i<nc->revisit_count;i++){if(i)text(&w,",");number(&w,nc->revisit_ns[i]);}
    text(&w,"]");
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
#endif
#ifdef LI2_SELECTED_PROVIDER
    selected_provider_report(status,code);
#endif
#ifdef LI2_EFFECT_PROVIDER
    selected_effect_report(status,code,detail);
#endif
#ifdef LI2_SELECTED_PROVIDER_BUILTINS
    selected_provider_builtins_report(status,code);
#endif
#ifdef LI2_CPUID_NX_ONLY
    selected_cpuid_nx_report(status,code);
#endif
    if(selected_repeat_attempts)selected_repeat_report(status,code,detail);
#ifdef LI2_REPEAT_RX_LEASE
    selected_repeat_lease_report(status,code,detail);
#endif
#ifdef LI2_ONESHOT_PUBLICATION
    selected_oneshot_report(status,code,detail);
#endif
#ifdef LI2_RSEQ_INACTIVE
    selected_rseq_report(status,code,detail);
#endif
#ifdef LI2_RSEQ_NATIVE
    selected_rseq_native_report(status,code,detail);
#ifdef LI2_RSEQ_NATIVE_BOUNDARY
    selected_rseq_boundary_report(status,code,detail);
#ifdef LI2_RSEQ_TCGETS_BTRFS
    selected_tcgets_report(status,code,detail);
#endif
#endif
#endif
#ifdef LI2_TF_HANDOFF
    if(selected_chain.initialized)selected_chain_report(status,code,detail);
#endif
#ifdef LI2_REGISTER_RUN
    selected_run_report(status,code,detail);
#if defined(LI2_EFFECT_PROVIDER) && defined(LI2_TF_HANDOFF) && defined(LI2_REGISTER_RUN)
    selected_run_trace_report(status,code,detail);
#endif
#ifdef LI2_RUN_TIMING
    selected_run_time_report(status,code,detail);
#ifdef LI2_ENTRY_TIMING
    li2_entry_time_report(status,code,detail);
#endif
#endif
#endif
}
static void fail(unsigned code,long detail) {
#ifdef LI2_ONESHOT_PUBLICATION
    if(selected_pending_route==SELECTED_ONESHOT || selected_oneshot_active)
        selected_oneshot_abort(code,detail);
#endif
#ifdef LI2_MAPS_PHASE_REUSE
    li2_maps_phase_fail();
#endif

#ifdef LI2_REGISTER_RUN
    if(selected_pending_route==SELECTED_REGISTER_RUN)selected_run_abort(code,detail);
#endif
#ifdef LI2_REPEAT_RX_LEASE
    if(selected_pending_route==SELECTED_REPEAT_LEASE)
        li2_repeat_lease_abort(&selected_repeat_lease,code,detail);
#endif
    if(selected_pending_route==SELECTED_REPEAT) li2_repeat_abort(&selected_repeat,code,detail);
#ifdef LI2_TF_HANDOFF
    if(selected_pending_route==SELECTED_GENERIC_TF) li2_tf_chain_abort(&selected_chain,code,detail);
#else
    if(selected_pending_route==SELECTED_GENERIC_TF) li2_tf_abort(&selected_tf,code,detail);
#endif
    if(selected_step_pending) li2_step_abort(&selected_step,code,detail);
#ifdef LI2_NATIVE_PAGES
#ifdef LI2_NATIVE_PAIR
    li2_native_pair_abort(code,detail);
#else
    li2_native_epoch_abort(code,detail);
#endif
#endif
    li2_lifecycle_abort(); report(125,code,detail);
    (void)raw(SYS_exit_group,125,0,0,0,0,0); __builtin_trap();
}
static void checked(int yes,unsigned code,long detail) { if(!yes) fail(code,detail); }
static void protect(uintptr_t first,size_t bytes) {
    checked(bytes && first<=UINTPTR_MAX-bytes && protected_count<RANGES,201,0);
    protected[protected_count++]=(struct li2_fork_range){first,first+bytes};
}
static int private_intersects(uintptr_t first,size_t bytes) {
    if (!bytes || first>UINTPTR_MAX-bytes) return 1;
    for(size_t i=0;i<protected_count;i++) if(first<protected[i].end && protected[i].first<first+bytes) return 1;
    return 0;
}
static int intersects(uintptr_t first,size_t bytes) {
    if(private_intersects(first,bytes))return 1;
#ifdef LI2_RSEQ_INACTIVE
    if(li2_rseq_mapping_overlap(first,bytes))return 1;
#endif
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
    case SYS_getrandom: case SYS_clock_gettime: case SYS_clock_getres: case SYS_gettimeofday:
    case SYS_getxattr: case SYS_lgetxattr: case SYS_fgetxattr:
    case SYS_listxattr: case SYS_llistxattr: case SYS_flistxattr:
    case SYS_brk: case SYS_futex: case SYS_fcntl: case SYS_prlimit64:
    case SYS_set_tid_address: case SYS_set_robust_list: case SYS_rseq:
        return 1;
    default: return 0;
    }
}
static void dispatch_operation(long n,ucontext_t *context) {
#ifdef LI2_TF_SEALED_CUSTODY
    li2_page_custody_discard(LI2_CUSTODY_SYSCALL);
#endif
#ifdef LI2_MAPS_PHASE_REUSE
    li2_maps_phase_end(); /* Even a query syscall crosses the application boundary. */
#endif
    greg_t *g=context->uc_mcontext.gregs;
    uintptr_t pc=(uintptr_t)g[REG_RIP];
    checked(!li2_lifecycle_fetch_interlock() && !selected_step_pending,600,n);
#ifdef LI2_RSEQ_INACTIVE
    checked(n!=SYS_fork && n!=SYS_clone && n!=SYS_vfork,601,n);
#else
    checked(n!=SYS_rseq && n!=SYS_fork && n!=SYS_clone && n!=SYS_vfork,601,n);
#endif
#ifdef LI2_NATIVE_PAGES
#ifdef LI2_NATIVE_PAIR
    checked(!li2_native_pair_effect_guard(),LI2_NP_STATE,n);
#endif
    /* No native source remains executable across a mapping or rseq change. */
    li2_lifecycle_native_close();
#endif
    ++syscall_count; last_syscall=n;
    long a[6]={g[REG_RDI],g[REG_RSI],g[REG_RDX],g[REG_R10],g[REG_R8],g[REG_R9]},result;
#ifdef LI2_RSEQ_INACTIVE
    int rseq_error=li2_rseq_before_syscall(n,a);
    checked(!rseq_error,(unsigned)rseq_error,li2_rseq_snapshot()->first_detail);
#endif
#ifdef LI2_SELECTED_PROVIDER_BUILTINS
    if(selected_provider_builtins_enabled)selected_provider_syscall_decide(n,a,context);
#endif
    if(n==SYS_exit || n==SYS_exit_group) {
#ifdef LI2_EFFECT_PROVIDER
        selected_effect_guarded();
        checked(selected_effect_is_native(),1700,n);
        selected_effect_raw=(struct selected_effect_raw_prefix){.number=n};
        selected_effect_native_enter();
#endif
#ifdef LI2_SELECTED_PROVIDER_BUILTINS
        if(selected_provider_builtins_enabled)selected_provider_syscall_exit();
#endif
        ++forwarded; report((unsigned)a[0],0,0);
#ifdef LI2_EFFECT_PROVIDER
        __asm__ volatile("":::"memory");selected_effect_raw.entered=1;
        __asm__ volatile("":::"memory");
        result=raw(n,a[0],a[1],a[2],a[3],a[4],a[5]);
        selected_effect_raw.result=result;__asm__ volatile("":::"memory");
        selected_effect_raw.returned=1;__asm__ volatile("":::"memory");
        const struct li2_effect_result returned_exit={.kind=LI2_SYSCALL,.value=(uint64_t)result};
        selected_effect_native_return(&returned_exit);
#else
        (void)raw(n,a[0],a[1],a[2],a[3],a[4],a[5]);
#endif
        fail(203,n);
    }
    checked(n!=SYS_close || ((unsigned int)a[0]!=(unsigned int)report_fd && !fork_reserved_fd(a[0])),204,n);
    checked(n!=SYS_fcntl || a[1]==F_GETFD || a[1]==F_GETFL || !fork_sink_alias(a[0]),274,n);

#ifdef LI2_REGISTER_RUN
    selected_run_before_syscall(n,a);
#endif
    li2_lifecycle_before_other(n,a);
#ifdef LI2_EFFECT_PROVIDER
    selected_effect_guarded();
    selected_effect_raw=(struct selected_effect_raw_prefix){.number=n};
    unsigned effect_native=selected_effect_is_native();
    if(!effect_native) {
        /* The leaf independently requires the same scalar-only seam. Every
           shared syscall/rseq guard above still ran; no kernel effect is made. */
        checked(n==SYS_getpid || n==SYS_gettid,1701,n);
        selected_effect_scripted_outcome();
        result=0; /* Frame application below uses the retained typed result. */
    } else {
        selected_effect_native_enter();
#endif
#ifdef LI2_SELECTED_PROVIDER_BUILTINS
    if(selected_provider_builtins_enabled)selected_provider_syscall_guarded();
#endif
#ifdef LI2_RSEQ_INACTIVE
    if(n==SYS_rseq) {
        rseq_error=li2_rseq_dispatch(a,&result);
        checked(!rseq_error,(unsigned)rseq_error,li2_rseq_snapshot()->first_detail);
    } else
#endif
    if(!fork_dispatch(n,a,context,&result) && !li2_lifecycle_dispatch(n,a,&result)) {
#ifdef LI2_EFFECT_PROVIDER
        if(li2_readonly_query(n,a,0)) { /* Exact query form; all shared guards ran. */ }
        else
#endif
        if(n==SYS_arch_prctl) checked(a[0]==ARCH_SET_FS || a[0]==ARCH_SET_GS || a[0]==ARCH_GET_FS || a[0]==ARCH_GET_GS || a[0]==0x3001 || a[0]==ARCH_SHSTK_STATUS,205,a[0]);
        /* Queries execute in our handler context. Do not expose its blocked
           mask, SS_ONSTACK state or reserved private signal dispositions. */
        else if(n==SYS_rt_sigaction) checked(!a[1] && (int)a[0]!=SIGSEGV && (int)a[0]!=SIGSYS && (int)a[0]!=SIGTRAP
#ifdef LI2_ONESHOT_PUBLICATION
            && (int)a[0]!=SIGILL
#endif
            ,206,n);
        else if(n==SYS_rt_sigprocmask) fail(206,n);
        else if(n==SYS_sigaltstack) fail(207,n);
        else if(n==SYS_prctl) checked(a[0]==PR_CAPBSET_READ,240,a[0]);
        else if(n==SYS_ioctl) checked(a[1]==0x5401 || a[1]==0x5413 || a[1]==0x541b,208,a[1]);
        else if(n==SYS_madvise) checked(!intersects((uintptr_t)a[0],(size_t)a[1]),209,n);
        else checked(ordinary(n),210,n);
#ifdef LI2_SELECTED_PROVIDER_BUILTINS
        if(!selected_provider_builtins_enabled || !selected_provider_syscall_replace(&result)) {
#endif
#ifdef LI2_RSEQ_TCGETS_BTRFS
        rseq_error=li2_rseq_tcgets_issuing(n,a);
        checked(!rseq_error,(unsigned)rseq_error,li2_rseq_snapshot()->first_detail);
#endif
#ifdef LI2_SELECTED_PROVIDER_BUILTINS
        if(selected_provider_builtins_enabled)selected_provider_syscall_raw_enter();
#endif
#ifdef LI2_EFFECT_PROVIDER
        __asm__ volatile("":::"memory");selected_effect_raw.entered=1;
        __asm__ volatile("":::"memory");
#endif
        result=raw(n,a[0],a[1],a[2],a[3],a[4],a[5]);
#ifdef LI2_SELECTED_PROVIDER_BUILTINS
        if(selected_provider_builtins_enabled)selected_provider_syscall_raw_return(result);
#endif
#ifdef LI2_EFFECT_PROVIDER
        selected_effect_raw.result=result;__asm__ volatile("":::"memory");
        selected_effect_raw.returned=1;__asm__ volatile("":::"memory");
        /* Record the actual result before the ioctl postguard can fail. */
        const struct li2_effect_result raw_result={.kind=LI2_SYSCALL,.value=(uint64_t)result};
        selected_effect_native_return(&raw_result);
#endif
#ifdef LI2_RSEQ_TCGETS_BTRFS
        rseq_error=li2_rseq_tcgets_result(n,a,result);
        checked(!rseq_error,(unsigned)rseq_error,li2_rseq_snapshot()->first_detail);
#endif
#ifdef LI2_SELECTED_PROVIDER_BUILTINS
        }
#endif
    }
#ifdef LI2_EFFECT_PROVIDER
        if(!selected_effect_raw.returned) {
            /* Mapping/rseq owner dispatch may perform its own raw operation.
               This prefix describes that backend, never a common raw issue. */
            const struct li2_effect_result owned_result={.kind=LI2_SYSCALL,.value=(uint64_t)result};
            selected_effect_native_return(&owned_result);
        }
    }
#endif
#ifdef LI2_RSEQ_INACTIVE
    rseq_error=li2_rseq_after_syscall(n,a);
    checked(!rseq_error,(unsigned)rseq_error,li2_rseq_snapshot()->first_detail);
#endif
#ifdef LI2_SELECTED_PROVIDER_BUILTINS
    if(!selected_provider_builtins_enabled || !selected_provider_syscall_replaced())++forwarded;
#elif defined(LI2_EFFECT_PROVIDER)
    if(effect_native)++forwarded;
#else
    ++forwarded;
#endif
    if(n==SYS_arch_prctl && !result && (a[0]==ARCH_SET_FS || a[0]==ARCH_SET_GS)) ++tls_changes;
    if(n==SYS_set_tid_address && result>=0) ++tid_sets;
    if(n==SYS_set_robust_list && !result) ++robust_sets;
    if(n==SYS_rseq) ++rseq_calls;
#ifdef LI2_EFFECT_PROVIDER
    (void)pc;
    if(effect_native)selected_effect_native_outcome();
    selected_effect_apply_and_commit(context);
#else
    g[REG_RAX]=result; g[REG_RCX]=pc; g[REG_R11]=g[REG_EFL];
#endif
#ifdef LI2_SELECTED_PROVIDER_BUILTINS
    if(selected_provider_builtins_enabled)selected_provider_syscall_commit(context,result);
#endif
}
static void dispatch(siginfo_t *si,ucontext_t *context) {
    (void)si;(void)context;fail(602,0);
}
#ifdef LI2_SELECTED_PROVIDER
#include "selected_provider.inc"
#endif
#include "selected_controller.inc"
#ifdef LI2_REGISTER_RUN
#include "selected_register_run.inc"
#endif

#ifdef LI2_NATIVE_PAGES
#include "native_controller.inc"
#endif
#ifdef LI2_ENTRY_TIMING
#include "entry_timing.inc"
#endif
static void handler(int sig,siginfo_t *si,void *ptr) {
#ifdef LI2_NATIVE_PAIR
    li2_native_pair_preentry();
#endif
#ifdef LI2_ONESHOT_REUSABLE
    li2_rseq_publication_preentry();
#endif
#ifdef LI2_RSEQ_NATIVE
    /* Must precede every old checked/fail and returning cleanup path. */
    li2_rseq_native_preentry();
#endif
#ifdef LI2_ONESHOT_PUBLICATION
    /* No generic ingress may resume a reserved-signal interruption of a writer
       or selected effect. Owner capture authenticates the real landing frame. */
    if((selected_pending_route==SELECTED_ONESHOT || selected_oneshot_active) &&
       (handling || !selected_step_pending || selected_pending_route!=SELECTED_ONESHOT ||
        !selected_oneshot_active || selected_oneshot_active->state.phase!=LI2_ONESHOT_PUBLISHED ||
        sig!=SIGILL || !si || !ptr))selected_oneshot_abort(1561,sig);
#endif
#ifdef LI2_REPEAT_RX_LEASE
    selected_repeat_lease_boundary();
#endif
#ifdef LI2_MAPS_PHASE_REUSE
    li2_maps_event_boundary(); /* First action, including nested/foreign events. */
#endif
#ifdef LI2_TF_HANDOFF
    li2_tf_chain_event_boundary(&selected_chain);
#endif
#if defined(LI2_EFFECT_PROVIDER) && defined(LI2_TF_HANDOFF) && defined(LI2_REGISTER_RUN)
    /* A nested event during fresh preparation has no armed run owner yet.
       Retain its actual event through the same terminal cache/run cleanup. */
    if(selected_run_trace_busy)selected_run_unexpected(sig,si,ptr);
#endif
#ifdef LI2_REGISTER_RUN
    if(selected_pending_route==SELECTED_REGISTER_RUN &&
       (handling || !selected_step_pending || !si || !ptr ||
        selected_run_owner.phase!=LI2_RUN_RUNNING))
        selected_run_unexpected(sig,si,ptr);
#endif
#ifdef LI2_REPEAT_RX_LEASE
    if(selected_pending_route==SELECTED_REPEAT_LEASE) {
        ucontext_t *uc=ptr;
        if(handling || !selected_step_pending || !si || !uc || sig!=SIGTRAP ||
           si->si_signo!=SIGTRAP || si->si_code!=TRAP_TRACE || si->si_errno ||
           uc->uc_mcontext.gregs[REG_TRAPNO]!=1 || uc->uc_mcontext.gregs[REG_ERR] ||
           (uintptr_t)si->si_addr!=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP])
            li2_repeat_lease_unexpected(&selected_repeat_lease,sig,si,uc);
    }
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
    if(!selected_selftesting && selected_session.self_test_complete
#ifdef LI2_ONESHOT_PUBLICATION
       && selected_pending_route!=SELECTED_ONESHOT
#endif
       )checked(!li2_maps_phase_begin(),770,0);
#endif
#ifdef LI2_ENTRY_TIMING
    li2_entry_time_ingress(sig,si,ptr);
#endif
#ifdef LI2_ONESHOT_PUBLICATION
    if(selected_pending_route==SELECTED_ONESHOT) {
        selected_oneshot_landed(sig,si,ptr);
    } else
#endif
#ifdef LI2_REGISTER_RUN
    if(selected_pending_route==SELECTED_REGISTER_RUN) {
        selected_run_exit(sig,si,ptr);
    } else
#endif
#ifdef LI2_REPEAT_RX_LEASE
    if(selected_pending_route==SELECTED_REPEAT_LEASE) {
        selected_repeat_lease_trace(sig,si,ptr);
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
#ifdef LI2_NATIVE_PAGES
        if(!selected_native_fetch(sig,si,ptr))
#endif
        selected_fetch(sig,si,ptr);
    }
    else if(sig==SIGSYS) dispatch(si,ptr);
    else fail(219,sig);
#ifdef LI2_ENTRY_TIMING
    li2_entry_time_arm();
#endif
#ifdef LI2_TF_HANDOFF
    li2_tf_chain_handler_end(&selected_chain);
#endif
#ifdef LI2_REPEAT_RX_LEASE
    selected_repeat_lease_end(ptr);
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
#ifdef LI2_ONESHOT_PUBLICATION
    checked(!(mask&((UINT64_C(1)<<(SIGILL-1))|(UINT64_C(1)<<(SIGTRAP-1)))),230,1);
#endif
    struct action old;
    for(int sig=1;sig<=64;sig++) { if(sig==SIGKILL || sig==SIGSTOP)continue;checked(!raw(SYS_rt_sigaction,sig,0,(long)&old,8,0,0) && (uintptr_t)old.handler<=1 && ((sig!=SIGSEGV && sig!=SIGSYS && sig!=SIGTRAP
#ifdef LI2_ONESHOT_PUBLICATION
        && sig!=SIGILL
#endif
        ) || !old.handler),231,sig); }
    size_t total=ALT_BYTES+2*PAGE;void *area=memory(total,PROT_NONE);protect((uintptr_t)area,total);
    checked(!raw(SYS_mprotect,(long)area+PAGE,ALT_BYTES,PROT_READ|PROT_WRITE,0,0,0),232,0);
    stack_t stack={.ss_sp=(char *)area+PAGE,.ss_size=ALT_BYTES}; fork_gate_stack=stack;checked(!raw(SYS_sigaltstack,(long)&stack,0,0,0,0,0),233,0);
    int fds[32];dependency_count=parse_fds(fds);
    const struct li2_lifecycle_hooks hooks={raw,fail,intersects};li2_lifecycle_initialize(fds,dependency_count,&hooks);
#ifdef LI2_RSEQ_INACTIVE
    int rseq_error=li2_rseq_initialize(private_intersects);
    checked(!rseq_error,(unsigned)rseq_error,li2_rseq_snapshot()->first_detail);
#ifdef LI2_RSEQ_TCGETS_BTRFS
    rseq_error=li2_rseq_tcgets_initialize();
    checked(!rseq_error,(unsigned)rseq_error,li2_rseq_snapshot()->first_detail);
#endif
#endif
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
#ifdef LI2_ONESHOT_PUBLICATION
    checked(!raw(SYS_rt_sigaction,SIGILL,(long)&action,0,8,0,0),235,1);
#endif
#ifdef LI2_CPUID_NX_ONLY
    /* The real entry.S CPUID and pre-arm hardware probe already returned.
       Never query, enable or disable CPUID in this explicit profile. */
    checked(selected_cpuid_nx.hardware_entered==1 && selected_cpuid_nx.hardware_returned==1 &&
            selected_hardware.abi_version==1 && !selected_hardware.reserved,1610,0);
    int tsc=0;
    checked(!raw(SYS_prctl,PR_GET_TSC,(long)&tsc,0,0,0,0) && tsc==PR_TSC_ENABLE,237,0);
    checked(!raw(SYS_prctl,PR_SET_TSC,PR_TSC_SIGSEGV,0,0,0,0),238,0);
#else
    checked(raw(SYS_arch_prctl,ARCH_GET_CPUID,0,0,0,0,0)==1,236,0);int tsc=0;
    checked(!raw(SYS_prctl,PR_GET_TSC,(long)&tsc,0,0,0,0) && tsc==PR_TSC_ENABLE,237,0);
    checked(!raw(SYS_arch_prctl,ARCH_SET_CPUID,0,0,0,0,0) && !raw(SYS_prctl,PR_SET_TSC,PR_TSC_SIGSEGV,0,0,0,0),238,0);
#endif
    checked(!raw(SYS_prctl,PR_SET_SYSCALL_USER_DISPATCH,PR_SYS_DISPATCH_ON,(long)li2_gateway_start,li2_gateway_end-li2_gateway_start,0,0),239,0);
#ifdef LI2_NATIVE_PAGES
    result=li2_native_seccomp_install(raw,(uintptr_t)li2_gateway_start,(uintptr_t)li2_gateway_end);
    checked(!result,1431,result);
#endif
    selected_selftest();
#ifdef LI2_REPEAT_RX_LEASE
    selected_repeat_lease_initialize();
#endif
#ifdef LI2_ONESHOT_PUBLICATION
    selected_oneshot_stage();
#endif
#ifdef LI2_NATIVE_PAGES
    int native_error=li2_native_epoch_initialize(&selected_session);
    checked(!native_error,(unsigned)native_error,0);
#ifdef LI2_NATIVE_PAIR
    native_error=li2_native_pair_initialize(&selected_session);
    checked(!native_error,(unsigned)native_error,1);
#endif
#endif
}
