#define _GNU_SOURCE
#include "rseq_guard.h"
#include "register_run.h"
#include "repeat_owner.h"
#include <asm/prctl.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/prctl.h>
#include <linux/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <time.h>

extern long raw(long,long,long,long,long,long,long);
#define RSEQ_PAGE UINT64_C(4096)
#define CALL(n,a,b,c,d,e,f) raw((n),(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
static struct li2_rseq_state state;
static int (*private_range)(uintptr_t,size_t);
_Static_assert(sizeof(struct stat)==144,"x86-64 stat output");
_Static_assert(sizeof(struct statx)==256,"statx output");
_Static_assert(sizeof(struct statfs)==120,"x86-64 statfs output");
_Static_assert(sizeof(struct utsname)==390,"newuname output");
_Static_assert(sizeof(struct sysinfo)==112,"x86-64 sysinfo output");
_Static_assert(sizeof(struct timespec)==16 && sizeof(struct timeval)==16,"x86-64 time output");
_Static_assert(sizeof(struct rlimit)==16,"x86-64 prlimit64 output");
static int bad(unsigned code,long detail) {
    if(!state.first_error){state.first_error=code;state.first_detail=detail;}
    return (int)state.first_error;
}
static int count(uint64_t *n) {
    if(*n==UINT64_MAX)return bad(LI2_RSEQ_OVERFLOW,0);
    ++*n;return 0;
}
static int ready(void) {
    if(!state.initialized || state.first_error)return bad(LI2_RSEQ_STATE,0);
    return 0;
}
static int tls_observe(void) {
    state.tls_attempted=1;state.tls_complete=0;
    state.fs_result=CALL(SYS_arch_prctl,ARCH_GET_FS,&state.fs_base,0,0,0,0);
    state.gs_result=CALL(SYS_arch_prctl,ARCH_GET_GS,&state.gs_base,0,0,0,0);
    if(state.fs_result || state.gs_result)return bad(LI2_RSEQ_TLS,state.fs_result?state.fs_result:state.gs_result);
    state.tls_complete=1;return 0;
}
static int word_zero(void) {
    if(!state.registered)return 0;
    if(!state.held || state.phase!=LI2_RSEQ_ACTIVE || !state.tls_complete)
        return bad(LI2_RSEQ_STATE,1);
    /* Diagnostic only: pre-effect exclusion, not this late observation, is
       what prevents the kernel from consuming a published descriptor. */
    if(*(const volatile uint64_t *)(state.address+8))return bad(LI2_RSEQ_WORD,0);
    return 0;
}
static int span(uintptr_t first,size_t bytes) {
    if(!bytes)return 0;
    if(first>UINTPTR_MAX-bytes)return bad(LI2_RSEQ_OVERFLOW,1);
    state.last_first=first;state.last_end=first+bytes;
    if(count(&state.range_checks))return (int)state.first_error;
    if(first<state.address+16 && state.address+8<first+bytes)
        return bad(LI2_RSEQ_OVERLAP,0);
    return 0;
}
static int optional_span(long address,size_t bytes) {
    return address?span((uintptr_t)address,bytes):0;
}
static void registers(const ucontext_t *uc,struct li2_write_registers *out) {
    static const unsigned ix[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,
        REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
    for(size_t i=0;i<16;i++)out->gpr[i]=(uint64_t)uc->uc_mcontext.gregs[ix[i]];
    out->fs_base=state.fs_base;out->gs_base=state.gs_base;
}
static int decoded_footprint(const struct li2_decoded *d,const ucontext_t *uc,int only_none) {
    if(!d || !uc || d->abi_version!=1 || d->reserved || d->decode_status!=LI2_VALID ||
       !d->length || d->length>15 || d->available<d->length || d->available>15 ||
       d->pc>UINTPTR_MAX-d->length || d->next_pc!=d->pc+d->length)
        return bad(LI2_RSEQ_ARGUMENT,1);
    struct li2_write_registers regs;registers(uc,&regs);
    struct li2_write_footprint *f=&state.last_footprint;
    *f=(struct li2_write_footprint){0};
    uint32_t result=li2_decoder_write_footprint(d->pc,d->bytes,d->available,&regs,f);
    state.last_pc=d->pc;state.last_code=d->code;state.last_policy=f->policy;
    state.last_first=f->first;state.last_end=f->end;
    if(result || f->abi_version!=1 || f->pc!=d->pc || f->next_pc!=d->next_pc ||
       f->code!=d->code || f->length!=d->length)
        return bad(LI2_RSEQ_FOOTPRINT,(long)result);
    if(f->policy==LI2_WRITE_NONE) {
        if(f->first || f->end)return bad(LI2_RSEQ_FOOTPRINT,1);
        return 0;
    }
    if(f->policy!=LI2_WRITE_RANGE || only_none)return bad(LI2_RSEQ_UNSUPPORTED,d->code);
    if(f->end<=f->first)return bad(LI2_RSEQ_FOOTPRINT,2);
    return span((uintptr_t)f->first,(size_t)(f->end-f->first));
}
int li2_rseq_initialize(int (*exclude)(uintptr_t,size_t)) {
    if(state.initialized || !exclude)return bad(LI2_RSEQ_ARGUMENT,2);
    state.pid=CALL(SYS_getpid,0,0,0,0,0,0);state.tid=CALL(SYS_gettid,0,0,0,0,0,0);
    if(state.pid<=0 || state.pid!=state.tid)return bad(LI2_RSEQ_IDENTITY,0);
    private_range=exclude;__asm__ volatile("":::"memory");state.initialized=1;return 0;
}
const struct li2_rseq_state *li2_rseq_snapshot(void) { return &state; }
int li2_rseq_mapping_overlap(uintptr_t first,size_t bytes) {
    if(!state.held || !bytes)return 0;
    if(first>UINTPTR_MAX-bytes)return 1;
    return first<state.page+RSEQ_PAGE && state.page<first+bytes;
}
static int same_data(const struct li2_rseq_data *a,const struct li2_rseq_data *b) {
    return a->complete && b->complete && !a->error && !b->error &&
        a->address==b->address && a->page==b->page && a->allocation==b->allocation &&
        a->generation==b->generation && a->offset==b->offset &&
        a->pid==b->pid && a->tid==b->tid;
}
#ifdef LI2_RSEQ_TCGETS_BTRFS
#include "rseq_tcgets_btrfs.inc"

#endif
int li2_rseq_dispatch(const long a[6],long *result) {
    if(ready())return (int)state.first_error;
    if(!a || !result || li2_lifecycle_fetch_interlock())return bad(LI2_RSEQ_ARGUMENT,3);
    if(state.phase!=LI2_RSEQ_IDLE && state.phase!=LI2_RSEQ_ACTIVE)return bad(LI2_RSEQ_STATE,2);
    if(CALL(SYS_getpid,0,0,0,0,0,0)!=state.pid || CALL(SYS_gettid,0,0,0,0,0,0)!=state.tid)
        return bad(LI2_RSEQ_IDENTITY,1);
    if(word_zero())return (int)state.first_error;
    int flags=(int)a[2];uint32_t length=(uint32_t)a[1],signature=(uint32_t)a[3];
    if(flags!=0 && flags!=1)return bad(LI2_RSEQ_UNSUPPORTED,flags);
    unsigned prior=state.registered;
    struct li2_rseq_transaction *t=&state.transaction;
    *t=(struct li2_rseq_transaction){.attempted=1,.prior_registered=prior};
    for(size_t i=0;i<6;i++)t->args[i]=a[i];
    if(count(&state.calls))return (int)state.first_error;
    if(!prior && !flags) {
        uintptr_t address=(uintptr_t)a[0];
        if(length!=32 || (address&31) || address>UINTPTR_MAX-32 || state.epoch==UINT64_MAX)
            return bad(LI2_RSEQ_AREA,0);
        uintptr_t page=address&~(RSEQ_PAGE-1);
        /* Includes the complete installed SA_ONSTACK area: kernel signal
           frames cannot overlap this ABI word even for an arbitrary app RSP.
           Nested reserved events are terminal under the unchanged handler. */
        if(private_range(page,RSEQ_PAGE))return bad(LI2_RSEQ_AREA,1);
        state.address=address;state.page=page;state.length=length;state.signature=signature;
        state.held=1;__asm__ volatile("":::"memory");state.phase=LI2_RSEQ_PREPARING;
        int e=li2_lifecycle_rseq_data(address,&t->before);
        if(e)return bad((unsigned)e,t->before.detail);
        if(t->before.pid!=state.pid || t->before.tid!=state.tid)return bad(LI2_RSEQ_IDENTITY,2);
        /* The first kernel entry is allowed only with an already-zero real
           publication word. Never depend on registration to repair it. */
        t->input_word=*(const volatile uint64_t *)(address+8);
        __asm__ volatile("":::"memory");t->input_word_observed=1;
        if(t->input_word)return bad(LI2_RSEQ_WORD,2);
    }
    state.phase=flags?LI2_RSEQ_UNREGISTERING:LI2_RSEQ_ISSUING;
    __asm__ volatile("":::"memory");t->issued=1;
    __asm__ volatile("":::"memory");
    t->result=CALL(SYS_rseq,a[0],a[1],a[2],a[3],a[4],a[5]);
    __asm__ volatile("":::"memory");t->returned=1;
    *result=t->result;
    if(t->result>0 || t->result< -4095)return bad(LI2_RSEQ_STATE,t->result);
    if(t->result) {
        if(count(&state.kernel_errors))return (int)state.first_error;
        state.phase=prior?LI2_RSEQ_ACTIVE:LI2_RSEQ_IDLE;
        if(!prior)state.held=0;
        return word_zero();
    }
    if(flags) {
        if(!prior || (uintptr_t)a[0]!=state.address || length!=state.length || signature!=state.signature)
            return bad(LI2_RSEQ_STATE,3);
        if(count(&state.unregistrations))return (int)state.first_error;
        state.registered=0;state.held=0;state.phase=LI2_RSEQ_IDLE;return 0;
    }
    if(prior)return bad(LI2_RSEQ_STATE,4);
    int e=li2_lifecycle_rseq_data(state.address,&t->after);
    if(e)return bad((unsigned)e,t->after.detail);
    if(!same_data(&t->before,&t->after))return bad(LI2_RSEQ_MAPPING,0);
    state.data=t->after;
    if(*(const volatile uint64_t *)(state.address+8))return bad(LI2_RSEQ_WORD,1);
    if(tls_observe() || count(&state.registrations))return (int)state.first_error;
    ++state.epoch;state.registered=1;__asm__ volatile("":::"memory");state.phase=LI2_RSEQ_ACTIVE;
    return 0;
}
int li2_rseq_check_instruction(const struct li2_decoded *d,const ucontext_t *uc) {
    if(ready())return (int)state.first_error;
    if(!state.registered)return 0;
    if(word_zero() || count(&state.instruction_checks))return (int)state.first_error;
    if(!d || !uc)return bad(LI2_RSEQ_ARGUMENT,4);
    const unsigned repeat_width=li2_repeat_width(d);
    if(repeat_width) {
        if(count(&state.repeat_checks))return (int)state.first_error;
        uint64_t n=(uint64_t)uc->uc_mcontext.gregs[REG_RCX];
        uintptr_t at=(uintptr_t)uc->uc_mcontext.gregs[REG_RDI];
        state.last_pc=d->pc;state.last_code=d->code;
        state.last_first=state.last_end=0;
        state.last_policy=n?LI2_WRITE_RANGE:LI2_WRITE_NONE;
        state.last_footprint=(struct li2_write_footprint){0};
        if(!n)return 0;
        if(n>UINT64_MAX/repeat_width)return bad(LI2_RSEQ_OVERFLOW,2);
        uint64_t bytes=n*repeat_width;
        if((uint64_t)uc->uc_mcontext.gregs[REG_EFL]&UINT64_C(0x400)) {
            if(at<bytes-repeat_width || at>UINTPTR_MAX-repeat_width)
                return bad(LI2_RSEQ_OVERFLOW,3);
            return span(at-(bytes-repeat_width),(size_t)bytes);
        }
        return span(at,(size_t)bytes);
    }
    return decoded_footprint(d,uc,0);
}
int li2_rseq_check_run(const struct li2_run_plan *p,const ucontext_t *uc) {
    if(ready())return (int)state.first_error;
    if(!state.registered)return 0;
    if(word_zero() || count(&state.run_checks))return (int)state.first_error;
    if(!p || !uc || p->policy!=LI2_RUN_POLICY || p->instruction_count<2 ||
       p->instruction_count>LI2_RUN_MAX_INSTRUCTIONS || !p->source_length || p->source_length>15 ||
       p->pc>UINTPTR_MAX-p->source_length || p->run_length>=p->source_length)
        return bad(LI2_RSEQ_PLAN,0);
    size_t offset=0;
    for(size_t i=0;i<p->instruction_count;i++) {
        const struct li2_run_instruction *x=&p->instructions[i];
        if(x->offset!=offset || !x->length || offset+x->length>p->run_length)
            return bad(LI2_RSEQ_PLAN,1);
        struct li2_decoded d={0};
        if(li2_decoder_decode(p->pc+offset,p->source+offset,p->source_length-offset,&d) ||
           d.pc!=p->pc+offset || d.code!=x->code || d.length!=x->length)
            return bad(LI2_RSEQ_PLAN,2);
        /* NONE cannot depend on the register values changed by earlier MOVs.
           A future copied writer is refused even if its initial EA misses. */
        int e=decoded_footprint(&d,uc,1);if(e)return e;
        offset+=x->length;
    }
    if(offset!=p->run_length || p->stop!=p->pc+offset)return bad(LI2_RSEQ_PLAN,3);
    return 0;
}
#ifdef LI2_EFFECT_PROVIDER
#include "readonly_query.h"
#endif
int li2_rseq_before_syscall(long n,const long a[6]) {
    if(ready())return (int)state.first_error;
#ifdef LI2_RSEQ_TCGETS_BTRFS
    int tcgets_error=tcgets_before(n,a);if(tcgets_error)return tcgets_error;
#endif
    if(!state.registered)return 0;
    if(!a)return bad(LI2_RSEQ_ARGUMENT,5);
    if(word_zero() || count(&state.syscall_checks))return (int)state.first_error;
    state.last_first=state.last_end=0;
#ifdef LI2_EFFECT_PROVIDER
    struct li2_readonly_query query;
    if(li2_readonly_query(n,a,&query)) {
        for(unsigned i=0;i<query.count;i++) {
            int error=span(query.write[i].address,query.write[i].bytes);
            if(error)return error;
        }
        return 0;
    }
#endif
    switch(n) {
    case SYS_rseq:case SYS_exit:case SYS_exit_group:return 0;
#ifdef LI2_RSEQ_TCGETS_BTRFS
    case SYS_ioctl:return tcgets_permit(a);
#endif
    case SYS_read:case SYS_pread64:return span((uintptr_t)a[1],(size_t)a[2]);
    case SYS_getrandom:return span((uintptr_t)a[0],(size_t)a[1]);
    case SYS_getdents64:return span((uintptr_t)a[1],(unsigned int)a[2]);
    case SYS_readlink:
        if((int)a[2]<0)return bad(LI2_RSEQ_UNSUPPORTED,n);
        return span((uintptr_t)a[1],(unsigned int)a[2]);
    case SYS_readlinkat:
        if((int)a[3]<0)return bad(LI2_RSEQ_UNSUPPORTED,n);
        return span((uintptr_t)a[2],(unsigned int)a[3]);
    case SYS_getcwd:return span((uintptr_t)a[0],(size_t)a[1]);
    case SYS_getxattr:case SYS_lgetxattr:case SYS_fgetxattr:return span((uintptr_t)a[2],(size_t)a[3]);
    case SYS_listxattr:case SYS_llistxattr:case SYS_flistxattr:return span((uintptr_t)a[1],(size_t)a[2]);
    case SYS_fstat:return span((uintptr_t)a[1],sizeof(struct stat));
    case SYS_newfstatat:return span((uintptr_t)a[2],sizeof(struct stat));
    case SYS_statx:return span((uintptr_t)a[4],sizeof(struct statx));
    case SYS_statfs:case SYS_fstatfs:return span((uintptr_t)a[1],sizeof(struct statfs));
    case SYS_uname:return span((uintptr_t)a[0],sizeof(struct utsname));
    case SYS_sysinfo:return span((uintptr_t)a[0],sizeof(struct sysinfo));
    case SYS_clock_gettime:return span((uintptr_t)a[1],sizeof(struct timespec));
    case SYS_gettimeofday: {
        int e=optional_span(a[0],sizeof(struct timeval));return e?e:optional_span(a[1],8);
    }
    case SYS_prlimit64:return optional_span(a[3],sizeof(struct rlimit));
    case SYS_rt_sigaction:
        if(a[1])return bad(LI2_RSEQ_UNSUPPORTED,n);
        return optional_span(a[2],32); /* x86-64 kernel action + 8-byte mask */
    case SYS_arch_prctl:
        if(a[0]==ARCH_SET_FS || a[0]==ARCH_SET_GS)return 0;
        if(a[0]==ARCH_GET_FS || a[0]==ARCH_GET_GS || a[0]==0x5005)return span((uintptr_t)a[1],8);
        return bad(LI2_RSEQ_UNSUPPORTED,n);
    case SYS_futex: {
        int op=(int)a[1]&FUTEX_CMD_MASK;
        if(op==FUTEX_WAIT || op==FUTEX_WAKE || op==FUTEX_WAIT_BITSET || op==FUTEX_WAKE_BITSET)return 0;
        return bad(LI2_RSEQ_UNSUPPORTED,n);
    }
    case SYS_fcntl:
        if(a[1]==F_GETFD || a[1]==F_SETFD || a[1]==F_GETFL || a[1]==F_SETFL ||
           a[1]==F_DUPFD || a[1]==F_DUPFD_CLOEXEC)return 0;
        return bad(LI2_RSEQ_UNSUPPORTED,n);
    case SYS_prctl:
        if(a[0]==PR_CAPBSET_READ)return 0;
        return bad(LI2_RSEQ_UNSUPPORTED,n);
    case SYS_mmap:case SYS_mprotect:case SYS_munmap:return 0; /* real protected_range hook */
    case SYS_madvise: {
        uintptr_t first=(uintptr_t)a[0];size_t length=(size_t)a[1];
        if(!length)return 0;
        if(length>UINTPTR_MAX-(RSEQ_PAGE-1))return bad(LI2_RSEQ_OVERFLOW,4);
        size_t extent=(length+RSEQ_PAGE-1)&~(RSEQ_PAGE-1);
        if(li2_rseq_mapping_overlap(first,extent))return bad(LI2_RSEQ_MAPPING,n);
        return 0;
    }
    case SYS_brk:
        if(a[0]) {
            long observed=CALL(SYS_brk,0,0,0,0,0,0);
            if(observed<=0 || (uintptr_t)observed>UINTPTR_MAX-(RSEQ_PAGE-1))return bad(LI2_RSEQ_MAPPING,observed);
            uintptr_t requested=(uintptr_t)a[0];
            if(requested<(uintptr_t)observed) {
                uintptr_t first=(requested+RSEQ_PAGE-1)&~(RSEQ_PAGE-1),end=((uintptr_t)observed+RSEQ_PAGE-1)&~(RSEQ_PAGE-1);
                if(first<end && li2_rseq_mapping_overlap(first,end-first))return bad(LI2_RSEQ_MAPPING,n);
            }
        }
        return 0;
    case SYS_write:case SYS_writev:case SYS_openat:case SYS_close:case SYS_lseek:
    case SYS_access:case SYS_faccessat:case SYS_faccessat2:
    case SYS_getuid:case SYS_geteuid:case SYS_getgid:case SYS_getegid:case SYS_getpid:case SYS_gettid:
        return 0; /* retain all original fd/suboperation/procfs checks */
    case SYS_set_tid_address:case SYS_set_robust_list:
        /* These record deferred writes at mm release. Exec/fork/threads stay
           refused, and the sole task's exit cannot resume application code. */
        return 0;
    default:
        /* In particular: readv without an authenticated iovec observer,
           ioctl without a closed FD-class contract, signals and new calls. */
        return bad(LI2_RSEQ_UNSUPPORTED,n);
    }
}
int li2_rseq_after_syscall(long n,const long a[6]) {
    if(ready())return (int)state.first_error;
    if(!state.registered)return 0;
    if(!a)return bad(LI2_RSEQ_ARGUMENT,5);
    /* SET_FS/GS is the only admitted writer of either base. Query actual
       results on either kernel outcome; never infer bases from saved selectors. */
    if(n==SYS_arch_prctl && (a[0]==ARCH_SET_FS || a[0]==ARCH_SET_GS)) {
        int e=tls_observe();if(e)return e;
    }
    return word_zero();
}

#ifdef LI2_RSEQ_NATIVE
#include "native_epoch.h"
#include "native_pages.h"
#include "maps_phase.h"
extern long li2_raw6(long,long,long,long,long,long,long);
static struct li2_rseq_native_state native_rseq;
const struct li2_rseq_native_state *li2_rseq_native_snapshot(void) { return &native_rseq; }
static int native_bad(unsigned code,long detail) {
    if(!native_rseq.first_error){native_rseq.first_error=code;native_rseq.first_detail=detail;}
    native_rseq.phase=LI2_RN_FAILED;return (int)native_rseq.first_error;
}
static _Noreturn void native_unsafe(unsigned code,long detail) {
    (void)native_bad(code,detail);native_rseq.unsafe_terminal=1;
    __asm__ volatile("":::"memory");
    /* No maps wrapper, logging, word repair, returning cleanup, or verified
       close claim. A still-live descriptor could cover a runtime syscall PC. */
    (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static int native_pin(void) {
    return state.initialized && !state.first_error && state.registered==1 && state.held==1 &&
        state.phase==LI2_RSEQ_ACTIVE && state.tls_complete==1 && state.pid>0 && state.pid==state.tid &&
        state.length==32 && !(state.address&31) && state.address<=UINTPTR_MAX-32 &&
        state.page==(state.address&~(RSEQ_PAGE-1)) && state.epoch &&
        state.data.complete==1 && !state.data.error && state.data.address==state.address &&
        state.data.page==state.page && state.data.pid==state.pid && state.data.tid==state.tid &&
        state.data.allocation && state.data.generation;
}
static int native_binding(void) {
    return native_pin() && state.pid==native_rseq.pid && state.tid==native_rseq.tid &&
        state.address==native_rseq.address && state.page==native_rseq.page &&
        state.length==native_rseq.length && state.signature==native_rseq.signature &&
        state.epoch==native_rseq.registration_epoch && same_data(&state.data,&native_rseq.before);
}
static void native_zero(uint64_t *out) {
    if(native_rseq.checking)native_unsafe(LI2_RN_REENTRY,0);
    native_rseq.checking=1;__asm__ volatile("":::"memory");
    if(!native_binding())native_unsafe(LI2_RN_PIN,0);
    *out=*(const volatile uint64_t *)(native_rseq.address+8);
    if(*out)native_unsafe(LI2_RN_WORD,0);
    __asm__ volatile("":::"memory");native_rseq.checking=0;
}
#ifdef LI2_RSEQ_NATIVE_BOUNDARY
#include "rseq_native_boundary.inc"
#endif
void li2_rseq_native_preentry(void) {
    if(native_rseq.checking)native_unsafe(LI2_RN_REENTRY,1);
#ifdef LI2_RSEQ_NATIVE_BOUNDARY
    if(boundary_preentry())return;
#endif
    if(native_rseq.phase==LI2_RN_IDLE)return;
    native_zero(&native_rseq.word_entry);
    if(native_rseq.preentries==UINT64_MAX)native_unsafe(LI2_RN_OVERFLOW,0);
    ++native_rseq.preentries;
    __asm__ volatile("mov %%fs,%0; mov %%gs,%1":"=r"(native_rseq.fs_selector_entry),
                     "=r"(native_rseq.gs_selector_entry)::"memory");
    native_rseq.entry_checked=1;
}
int li2_rseq_native_prepare(uintptr_t pc) {
    if(native_rseq.phase!=LI2_RN_IDLE || native_rseq.first_error)return native_bad(LI2_RN_STATE,0);
    if(!state.registered)return 0;
    if(!native_pin())native_unsafe(LI2_RN_PIN,1);
    if(native_rseq.attempts==UINT64_MAX || native_rseq.admissions==UINT64_MAX ||
       native_rseq.preentries==UINT64_MAX || native_rseq.entries==UINT64_MAX || native_rseq.closed==UINT64_MAX ||
       native_rseq.tls_refreshes==UINT64_MAX)return native_bad(LI2_RN_OVERFLOW,1);
    const struct li2_native_counts *n=li2_lifecycle_native_counts();
    if(!pc || n->admissions!=n->closed || n->admissions==UINT64_MAX ||
       native_rseq.attempts!=native_rseq.admissions || native_rseq.admissions!=native_rseq.closed ||
       native_rseq.preentries!=native_rseq.closed || native_rseq.entries!=native_rseq.closed ||
       native_rseq.tls_refreshes!=native_rseq.closed)
        return native_bad(LI2_RN_STATE,1);
    native_rseq=(struct li2_rseq_native_state){.attempts=native_rseq.attempts+1,
        .admissions=native_rseq.admissions,.preentries=native_rseq.preentries,.entries=native_rseq.entries,
        .closed=native_rseq.closed,.tls_refreshes=native_rseq.tls_refreshes,
        .pc=pc,.address=state.address,.page=state.page,.pid=state.pid,.tid=state.tid,
        .registration_epoch=state.epoch,.length=state.length,.signature=state.signature,
        .native_admissions_before=n->admissions,.native_closed_before=n->closed,
        .fs_before=state.fs_base,.gs_before=state.gs_base,.before=state.data};
    __asm__ volatile("":::"memory");native_rseq.phase=LI2_RN_PREPARED;
    native_zero(&native_rseq.word_before);
    li2_maps_phase_end(); /* New actual page observation, never reused rows. */
    struct li2_rseq_data observed={0};
    int e=li2_lifecycle_rseq_data(state.address,&observed);
    if(e || !same_data(&state.data,&observed))return native_bad(LI2_RN_PIN,e?e:1);
    native_rseq.before=observed;native_zero(&native_rseq.word_before);
    return 0;
}
int li2_rseq_native_publish(uintptr_t pc) {
    if(!state.registered && native_rseq.phase==LI2_RN_IDLE)return 0;
    const struct li2_native_counts *n=li2_lifecycle_native_counts();
    if(native_rseq.phase!=LI2_RN_PREPARED || native_rseq.first_error || pc!=native_rseq.pc ||
       n->admissions!=native_rseq.native_admissions_before+1 ||
       n->closed!=native_rseq.native_closed_before)return native_bad(LI2_RN_STATE,2);
    native_zero(&native_rseq.word_before);
    ++native_rseq.admissions;native_rseq.entry_checked=0;
    __asm__ volatile("":::"memory");native_rseq.phase=LI2_RN_EXECUTING;
    return 0;
}
int li2_rseq_native_enter(int sig,siginfo_t *si,const ucontext_t *uc) {
    if(native_rseq.phase==LI2_RN_IDLE && !state.registered)return 0;
    if(native_rseq.phase!=LI2_RN_EXECUTING || native_rseq.first_error ||
       !native_rseq.entry_checked || !native_binding())return native_bad(LI2_RN_STATE,3);
    if(!si || !uc || sig!=SIGSEGV || si->si_signo!=SIGSEGV || si->si_code!=SEGV_ACCERR ||
       si->si_errno || uc->uc_mcontext.gregs[REG_TRAPNO]!=14 || uc->uc_mcontext.gregs[REG_ERR]!=21 ||
       (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]!=(uintptr_t)si->si_addr ||
       (uintptr_t)uc->uc_mcontext.gregs[REG_CR2]!=(uintptr_t)si->si_addr)
        return native_bad(LI2_RN_ENTRY,sig);
    /* The old native owner has already checked every mask/CS/RF/source gate.
       This is the current kernel PC; equality does not imply absence of abort. */
    native_zero(&native_rseq.word_entry);++native_rseq.entries;
    native_rseq.phase=LI2_RN_CLOSING;return 0;
}
int li2_rseq_native_closed(void) {
#ifdef LI2_RSEQ_NATIVE_BOUNDARY
    if(native_boundary.phase==LI2_RNB_ENTERING)return boundary_observe();
#endif
    if(native_rseq.phase==LI2_RN_IDLE && !state.registered)return 0;
    const struct li2_native_close *c=li2_lifecycle_native_close_progress();
    const struct li2_native_counts *n=li2_lifecycle_native_counts();
    if(native_rseq.phase!=LI2_RN_CLOSING || native_rseq.first_error || !native_rseq.entry_checked ||
       !c->complete || c->busy || c->first_error || c->pages!=1 || c->verified!=1 ||
       c->pid!=native_rseq.pid || c->tid!=native_rseq.tid ||
       n->admissions!=native_rseq.native_admissions_before+1 || n->closed!=n->admissions)
        return native_bad(LI2_RN_CLOSE,0);
    native_zero(&native_rseq.word_after);li2_maps_phase_end();
    int e=li2_lifecycle_rseq_data(state.address,&native_rseq.after);
    if(e || !same_data(&native_rseq.before,&native_rseq.after))return native_bad(LI2_RN_PIN,e?e:2);
    native_zero(&native_rseq.word_after);
    if(tls_observe())return native_bad(LI2_RN_TLS,state.first_detail);
    native_rseq.fs_after=state.fs_base;native_rseq.gs_after=state.gs_base;
    __asm__ volatile("mov %%fs,%0; mov %%gs,%1":"=r"(native_rseq.fs_selector_after),
                     "=r"(native_rseq.gs_selector_after)::"memory");
    if(native_rseq.fs_selector_entry!=native_rseq.fs_selector_after ||
       native_rseq.gs_selector_entry!=native_rseq.gs_selector_after)return native_bad(LI2_RN_TLS,1);
    native_zero(&native_rseq.word_after);
    ++native_rseq.tls_refreshes;++native_rseq.closed;
#ifdef LI2_RSEQ_NATIVE_BOUNDARY
    if(native_boundary.phase==LI2_RNB_FIRST)return boundary_arm(c,n);
#endif
    __asm__ volatile("":::"memory");native_rseq.phase=LI2_RN_IDLE;return 0;
}
#endif
#ifdef LI2_EFFECT_PROVIDER
#include "rseq_selected.inc"
#endif
#ifdef LI2_ONESHOT_REUSABLE
#include "rseq_publication.inc"
#endif
