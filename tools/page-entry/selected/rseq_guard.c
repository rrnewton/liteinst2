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
    if(li2_repeat_candidate(d)) {
        if(count(&state.repeat_checks))return (int)state.first_error;
        uint64_t n=(uint64_t)uc->uc_mcontext.gregs[REG_RCX];
        uintptr_t at=(uintptr_t)uc->uc_mcontext.gregs[REG_RDI];
        state.last_pc=d->pc;state.last_code=d->code;
        state.last_first=state.last_end=0;
        state.last_policy=n?LI2_WRITE_RANGE:LI2_WRITE_NONE;
        state.last_footprint=(struct li2_write_footprint){0};
        if(!n)return 0;
        if(n>UINT64_MAX/8)return bad(LI2_RSEQ_OVERFLOW,2);
        uint64_t bytes=n*8;
        if((uint64_t)uc->uc_mcontext.gregs[REG_EFL]&UINT64_C(0x400)) {
            if(at<bytes-8 || at>UINTPTR_MAX-8)return bad(LI2_RSEQ_OVERFLOW,3);
            return span(at-(bytes-8),(size_t)bytes);
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
int li2_rseq_before_syscall(long n,const long a[6]) {
    if(ready())return (int)state.first_error;
    if(!state.registered)return 0;
    if(!a)return bad(LI2_RSEQ_ARGUMENT,5);
    if(word_zero() || count(&state.syscall_checks))return (int)state.first_error;
    state.last_first=state.last_end=0;
    switch(n) {
    case SYS_rseq:case SYS_exit:case SYS_exit_group:return 0;
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
