#include "native_epoch.h"
#ifdef LI2_RSEQ_NATIVE
#include "rseq_guard.h"
#endif
#include <sys/syscall.h>
#ifdef LI2_MAPS_PHASE_REUSE
#include "maps_phase.h"
#define RAW(n,a,b,c,d,e,f) li2_maps_raw(li2_step_raw,n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
#else
#define RAW(n,a,b,c,d,e,f) li2_step_raw(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
#endif
static struct li2_native_epoch epoch;
static int same(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;return 1;
}
static void copy(void *to,const void *from,size_t n) {
    unsigned char *a=to;const unsigned char *b=from;for(size_t i=0;i<n;i++)a[i]=b[i];
}
static uint32_t u32(const unsigned char *p) {
    uint32_t x;copy(&x,p,sizeof(x));return x;
}
static int error(unsigned code,long detail) {
    if(!epoch.first_error){epoch.first_error=code;epoch.first_detail=detail;}
    epoch.phase=LI2_NATIVE_FAILED;return (int)epoch.first_error;
}
static int identity(void) {
    const struct li2_step_session *s=epoch.session;
    return s && s->initialized && s->self_test_complete && s->pid>0 && s->pid==s->tid &&
        !s->sync_register && s->sync_query>=0 && (s->sync_query&96)==96 &&
        RAW(SYS_getpid,0,0,0,0,0,0)==s->pid && RAW(SYS_gettid,0,0,0,0,0,0)==s->tid;
}
const struct li2_native_epoch *li2_native_epoch_progress(void) { return &epoch; }
void li2_native_epoch_abort(unsigned code,long detail) {
    (void)error(code?code:LI2_NATIVE_STATE,detail);
    li2_lifecycle_native_close_abort();
}
int li2_native_epoch_initialize(struct li2_step_session *s) {
    if(!s)return LI2_NATIVE_ARGUMENT;
    if(epoch.phase!=LI2_NATIVE_EMPTY || epoch.session)return LI2_NATIVE_STATE;
    epoch.session=s;
    if(!identity() || !li2_lifecycle_enabled())return error(LI2_NATIVE_IDENTITY,0);
    epoch.phase=LI2_NATIVE_IDLE;return 0;
}
static int capture(struct li2_step_frame *out,const ucontext_t *uc) {
    for(size_t i=0;i<NGREG;i++)out->greg[i]=uc->uc_mcontext.gregs[i];
    copy(&out->mask,&uc->uc_sigmask,8);out->fp_address=(uintptr_t)uc->uc_mcontext.fpregs;
    out->fp_bytes=0;out->initialized=0;
    const unsigned char *p=(const void *)out->fp_address;
    if(!p || (out->fp_address&15))return error(LI2_NATIVE_FRAME,0);
    size_t n=512;
    if(u32(p+464)==UINT32_C(0x46505853)) {
        n=u32(p+468);size_t x=u32(p+480);
        if(n<580 || n>LI2_STEP_FP_BYTES || x<576 || x>n-4 ||
           u32(p+n-4)!=UINT32_C(0x46505845))return error(LI2_NATIVE_FRAME,1);
    }
    out->fp_bytes=n;
    for(size_t i=0;i<n;i++){out->fp[i]=p[i];out->initialized=i+1;}
    return 0;
}
int li2_native_epoch_nx(int sig,siginfo_t *si,ucontext_t *uc,uint64_t *logical_flags) {
    if(!si || !uc || !logical_flags)return LI2_NATIVE_ARGUMENT;
    if(epoch.first_error)return (int)epoch.first_error;
    if(epoch.in_handler)return error(LI2_NATIVE_REENTRY,sig);
    if(epoch.phase!=LI2_NATIVE_IDLE && epoch.phase!=LI2_NATIVE_RETRY)return error(LI2_NATIVE_STATE,epoch.phase);
    unsigned retry=epoch.phase==LI2_NATIVE_RETRY;
    epoch.in_handler=1;epoch.phase=LI2_NATIVE_ENTERING;
    if(!identity() || li2_lifecycle_fetch_interlock())return error(LI2_NATIVE_IDENTITY,1);
    if(epoch.events==UINT64_MAX || epoch.retries==UINT64_MAX || epoch.ready==UINT64_MAX)
        return error(LI2_NATIVE_OVERFLOW,0);
    ++epoch.events;
    epoch.signal_number=sig;epoch.signal_code=si->si_code;epoch.signal_errno=si->si_errno;
    epoch.signal_address=(uintptr_t)si->si_addr;
    const greg_t *g=uc->uc_mcontext.gregs;uintptr_t pc=(uintptr_t)g[REG_RIP];
    uint64_t mask=0;copy(&mask,&uc->uc_sigmask,8);
    if(sig!=SIGSEGV || si->si_signo!=SIGSEGV || si->si_code!=SEGV_ACCERR || si->si_errno ||
       g[REG_TRAPNO]!=14 || g[REG_ERR]!=21 || ((uint64_t)g[REG_CSGSFS]&0xffff)!=0x33 ||
       mask!=epoch.session->application_mask || !li2_lifecycle_known_code(pc,1) ||
       epoch.signal_address<pc || epoch.signal_address-pc>14 ||
       (uintptr_t)g[REG_CR2]!=epoch.signal_address)
        return error(LI2_NATIVE_FOREIGN,sig);
    uint64_t flags=(uint64_t)g[REG_EFL];
    if((flags&LI2_STEP_TF) || !(flags&LI2_STEP_RF))return error(LI2_NATIVE_FLAGS,(long)flags);
#ifdef LI2_RSEQ_NATIVE
#ifdef LI2_RSEQ_NATIVE_BOUNDARY
    int rseq_result=li2_rseq_native_boundary_enter(sig,si,uc,retry);
#else
    if(retry && (li2_rseq_snapshot()->registered ||
       li2_rseq_native_snapshot()->phase!=LI2_RN_IDLE))return error(LI2_RN_ENTRY,LI2_NATIVE_RETRY);
    int rseq_result=li2_rseq_native_enter(sig,si,uc);
#endif
    if(rseq_result)return error((unsigned)rseq_result,li2_rseq_native_snapshot()->first_detail);
#endif
    struct li2_step_frame *frame=retry?&epoch.second:&epoch.first;
    if(!retry){epoch.first_observed=0;epoch.second_observed=0;}
    int r=capture(frame,uc);if(r)return r;
    if(retry)epoch.second_observed=1;else epoch.first_observed=1;
    li2_lifecycle_native_close();
    const struct li2_native_close *closed=li2_lifecycle_native_close_progress();
    if(!closed->complete || closed->busy || closed->first_error || closed->pid!=epoch.session->pid ||
       closed->tid!=epoch.session->tid || closed->pages!=closed->verified)
        return error(LI2_NATIVE_STATE,2);
#ifdef LI2_RSEQ_NATIVE
    rseq_result=li2_rseq_native_closed();
    if(rseq_result)return error((unsigned)rseq_result,li2_rseq_native_snapshot()->first_detail);
#endif
    if(retry) {
        if(closed->pages || !epoch.first_observed || epoch.signal_address!=pc ||
           epoch.first.fp_bytes!=epoch.second.fp_bytes || epoch.first.mask!=epoch.second.mask ||
           !same(epoch.first.fp,epoch.second.fp,epoch.first.fp_bytes))
            return error(LI2_NATIVE_RETRY_CHANGED,0);
        /* CR2 legitimately changes from the second fetch page to original RIP.
           Every other saved GPR/selector/flag and complete FP byte stays exact. */
        for(size_t i=0;i<NGREG;i++)if(i!=REG_CR2 && epoch.first.greg[i]!=epoch.second.greg[i])
            return error(LI2_NATIVE_RETRY_CHANGED,(long)i);
#ifdef LI2_RSEQ_NATIVE_BOUNDARY
        rseq_result=li2_rseq_native_boundary_complete();
        if(rseq_result)return error((unsigned)rseq_result,li2_rseq_native_snapshot()->first_detail);
#endif
    } else {
        if(!closed->pages) {
            epoch.phase=LI2_NATIVE_IDLE;epoch.in_handler=0;
            return LI2_NATIVE_NOT_ACTIVE;
        }
        if(epoch.signal_address!=pc) {
            if((epoch.signal_address&~(LI2_STEP_PAGE-1))==(pc&~(LI2_STEP_PAGE-1)))
                return error(LI2_NATIVE_FOREIGN,1);
            ++epoch.retries;epoch.phase=LI2_NATIVE_RETRY;epoch.in_handler=0;
            return LI2_NATIVE_REFAULT;
        }
    }
    /* This is the NEW policy-bound native ingress, not a change to old
       known-input flags checks. The retained #PF RF bit is not evidence of
       pre-fault RF. Intel Vol.3 section 18.3.1.1 clears RF at the next successful
       instruction start after debug/CS-limit/FP checks. The separate native
       profile excludes debuggers/resumable async events and terminates other
       faults; its native NX oracle must qualify this new ingress. */
    epoch.logical_flags=flags&~LI2_STEP_RF;*logical_flags=epoch.logical_flags;
    ++epoch.ready;epoch.phase=LI2_NATIVE_IDLE;epoch.in_handler=0;
    return LI2_NATIVE_READY;
}
