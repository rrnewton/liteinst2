/* Included by native_epoch.c only in the separate two-page profile. */
#include "native_pair.h"
struct li2_native_pair_owner {
    struct li2_native_pair_progress p;
    struct li2_step_session session;
    ucontext_t saved_uc;
    siginfo_t saved_si;
    struct li2_step_frame returned;
};
static struct li2_native_pair_owner np_owner;
#define NP (np_owner.p)
const struct li2_native_pair_progress *li2_native_pair_progress(void) { return &NP; }
static int np_bad(unsigned code,long detail) {
    if(!NP.first_error){NP.first_error=code;NP.first_detail=detail;}
    NP.phase=LI2_NP_FAILED;return (int)NP.first_error;
}
int li2_native_pair_owner_check(const struct li2_native_pair_owner *o,unsigned phase) {
    return o==&np_owner && NP.initialized==1 && !NP.first_error && NP.phase==phase &&
        NP.session && same(NP.session,&np_owner.session,sizeof(np_owner.session));
}
static int np_identity(void) {
    const struct li2_step_session *s=NP.session;
    return s && same(s,&np_owner.session,sizeof(*s)) && s->initialized && s->self_test_complete &&
        s->pid>0 && s->pid==s->tid && !s->sync_register && s->sync_query>=0 && (s->sync_query&96)==96 &&
        RAW(SYS_getpid,0,0,0,0,0,0)==s->pid && RAW(SYS_gettid,0,0,0,0,0,0)==s->tid;
}
int li2_native_pair_initialize(struct li2_step_session *s) {
    if(!s || NP.initialized || NP.session || NP.phase!=LI2_NP_EMPTY)return LI2_NP_ARGUMENT;
    NP.session=s;copy(&np_owner.session,s,sizeof(*s));NP.initialized=1;NP.phase=LI2_NP_INITIALIZING;
    if(!np_identity() || !li2_lifecycle_enabled() || li2_lifecycle_fetch_interlock())
        return np_bad(LI2_NP_IDENTITY,0);
    NP.pid=s->pid;NP.tid=s->tid;
    int r=li2_lifecycle_pair_initialize(&np_owner);if(r)return np_bad((unsigned)r,0);
    r=li2_rseq_pair_initialize(&np_owner);if(r)return np_bad((unsigned)r,1);
    NP.phase=LI2_NP_IDLE;return 0;
}
int li2_native_pair_quiet(void) {
    /* Bootstrap has no pair owner and no pair-issued permission. */
    if(!NP.initialized)return !NP.session && NP.phase==LI2_NP_EMPTY && !NP.first_error;
    return li2_native_pair_owner_check(&np_owner,LI2_NP_IDLE) && !NP.in_handler && !NP.live &&
        !NP.entry_pending && li2_lifecycle_pair_quiet(&np_owner) && li2_rseq_pair_quiet(&np_owner);
}
int li2_native_pair_effect_guard(void) { return li2_native_pair_quiet()?0:LI2_NP_STATE; }
void li2_native_pair_abort(unsigned code,long detail) {
    (void)np_bad(code?code:LI2_NP_STATE,detail);
    /* Actual lifecycle records, including a separately occupied transaction,
       remain available to the original verified/best-effort close + abort. */
    li2_lifecycle_native_close_abort();
}
void li2_native_pair_preentry(void) {
    if(!NP.initialized)return;
    li2_rseq_pair_preentry(&np_owner); /* pure pin/zero check precedes RAW */
    const struct li2_rseq_pair_progress *r=li2_rseq_pair_progress();
    if(r->first_error){(void)np_bad(r->first_error,r->first_detail);return;}
    if(NP.phase==LI2_NP_IDLE)return;
    if(NP.in_handler || NP.entry_pending ||
       (NP.phase!=LI2_NP_EXECUTING_ONE && NP.phase!=LI2_NP_EXECUTING_TWO &&
        NP.phase!=LI2_NP_WAIT_REFAULT)) {(void)np_bad(LI2_NP_REENTRY,0);return;}
    NP.entry_pending=1;
}
static int np_capture(struct li2_step_frame *out,const ucontext_t *uc) {
    for(size_t i=0;i<NGREG;i++)out->greg[i]=uc->uc_mcontext.gregs[i];
    copy(&out->mask,&uc->uc_sigmask,8);out->fp_address=(uintptr_t)uc->uc_mcontext.fpregs;
    out->fp_bytes=0;out->initialized=0;
    const unsigned char *p=(const void *)out->fp_address;
    if(!p || (out->fp_address&15))return np_bad(LI2_NP_FRAME,0);
    size_t n=512;
    if(u32(p+464)==UINT32_C(0x46505853)) {
        n=u32(p+468);size_t x=u32(p+480);
        if(n<580 || n>LI2_STEP_FP_BYTES || x<576 || x>n-4 ||
           u32(p+n-4)!=UINT32_C(0x46505845))return np_bad(LI2_NP_FRAME,1);
    }
    out->fp_bytes=n;for(size_t i=0;i<n;i++){out->fp[i]=p[i];out->initialized=i+1;}
    return 0;
}
static int np_unchanged(const siginfo_t *si,const ucontext_t *uc,const struct li2_step_frame *before) {
    if(!same(si,&np_owner.saved_si,sizeof(*si)) || !same(uc,&np_owner.saved_uc,sizeof(*uc)))
        return np_bad(LI2_NP_FRAME,2);
    if(np_capture(&np_owner.returned,uc))return (int)NP.first_error;
    const struct li2_step_frame *after=&np_owner.returned;
    if(before->fp_address!=after->fp_address || before->fp_bytes!=after->fp_bytes ||
       before->initialized!=after->initialized || before->mask!=after->mask ||
       !same(before->greg,after->greg,sizeof(before->greg)) || !same(before->fp,after->fp,before->fp_bytes))
        return np_bad(LI2_NP_FRAME,3);
    return 0;
}
static int np_life_result(int r) {
    return r?np_bad((unsigned)r,li2_lifecycle_pair_progress()->first_detail):0;
}
static int np_rseq_result(int r) {
    return r?np_bad((unsigned)r,li2_rseq_pair_progress()->first_detail):0;
}
static int np_seed(uintptr_t pc,int *admitted) {
    NP.phase=LI2_NP_SEEDING;*admitted=0;
    int eligible=0;
    if(np_life_result(li2_lifecycle_pair_prepare(&np_owner,pc,&eligible)))return (int)NP.first_error;
    if(!eligible){NP.phase=LI2_NP_IDLE;return 0;}
    if(NP.seeds==UINT64_MAX)return np_bad(LI2_NP_OVERFLOW,0);
    if(np_rseq_result(li2_rseq_pair_seed(&np_owner)) ||
       np_life_result(li2_lifecycle_pair_publish(&np_owner,pc)) ||
       np_rseq_result(li2_rseq_pair_published(&np_owner)))return (int)NP.first_error;
    NP.live=1;++NP.seeds;NP.phase=LI2_NP_EXECUTING_ONE;*admitted=1;return 0;
}
static int np_close(unsigned reason,int wait_refault) {
    unsigned live=NP.live;
    if(!live || live>2 || NP.epochs_closed==UINT64_MAX ||
       (live==1?NP.one_page_closes:NP.two_page_closes)==UINT64_MAX ||
       (reason==LI2_NP_POLICY && NP.policy_closes==UINT64_MAX) ||
       (reason==LI2_NP_CAPACITY && NP.capacity_closes==UINT64_MAX))return np_bad(LI2_NP_OVERFLOW,1);
    NP.close_reason=reason;NP.phase=LI2_NP_CLOSING;
    if(np_life_result(li2_lifecycle_pair_close(&np_owner)))return (int)NP.first_error;
    NP.first_close=li2_lifecycle_pair_progress()->close;
    if(np_rseq_result(li2_rseq_pair_closed(&np_owner,wait_refault)))return (int)NP.first_error;
    ++NP.epochs_closed;if(live==1)++NP.one_page_closes;else ++NP.two_page_closes;
    if(reason==LI2_NP_POLICY)++NP.policy_closes;
    if(reason==LI2_NP_CAPACITY)++NP.capacity_closes;
    NP.live=0;NP.phase=wait_refault?LI2_NP_WAIT_REFAULT:LI2_NP_IDLE;return 0;
}
static int np_retry(void) {
    const struct li2_native_close *first=&NP.first_close;
    if(!NP.first_observed || !NP.second_observed || !first->complete || !first->pages || first->pages>2 ||
       first->sequence==UINT64_MAX || NP.signal_address!=NP.pc ||
       NP.first.fp_bytes!=NP.second.fp_bytes || NP.first.mask!=NP.second.mask ||
       !same(NP.first.fp,NP.second.fp,NP.first.fp_bytes))return np_bad(LI2_NP_RETRY_CHANGED,0);
    for(size_t i=0;i<NGREG;i++)if(i!=REG_CR2 && NP.first.greg[i]!=NP.second.greg[i])
        return np_bad(LI2_NP_RETRY_CHANGED,(long)i);
    if(np_life_result(li2_lifecycle_pair_close(&np_owner)))return (int)NP.first_error;
    const struct li2_native_close *c=&li2_lifecycle_pair_progress()->close;
    if(c->sequence!=first->sequence+1 || !c->complete || c->busy || c->first_error ||
       c->pages || c->attempted || c->returned || c->closed || c->verified || c->last_address ||
       c->last_result || c->sync_started || c->sync_returned || c->sync_result ||
       c->cleanup_started || c->cleanup_complete || c->pid!=first->pid || c->tid!=first->tid ||
       c->allocation_epoch!=first->allocation_epoch || c->generation_epoch!=first->generation_epoch ||
       c->transactions_epoch!=first->transactions_epoch || c->records_epoch!=first->records_epoch)
        return np_bad(LI2_NP_RETRY_CHANGED,NGREG);
    if(np_rseq_result(li2_rseq_pair_refault(&np_owner)))return (int)NP.first_error;
    if(NP.refault_completed==UINT64_MAX)return np_bad(LI2_NP_OVERFLOW,2);
    ++NP.refault_completed;NP.phase=LI2_NP_IDLE;return 0;
}
int li2_native_pair_nx(int sig,siginfo_t *si,ucontext_t *uc,unsigned known,uint64_t *logical_flags) {
    if(!si || !uc || !logical_flags || known>1)return LI2_NP_ARGUMENT;
    if(NP.first_error)return (int)NP.first_error;
    unsigned phase=NP.phase,retry=phase==LI2_NP_WAIT_REFAULT,cold=phase==LI2_NP_IDLE;
    if(!NP.initialized || NP.in_handler || (cold?(!known || NP.entry_pending || NP.live):
       (known || NP.entry_pending!=1 ||
        (phase!=LI2_NP_EXECUTING_ONE && phase!=LI2_NP_EXECUTING_TWO && !retry))))
        return np_bad(LI2_NP_STATE,0);
    if(cold && (!li2_lifecycle_pair_quiet(&np_owner) || !li2_rseq_pair_quiet(&np_owner)))
        return np_bad(LI2_NP_STATE,1);
    if(cold)li2_rseq_pair_preentry(&np_owner); /* pure current cold guard, even for direct API callers */
    NP.in_handler=1;NP.phase=retry?LI2_NP_REFAULTING:LI2_NP_ENTERING;
    if(!np_identity() || li2_lifecycle_fetch_interlock())return np_bad(LI2_NP_IDENTITY,1);
    if(NP.events==UINT64_MAX)return np_bad(LI2_NP_OVERFLOW,3);
    ++NP.events;NP.signal_number=sig;NP.signal_code=si->si_code;NP.signal_errno=si->si_errno;
    NP.signal_address=(uintptr_t)si->si_addr;
    const greg_t *g=uc->uc_mcontext.gregs;NP.pc=(uintptr_t)g[REG_RIP];
    uint64_t mask=0;copy(&mask,&uc->uc_sigmask,8);uint64_t flags=(uint64_t)g[REG_EFL];
    if(sig!=SIGSEGV || si->si_signo!=SIGSEGV || si->si_code!=SEGV_ACCERR || si->si_errno ||
       g[REG_TRAPNO]!=14 || g[REG_ERR]!=21 || ((uint64_t)g[REG_CSGSFS]&0xffff)!=0x33 ||
       mask!=NP.session->application_mask || !li2_lifecycle_known_code(NP.pc,1) ||
       NP.signal_address<NP.pc || NP.signal_address-NP.pc>14 || (uintptr_t)g[REG_CR2]!=NP.signal_address)
        return np_bad(LI2_NP_FOREIGN,sig);
    if((flags&LI2_STEP_TF) || !(flags&LI2_STEP_RF) || (cold && flags!=(*logical_flags|LI2_STEP_RF)))
        return np_bad(LI2_NP_FLAGS,(long)flags);
    copy(&np_owner.saved_uc,uc,sizeof(*uc));copy(&np_owner.saved_si,si,sizeof(*si));
    struct li2_step_frame *frame=retry?&NP.second:&NP.first;
    if(!retry){NP.first_observed=0;NP.second_observed=0;}
    if(np_capture(frame,uc))return (int)NP.first_error;
    if(retry)NP.second_observed=1;else NP.first_observed=1;
    int result=LI2_NP_FALLBACK;
    if(retry) {
        if(np_retry())return (int)NP.first_error;
        NP.logical_flags=flags&~LI2_STEP_RF;*logical_flags=NP.logical_flags;
    } else if(cold) {
        if(NP.signal_address==NP.pc) {
            int admitted=0;if(np_seed(NP.pc,&admitted))return (int)NP.first_error;
            if(admitted)result=LI2_NP_RESUME;
        } else NP.phase=LI2_NP_IDLE; /* unchanged old cross-page instruction route */
    } else {
        if(np_rseq_result(li2_rseq_pair_enter(&np_owner)))return (int)NP.first_error;
        if(NP.signal_address!=NP.pc) {
            uintptr_t page=NP.pc&~(LI2_STEP_PAGE-1);unsigned found=0;
            const struct li2_native_pair_lifecycle *l=li2_lifecycle_pair_progress();
            for(unsigned i=0;i<l->live;i++)if(l->slots[i].page.address==page && l->slots[i].published==1)++found;
            if(found!=1 || page>UINTPTR_MAX-LI2_STEP_PAGE || NP.signal_address!=page+LI2_STEP_PAGE ||
               NP.refaults==UINT64_MAX)return np_bad(LI2_NP_FOREIGN,1);
            if(np_close(LI2_NP_STRADDLER,1))return (int)NP.first_error;
            ++NP.refaults;result=LI2_NP_REFAULT;
        } else {
            /* Refresh the current pin/TLS before any owner-internal extension
               RAW. Current native bases are observations, not stale inputs. */
            if(np_rseq_result(li2_rseq_pair_refresh(&np_owner,0)))return (int)NP.first_error;
            if(NP.live==1) {
                NP.phase=LI2_NP_EXTENDING;int eligible=0;
                if(np_life_result(li2_lifecycle_pair_prepare(&np_owner,NP.pc,&eligible)))return (int)NP.first_error;
                if(eligible) {
                    if(NP.extensions==UINT64_MAX)return np_bad(LI2_NP_OVERFLOW,4);
                    if(np_life_result(li2_lifecycle_pair_publish(&np_owner,NP.pc)) ||
                       np_rseq_result(li2_rseq_pair_published(&np_owner)))return (int)NP.first_error;
                    ++NP.extensions;NP.live=2;NP.phase=LI2_NP_EXECUTING_TWO;result=LI2_NP_RESUME;
                } else if(np_close(LI2_NP_POLICY,0))return (int)NP.first_error;
            } else if(NP.live==2) {
                if(np_close(LI2_NP_CAPACITY,0))return (int)NP.first_error;
                int admitted=0;if(np_seed(NP.pc,&admitted))return (int)NP.first_error;
                if(admitted)result=LI2_NP_RESUME;
            } else return np_bad(LI2_NP_STATE,2);
            if(result==LI2_NP_FALLBACK){NP.logical_flags=flags&~LI2_STEP_RF;*logical_flags=NP.logical_flags;}
        }
    }
    if(np_unchanged(si,uc,frame))return (int)NP.first_error;
    NP.entry_pending=0;NP.in_handler=0;
    if(result==LI2_NP_FALLBACK && !li2_native_pair_quiet())return np_bad(LI2_NP_STATE,3);
    return result;
}
#undef NP
