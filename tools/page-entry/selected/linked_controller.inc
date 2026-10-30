#ifdef LI2_LINKED_PREEDGE_CAPTURE
#include "linked_preedge_observe.h"
#endif
#ifdef LI2_SPAN_FAST_BYTES
#include "span_fast_bytes.h"
#endif
/* Distinct genuine-TRACE linked graph owner. The unchanged scalar-region
   owner remains earlier in the runtime. Primary graph proofs are actual R/NX
   publications; code follows W^X. No memfd seal is invented for anonymous
   memory. CPU load operands are never pre-read by this controller. */
#include "linked_source.h"
#ifdef LI2_LINKED_NATIVE_HINT
#include "linked_native_hint.h"
#endif
#ifdef LI2_LINKED_EPOCH_CAPTURE
#ifdef LI2_LINKED_EPOCH_REUSE_CAPTURE
#include "linked_epoch_reuse_observe.h"
#else
#include "linked_epoch_observe.h"
#endif
#endif
#include "linked_rseq.h"
#include "linked_proof.h"
#ifdef LI2_LINKED_PREEDGE
#include "linked_preedge_proof.h"
#if LI2_LINKED_PREEDGE != 1 || defined(LI2_LINKED_EPOCH_CAPTURE) || defined(LI2_LINK_GRAPH_OBSERVE)
#error "pre-edge v2 requires its own capture/observer adapter; old wire is rejected"
#endif
#endif
#include "tf_span_transfer.h"
#include "private_code_query.h"
#if !defined(LI2_LINKED_EPOCH) || LI2_LINKED_EPOCH != 1 || LI2_SCALAR_SPAN_TRACE != 1
#error "literal scalar reuse profile only"
#endif
#if LI2_SCALAR_SPAN != 1 || LI2_UNROLLED_HASH != 1 || LI2_NATIVE_PAIR != 1 || \
    LI2_MAPS_MAINTAINED != 1 || LI2_RUN_CACHE_REUSE != 1 || LI2_TF_HANDOFF != 1 || \
    LI2_REPEAT_RX_LEASE != 1 || LI2_RSEQ_INACTIVE != 1
#error "scalar region requires the unchanged complete unrolled/native-pair profile"
#endif
#ifdef LI2_SCALAR_SPAN_CAPTURE
#error "linked epoch requires a distinct full-state wire; old span capture is not accepted"
#endif
#ifdef LI2_EVENT_PROFILE
#error "the old event route table has no scalar-region row"
#endif
_Static_assert(__atomic_always_lock_free(sizeof(uint64_t),0),"no external event counter gateway");
#define LE_PAGES 64U
#define LE_BYTES (LE_PAGES*PAGE)
enum le_error { LE_STATE=3100,LE_FRAME,LE_SOURCE,LE_PUBLICATION,LE_EVENT,
    LE_RESULT,LE_REENTRY,LE_OVERFLOW,LE_TLS,LE_RELEASE,LE_PLAN,LE_RSEQ };
struct le_frame {
    unsigned started,si_saved,uc_saved,complete;
    int sig;
    siginfo_t si;
    ucontext_t uc;
    struct li2_step_frame frame;
    uint64_t fs,gs;
    long fs_result,gs_result;
    unsigned tls_complete;
};
struct le_permission {
    unsigned started,returned,sync_started,sync_returned,complete;
    int prot;
    long result,sync_result;
    struct li2_private_code_query query;
};
struct le_slot {
    unsigned installed,complete;
    uint64_t identity;
    size_t filled,verified;
    uintptr_t generated,proof; /* Payload is actual R/NX, not a mutable mirror. */
    struct li2_private_code_query writable;
    struct le_permission publication;
};
struct le_record {
    unsigned slot_present,slot,redirected,exit_seen,completed,release_started,release_complete;
    unsigned cleanup_started,cleanup_complete,unexpected_seen,build_started,build_returned;
    int release_result,map_result,build_result;
    uint64_t flags,gpr_written,flags_written;
    unsigned exit_index;
    struct li2_span_source source;
    struct le_frame ingress,before,after,unexpected;
    struct li2_span_transfer_progress transfer;
    unsigned close_started,close_complete,prepare_started,prepare_complete;
    unsigned miss_release_started,miss_release_complete,resume_started,resume_complete;
    int prepare_result,miss_release_result,resume_result;
    unsigned refault_started,refault_complete;
    int refault_result;
#ifdef LI2_LINKED_NATIVE_HINT
    unsigned hint_checked,hint_hit;
    uint64_t hint_publication;
#endif
    enum li2_chain_result resumed_route;
    struct li2_fetch_progress miss_fetch;
    struct li2_region_pc original;
    struct li2_private_code_query idle,live;
    size_t idle_bytes,live_bytes,closed_bytes;
    struct le_permission open,close,cleanup;
    struct li2_fetch_progress final_fetch;
    uint64_t publication_generation,cold_plan_proof,cold_none_proof;
#ifdef LI2_LINKED_PREEDGE
    struct li2_preedge_epoch_token epoch;
#else
    struct li2_link_epoch_token epoch;
#endif
#ifdef LI2_LINKED_PREEDGE
    struct li2_preedge_epoch_progress epoch_final;
#else
    struct li2_link_epoch_progress epoch_final;
#endif
    struct li2_link_rseq_live live_rseq[4];
    struct li2_private_code_query proof_before,proof_enter,proof_exit;
};
static struct {
    unsigned initialized,first_error,metadata_registered,arena_registered,allocated;
    unsigned low_arena_registered,low_allocated;
    long first_detail,allocation_result,low_allocation_result;
    uintptr_t arena,low_arena;
    size_t used;
    uint64_t offers,closed,resumed,hash_misses,refaults;
#ifdef LI2_LINKED_NATIVE_HINT
    uint64_t graph_refaults;
#endif
    uint64_t candidates,source_misses,plan_misses,capacity_misses,publications,hits;
    uint64_t entries,completed,unexpected,events,signals[5],refusals[4],exit_counts[LI2_REGION_EXITS];
    uint64_t plan_checks,rseq_checks,live_checks,proof_checks;
#ifdef LI2_LINKED_PREEDGE
    uint64_t cut_exits; /* Completed original in-page NX, before cut effects. */
#endif
    struct li2_step_session session;
    struct li2_private_code_query initial,low_initial;
#ifdef LI2_LINKED_PREEDGE
    struct li2_preedge_plan scratch; /* Reusable unpublished description only. */
#else
    struct li2_link_plan scratch; /* Reusable unpublished description only. */
#endif
    struct le_slot slots[LE_PAGES];
    struct le_record current,last;
} selected_linked_epoch;
static volatile sig_atomic_t selected_linked_epoch_active,selected_linked_epoch_busy;
static volatile sig_atomic_t selected_linked_epoch_failing,selected_linked_epoch_decoding;
static volatile sig_atomic_t selected_linked_epoch_closing,selected_linked_epoch_resuming;
static const struct li2_tf_span_transfer *selected_linked_epoch_ticket;
struct le_proof_publication {
    unsigned started,complete;
    size_t zeroed,copied,verified;
#ifdef LI2_LINKED_PREEDGE
    struct li2_preedge_proof_header header;
#else
    struct li2_link_proof_header header;
#endif
    struct li2_private_code_query writable;
    struct le_permission sealed;
};
static struct {
    unsigned initialized,registered,allocated,arena_registered,pending;
    long allocation_result;
    uintptr_t arena,target;
    size_t slot;
    uint64_t ready_generation[LE_PAGES];
    struct le_proof_publication slot_publication[LE_PAGES];
    struct li2_private_code_query initial[16];
    struct le_permission close,writable,cleanup;
#ifdef LI2_LINKED_PREEDGE
    struct li2_preedge_proof scratch;
#else
    struct li2_link_proof scratch;
#endif
} lep;
static void le_proof_initialize(void);
static int le_proof_ready(const struct le_slot *);
static int le_proof_check(const struct le_slot *,struct li2_private_code_query *);
static void le_proof_writable(size_t);
static void le_proof_publish(struct le_slot *);
static void le_proof_abort(void);
static void ler_initialize(void);
static void ler_abort(void);
static int ler_claimed(void);
static _Noreturn void selected_linked_epoch_abort(unsigned,long);
static void le_need(int yes,unsigned code,long detail) {
    if(!yes)selected_linked_epoch_abort(code,detail);
}

#ifdef LI2_LINKED_PREEDGE
static const struct li2_preedge_proof *le_payload(const struct le_slot *s) {
#else
static const struct li2_link_proof *le_payload(const struct le_slot *s) {
#endif
    return (const void *)s->proof;
}
#ifdef LI2_LINKED_PREEDGE
static const struct li2_preedge_plan *le_plan(const struct le_slot *s) {return &le_payload(s)->plan;}
#else
static const struct li2_link_plan *le_plan(const struct le_slot *s) {return &le_payload(s)->plan;}
#endif
static const struct li2_span_source_key *le_key(const struct le_slot *s) {return &le_payload(s)->key;}

static void le_count(uint64_t *p) {le_need(*p!=UINT64_MAX,LE_OVERFLOW,0);++*p;}

static void le_event_count(uint64_t *p) {
    uint64_t old=__atomic_load_n(p,__ATOMIC_RELAXED);
    le_need(old!=UINT64_MAX,LE_OVERFLOW,2);
    le_need(__atomic_compare_exchange_n(p,&old,old+1,0,__ATOMIC_RELAXED,__ATOMIC_RELAXED),LE_REENTRY,0);
}

static uint32_t le_u32(const unsigned char *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}

#ifdef LI2_SPAN_FAST_BYTES
static void le_zero(void *p,size_t n) { li2_span_bytes_zero(p,n); }
#else
static void le_zero(void *p,size_t n) {
    unsigned char *b=p;for(size_t i=0;i<n;i++)b[i]=0;
}
#endif

static int le_range(const void *p,size_t n) {
    uintptr_t a=(uintptr_t)p,b=(uintptr_t)fork_gate_stack.ss_sp;
    return p && n && b<=UINTPTR_MAX-fork_gate_stack.ss_size &&
        a>=b && a<=b+fork_gate_stack.ss_size && n<=b+fork_gate_stack.ss_size-a;
}

static int le_capture(struct le_frame *f,int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(f->started)return LE_FRAME;
    f->started=1;f->sig=sig;
    if(!le_range(si,sizeof(*si)) || !le_range(uc,sizeof(*uc)))return LE_FRAME;
    /* Linux x86-64 ends ucontext after its 64-signal mask; siginfo follows.
       The remaining glibc sigset_t bytes alias that distinct event record. */
    if((const unsigned char *)si!=(const unsigned char *)&uc->uc_sigmask+sizeof(f->frame.mask))return LE_FRAME;
    copy(&f->si,si,sizeof(*si));f->si_saved=1;copy(&f->uc,uc,sizeof(*uc));f->uc_saved=1;
    struct li2_step_frame *s=&f->frame;
    copy(s->greg,uc->uc_mcontext.gregs,sizeof s->greg);copy(&s->mask,&uc->uc_sigmask,8);
    s->fp_address=(uintptr_t)uc->uc_mcontext.fpregs;
    if((s->fp_address&15) || !le_range((void *)s->fp_address,512))return LE_FRAME;
    const unsigned char *p=(void *)s->fp_address;size_t n=512;
    if(le_u32(p+464)==UINT32_C(0x46505853)) {
        n=le_u32(p+468);size_t x=le_u32(p+480);
        if(n<580 || n>LI2_STEP_FP_BYTES || x<576 || x>n-4 ||
           !le_range(p,n) || le_u32(p+n-4)!=UINT32_C(0x46505845))return LE_FRAME;
    }
    s->fp_bytes=n;for(size_t i=0;i<n;i++){s->fp[i]=p[i];s->initialized=i+1;}
    f->complete=1;return 0;
}

static int le_unchanged(const struct le_frame *f,const siginfo_t *si,const ucontext_t *uc) {
    return f->complete && le_range(si,sizeof(*si)) && le_range(uc,sizeof(*uc)) &&
        equal(si,&f->si,sizeof(*si)) && equal(uc,&f->uc,sizeof(*uc)) &&
        le_range(uc->uc_mcontext.fpregs,f->frame.fp_bytes) &&
        equal(uc->uc_mcontext.fpregs,f->frame.fp,f->frame.fp_bytes);
}

static void le_tls(struct le_frame *f) {
    f->fs_result=raw(SYS_arch_prctl,ARCH_GET_FS,(long)&f->fs,0,0,0,0);
    f->gs_result=raw(SYS_arch_prctl,ARCH_GET_GS,(long)&f->gs,0,0,0,0);
    le_need(!f->fs_result && !f->gs_result,LE_TLS,0);f->tls_complete=1;
}

static int le_identity(void) {
    const struct li2_step_session *s=&selected_linked_epoch.session;
    return equal(s,&selected_session,sizeof(*s)) && s->initialized && s->self_test_complete &&
        s->pid>0 && s->pid==s->tid && s->sync_query>=0 && (s->sync_query&96)==96 &&
        !s->sync_register && raw(SYS_getpid,0,0,0,0,0,0)==s->pid &&
        raw(SYS_gettid,0,0,0,0,0,0)==s->tid;
}

static int le_protected(void) {
    return selected_run_protection.context==0 &&
        selected_run_protection.add==selected_run_protect_add &&
        selected_run_protection.contains==selected_run_protect_contains &&
        selected_run_protect_contains(0,(uintptr_t)&selected_linked_epoch,sizeof selected_linked_epoch)==1 &&
        selected_run_protect_contains(0,selected_linked_epoch.arena,LE_BYTES)==1 &&
        selected_run_protect_contains(0,selected_linked_epoch.low_arena,LE_BYTES)==1;
}

static int le_query(uintptr_t entry,int prot,struct li2_private_code_query *q) {
    int e=li2_lifecycle_private_code_query(entry,PAGE,prot,q);
    return e || !q->complete || q->pages_checked!=1 || q->actual_prot!=prot?LE_PUBLICATION:0;
}

static int le_permission(struct le_slot *s,int prot,struct le_permission *p) {
    if(p->started)return LE_STATE;
    p->prot=prot;p->started=1;__asm__ volatile("":::"memory");
    p->result=raw(SYS_mprotect,s->generated,PAGE,prot,0,0,0);p->returned=1;
    p->sync_started=1;__asm__ volatile("":::"memory");
    p->sync_result=raw(SYS_membarrier,32,0,0,0,0,0);p->sync_returned=1;
    int q=le_query(s->generated,prot,&p->query);
    if(p->result || p->sync_result || q)return LE_PUBLICATION;
    p->complete=1;return 0;
}

static void le_nx(const struct le_frame *f,uintptr_t pc) {
    const greg_t *g=f->frame.greg;
    le_need(f->complete && f->sig==SIGSEGV && f->si.si_signo==SIGSEGV &&
        f->si.si_code==SEGV_ACCERR && !f->si.si_errno && g[REG_TRAPNO]==14 && g[REG_ERR]==21 &&
        (uintptr_t)g[REG_RIP]==pc && (uintptr_t)f->si.si_addr==pc &&
        (uintptr_t)g[REG_CR2]==pc &&
        ((uint64_t)g[REG_CSGSFS]&65535)==0x33 && (uint64_t)g[REG_RSP]<(UINT64_C(1)<<47) &&
        f->frame.mask==selected_linked_epoch.session.application_mask,LE_EVENT,f->sig);
}
/* The original helper checks every old step/run/REP/effect/native/rseq owner.
   Add the actual unrolled owner itself; never forge its route or old plan. */
static int le_quiet(const struct li2_fetch_ref *ref) {
    return selected_scalar_region.initialized==1 && !selected_scalar_region_active &&
        !selected_scalar_region_busy && !selected_scalar_region_failing &&
        !selected_scalar_region_decoding && !selected_scalar_region.first_error &&
        selected_pending_route!=SELECTED_SCALAR_REGION &&
        selected_scalar_region.entries==selected_scalar_region.completed &&
        selected_scalar_region.used<=SR_PAGES && srr_protected() && !srr.pending && !srr.retiring &&
        uh_quiet(ref) && selected_unrolled.initialized==1 &&
        !selected_unrolled_active && !selected_unrolled_busy && !selected_unrolled_failing &&
        !selected_unrolled.first_error && selected_pending_route!=SELECTED_UNROLLED_HASH &&
        selected_unrolled.entries==selected_unrolled.completed &&
        selected_unrolled.publications==selected_unrolled.used && selected_unrolled.used<=LE_PAGES;
}
static int le_bytes(const struct le_slot *s,size_t *observed) {
    const volatile unsigned char *p=(void *)le_plan(s)->generated;
    for(size_t i=0;i<PAGE;i++) {
        if(p[i]!=le_plan(s)->image[i])return LE_PUBLICATION;
        *observed=i+1;
    }
    return 0;
}
#ifdef LI2_LINKED_PREEDGE
static int le_rebuild(const struct li2_preedge_plan *p) {
#else
static int le_rebuild(const struct li2_link_plan *p) {
#endif
    le_need(!selected_linked_epoch_decoding,LE_REENTRY,1);
    selected_linked_epoch_decoding=1;__asm__ volatile("":::"memory");
#ifdef LI2_LINKED_PREEDGE
    int e=li2_preedge_plan_validate(p);
#else
    int e=li2_link_plan_validate(p);
#endif
    __asm__ volatile("":::"memory");selected_linked_epoch_decoding=0;
    selected_initialized();le_count(&selected_linked_epoch.plan_checks);return e;
}
#ifdef LI2_LINKED_PREEDGE
static int le_rseq(const struct li2_preedge_plan *p,const ucontext_t *uc) {
#else
static int le_rseq(const struct li2_link_plan *p,const ucontext_t *uc) {
#endif
    le_need(!selected_linked_epoch_decoding,LE_REENTRY,2);
    selected_linked_epoch_decoding=1;__asm__ volatile("":::"memory");
#ifdef LI2_LINKED_PREEDGE
    int e=li2_rseq_check_preedge_cold(p,uc);
#else
    int e=li2_rseq_check_link_cold(p,uc);
#endif
    __asm__ volatile("":::"memory");selected_linked_epoch_decoding=0;
    selected_initialized();le_count(&selected_linked_epoch.rseq_checks);return e;
}
static int le_live(const ucontext_t *uc,struct li2_link_rseq_live *out) {
    int e=li2_rseq_link_live(uc,out);le_count(&selected_linked_epoch.live_checks);return e;
}
/* Terminal association does not recursively re-enter an interrupted decoder.
   These are the exact rows of the fully validated protected immutable plan.
   Interior/tail PCs remain MISS; no association grants resume/completion. */
static int le_map_actual(const struct le_slot *s,uintptr_t pc,struct li2_region_pc *out) {
#ifdef LI2_LINKED_PREEDGE
    if(!s->installed || !s->complete || !le_proof_ready(s) || le_plan(s)->version!=LI2_PREEDGE_VERSION ||
#else
    if(!s->installed || !s->complete || !le_proof_ready(s) || le_plan(s)->version!=LI2_LINK_VERSION ||
#endif
#ifdef LI2_LINKED_PREEDGE
       le_plan(s)->ready!=1 || !le_plan(s)->maps || le_plan(s)->maps>LI2_PREEDGE_MAPS)
#else
       le_plan(s)->ready!=1 || !le_plan(s)->maps || le_plan(s)->maps>LI2_LINK_MAPS)
#endif
        return LI2_REGION_PLAN_CORRUPT;
    if(!ler_claimed())return LI2_REGION_PLAN_CORRUPT;
    for(size_t i=0;i<le_plan(s)->maps;i++) {
        const struct li2_region_pc *m=&le_plan(s)->map[i];
        if(m->generated_pc==pc) {copy(out,m,sizeof *out);return LI2_REGION_PLAN_OK;}
    }
    return LI2_REGION_PLAN_MISS;
}
static _Noreturn void selected_linked_epoch_abort(unsigned code,long detail) {
    if(!selected_linked_epoch.first_error) {
        selected_linked_epoch.first_error=code;selected_linked_epoch.first_detail=detail;
    }
    if(selected_linked_epoch_failing) {
        (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    selected_linked_epoch_failing=1;selected_linked_epoch_busy=1;li2_maps_phase_fail();
    /* A CLOSING predecessor or RESUMING successor still has the actual chain
       permission owner. Never substitute the new unpublished slot cleanup. */
    if(selected_linked_epoch_closing || selected_linked_epoch_resuming)
        li2_tf_chain_abort(&selected_chain,code,detail);
    struct le_record *r=&selected_linked_epoch.current;
    const struct li2_span_transfer_progress *t=li2_tf_chain_span_progress();
    if(r->close_started && t && t->event==selected_chain.event_id)
        copy(&r->transfer,t,sizeof r->transfer);
    ler_abort();le_proof_abort();
    const struct li2_fetch_progress *p=li2_lifecycle_fetch_progress();
    if(p)copy(&r->final_fetch,p,sizeof r->final_fetch);
    li2_lifecycle_abort();
#ifdef LI2_LINKED_EPOCH_CAPTURE
    leto_abort_observe();
#endif
#ifdef LI2_LINKED_PREEDGE_CAPTURE
    lpeo_abort_observe();
#endif
    report(125,selected_linked_epoch.first_error,selected_linked_epoch.first_detail);
    (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static _Noreturn void selected_linked_epoch_unexpected(int sig,siginfo_t *si,ucontext_t *uc) {
    struct le_record *r=&selected_linked_epoch.current;
    if(!r->unexpected_seen) {
        r->unexpected_seen=1;
        if(selected_linked_epoch.unexpected!=UINT64_MAX)++selected_linked_epoch.unexpected;
        int e=le_capture(&r->unexpected,sig,si,uc);
        r->map_result=e?e:LI2_REGION_PLAN_MISS;
        if(!e && !handling && selected_linked_epoch_active && r->redirected && !r->completed &&
           r->open.complete && r->slot_present && r->slot<selected_linked_epoch.used) {
            const struct le_slot *s=&selected_linked_epoch.slots[r->slot];
            const struct li2_fetch_progress *f=li2_lifecycle_fetch_progress();
            if(
               ler_claimed() &&
               s->publication.complete &&
               s->filled==PAGE && s->verified==PAGE && r->source.ready==1 &&
               r->source.borrow.owner==selected_borrow.owner &&
               r->source.borrow.sequence==selected_borrow.sequence && f && f->held && f->complete &&
               !f->first_error && f->sequence==r->source.borrow.sequence &&
               li2_span_source_key_equal(le_key(s),&r->source.key) &&
               le_plan(s)->page==le_key(s)->page.address && le_plan(s)->entry==le_key(s)->entry &&
               le_plan(s)->generated==(le_key(s)->entry<(UINT64_C(1)<<31)?selected_linked_epoch.low_arena:
                   selected_linked_epoch.arena)+(uintptr_t)r->slot*PAGE)
                r->map_result=le_map_actual(s,(uintptr_t)r->unexpected.frame.greg[REG_RIP],&r->original);
        }
    }
    if(selected_linked_epoch_closing || selected_linked_epoch_resuming) {
        if(!selected_linked_epoch.first_error) {
            selected_linked_epoch.first_error=LE_EVENT;selected_linked_epoch.first_detail=sig;
        }
        li2_tf_chain_unexpected(&selected_chain,sig,si,uc);
    }
    selected_linked_epoch_abort(LE_EVENT,sig);
}
#ifdef LI2_LINKED_PREEDGE
static int le_exit_index(const struct li2_preedge_plan *p,uintptr_t pc) {
#else
static int le_exit_index(const struct li2_link_plan *p,uintptr_t pc) {
#endif
    if(p->ready!=1 || !p->exits || p->exits>LI2_REGION_EXITS)return -1;
    for(unsigned i=0;i<p->exits;i++)if(p->exit_pc[i]==pc)return (int)i;
    return -1;
}
/* Runs after the unchanged pure native/rseq guards and BEFORE returning RAW,
   map/event callbacks or any old pending-owner route. */
static void selected_linked_epoch_preentry(int sig,siginfo_t *si,ucontext_t *uc) {
    le_event_count(&selected_linked_epoch.events);
    unsigned kind=sig==SIGSEGV?0:sig==SIGTRAP?1:sig==SIGILL?2:sig==SIGSYS?3:4;
    le_event_count(&selected_linked_epoch.signals[kind]);
    int routed=selected_pending_route==SELECTED_LINKED_EPOCH;
    if(!selected_linked_epoch_active && !selected_linked_epoch_busy &&
       !selected_linked_epoch_closing && !selected_linked_epoch_resuming && !routed)return;
    struct le_record *r=&selected_linked_epoch.current;
    if(selected_linked_epoch_busy || selected_linked_epoch_closing || selected_linked_epoch_resuming ||
       selected_linked_epoch_decoding ||
       !selected_linked_epoch_active || handling || !routed || selected_step_pending!=1 ||
       !r->slot_present || r->slot>=selected_linked_epoch.used || !r->redirected || r->completed ||
       selected_linked_epoch.first_error || !le_range(si,sizeof(*si)) || !le_range(uc,sizeof(*uc)))
        selected_linked_epoch_unexpected(sig,si,uc);
    const struct le_slot *s=&selected_linked_epoch.slots[r->slot];
    const greg_t *g=uc->uc_mcontext.gregs;uintptr_t pc=(uintptr_t)g[REG_RIP];
    uint64_t mask=0;copy(&mask,&uc->uc_sigmask,sizeof mask);
    if(!s->installed || !s->complete || !le_proof_ready(s) || !r->open.complete || le_exit_index(le_plan(s),pc)<0 ||
       sig!=SIGSEGV || si->si_signo!=SIGSEGV || si->si_code!=SEGV_ACCERR || si->si_errno ||
       g[REG_TRAPNO]!=14 || g[REG_ERR]!=21 || (uintptr_t)si->si_addr!=pc || (uintptr_t)g[REG_CR2]!=pc ||
       ((uint64_t)g[REG_EFL]&(SELECTED_TF|SELECTED_RF))!=SELECTED_RF ||
       ((uint64_t)g[REG_CSGSFS]&65535)!=0x33 || (uint64_t)g[REG_RSP]>=(UINT64_C(1)<<47) ||
       mask!=selected_linked_epoch.session.application_mask)
        selected_linked_epoch_unexpected(sig,si,uc);
}
static void selected_linked_epoch_initialize(void) {
    le_need(!selected_linked_epoch.initialized && !selected_linked_epoch_active &&
        !selected_linked_epoch_busy,LE_STATE,1);selected_linked_epoch_busy=1;
    copy(&selected_linked_epoch.session,&selected_session,sizeof selected_session);
    le_need(le_identity() && !li2_lifecycle_fetch_interlock() &&
        selected_unrolled.initialized && !selected_unrolled_active && !selected_unrolled_busy &&
        selected_scalar_region.initialized && !selected_scalar_region_active && !selected_scalar_region_busy,
        LE_STATE,2);
    le_need(!selected_run_protect_add(0,(uintptr_t)&selected_linked_epoch,sizeof selected_linked_epoch),LE_STATE,3);
    selected_linked_epoch.metadata_registered=1;
    selected_linked_epoch.allocation_result=raw(SYS_mmap,0,LE_BYTES,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    long a=selected_linked_epoch.allocation_result;
    le_need(!(a<0 && a>=-4095) && a>0 && !((uintptr_t)a&(PAGE-1)) &&
        (uintptr_t)a<(UINT64_C(1)<<47)-LE_BYTES,LE_PUBLICATION,a);
    selected_linked_epoch.arena=(uintptr_t)a;selected_linked_epoch.allocated=1;
    le_need(!selected_run_protect_add(0,(uintptr_t)a,LE_BYTES),LE_STATE,4);
    selected_linked_epoch.arena_registered=1;
    selected_linked_epoch.low_allocation_result=raw(SYS_mmap,0,LE_BYTES,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT,-1,0);
    long low=selected_linked_epoch.low_allocation_result;
    le_need(!(low<0 && low>=-4095) && low>0 && !((uintptr_t)low&(PAGE-1)) &&
        (uintptr_t)low<=(UINT64_C(1)<<31)-LE_BYTES,LE_PUBLICATION,low);
    selected_linked_epoch.low_arena=(uintptr_t)low;selected_linked_epoch.low_allocated=1;
    le_need((uintptr_t)low+LE_BYTES<=(uintptr_t)a || (uintptr_t)a+LE_BYTES<=(uintptr_t)low,LE_PUBLICATION,10);
    le_need(!selected_run_protect_add(0,(uintptr_t)low,LE_BYTES),LE_STATE,10);
    selected_linked_epoch.low_arena_registered=1;le_need(le_protected(),LE_STATE,5);
    int e=li2_lifecycle_private_code_query(a,LE_BYTES,PROT_READ|PROT_WRITE,&selected_linked_epoch.initial);
    le_need(!e && selected_linked_epoch.initial.complete && selected_linked_epoch.initial.pages_checked==LE_PAGES,
        LE_PUBLICATION,e);
    e=li2_lifecycle_private_code_query(low,LE_BYTES,PROT_READ|PROT_WRITE,&selected_linked_epoch.low_initial);
    le_need(!e && selected_linked_epoch.low_initial.complete && selected_linked_epoch.low_initial.pages_checked==LE_PAGES,
        LE_PUBLICATION,e);
    ler_initialize();le_proof_initialize();
#ifdef LI2_LINKED_PREEDGE
    le_need(!li2_lifecycle_preedge_initialize(),LE_SOURCE,414);
#else
    le_need(!li2_lifecycle_link_initialize(),LE_SOURCE,414);
#endif
    selected_linked_epoch.initialized=1;selected_linked_epoch_busy=0;
#ifdef LI2_LINKED_EPOCH_CAPTURE
    leto_initialize();
#endif
#ifdef LI2_LINKED_PREEDGE_CAPTURE
    lpeo_initialize();
#endif
}
static uintptr_t le_entry(uintptr_t pc,size_t slot) {
    uintptr_t arena=pc<(UINT64_C(1)<<31)?selected_linked_epoch.low_arena:selected_linked_epoch.arena;
    return arena+slot*PAGE;
}
#include "linked_reuse.inc"
#include "linked_proof.inc"
static int le_refusal(int result) {
    return result==LI2_REGION_PLAN_MISS?0:result==LI2_REGION_PLAN_BOUNDARY?1:
        result==LI2_REGION_PLAN_GRAPH?2:result==LI2_REGION_PLAN_RELOCATION?3:-1;
}
/* Union only: these are definitely-unchanged masks, not an executed-path
   reconstruction. All affected outputs/undefined flags remain actual. */
#ifdef LI2_LINKED_PREEDGE
static void le_effects(const struct li2_preedge_plan *p,struct le_record *r) {
#else
static void le_effects(const struct li2_link_plan *p,struct le_record *r) {
#endif
    le_need(p->heads && p->heads<=LI2_REGION_HEADS,LE_PLAN,1);
    for(size_t i=0;i<p->heads;i++) {
        const struct li2_span_decoded *d=&p->original[i];
        r->gpr_written|=d->gpr_write;
        r->flags_written|=d->flags_written|d->flags_set|d->flags_cleared|d->flags_undefined;
    }
    le_need(!(r->gpr_written&~UINT64_C(0xffff)) && !(r->gpr_written&(UINT64_C(1)<<4)) &&
        !(r->flags_written&~UINT64_C(0x8d5)),LE_PLAN,2);
}
/* This helper is entered only with the actual closed predecessor ticket and
   a newly prepared full15 borrow. No descriptive refusal clears the busy guard;
   the wrapper must release that real borrow and consume RESUMING instead. */
static int selected_linked_epoch_try(int sig,siginfo_t *si,ucontext_t *uc,uint64_t flags) {
    le_need(selected_view.length==15 && selected_linked_epoch.initialized &&
        !selected_linked_epoch_active && selected_linked_epoch_busy &&
        !selected_linked_epoch.first_error && !selected_step_pending &&
        selected_pending_route==SELECTED_NO_STEP && le_quiet(&selected_borrow) &&
        !li2_tf_chain_span_quiet(selected_linked_epoch_ticket),LE_STATE,6);
    le_count(&selected_linked_epoch.candidates);
    struct le_record *r=&selected_linked_epoch.current;
    ler_begin();
    le_need(!le_capture(&r->before,sig,si,uc),LE_FRAME,0);r->flags=flags;
    const greg_t *before=r->before.frame.greg;
    le_need(sig==SIGTRAP && r->before.si.si_signo==SIGTRAP &&
        r->before.si.si_code==TRAP_TRACE && !r->before.si.si_errno &&
        before[REG_TRAPNO]==1 && !before[REG_ERR] &&
        (uintptr_t)before[REG_RIP]==selected_view.pc &&
        (uintptr_t)r->before.si.si_addr==selected_view.pc &&
        ((uint64_t)before[REG_CSGSFS]&65535)==0x33 &&
        (uint64_t)before[REG_RSP]<(UINT64_C(1)<<47) &&
        r->before.frame.mask==selected_linked_epoch.session.application_mask &&
        !(flags&(SELECTED_TF|SELECTED_RF)) && (uint64_t)before[REG_EFL]==flags,LE_FRAME,1);
    int e=li2_lifecycle_span_source(&selected_borrow,&r->source);le_need(!e,LE_SOURCE,e);
    if(!r->source.ready) {
        le_count(&selected_linked_epoch.source_misses);le_need(le_unchanged(&r->before,si,uc),LE_FRAME,2);
        return 0;
    }
    le_need(r->source.ready==1 && r->source.key.entry==selected_view.pc &&
        r->source.borrow.owner==selected_borrow.owner && r->source.borrow.sequence==selected_borrow.sequence &&
        le_identity() && le_protected(),LE_SOURCE,0);le_tls(&r->before);
#ifdef LI2_LINKED_EPOCH_CAPTURE
    leto_source();
#endif
#ifdef LI2_LINKED_PREEDGE_CAPTURE
    lpeo_source();
#endif
    /* Preserve the larger existing bounded-hash opportunity. This exact literal
       is only a descriptive decline; the old route still owns its own proof. */
    static const unsigned char hash_head[26]={
        0x48,0x89,0xd8,0x48,0x83,0xc1,0x01,0x48,0xc1,0xe0,0x05,0x48,
        0x01,0xc3,0x48,0x01,0xd3,0x0f,0xb6,0x11,0x84,0xd2,0x75,0xe8,0x89,0xdb};
    size_t offset=(size_t)(r->source.key.entry-r->source.key.page.address);
    if(offset<=PAGE-sizeof hash_head && equal(r->source.key.bytes+offset,hash_head,sizeof hash_head)) {
        le_count(&selected_linked_epoch.hash_misses);
        le_need(le_unchanged(&r->before,si,uc),LE_FRAME,8);return 0;
    }
    size_t slot=0;
    while(slot<selected_linked_epoch.used) {
        const struct le_slot *candidate=&selected_linked_epoch.slots[slot];
        le_need(le_proof_ready(candidate),LE_PUBLICATION,410);
        if(li2_span_source_key_equal(le_key(candidate),&r->source.key))break;
        ++slot;
    }
    int reuse_hit=slot<selected_linked_epoch.used;
    if(!reuse_hit) {
        if(slot==LE_PAGES)slot=ler_choose();
        if(slot==LE_PAGES) {
            le_count(&selected_linked_epoch.capacity_misses);le_need(le_unchanged(&r->before,si,uc),LE_FRAME,3);
            return 0;
        }
        uintptr_t entry=le_entry(r->source.key.entry,slot);
        le_need(!selected_linked_epoch_decoding,LE_REENTRY,3);
        r->build_started=1;selected_linked_epoch_decoding=1;__asm__ volatile("":::"memory");
#ifdef LI2_LINKED_PREEDGE
        e=li2_preedge_plan_page(r->source.key.page.address,r->source.key.bytes,r->source.key.entry,
#else
        e=li2_link_plan_page(r->source.key.page.address,r->source.key.bytes,r->source.key.entry,
#endif
            entry,&selected_linked_epoch.scratch);
        r->build_result=e;r->build_returned=1;__asm__ volatile("":::"memory");selected_linked_epoch_decoding=0;
        selected_initialized();int refusal=le_refusal(e);
        if(refusal>=0) {
            le_need(!selected_linked_epoch.scratch.ready && !selected_linked_epoch.scratch.decoder_result,
                LE_PLAN,e);le_count(&selected_linked_epoch.plan_misses);
            le_count(&selected_linked_epoch.refusals[refusal]);
            le_need(le_unchanged(&r->before,si,uc) && le_quiet(&selected_borrow),LE_FRAME,4);
            return 0;
        }
        le_need(!e && !le_rebuild(&selected_linked_epoch.scratch),LE_PLAN,e);
        r->cold_plan_proof=selected_linked_epoch.plan_checks;
#ifdef LI2_LINKED_PREEDGE
        le_need(!li2_lifecycle_preedge_validate(&selected_borrow,&r->source,&selected_linked_epoch.scratch) &&
#else
        le_need(!li2_lifecycle_link_validate(&selected_borrow,&r->source,&selected_linked_epoch.scratch) &&
#endif
            !le_rseq(&selected_linked_epoch.scratch,uc),LE_SOURCE,1);
        r->cold_none_proof=selected_linked_epoch.rseq_checks;
        struct le_slot *s=&selected_linked_epoch.slots[slot];
        le_need(!li2_tf_chain_span_consume(selected_linked_epoch_ticket,&selected_session,
            &selected_borrow,selected_view.pc,sig,si,uc),LE_EVENT,1);
        copy(&r->transfer,li2_tf_chain_span_progress(),sizeof r->transfer);
        ler_prepare(slot,entry,si,uc);
        le_need(!s->installed && !s->complete && !s->identity &&
            (entry+PAGE<=r->source.key.page.address || entry>=r->source.key.page.address+PAGE),LE_PUBLICATION,1);
        s->generated=entry;s->proof=lep.arena+slot*LI2_LINK_PROOF_BYTES;
        s->identity=r->publication_generation;
        /* Complete cold proof output is copied to protected RW staging before
           its one R/NX publication; no warm path has a writable mirror. */
        le_zero(&lep.scratch,sizeof lep.scratch);
        copy(&lep.scratch.key,&r->source.key,sizeof lep.scratch.key);
        copy(&lep.scratch.plan,&selected_linked_epoch.scratch,sizeof lep.scratch.plan);
        if(slot==selected_linked_epoch.used)++selected_linked_epoch.used;
        r->slot=(unsigned)slot;r->slot_present=1;s->installed=1;
        selected_pending_route=SELECTED_LINKED_EPOCH;selected_step_pending=1;
        le_need(!le_query(entry,PROT_READ|PROT_WRITE,&s->writable),LE_PUBLICATION,2);
        volatile unsigned char *p=(void *)entry;
        for(size_t i=0;i<PAGE;i++){p[i]=selected_linked_epoch.scratch.image[i];s->filled=i+1;}
        le_need(!le_permission(s,PROT_READ,&s->publication),LE_PUBLICATION,3);
        const volatile unsigned char *actual=(const void *)entry;
        for(size_t i=0;i<PAGE;i++) {
            le_need(actual[i]==selected_linked_epoch.scratch.image[i],LE_PUBLICATION,411);s->verified=i+1;
        }
        le_proof_publish(s);
        s->complete=1;le_count(&selected_linked_epoch.publications);
        ler_published(slot);
    } else {
        /* Authenticate this generation's actual R/NX primary graph/static
           NONE payload and the complete fresh source. Current live rseq state
           remains checked before consuming the genuine transfer. */
        const struct le_slot *cached=&selected_linked_epoch.slots[slot];
        le_need(cached->installed==1 && cached->complete==1 &&
            li2_span_source_key_equal(le_key(cached),&r->source.key) && !le_proof_check(cached,&r->proof_before) &&
#ifdef LI2_LINKED_PREEDGE
            !li2_lifecycle_preedge_validate(&selected_borrow,&r->source,le_plan(cached)) &&
#else
            !li2_lifecycle_link_validate(&selected_borrow,&r->source,le_plan(cached)) &&
#endif
            !le_live(uc,&r->live_rseq[0]),LE_SOURCE,7);
        le_need(!li2_tf_chain_span_consume(selected_linked_epoch_ticket,&selected_session,
            &selected_borrow,selected_view.pc,sig,si,uc),LE_EVENT,2);
        copy(&r->transfer,li2_tf_chain_span_progress(),sizeof r->transfer);
        r->slot=(unsigned)slot;r->slot_present=1;
        selected_pending_route=SELECTED_LINKED_EPOCH;selected_step_pending=1;le_count(&selected_linked_epoch.hits);
    }
    struct le_slot *s=&selected_linked_epoch.slots[slot];
    ler_claim(slot,reuse_hit);
    le_need(s->installed && s->complete &&
        ler_claimed() &&
        s->filled==PAGE && s->verified==PAGE &&
        s->publication.complete && le_plan(s)->generated==le_entry(r->source.key.entry,slot) &&
        li2_span_source_key_equal(le_key(s),&r->source.key) &&
        !le_proof_check(s,&r->proof_enter),LE_PUBLICATION,5);
    le_effects(le_plan(s),r);
    le_need(!le_query(le_plan(s)->generated,PROT_READ,&r->idle) && !le_bytes(s,&r->idle_bytes),LE_PUBLICATION,6);
#ifdef LI2_LINKED_PREEDGE
    le_need(!li2_lifecycle_preedge_validate(&selected_borrow,&r->source,le_plan(s)) &&
#else
    le_need(!li2_lifecycle_link_validate(&selected_borrow,&r->source,le_plan(s)) &&
#endif
        !le_live(uc,&r->live_rseq[1]) && le_quiet(&selected_borrow),LE_SOURCE,3);
#ifdef LI2_LINKED_PREEDGE
    le_need(!li2_lifecycle_preedge_begin(&selected_borrow,&r->source,le_plan(s),
#else
    le_need(!li2_lifecycle_link_begin(&selected_borrow,&r->source,le_plan(s),
#endif
        r->publication_generation,&r->epoch),LE_SOURCE,412);
#ifdef LI2_LINKED_EPOCH_CAPTURE
    leto_held();
#endif
#ifdef LI2_LINKED_PREEDGE_CAPTURE
    lpeo_held();
#endif
    le_need(!le_permission(s,PROT_READ|PROT_EXEC,&r->open),LE_PUBLICATION,7);
    le_need(!le_query(le_plan(s)->generated,PROT_READ|PROT_EXEC,&r->live) && !le_bytes(s,&r->live_bytes),LE_PUBLICATION,8);
#ifdef LI2_LINKED_PREEDGE
    le_need(!li2_lifecycle_preedge_validate(&selected_borrow,&r->source,le_plan(s)) &&
#else
    le_need(!li2_lifecycle_link_validate(&selected_borrow,&r->source,le_plan(s)) &&
#endif
        !le_live(uc,&r->live_rseq[2]),LE_SOURCE,4);
#ifdef LI2_LINKED_PREEDGE
    le_need(!li2_lifecycle_preedge_opened(&r->epoch,&r->source,le_plan(s)),LE_SOURCE,413);
#else
    le_need(!li2_lifecycle_link_opened(&r->epoch,&r->source,le_plan(s)),LE_SOURCE,413);
#endif
    selected_initialized();le_need(le_unchanged(&r->before,si,uc),LE_FRAME,5);
    le_count(&selected_linked_epoch.entries);selected_linked_epoch_active=1;r->redirected=1;
    __asm__ volatile("":::"memory");uc->uc_mcontext.gregs[REG_RIP]=(greg_t)le_plan(s)->generated;
    #ifdef LI2_LINKED_EPOCH_CAPTURE
    leto_redirected(sig,si,uc);
#endif
#ifdef LI2_LINKED_PREEDGE_CAPTURE
    lpeo_redirected(sig,si,uc);
#endif
    selected_linked_epoch_busy=0;return 1;
}
/* Pure coarse eligibility never releases or edits the predecessor. It is not
   a decode, page-read, fresh mapping observation, or execution permit. */
static int le_trace_coarse(int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(selected_selftesting || !selected_linked_epoch.initialized ||
       selected_linked_epoch_active || selected_linked_epoch_busy || selected_linked_epoch.first_error ||
       selected_pending_route!=SELECTED_GENERIC_TF || selected_step_pending!=1 ||
       handling!=1 || !si || !uc || selected_chain.active<0 || selected_chain.active>=2 ||
       !selected_chain.pending || selected_chain.in_handler || selected_chain.first_error)return 0;
    const struct li2_tf_chain_slot *s=&selected_chain.slots[selected_chain.active];
    const struct li2_step_owner *p=&s->owner.step;
    if(s->phase!=LI2_CHAIN_EXECUTING || p->phase!=LI2_STEP_RUNNING || p->in_handler ||
       p->request.page_count!=1 || s->fetch.page_count!=1 ||
       selected_chain.event_id<=s->event_id || sig!=SIGTRAP ||
       si->si_signo!=SIGTRAP || si->si_code!=TRAP_TRACE || si->si_errno ||
       uc->uc_mcontext.gregs[REG_TRAPNO]!=1 || uc->uc_mcontext.gregs[REG_ERR] ||
       (uintptr_t)si->si_addr!=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP] ||
       ((uint64_t)uc->uc_mcontext.gregs[REG_EFL]&(SELECTED_TF|SELECTED_RF))!=SELECTED_TF)return 0;
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    uintptr_t page=p->request.pages[0].address;
    return pc>=page && pc-page<=PAGE-15;
}
/* A relocation miss may be a native-clean page far from either generated
   arena. Give the real NX dispatcher an opportunity after a genuinely closed
   predecessor and released fresh borrow. The address/miss selector grants no
   native eligibility: the next hardware execute fault runs all existing page,
   backing, halo-policy, rseq, identity and permission checks independently. */
static int le_closed_nx_retry(int sig,siginfo_t *si,ucontext_t *uc) {
    struct le_record *r=&selected_linked_epoch.current;
    if(!r->build_started || !r->build_returned ||
#ifdef LI2_LINKED_NATIVE_HINT
       (r->build_result!=LI2_REGION_PLAN_RELOCATION && r->build_result!=LI2_REGION_PLAN_GRAPH) ||
#else
       r->build_result!=LI2_REGION_PLAN_RELOCATION ||
#endif
       r->source.key.entry<UINT64_C(0x200000000))return 0;
#ifdef LI2_LINKED_NATIVE_HINT
    if(r->build_result==LI2_REGION_PLAN_GRAPH) {
#if defined(LI2_LINKED_EPOCH_CAPTURE) && !defined(LI2_LINKED_EPOCH_REUSE_CAPTURE)
        leto_hint_before(sig,si,uc);
#endif
        r->hint_checked=1;
        r->hint_hit=(unsigned)li2_lifecycle_link_native_hint_choose(
            &r->source,r->transfer.serial,&r->hint_publication);
#if defined(LI2_LINKED_EPOCH_CAPTURE) && !defined(LI2_LINKED_EPOCH_REUSE_CAPTURE)
        leto_hint_chosen();
#endif
        if(!r->hint_hit)return 0;
    }
#endif
    le_need(selected_linked_epoch_busy && !selected_linked_epoch_active &&
        !selected_linked_epoch_closing && !selected_linked_epoch_resuming &&
        !selected_linked_epoch_decoding && !selected_step_pending &&
        selected_pending_route==SELECTED_NO_STEP && selected_flags_known==1 &&
        r->close_complete && r->prepare_complete && r->miss_release_complete &&
        !r->miss_release_result && !r->slot_present && !r->redirected &&
        !r->resume_started && !r->refault_started && !ler.pending && !ler.retiring &&
        !lep.pending && !li2_lifecycle_fetch_interlock() && le_quiet(0) &&
        !li2_tf_chain_span_quiet(selected_linked_epoch_ticket) &&
        le_unchanged(&r->before,si,uc),LE_STATE,23);
#if defined(LI2_LINKED_EPOCH_CAPTURE) && !defined(LI2_LINKED_EPOCH_REUSE_CAPTURE)
    leto_refault_before(sig,si,uc);
#endif
    r->refault_started=1;
    r->refault_result=li2_tf_chain_span_refault(selected_linked_epoch_ticket,r->transfer.serial,sig,si,uc);
    le_need(!r->refault_result,LE_EVENT,r->refault_result);
    copy(&r->transfer,li2_tf_chain_span_progress(),sizeof r->transfer);
    le_need(r->transfer.phase==LI2_ST_REFAULT && r->transfer.refault_attempted==1 &&
        r->transfer.refaulted==1 && !r->transfer.successor_installed &&
        !r->transfer.consume_attempted && !r->transfer.consumed &&
        !r->transfer.resume_attempted && !r->transfer.resumed &&
        !selected_chain.pending && !selected_chain.in_handler &&
        !li2_lifecycle_fetch_interlock() && le_quiet(0) &&
        (uint64_t)uc->uc_mcontext.gregs[REG_EFL]==selected_logical_flags &&
        le_unchanged(&r->before,si,uc),LE_STATE,24);
#ifdef LI2_LINKED_NATIVE_HINT
    r->refault_complete=1;
    if(r->build_result==LI2_REGION_PLAN_GRAPH)le_count(&selected_linked_epoch.graph_refaults);
    else le_count(&selected_linked_epoch.refaults);
#else
    r->refault_complete=1;le_count(&selected_linked_epoch.refaults);
#endif
#if defined(LI2_LINKED_EPOCH_CAPTURE) && !defined(LI2_LINKED_EPOCH_REUSE_CAPTURE)
    leto_refault_after(sig,si,uc);
#ifdef LI2_LINKED_NATIVE_HINT
    leto_hint_after();
#endif
#endif
    selected_linked_epoch_ticket=0;selected_initialized();
    /* No page is executable and no event metadata is manufactured. Returning
       the unchanged closed TRACE frame causes the original instruction fetch
       itself to raise the next SEGV_ACCERR. */
    __asm__ volatile("":::"memory");selected_linked_epoch_busy=0;return 1;
}
static int selected_linked_epoch_trace_try(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!le_trace_coarse(sig,si,uc))return 0;
    /* Visible before capture, close, and every returning RAW. Nested ingress
       routes to the real old chain until close returns, then to this owner. */
    selected_linked_epoch_closing=1;selected_linked_epoch_busy=1;
    __asm__ volatile("":::"memory");le_count(&selected_linked_epoch.offers);
    struct le_record *r=&selected_linked_epoch.current;le_zero(r,sizeof *r);
    selected_linked_epoch_ticket=0;
    le_need(!le_capture(&r->ingress,sig,si,uc),LE_FRAME,10);
#ifdef LI2_LINKED_EPOCH_CAPTURE
    leto_begin();
#endif
#ifdef LI2_LINKED_PREEDGE_CAPTURE
    lpeo_begin();
#endif
    r->close_started=1;
    int e=li2_tf_chain_span_close(&selected_chain,sig,si,uc,&selected_linked_epoch_ticket);
    le_need(!e && selected_linked_epoch_ticket,LE_EVENT,e);
    copy(&r->transfer,li2_tf_chain_span_progress(),sizeof r->transfer);
    le_need(r->transfer.phase==LI2_ST_CLOSED && r->transfer.issued==1 &&
        r->transfer.previous==(unsigned)selected_chain.active &&
        r->transfer.event==selected_chain.event_id &&
        r->transfer.flags==((uint64_t)r->ingress.frame.greg[REG_EFL]&~SELECTED_TF),LE_EVENT,3);
    r->close_complete=1;le_count(&selected_linked_epoch.closed);
#ifdef LI2_LINKED_EPOCH_CAPTURE
    leto_closed();
#endif
#ifdef LI2_LINKED_PREEDGE_CAPTURE
    lpeo_closed();
#endif
    selected_linked_epoch_closing=0;
    selected_logical_flags=r->transfer.flags;selected_flags_known=1;
    selected_step_pending=0;selected_pending_route=SELECTED_NO_STEP;
    le_need(!li2_tf_chain_span_quiet(selected_linked_epoch_ticket) &&
        !li2_lifecycle_fetch_interlock() && le_quiet(0),LE_STATE,20);
    /* fetch_prepare itself installs the actual held singleton and output ref
       before its first fallible identity/maps call. This busy owner already
       owns a failed preparation; no old CLOSED slot is restored. */
    le_zero(&selected_borrow,sizeof selected_borrow);le_zero(&selected_view,sizeof selected_view);
    r->prepare_started=1;
    r->prepare_result=li2_lifecycle_fetch_prepare(r->transfer.pc,15,&selected_borrow);
    le_need(!r->prepare_result,LE_SOURCE,r->prepare_result);
    e=li2_lifecycle_fetch_view(&selected_borrow,&selected_view);
    le_need(!e && selected_view.pc==r->transfer.pc && selected_view.length==15 &&
        selected_view.page_count==1 && selected_view.identity_observed &&
        selected_view.pid==selected_session.pid && selected_view.tid==selected_session.tid,
        LE_SOURCE,e);r->prepare_complete=1;
    if(selected_linked_epoch_try(sig,si,uc,selected_logical_flags))return 1;
    /* The four descriptive classes above have not claimed a slot or changed
       permissions. Release only this genuine fresh borrow, then ask the
       private lifecycle observer to prove that release to RESUMING. */
    le_need(selected_linked_epoch_busy && !selected_linked_epoch_active &&
        !r->slot_present && !r->redirected && !ler.pending && !ler.retiring &&
        !selected_step_pending && selected_pending_route==SELECTED_NO_STEP &&
        !li2_tf_chain_span_quiet(selected_linked_epoch_ticket) &&
        le_unchanged(&r->before,si,uc),LE_STATE,21);
#if defined(LI2_LINKED_EPOCH_CAPTURE) && !defined(LI2_LINKED_EPOCH_REUSE_CAPTURE)
    leto_refault_before_release(sig,si,uc);
#endif
    r->miss_release_started=1;
    r->miss_release_result=li2_lifecycle_fetch_release(&selected_borrow);
    const struct li2_fetch_progress *f=li2_lifecycle_fetch_progress();
    if(f)copy(&r->miss_fetch,f,sizeof r->miss_fetch);
    le_need(!r->miss_release_result && f && f->complete && !f->held && !f->first_error &&
        f->sequence==selected_borrow.sequence && le_unchanged(&r->before,si,uc),
        LE_RELEASE,r->miss_release_result);r->miss_release_complete=1;
    if(le_closed_nx_retry(sig,si,uc))return 1;
    selected_linked_epoch_resuming=1;r->resume_started=1;
    __asm__ volatile("":::"memory");
    r->resume_result=li2_tf_chain_span_resume(selected_linked_epoch_ticket,sig,si,uc,&r->resumed_route);
    le_need(!r->resume_result,LE_EVENT,r->resume_result);
    copy(&r->transfer,li2_tf_chain_span_progress(),sizeof r->transfer);
    le_need(r->transfer.phase==LI2_ST_RESUMED && r->transfer.resumed==1 &&
        r->transfer.successor_installed==1 && r->transfer.next==(unsigned)selected_chain.active &&
        (r->resumed_route==LI2_CHAIN_RUNNING || r->resumed_route==LI2_CHAIN_NX_FALLBACK),LE_STATE,22);
    r->resume_complete=1;le_count(&selected_linked_epoch.resumed);
    uint64_t expected=selected_logical_flags;
    if(r->resumed_route==LI2_CHAIN_RUNNING)expected|=SELECTED_TF;
    le_need((uint64_t)uc->uc_mcontext.gregs[REG_EFL]==expected,LE_FRAME,11);
    selected_step_pending=r->resumed_route==LI2_CHAIN_RUNNING;
    selected_pending_route=selected_step_pending?SELECTED_GENERIC_TF:SELECTED_NO_STEP;
    selected_linked_epoch_ticket=0;selected_initialized();
    /* Keep the real chain cleanup selection visible until this temporary busy
       owner is gone: the successfully armed successor may already be RX. */
    __asm__ volatile("":::"memory");selected_linked_epoch_busy=0;
    selected_linked_epoch_resuming=0;
#if defined(LI2_EFFECT_PROVIDER) && defined(LI2_TF_HANDOFF) && defined(LI2_REGISTER_RUN)
    if(r->resumed_route==LI2_CHAIN_NX_FALLBACK &&
       selected_chain.slots[selected_chain.active].fallback==LI2_CHAIN_OLD_STEP)
        selected_run_trace_try(sig,si,uc,selected_logical_flags);
#endif
    return 1;
}

static void selected_linked_epoch_exit(int sig,siginfo_t *si,ucontext_t *uc) {
    le_need(selected_linked_epoch_active && !selected_linked_epoch_busy && selected_step_pending &&
        selected_pending_route==SELECTED_LINKED_EPOCH,LE_STATE,7);
    selected_linked_epoch_busy=1;struct le_record *r=&selected_linked_epoch.current;
    le_need(r->slot_present && r->slot<selected_linked_epoch.used && r->redirected,LE_STATE,8);
    le_need(ler_claimed(),LE_STATE,316);
    struct le_slot *s=&selected_linked_epoch.slots[r->slot];
    le_need(!le_capture(&r->after,sig,si,uc),LE_FRAME,6);
    uintptr_t pc=(uintptr_t)r->after.frame.greg[REG_RIP];int exit=le_exit_index(le_plan(s),pc);
    if(exit<0)selected_linked_epoch_unexpected(sig,si,uc);
    le_nx(&r->after,pc);r->exit_seen=1;r->exit_index=(unsigned)exit;
#ifdef LI2_LINKED_PREEDGE
    unsigned frontier_kind=le_plan(s)->frontier_kind[exit];
    le_need(frontier_kind==LI2_PREEDGE_UNSUPPORTED || frontier_kind==LI2_PREEDGE_PAGE_CUT,LE_PLAN,440);
    le_need(li2_preedge_frontier_kind(le_plan(s)->page,&le_plan(s)->frontier[exit])==frontier_kind,
        LE_PLAN,441); /* Authenticated original NX precedes the whole cut instruction. */
#endif
    le_need(le_identity() && le_protected() && le_quiet(&selected_borrow),LE_STATE,9);le_tls(&r->after);
    le_need(r->before.fs==r->after.fs && r->before.gs==r->after.gs,LE_TLS,1);
    const greg_t *a=r->before.frame.greg,*b=r->after.frame.greg;
    static const unsigned greg[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,
        REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
    for(unsigned i=0;i<16;i++)if(!(r->gpr_written&(UINT64_C(1)<<i)))
        le_need(a[greg[i]]==b[greg[i]],LE_RESULT,i);
    for(unsigned i=0;i<NGREG;i++) {
        unsigned ordinary=0;for(unsigned j=0;j<16;j++)if(i==greg[j])ordinary=1;
        if(!ordinary && i!=REG_RIP && i!=REG_EFL && i!=REG_CR2 &&
           i!=REG_TRAPNO && i!=REG_ERR)le_need(a[i]==b[i],LE_RESULT,16+i);
    }
    /* The only differing event metadata is the actual closed TRACE origin
       (1/0) versus the genuine original-page execute fault (14/21). */
    le_need(a[REG_TRAPNO]==1 && !a[REG_ERR] && b[REG_TRAPNO]==14 && b[REG_ERR]==21,
        LE_RESULT,42);
    uint64_t physical=(uint64_t)b[REG_EFL];
    le_need((physical&(SELECTED_TF|SELECTED_RF))==SELECTED_RF &&
        (physical&~(r->flags_written|SELECTED_RF))==(r->flags&~r->flags_written),LE_RESULT,40);
    le_need(r->before.frame.mask==r->after.frame.mask &&
        equal(&r->before.uc.uc_stack,&r->after.uc.uc_stack,sizeof(uc->uc_stack)) &&
        r->before.uc.uc_flags==r->after.uc.uc_flags && r->before.uc.uc_link==r->after.uc.uc_link &&
        r->before.frame.fp_bytes==r->after.frame.fp_bytes &&
        equal(r->before.frame.fp,r->after.frame.fp,LI2_STEP_FP_BYTES),LE_RESULT,41);
#ifdef LI2_LINKED_PREEDGE
    le_need(!le_proof_check(s,&r->proof_exit) && !li2_lifecycle_preedge_validate(&selected_borrow,&r->source,le_plan(s)) &&
#else
    le_need(!le_proof_check(s,&r->proof_exit) && !li2_lifecycle_link_validate(&selected_borrow,&r->source,le_plan(s)) &&
#endif
        !le_live(uc,&r->live_rseq[3]),LE_SOURCE,5);
    #ifdef LI2_LINKED_EPOCH_CAPTURE
    leto_before_close();
#endif
    le_need(!le_permission(s,PROT_READ,&r->close) && !le_bytes(s,&r->closed_bytes),LE_PUBLICATION,9);
#ifdef LI2_LINKED_PREEDGE
    le_need(!li2_lifecycle_preedge_validate(&selected_borrow,&r->source,le_plan(s)) &&
#else
    le_need(!li2_lifecycle_link_validate(&selected_borrow,&r->source,le_plan(s)) &&
#endif
        le_unchanged(&r->after,si,uc),LE_SOURCE,6);
#ifdef LI2_LINKED_PREEDGE
    r->release_started=1;r->release_result=li2_lifecycle_preedge_release(&r->epoch,&r->source,le_plan(s));
#else
    r->release_started=1;r->release_result=li2_lifecycle_link_release(&r->epoch,&r->source,le_plan(s));
#endif
#ifdef LI2_LINKED_PREEDGE
    copy(&r->epoch_final,li2_lifecycle_preedge_progress(),sizeof r->epoch_final);
#else
    copy(&r->epoch_final,li2_lifecycle_link_progress(),sizeof r->epoch_final);
#endif
    const struct li2_fetch_progress *p=li2_lifecycle_fetch_progress();
    if(p)copy(&r->final_fetch,p,sizeof r->final_fetch);
    le_need(!r->release_result && p && !p->held && p->complete && !p->first_error &&
        p->sequence==r->source.borrow.sequence,LE_RELEASE,r->release_result);r->release_complete=1;
    le_need(le_unchanged(&r->after,si,uc),LE_FRAME,7);
    r->completed=1;le_count(&selected_linked_epoch.completed);le_count(&selected_linked_epoch.exit_counts[exit]);
#ifdef LI2_LINKED_PREEDGE
    if(frontier_kind==LI2_PREEDGE_PAGE_CUT)le_count(&selected_linked_epoch.cut_exits);
#endif
    copy(&selected_linked_epoch.last,r,sizeof *r);
    /* Only the original exit RIP is already present. Import every actual
       logical flag, including AF; no GPR, guest data or FP is predicted/reset. */
    selected_logical_flags=physical&~SELECTED_RF;selected_flags_known=1;
    selected_linked_epoch_active=0;selected_step_pending=0;selected_pending_route=SELECTED_NO_STEP;
    ler_quiesce(sig,si,uc);
#ifdef LI2_LINKED_EPOCH_CAPTURE
    leto_complete();
#endif
#ifdef LI2_LINKED_PREEDGE_CAPTURE
    lpeo_complete();
#endif
    __asm__ volatile("":::"memory");selected_linked_epoch_busy=0;selected_fetch(sig,si,uc);
}
static void selected_linked_epoch_report(unsigned status,unsigned code,long detail) {
#ifdef LI2_LINKED_EPOCH_CAPTURE
    leto_finish(status,code,detail);
#endif
#ifdef LI2_LINKED_PREEDGE_CAPTURE
    lpeo_finish(status,code,detail);
#endif
    ler_report(status,code,detail);
#ifdef LI2_LINKED_PREEDGE
    struct writer w={.used=0};text(&w,"LI2_LINKED_PREEDGE {\"version\":2");
#else
    struct writer w={.used=0};text(&w,"LI2_LINKED_EPOCH {\"version\":1");
#endif
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",detail<0?0ULL-(uint64_t)detail:(uint64_t)detail);
    field(&w,",\"detail_negative\":",detail<0);
#define LE_FIELD(name) field(&w,",\"" #name "\":",selected_linked_epoch.name)
    LE_FIELD(initialized);LE_FIELD(first_error);LE_FIELD(used);LE_FIELD(offers);LE_FIELD(closed);
#ifdef LI2_LINKED_NATIVE_HINT
    LE_FIELD(resumed);LE_FIELD(refaults);LE_FIELD(graph_refaults);
    LE_FIELD(hash_misses);LE_FIELD(candidates);LE_FIELD(source_misses);
#else
    LE_FIELD(resumed);LE_FIELD(refaults);LE_FIELD(hash_misses);LE_FIELD(candidates);LE_FIELD(source_misses);
#endif
    LE_FIELD(plan_misses);LE_FIELD(capacity_misses);LE_FIELD(publications);LE_FIELD(hits);LE_FIELD(entries);
    LE_FIELD(completed);LE_FIELD(unexpected);LE_FIELD(events);LE_FIELD(plan_checks);LE_FIELD(rseq_checks);LE_FIELD(live_checks);LE_FIELD(proof_checks);
#ifdef LI2_LINKED_PREEDGE
    LE_FIELD(cut_exits);
#endif
#undef LE_FIELD
    field(&w,",\"active\":",selected_linked_epoch_active);field(&w,",\"busy\":",selected_linked_epoch_busy);
    field(&w,",\"decoding\":",selected_linked_epoch_decoding);
    field(&w,",\"closing\":",selected_linked_epoch_closing);
    field(&w,",\"resuming\":",selected_linked_epoch_resuming);
    const struct li2_span_transfer_progress *t=li2_tf_chain_span_progress();
    const uint64_t origin[]={t->phase,t->serial,t->event,t->previous,t->next,t->successor_installed,
        t->previous_generation,t->previous_borrow,t->fresh_borrow,t->pc,t->flags,t->issued,
        t->consume_attempted,t->consumed,t->resume_attempted,t->resumed,t->first_error,
        t->first_detail<0?0ULL-(uint64_t)t->first_detail:(uint64_t)t->first_detail,t->first_detail<0,
        t->refault_attempted,t->refaulted};
    selected_repeat_array(&w,",\"transfer\":",origin,sizeof origin/sizeof origin[0]);
    selected_repeat_array(&w,",\"signals\":",selected_linked_epoch.signals,5);
    selected_repeat_array(&w,",\"refusals\":",selected_linked_epoch.refusals,4);
    selected_repeat_array(&w,",\"exit_indices\":",selected_linked_epoch.exit_counts,LI2_REGION_EXITS);
    const struct le_record *r=&selected_linked_epoch.current;
    const uint64_t last[]={r->slot_present,r->slot,r->redirected,r->exit_seen,r->completed,r->exit_index,
        r->open.started,r->open.returned,r->open.complete,r->close.started,r->close.returned,r->close.complete,
        r->release_started,r->release_complete,r->cleanup_started,r->cleanup_complete,
        r->before.complete,r->after.complete,r->unexpected_seen,r->unexpected.complete,
        r->original.ready,r->original.kind,r->original.head_index,r->original.source_offset,
        r->idle_bytes,r->live_bytes,r->closed_bytes,r->final_fetch.held,r->final_fetch.complete,
        r->build_started,r->build_returned,(unsigned)r->build_result,r->gpr_written,r->flags_written,
        r->refault_started,r->refault_complete,(unsigned)r->refault_result};
    selected_repeat_array(&w,",\"current\":",last,sizeof last/sizeof last[0]);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
#ifdef LI2_LINKED_NATIVE_HINT
    const struct li2_link_native_hint_progress *h=li2_lifecycle_link_native_hint_progress();
    struct writer q={.used=0};text(&q,"LI2_LINKED_NATIVE_HINT {\"version\":1");
    field(&q,",\"status\":",status);field(&q,",\"failure_code\":",code);
#define LNH_FIELD(name) field(&q,",\"" #name "\":",h->name)
    LNH_FIELD(ready);LNH_FIELD(pending);LNH_FIELD(outcome_complete);
    LNH_FIELD(publications);LNH_FIELD(evictions);LNH_FIELD(lookups);LNH_FIELD(hits);LNH_FIELD(invalidations);
    LNH_FIELD(next_nx);LNH_FIELD(admitted);LNH_FIELD(refused);LNH_FIELD(errors);
    LNH_FIELD(receipt_sequence);LNH_FIELD(receipt_publication);
    LNH_FIELD(selected_publication);LNH_FIELD(selected_serial);LNH_FIELD(selected_event);
    LNH_FIELD(selected_pc);LNH_FIELD(selected_seeds);LNH_FIELD(selected_published);
    field(&q,",\"outcome_result\":",(unsigned)h->outcome_result);
    field(&q,",\"current_checked\":",r->hint_checked);
    field(&q,",\"current_hit\":",r->hint_hit);
    field(&q,",\"current_publication\":",r->hint_publication);
#undef LNH_FIELD
    text(&q,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)q.bytes,q.used,0,0,0);
#endif
#ifdef LI2_LINK_GRAPH_OBSERVE
    const struct li2_link_graph_observation *g=li2_link_graph_observation();
    struct writer gw={.used=0};text(&gw,"LI2_LINKED_GRAPH_OBSERVE {\"version\":1");
    field(&gw,",\"status\":",status);field(&gw,",\"failure_code\":",code);
    field(&gw,",\"overflow\":",g->overflow);
    selected_repeat_array(&gw,",\"reasons\":",g->reasons,LI2_LG_REASON_COUNT);
    text(&gw,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)gw.bytes,gw.used,0,0,0);
#endif
}
#ifdef LI2_LINK_GRAPH_OBSERVE
_Static_assert(17*21+160<=sizeof(((struct writer *)0)->bytes),"bounded graph observation report");
#endif
#ifdef LI2_LINKED_NATIVE_HINT
#ifdef LI2_LINKED_PREEDGE
_Static_assert(116*21+1620<=sizeof(((struct writer *)0)->bytes),"bounded pre-edge hint report");
#else
_Static_assert(115*21+1600<=sizeof(((struct writer *)0)->bytes),"bounded linked-epoch hint report");
#endif
_Static_assert(26*21+700<=sizeof(((struct writer *)0)->bytes),"bounded native-hint report");
#else
#ifdef LI2_LINKED_PREEDGE
_Static_assert(115*21+1572<=sizeof(((struct writer *)0)->bytes),"bounded pre-edge report");
#else
_Static_assert(114*21+1552<=sizeof(((struct writer *)0)->bytes),"bounded linked-epoch report");
#endif
#endif

#ifdef LI2_LINKED_EPOCH_CAPTURE
#ifdef LI2_LINKED_EPOCH_REUSE_CAPTURE
#include "linked_epoch_reuse_observe.inc"
#else
#include "linked_epoch_observe.inc"
#endif
#endif
#ifdef LI2_LINKED_PREEDGE_CAPTURE
#include "linked_preedge_observe.inc"
#endif
