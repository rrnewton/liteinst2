/* Private candidate: include after selected_register_run.inc. Root supplies
   early prototypes/route tag, unrolled_source.h and the lifecycle/rseq seams.
   Anonymous publication uses the old protected private-code provenance; no
   memfd/seal observation is invented. This explicit owner contract supersedes
   the planner header's proposed sealed-slot obligation for this profile only. */
#include "unrolled_hash.h"
#include "unrolled_source.h"
#include "private_code_query.h"
#if LI2_UNROLLED_HASH != 1 || LI2_NATIVE_PAIR != 1 || LI2_MAPS_MAINTAINED != 1 || \
    LI2_RUN_CACHE_REUSE != 1 || LI2_TF_HANDOFF != 1 || LI2_REPEAT_RX_LEASE != 1
#error "unrolled hash requires the complete maintained native-pair profile"
#endif
#if defined(LI2_UNROLLED_HASH_OBSERVE_ONLY) && LI2_UNROLLED_HASH_OBSERVE_ONLY != 1
#error "unrolled observation-only mode is the literal value 1"
#endif
#define UH_PAGES 64U
#define UH_BYTES (UH_PAGES*PAGE)
enum uh_error { UH_STATE=2400,UH_FRAME,UH_SOURCE,UH_PUBLICATION,UH_EVENT,
    UH_RESULT,UH_REENTRY,UH_OVERFLOW,UH_TLS,UH_RELEASE };
struct uh_frame {
    unsigned started,si_saved,uc_saved,complete;
    int sig;
    siginfo_t si;
    ucontext_t uc;
    struct li2_step_frame frame;
    uint64_t fs,gs;
    long fs_result,gs_result;
    unsigned tls_complete;
};
struct uh_permission {
    unsigned started,returned,sync_started,sync_returned,complete;
    int prot;
    long result,sync_result;
    struct li2_private_code_query query;
};
struct uh_slot {
    unsigned installed,complete;
    uint64_t identity;
    size_t filled,verified;
    struct li2_unrolled_source source;
    struct li2_unrolled_hash_plan plan;
    struct li2_private_code_query writable;
    struct uh_permission publication;
};
struct uh_record {
    unsigned slot_present,slot,redirected,exit_seen,completed,release_started,release_complete;
    unsigned cleanup_started,cleanup_complete,unexpected_seen;
    int release_result,map_result;
    uint64_t flags,iterations;
    struct li2_unrolled_source source;
    struct uh_frame before,after,unexpected;
    struct li2_unrolled_hash_pc original;
    struct li2_private_code_query idle,live;
    size_t idle_bytes,live_bytes,closed_bytes;
    struct uh_permission open,close,cleanup;
    struct li2_fetch_progress final_fetch;
};
static struct {
    unsigned initialized,first_error,metadata_registered,arena_registered,allocated;
    unsigned low_arena_registered,low_allocated;
    long first_detail,allocation_result,low_allocation_result;
    uintptr_t arena,low_arena;
    size_t used;
    uint64_t candidates,source_misses,plan_misses,capacity_misses,publications,hits;
    uint64_t entries,completed,head_exits,stop_exits,iterations,unexpected;
    uint64_t events,signals[5];
    struct li2_step_session session;
    struct li2_private_code_query initial,low_initial;
    struct uh_slot slots[UH_PAGES];
    struct uh_record current,last;
} selected_unrolled;
static volatile sig_atomic_t selected_unrolled_active,selected_unrolled_busy,selected_unrolled_failing;
static _Noreturn void selected_unrolled_abort(unsigned,long);
#ifdef LI2_UNROLLED_HASH_CAPTURE
static void uho_initialize(void);
static void uho_preentry(int,siginfo_t *,ucontext_t *);
static void uho_entry_frame(int,siginfo_t *,ucontext_t *);
static void uho_source(void);
static void uho_slot(struct uh_slot *);
static void uho_before_open(struct uh_slot *);
static void uho_redirected(int,siginfo_t *,ucontext_t *);
static void uho_complete(void);
static void uho_abort_observe(void);
static void uho_finish(unsigned,unsigned,long);
#endif
static void uh_need(int yes,unsigned code,long detail) {
    if(!yes)selected_unrolled_abort(code,detail);
}
static void uh_count(uint64_t *p) {uh_need(*p!=UINT64_MAX,UH_OVERFLOW,0);++*p;}
/* Nested signal ingress never returns, but publish each count atomically so
   its terminal prefix cannot observe a torn/read-modify-write count. */
static void uh_event_count(uint64_t *p) {
    uint64_t old=__atomic_load_n(p,__ATOMIC_RELAXED);
    uh_need(old!=UINT64_MAX,UH_OVERFLOW,2);
    uh_need(__atomic_compare_exchange_n(p,&old,old+1,0,__ATOMIC_RELAXED,__ATOMIC_RELAXED),UH_REENTRY,0);
}
_Static_assert(__atomic_always_lock_free(sizeof(uint64_t),0),"no external event counter gateway");
static uint32_t uh_u32(const unsigned char *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static void uh_zero(void *p,size_t n) {
    unsigned char *b=p;for(size_t i=0;i<n;i++)b[i]=0;
}
static int uh_range(const void *p,size_t n) {
    uintptr_t a=(uintptr_t)p,b=(uintptr_t)fork_gate_stack.ss_sp;
    return p && n && b<=UINTPTR_MAX-fork_gate_stack.ss_size &&
        a>=b && a<=b+fork_gate_stack.ss_size && n<=b+fork_gate_stack.ss_size-a;
}
/* Capture actual data before interpreting an event. The FP extent is bounded
   by the real alternate stack before each read; untouched storage stays zero. */
static int uh_capture(struct uh_frame *f,int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(f->started)return UH_FRAME;
    f->started=1;f->sig=sig;
    if(!uh_range(si,sizeof(*si)) || !uh_range(uc,sizeof(*uc)))return UH_FRAME;
    /* Linux x86-64 ends ucontext after its 64-signal mask; siginfo follows.
       The remaining glibc sigset_t bytes alias that distinct event record. */
    if((const unsigned char *)si!=(const unsigned char *)&uc->uc_sigmask+sizeof(f->frame.mask))return UH_FRAME;
    copy(&f->si,si,sizeof(*si));f->si_saved=1;copy(&f->uc,uc,sizeof(*uc));f->uc_saved=1;
    struct li2_step_frame *s=&f->frame;
    copy(s->greg,uc->uc_mcontext.gregs,sizeof s->greg);copy(&s->mask,&uc->uc_sigmask,8);
    s->fp_address=(uintptr_t)uc->uc_mcontext.fpregs;
    if((s->fp_address&15) || !uh_range((void *)s->fp_address,512))return UH_FRAME;
    const unsigned char *p=(void *)s->fp_address;size_t n=512;
    if(uh_u32(p+464)==UINT32_C(0x46505853)) {
        n=uh_u32(p+468);size_t x=uh_u32(p+480);
        if(n<580 || n>LI2_STEP_FP_BYTES || x<576 || x>n-4 ||
           !uh_range(p,n) || uh_u32(p+n-4)!=UINT32_C(0x46505845))return UH_FRAME;
    }
    s->fp_bytes=n;for(size_t i=0;i<n;i++){s->fp[i]=p[i];s->initialized=i+1;}
    f->complete=1;return 0;
}
static int uh_unchanged(const struct uh_frame *f,const siginfo_t *si,const ucontext_t *uc) {
    return f->complete && uh_range(si,sizeof(*si)) && uh_range(uc,sizeof(*uc)) &&
        equal(si,&f->si,sizeof(*si)) && equal(uc,&f->uc,sizeof(*uc)) &&
        uh_range(uc->uc_mcontext.fpregs,f->frame.fp_bytes) &&
        equal(uc->uc_mcontext.fpregs,f->frame.fp,f->frame.fp_bytes);
}
static void uh_tls(struct uh_frame *f) {
    f->fs_result=raw(SYS_arch_prctl,ARCH_GET_FS,(long)&f->fs,0,0,0,0);
    f->gs_result=raw(SYS_arch_prctl,ARCH_GET_GS,(long)&f->gs,0,0,0,0);
    uh_need(!f->fs_result && !f->gs_result,UH_TLS,0);f->tls_complete=1;
}
static int uh_identity(void) {
    const struct li2_step_session *s=&selected_unrolled.session;
    return equal(s,&selected_session,sizeof(*s)) && s->initialized && s->self_test_complete &&
        s->pid>0 && s->pid==s->tid && s->sync_query>=0 && (s->sync_query&96)==96 &&
        !s->sync_register && raw(SYS_getpid,0,0,0,0,0,0)==s->pid &&
        raw(SYS_gettid,0,0,0,0,0,0)==s->tid;
}
static int uh_protected(void) {
    return selected_run_protection.context==0 &&
        selected_run_protection.add==selected_run_protect_add &&
        selected_run_protection.contains==selected_run_protect_contains &&
        selected_run_protect_contains(0,(uintptr_t)&selected_unrolled,sizeof selected_unrolled)==1 &&
        selected_run_protect_contains(0,selected_unrolled.arena,UH_BYTES)==1 &&
        selected_run_protect_contains(0,selected_unrolled.low_arena,UH_BYTES)==1;
}
/* Pure actual-owner joins. Do not call old run_reuse_runtime with a forged
   REGISTER_RUN route or a forged old plan. Native-pair preentry precedes RAW. */
static int uh_quiet(const struct li2_fetch_ref *ref) {
    const struct li2_run_cache_diagnostic *cache=li2_run_cache_diagnostic(selected_run_cache);
    struct li2_run_reuse_observation reuse={0};
    const struct li2_page_custody_stats *custody=li2_page_custody_snapshot();
    const struct li2_fetch_rx_view *rx=li2_lifecycle_fetch_rx_progress();
    if(handling!=1 || reported || selected_selftesting || !selected_flags_known ||
       selected_run_failing || selected_run_interrupted.event.observed ||
       selected_run_interrupted.frame_observed || selected_run_owner.phase!=LI2_RUN_EMPTY ||
       selected_run_owner.first_error || selected_run_owner.session || selected_run_trace_busy ||
       selected_run_trace_active || selected_run_trace_origin || selected_run_reuse_frame ||
       selected_step.phase!=LI2_STEP_EMPTY || selected_step.session ||
       selected_step.first_error || selected_step.in_handler || !cache ||
       cache->phase!=LI2_CACHE_READY || cache->first_error ||
       li2_run_reuse_snapshot(selected_run_cache,&reuse) || reuse.lookup || reuse.lease || reuse.reset_pending ||
       selected_run_history.first_error || selected_run_history.reset_started!=selected_run_history.reset_complete ||
       selected_run_history.completed_runs!=reuse.completions ||
       selected_run_history.copied_instructions!=reuse.copied_instructions ||
       li2_lifecycle_run_reuse_quiet(ref) || li2_tf_chain_run_reuse_quiet(&selected_chain,0) ||
       !selected_run_reuse_repeat_closed() || !selected_repeat_lease_closed() ||
       !selected_run_reuse_effects_closed() || !selected_run_reuse_native_closed() ||
       !custody || custody->phase!=LI2_CUSTODY_EMPTY || !rx || rx->result ||
       (rx->phase!=LI2_RX_EMPTY && (!rx->complete ||
        (rx->phase!=LI2_RX_COMMITTED && rx->phase!=LI2_RX_CANCELLED))))return 0;
    const struct li2_rseq_state *rseq=li2_rseq_snapshot();
    if(!rseq || !rseq->initialized || rseq->first_error ||
       rseq->pid!=selected_session.pid || rseq->tid!=selected_session.tid)return 0;
    if(rseq->registered) {
        if(rseq->registered!=1 || rseq->held!=1 || rseq->phase!=LI2_RSEQ_ACTIVE ||
           !rseq->tls_complete || !rseq->address || rseq->address>UINTPTR_MAX-16 ||
           *(const volatile uint64_t *)(rseq->address+8))return 0;
    } else if(rseq->held || rseq->phase!=LI2_RSEQ_IDLE)return 0;
    const struct li2_tcgets_state *io=li2_rseq_tcgets_snapshot();
    if(!io || !io->initialized || io->first_error ||
       (io->phase!=LI2_TCGETS_IDLE && io->phase!=LI2_TCGETS_COMPLETE) ||
       io->issued!=io->returned || io->returned!=io->completed)return 0;
    return 1;
}
static int uh_query(uintptr_t entry,int prot,struct li2_private_code_query *q) {
    int e=li2_lifecycle_private_code_query(entry,PAGE,prot,q);
    return e || !q->complete || q->pages_checked!=1 || q->actual_prot!=prot?UH_PUBLICATION:0;
}
static int uh_bytes(struct uh_slot *s,size_t *observed) {
    const volatile unsigned char *p=(void *)s->plan.entry;
    for(size_t i=0;i<PAGE;i++) {
        unsigned char b=i<LI2_UNROLLED_HASH_CODE?s->plan.generated[i]:0xcc;
        if(p[i]!=b)return UH_PUBLICATION;
        *observed=i+1;
    }
    return 0;
}
static int uh_permission(struct uh_slot *s,int prot,struct uh_permission *p) {
    if(p->started)return UH_STATE;
    p->prot=prot;p->started=1;__asm__ volatile("":::"memory");
    p->result=raw(SYS_mprotect,s->plan.entry,PAGE,prot,0,0,0);p->returned=1;
    p->sync_started=1;__asm__ volatile("":::"memory");
    p->sync_result=raw(SYS_membarrier,32,0,0,0,0,0);p->sync_returned=1;
    int q=uh_query(s->plan.entry,prot,&p->query);
    if(p->result || p->sync_result || q)return UH_PUBLICATION;
    p->complete=1;return 0;
}
static _Noreturn void selected_unrolled_abort(unsigned code,long detail) {
    if(!selected_unrolled.first_error){selected_unrolled.first_error=code;selected_unrolled.first_detail=detail;}
    if(selected_unrolled_failing) {
        (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    selected_unrolled_failing=1;selected_unrolled_busy=1;li2_maps_phase_fail();
    struct uh_record *r=&selected_unrolled.current;
#ifdef LI2_UNROLLED_HASH_CAPTURE
    uho_abort_observe();
#endif
    if(r->slot_present && r->slot<selected_unrolled.used && !r->cleanup_started) {
        r->cleanup_started=1;__asm__ volatile("":::"memory");
        struct uh_slot *s=&selected_unrolled.slots[r->slot];
        if(!uh_permission(s,PROT_READ,&r->cleanup))r->cleanup_complete=1;
    }
    const struct li2_fetch_progress *p=li2_lifecycle_fetch_progress();
    if(p)r->final_fetch=*p;
    li2_lifecycle_abort();report(125,selected_unrolled.first_error,selected_unrolled.first_detail);
    (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static _Noreturn void selected_unrolled_unexpected(int sig,siginfo_t *si,ucontext_t *uc) {
    struct uh_record *r=&selected_unrolled.current;
    if(!r->unexpected_seen) {
        r->unexpected_seen=1;
        if(selected_unrolled.unexpected!=UINT64_MAX)++selected_unrolled.unexpected;
        int captured=uh_capture(&r->unexpected,sig,si,uc);
        if(!captured && r->slot_present && r->slot<selected_unrolled.used)
            r->map_result=li2_unrolled_hash_map_pc(&selected_unrolled.slots[r->slot].plan,
                (uintptr_t)r->unexpected.frame.greg[REG_RIP],&r->original);
        else r->map_result=captured?captured:LI2_UNROLLED_HASH_MISS;
    }
    selected_unrolled_abort(UH_EVENT,sig);
}
static void uh_nx(const struct uh_frame *f,uintptr_t pc) {
    const greg_t *g=f->frame.greg;
    uh_need(f->complete && f->sig==SIGSEGV && f->si.si_signo==SIGSEGV &&
        f->si.si_code==SEGV_ACCERR && !f->si.si_errno && g[REG_TRAPNO]==14 && g[REG_ERR]==21 &&
        (uintptr_t)g[REG_RIP]==pc && (uintptr_t)f->si.si_addr==pc &&
        (uintptr_t)g[REG_CR2]==pc &&
        ((uint64_t)g[REG_CSGSFS]&65535)==0x33 && (uint64_t)g[REG_RSP]<(UINT64_C(1)<<47) &&
        f->frame.mask==selected_unrolled.session.application_mask,UH_EVENT,f->sig);
}
/* Root calls this after the existing pure native/rseq preentry guards, before
   every returning RAW or map/chain event observation. It never grants entry. */
static void selected_unrolled_preentry(int sig,siginfo_t *si,ucontext_t *uc) {
    uh_event_count(&selected_unrolled.events);
    unsigned kind=sig==SIGSEGV?0:sig==SIGTRAP?1:sig==SIGILL?2:sig==SIGSYS?3:4;
    uh_event_count(&selected_unrolled.signals[kind]);
#ifdef LI2_UNROLLED_HASH_CAPTURE
    uho_preentry(sig,si,uc);
#endif
    int routed=selected_pending_route==SELECTED_UNROLLED_HASH;
    if(!selected_unrolled_active && !selected_unrolled_busy && !routed)return;
    struct uh_record *r=&selected_unrolled.current;
    if(selected_unrolled_busy || !selected_unrolled_active || handling || !routed ||
       selected_step_pending!=1 || !r->slot_present || r->slot>=selected_unrolled.used ||
       !r->redirected || r->completed || selected_unrolled.first_error ||
       !uh_range(si,sizeof(*si)) || !uh_range(uc,sizeof(*uc)))
        selected_unrolled_unexpected(sig,si,uc);
    const struct uh_slot *s=&selected_unrolled.slots[r->slot];
    const greg_t *g=uc->uc_mcontext.gregs;uintptr_t pc=(uintptr_t)g[REG_RIP];
    uint64_t mask=0;copy(&mask,&uc->uc_sigmask,sizeof mask);
    if(!s->installed || !s->complete || !r->open.complete ||
       (pc!=s->plan.pc && pc!=s->plan.stop) || sig!=SIGSEGV || si->si_signo!=SIGSEGV ||
       si->si_code!=SEGV_ACCERR || si->si_errno || g[REG_TRAPNO]!=14 || g[REG_ERR]!=21 ||
       (uintptr_t)si->si_addr!=pc || (uintptr_t)g[REG_CR2]!=pc ||
       ((uint64_t)g[REG_EFL]&(SELECTED_TF|SELECTED_RF))!=SELECTED_RF ||
       ((uint64_t)g[REG_CSGSFS]&65535)!=0x33 || (uint64_t)g[REG_RSP]>=(UINT64_C(1)<<47) ||
       mask!=selected_unrolled.session.application_mask)
        selected_unrolled_unexpected(sig,si,uc);
}
static void selected_unrolled_initialize(void) {
    uh_need(!selected_unrolled.initialized && !selected_unrolled_active && !selected_unrolled_busy,
        UH_STATE,1);selected_unrolled_busy=1;
    copy(&selected_unrolled.session,&selected_session,sizeof selected_session);
    uh_need(uh_identity() && !li2_lifecycle_fetch_interlock(),UH_STATE,2);
    uh_need(!selected_run_protect_add(0,(uintptr_t)&selected_unrolled,sizeof selected_unrolled),UH_STATE,3);
    selected_unrolled.metadata_registered=1;
    selected_unrolled.allocation_result=raw(SYS_mmap,0,UH_BYTES,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    long a=selected_unrolled.allocation_result;
    uh_need(!(a<0 && a>=-4095) && a>0 && !((uintptr_t)a&(PAGE-1)) &&
        (uintptr_t)a<(UINT64_C(1)<<47)-UH_BYTES,UH_PUBLICATION,a);
    selected_unrolled.arena=(uintptr_t)a;selected_unrolled.allocated=1;
    uh_need(!selected_run_protect_add(0,(uintptr_t)a,UH_BYTES),UH_STATE,4);
    selected_unrolled.arena_registered=1;
    selected_unrolled.low_allocation_result=raw(SYS_mmap,0,UH_BYTES,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT,-1,0);
    long low=selected_unrolled.low_allocation_result;
    uh_need(!(low<0 && low>=-4095) && low>0 && !((uintptr_t)low&(PAGE-1)) &&
        (uintptr_t)low<=(UINT64_C(1)<<31)-UH_BYTES,UH_PUBLICATION,low);
    selected_unrolled.low_arena=(uintptr_t)low;selected_unrolled.low_allocated=1;
    uh_need((uintptr_t)low+UH_BYTES<=(uintptr_t)a || (uintptr_t)a+UH_BYTES<=(uintptr_t)low,
        UH_PUBLICATION,10);
    uh_need(!selected_run_protect_add(0,(uintptr_t)low,UH_BYTES),UH_STATE,10);
    selected_unrolled.low_arena_registered=1;uh_need(uh_protected(),UH_STATE,5);
    int e=li2_lifecycle_private_code_query(a,UH_BYTES,PROT_READ|PROT_WRITE,&selected_unrolled.initial);
    uh_need(!e && selected_unrolled.initial.complete && selected_unrolled.initial.pages_checked==UH_PAGES,
        UH_PUBLICATION,e);
    e=li2_lifecycle_private_code_query(low,UH_BYTES,PROT_READ|PROT_WRITE,&selected_unrolled.low_initial);
    uh_need(!e && selected_unrolled.low_initial.complete && selected_unrolled.low_initial.pages_checked==UH_PAGES,
        UH_PUBLICATION,e);
    selected_unrolled.initialized=1;
#ifdef LI2_UNROLLED_HASH_CAPTURE
    uho_initialize();
#endif
    selected_unrolled_busy=0;
}
/* Both actual allocations exist in execution and observation-only modes.
   A slot is immutable and source-bound; this chooses its one actual page,
   without address retries, eviction or enlarging the total 64-slot cap. */
static uintptr_t uh_entry(uintptr_t pc,size_t slot) {
    uintptr_t arena=pc<(UINT64_C(1)<<31)?selected_unrolled.low_arena:selected_unrolled.arena;
    return arena+slot*PAGE;
}
static int uh_source_same(const struct li2_unrolled_source *a,const struct li2_unrolled_source *b) {
    const struct li2_fetch_backing *x=&a->backing,*y=&b->backing;
    return a->ready==1 && b->ready==1 && a->pc==b->pc && equal(&a->page,&b->page,sizeof a->page) &&
        equal(a->bytes,b->bytes,sizeof a->bytes) && x->retained_fd==y->retained_fd &&
        x->seals==y->seals && !x->stat_result && !y->stat_result &&
        x->seals_observed==1 && y->seals_observed==1 && x->stat_observed==1 && y->stat_observed==1 &&
        x->stat.st_dev==y->stat.st_dev && x->stat.st_ino==y->stat.st_ino &&
        x->stat.st_mode==y->stat.st_mode && x->stat.st_size==y->stat.st_size;
}
static int selected_unrolled_try(int sig,siginfo_t *si,ucontext_t *uc,uint64_t flags) {
#ifdef LI2_UNROLLED_HASH_OBSERVE_ONLY
    (void)sig;(void)si;(void)uc;(void)flags;return 0;
#endif
    static const unsigned char prefix[15]={0x48,0x89,0xd8,0x48,0x83,0xc1,1,0x48,0xc1,0xe0,5,0x48,1,0xc3,0x48};
    if(selected_view.length!=15 || !equal(selected_view.bytes,prefix,15))return 0;
    uh_need(selected_unrolled.initialized && !selected_unrolled_active && !selected_unrolled_busy &&
        !selected_unrolled.first_error && !selected_step_pending && selected_pending_route==SELECTED_NO_STEP &&
        uh_quiet(&selected_borrow),UH_STATE,6);
    selected_unrolled_busy=1;__asm__ volatile("":::"memory");uh_count(&selected_unrolled.candidates);
    struct uh_record *r=&selected_unrolled.current;uh_zero(r,sizeof(*r));
#ifdef LI2_UNROLLED_HASH_CAPTURE
    uho_entry_frame(sig,si,uc);
#endif
    uh_need(!uh_capture(&r->before,sig,si,uc),UH_FRAME,0);r->flags=flags;
    uh_nx(&r->before,selected_view.pc);
    uh_need(!(flags&(SELECTED_TF|SELECTED_RF)) &&
        (uint64_t)r->before.frame.greg[REG_EFL]==(flags|SELECTED_RF),UH_FRAME,1);
    int e=li2_lifecycle_unrolled_source(&selected_borrow,&r->source);
    uh_need(!e,UH_SOURCE,e);
    if(!r->source.ready) {
        uh_count(&selected_unrolled.source_misses);uh_need(uh_unchanged(&r->before,si,uc),UH_FRAME,2);
        selected_unrolled_busy=0;return 0;
    }
    uh_need(r->source.ready==1 && r->source.pc==selected_view.pc &&
        r->source.borrow.owner==selected_borrow.owner && r->source.borrow.sequence==selected_borrow.sequence &&
        r->source.pc>=PAGE && r->source.pc<(UINT64_C(1)<<47)-39 && uh_identity() && uh_protected(),UH_SOURCE,0);
#ifdef LI2_UNROLLED_HASH_CAPTURE
    uho_source();
#endif
    uh_tls(&r->before);
    size_t slot=0;
    while(slot<selected_unrolled.used && !uh_source_same(&selected_unrolled.slots[slot].source,&r->source))++slot;
    if(slot==selected_unrolled.used) {
        if(slot==UH_PAGES) {
            uh_count(&selected_unrolled.capacity_misses);uh_need(uh_unchanged(&r->before,si,uc),UH_FRAME,3);
            selected_unrolled_busy=0;return 0;
        }
        struct uh_slot *s=&selected_unrolled.slots[slot];
        uintptr_t entry=uh_entry(r->source.pc,slot);
        e=li2_unrolled_hash_plan_bytes(r->source.pc,r->source.bytes,39,entry,&s->plan);
        if(e==LI2_UNROLLED_HASH_MISS) {
            uh_zero(s,sizeof(*s));uh_count(&selected_unrolled.plan_misses);
            uh_need(uh_unchanged(&r->before,si,uc),UH_FRAME,4);selected_unrolled_busy=0;return 0;
        }
        uh_need(!e,UH_SOURCE,e);s->source=r->source;s->identity=slot+1;
        uh_need(!li2_rseq_check_unrolled(&s->plan,uc),UH_SOURCE,1);
        uh_need(entry+PAGE<=r->source.page.address || entry>=r->source.page.address+PAGE,UH_PUBLICATION,1);
        r->slot=(unsigned)slot;r->slot_present=1;s->installed=1;++selected_unrolled.used;
        selected_pending_route=SELECTED_UNROLLED_HASH;selected_step_pending=1;
        uh_need(!uh_query(entry,PROT_READ|PROT_WRITE,&s->writable),UH_PUBLICATION,2);
        volatile unsigned char *p=(void *)entry;
        for(size_t i=0;i<PAGE;i++){p[i]=i<LI2_UNROLLED_HASH_CODE?s->plan.generated[i]:0xcc;s->filled=i+1;}
        uh_need(!uh_permission(s,PROT_READ,&s->publication),UH_PUBLICATION,3);
        uh_need(!uh_bytes(s,&s->verified),UH_PUBLICATION,4);s->complete=1;uh_count(&selected_unrolled.publications);
    } else {
        r->slot=(unsigned)slot;r->slot_present=1;
        selected_pending_route=SELECTED_UNROLLED_HASH;selected_step_pending=1;uh_count(&selected_unrolled.hits);
    }
    struct uh_slot *s=&selected_unrolled.slots[slot];
#ifdef LI2_UNROLLED_HASH_CAPTURE
    uho_slot(s);
#endif
    uh_need(s->installed && s->complete && s->identity==slot+1 && s->filled==PAGE && s->verified==PAGE &&
        s->publication.complete && s->plan.entry==uh_entry(r->source.pc,slot) &&
        uh_source_same(&s->source,&r->source),UH_PUBLICATION,5);
    uh_need(!li2_unrolled_hash_map_pc(&s->plan,s->plan.entry,&r->original),UH_SOURCE,2);
    uh_need(!uh_query(s->plan.entry,PROT_READ,&r->idle) && !uh_bytes(s,&r->idle_bytes),UH_PUBLICATION,6);
    uh_need(!li2_lifecycle_unrolled_validate(&selected_borrow,&r->source) &&
        !li2_rseq_check_unrolled(&s->plan,uc) && uh_quiet(&selected_borrow),UH_SOURCE,3);
#ifdef LI2_UNROLLED_HASH_CAPTURE
    uho_before_open(s);
#endif
    uh_need(!uh_permission(s,PROT_READ|PROT_EXEC,&r->open),UH_PUBLICATION,7);
    uh_need(!uh_query(s->plan.entry,PROT_READ|PROT_EXEC,&r->live) && !uh_bytes(s,&r->live_bytes),UH_PUBLICATION,8);
    uh_need(!li2_lifecycle_unrolled_validate(&selected_borrow,&r->source) &&
        !li2_rseq_check_unrolled(&s->plan,uc),UH_SOURCE,4);
    selected_initialized();uh_need(uh_unchanged(&r->before,si,uc),UH_FRAME,5);
    uh_count(&selected_unrolled.entries);selected_unrolled_active=1;r->redirected=1;
    __asm__ volatile("":::"memory");uc->uc_mcontext.gregs[REG_RIP]=(greg_t)s->plan.entry;
#ifdef LI2_UNROLLED_HASH_CAPTURE
    uho_redirected(sig,si,uc);
#endif
    selected_unrolled_busy=0;return 1;
}
static void selected_unrolled_exit(int sig,siginfo_t *si,ucontext_t *uc) {
    uh_need(selected_unrolled_active && !selected_unrolled_busy && selected_step_pending &&
        selected_pending_route==SELECTED_UNROLLED_HASH,UH_STATE,7);
    selected_unrolled_busy=1;struct uh_record *r=&selected_unrolled.current;
    uh_need(r->slot_present && r->slot<selected_unrolled.used && r->redirected,UH_STATE,8);
    struct uh_slot *s=&selected_unrolled.slots[r->slot];
    uh_need(!uh_capture(&r->after,sig,si,uc),UH_FRAME,6);
    uintptr_t pc=(uintptr_t)r->after.frame.greg[REG_RIP];
    if(pc!=s->plan.pc && pc!=s->plan.stop)selected_unrolled_unexpected(sig,si,uc);
    uh_nx(&r->after,pc);r->exit_seen=1;
    uh_need(uh_identity() && uh_protected() && uh_quiet(&selected_borrow),UH_STATE,9);uh_tls(&r->after);
    uh_need(r->before.fs==r->after.fs && r->before.gs==r->after.gs,UH_TLS,1);
    const greg_t *a=r->before.frame.greg,*b=r->after.frame.greg;
    uint64_t count=(uint64_t)b[REG_RCX]-(uint64_t)a[REG_RCX],d=(uint64_t)b[REG_RDX];
    uh_need(count>=1 && count<=64 && (pc==s->plan.stop?d==0:count==64 && d>=1 && d<=255),UH_RESULT,0);
    uint64_t physical=(uint64_t)b[REG_EFL];unsigned parity=(unsigned)(d&255);
    parity^=parity>>4;parity^=parity>>2;parity^=parity>>1;
    uint64_t defined=((parity&1)?0U:4U)|(d?0U:64U)|(d&128U);
    uh_need((physical&(SELECTED_RF|SELECTED_TF))==SELECTED_RF &&
        (physical&UINT64_C(0x8c5))==defined &&
        (physical&~(UINT64_C(0x8d5)|SELECTED_RF))==(r->flags&~UINT64_C(0x8d5)),UH_RESULT,1);
    for(unsigned i=0;i<NGREG;i++)
        if(i!=REG_RAX && i!=REG_RCX && i!=REG_RDX && i!=REG_RBX && i!=REG_RIP && i!=REG_EFL && i!=REG_CR2)
            uh_need(a[i]==b[i],UH_RESULT,i+2);
    /* Compare every Linux mask bit, not glibc's overlapping siginfo tail. */
    uh_need(r->before.frame.mask==r->after.frame.mask &&
        equal(&r->before.uc.uc_stack,&r->after.uc.uc_stack,sizeof(uc->uc_stack)) &&
        r->before.uc.uc_flags==r->after.uc.uc_flags && r->before.uc.uc_link==r->after.uc.uc_link &&
        r->before.frame.fp_bytes==r->after.frame.fp_bytes &&
        equal(r->before.frame.fp,r->after.frame.fp,LI2_STEP_FP_BYTES),UH_RESULT,30);
    uh_need(!li2_lifecycle_unrolled_validate(&selected_borrow,&r->source) &&
        !li2_rseq_check_unrolled(&s->plan,uc),UH_SOURCE,5);
    uh_need(!uh_permission(s,PROT_READ,&r->close) && !uh_bytes(s,&r->closed_bytes),UH_PUBLICATION,9);
    uh_need(!li2_lifecycle_unrolled_validate(&selected_borrow,&r->source) &&
        uh_unchanged(&r->after,si,uc),UH_SOURCE,6);
    r->release_started=1;r->release_result=li2_lifecycle_fetch_release(&selected_borrow);
    const struct li2_fetch_progress *p=li2_lifecycle_fetch_progress();if(p)r->final_fetch=*p;
    uh_need(!r->release_result && p && !p->held && p->complete && !p->first_error &&
        p->sequence==r->source.borrow.sequence,UH_RELEASE,r->release_result);r->release_complete=1;
    uh_need(uh_unchanged(&r->after,si,uc),UH_FRAME,7);
    r->iterations=count;r->completed=1;uh_count(&selected_unrolled.completed);
    uh_count(pc==s->plan.stop?&selected_unrolled.stop_exits:&selected_unrolled.head_exits);
    uh_need(selected_unrolled.iterations<=UINT64_MAX-count,UH_OVERFLOW,1);selected_unrolled.iterations+=count;
#ifdef LI2_UNROLLED_HASH_CAPTURE
    uho_complete();
#endif
    copy(&selected_unrolled.last,r,sizeof(*r));
    /* Genuine NX added physical RF after final TEST/Jcc; import every actual
       logical bit, including AF. No handler-computed hash or AF prediction. */
    selected_logical_flags=physical&~SELECTED_RF;selected_flags_known=1;
    selected_unrolled_active=0;selected_step_pending=0;selected_pending_route=SELECTED_NO_STEP;
    __asm__ volatile("":::"memory");selected_unrolled_busy=0;
    selected_fetch(sig,si,uc);
}
static void selected_unrolled_report(unsigned status,unsigned code,long detail) {
#ifdef LI2_UNROLLED_HASH_CAPTURE
#ifdef LI2_CURRENT_TF_CAPTURE
    cto_terminal_snapshot(status,code,detail);
#endif
    uho_finish(status,code,detail);
#ifdef LI2_CURRENT_TF_CAPTURE
    cto_write(status,code);
#endif
#endif
    struct writer w={.used=0};text(&w,"LI2_UNROLLED_HASH {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",detail<0?0ULL-(uint64_t)detail:(uint64_t)detail);
    field(&w,",\"detail_negative\":",detail<0);
#ifdef LI2_UNROLLED_HASH_OBSERVE_ONLY
    field(&w,",\"observe_only\":",1);
#else
    field(&w,",\"observe_only\":",0);
#endif
#define UH_FIELD(name) field(&w,",\"" #name "\":",selected_unrolled.name)
    UH_FIELD(initialized);UH_FIELD(first_error);UH_FIELD(used);UH_FIELD(candidates);
    UH_FIELD(source_misses);UH_FIELD(plan_misses);UH_FIELD(capacity_misses);UH_FIELD(publications);
    UH_FIELD(hits);UH_FIELD(entries);UH_FIELD(completed);UH_FIELD(head_exits);UH_FIELD(stop_exits);
    UH_FIELD(iterations);UH_FIELD(unexpected);
    UH_FIELD(events);
#undef UH_FIELD
    selected_repeat_array(&w,",\"signals\":",selected_unrolled.signals,5);
    field(&w,",\"active\":",selected_unrolled_active);field(&w,",\"busy\":",selected_unrolled_busy);
    field(&w,",\"first_detail_abs\":",selected_unrolled.first_detail<0?0ULL-(uint64_t)selected_unrolled.first_detail:(uint64_t)selected_unrolled.first_detail);
    field(&w,",\"first_detail_negative\":",selected_unrolled.first_detail<0);
    const struct uh_record *r=&selected_unrolled.current;
    const uint64_t last[]={r->slot_present,r->slot,r->redirected,r->exit_seen,r->completed,r->iterations,
        r->open.started,r->open.returned,r->open.complete,r->close.started,r->close.returned,r->close.complete,
        r->release_started,r->release_complete,r->cleanup_started,r->cleanup_complete,
        r->before.complete,r->after.complete,r->unexpected_seen,r->unexpected.complete,
        r->original.ready,r->original.kind,r->original.copy_index,r->original.source_offset,
        r->idle_bytes,r->live_bytes,r->closed_bytes,r->final_fetch.held,r->final_fetch.complete};
    selected_repeat_array(&w,",\"current\":",last,sizeof last/sizeof last[0]);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
_Static_assert(64*21+1200<=sizeof(((struct writer *)0)->bytes),"bounded unrolled report");
#ifdef LI2_UNROLLED_HASH_CAPTURE
#include "unrolled_hash_observe.inc"
#endif
