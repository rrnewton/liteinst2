/* Distinct bounded scalar DAG owner. Include after the unchanged unrolled
   owner. Anonymous protected write-once slots use actual private-code W^X
   provenance, not fabricated memfd seals. C does not pre-read region load
   operands; the unchanged actual rseq registration-word checks remain. */
#include "region_source.h"
#include "private_code_query.h"
#ifdef LI2_SCALAR_REGION_REUSE
#if LI2_SCALAR_REGION_REUSE != 1
#error "literal scalar reuse profile only"
#endif
#endif
#if LI2_SCALAR_REGION != 1 || LI2_UNROLLED_HASH != 1 || LI2_NATIVE_PAIR != 1 || \
    LI2_MAPS_MAINTAINED != 1 || LI2_RUN_CACHE_REUSE != 1 || LI2_TF_HANDOFF != 1 || \
    LI2_REPEAT_RX_LEASE != 1 || LI2_RSEQ_INACTIVE != 1
#error "scalar region requires the unchanged complete unrolled/native-pair profile"
#endif
#ifdef LI2_EVENT_PROFILE
#error "the old event route table has no scalar-region row"
#endif
_Static_assert(__atomic_always_lock_free(sizeof(uint64_t),0),"no external event counter gateway");
#define SR_PAGES 64U
#define SR_BYTES (SR_PAGES*PAGE)
enum sr_error { SR_STATE=2600,SR_FRAME,SR_SOURCE,SR_PUBLICATION,SR_EVENT,
    SR_RESULT,SR_REENTRY,SR_OVERFLOW,SR_TLS,SR_RELEASE,SR_PLAN,SR_RSEQ };
struct sr_frame {
    unsigned started,si_saved,uc_saved,complete;
    int sig;
    siginfo_t si;
    ucontext_t uc;
    struct li2_step_frame frame;
    uint64_t fs,gs;
    long fs_result,gs_result;
    unsigned tls_complete;
};
struct sr_permission {
    unsigned started,returned,sync_started,sync_returned,complete;
    int prot;
    long result,sync_result;
    struct li2_private_code_query query;
};
struct sr_slot {
    unsigned installed,complete;
    uint64_t identity;
    size_t filled,verified;
    struct li2_region_source_key key; /* No old admission ticket is reused. */
    struct li2_region_plan plan;
    struct li2_private_code_query writable;
    struct sr_permission publication;
};
struct sr_record {
    unsigned slot_present,slot,redirected,exit_seen,completed,release_started,release_complete;
    unsigned cleanup_started,cleanup_complete,unexpected_seen,build_started,build_returned;
    int release_result,map_result,build_result;
    uint64_t flags,gpr_written,flags_written;
    unsigned exit_index;
    struct li2_region_source source;
    struct sr_frame before,after,unexpected;
    struct li2_region_pc original;
    struct li2_private_code_query idle,live;
    size_t idle_bytes,live_bytes,closed_bytes;
    struct sr_permission open,close,cleanup;
    struct li2_fetch_progress final_fetch;
#ifdef LI2_SCALAR_REGION_REUSE
    uint64_t publication_generation;
#endif
};
static struct {
    unsigned initialized,first_error,metadata_registered,arena_registered,allocated;
    unsigned low_arena_registered,low_allocated;
    long first_detail,allocation_result,low_allocation_result;
    uintptr_t arena,low_arena;
    size_t used;
    uint64_t candidates,source_misses,plan_misses,capacity_misses,publications,hits;
    uint64_t entries,completed,unexpected,events,signals[5],refusals[4],exit_counts[LI2_REGION_EXITS];
    uint64_t plan_checks,rseq_checks;
    struct li2_step_session session;
    struct li2_private_code_query initial,low_initial;
    struct li2_region_plan scratch; /* Reusable unpublished description only. */
    struct sr_slot slots[SR_PAGES];
    struct sr_record current,last;
} selected_scalar_region;
static volatile sig_atomic_t selected_scalar_region_active,selected_scalar_region_busy;
static volatile sig_atomic_t selected_scalar_region_failing,selected_scalar_region_decoding;
#ifdef LI2_SCALAR_REGION_CAPTURE
static void sro_initialize(void);
static void sro_preentry(int,siginfo_t *,ucontext_t *);
static void sro_entry_frame(int,siginfo_t *,ucontext_t *);
static void sro_source(void);
static void sro_decoder_prefix(void);
static void sro_slot(struct sr_slot *);
static void sro_before_open(struct sr_slot *);
static void sro_redirected(int,siginfo_t *,ucontext_t *);
static void sro_complete(void);
static void sro_abort_observe(void);
static void sro_abort_after_cleanup(void);
static void sro_finish(unsigned,unsigned,long);
#endif
#ifdef LI2_SCALAR_REGION_REUSE
static void srr_initialize(void);
static void srr_abort(void);
static int srr_claimed(void);
#endif
static _Noreturn void selected_scalar_region_abort(unsigned,long);
static void sr_need(int yes,unsigned code,long detail) {
    if(!yes)selected_scalar_region_abort(code,detail);
}

static void sr_count(uint64_t *p) {sr_need(*p!=UINT64_MAX,SR_OVERFLOW,0);++*p;}

static void sr_event_count(uint64_t *p) {
    uint64_t old=__atomic_load_n(p,__ATOMIC_RELAXED);
    sr_need(old!=UINT64_MAX,SR_OVERFLOW,2);
    sr_need(__atomic_compare_exchange_n(p,&old,old+1,0,__ATOMIC_RELAXED,__ATOMIC_RELAXED),SR_REENTRY,0);
}

static uint32_t sr_u32(const unsigned char *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}

static void sr_zero(void *p,size_t n) {
    unsigned char *b=p;for(size_t i=0;i<n;i++)b[i]=0;
}

static int sr_range(const void *p,size_t n) {
    uintptr_t a=(uintptr_t)p,b=(uintptr_t)fork_gate_stack.ss_sp;
    return p && n && b<=UINTPTR_MAX-fork_gate_stack.ss_size &&
        a>=b && a<=b+fork_gate_stack.ss_size && n<=b+fork_gate_stack.ss_size-a;
}

static int sr_capture(struct sr_frame *f,int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(f->started)return SR_FRAME;
    f->started=1;f->sig=sig;
    if(!sr_range(si,sizeof(*si)) || !sr_range(uc,sizeof(*uc)))return SR_FRAME;
    /* Linux x86-64 ends ucontext after its 64-signal mask; siginfo follows.
       The remaining glibc sigset_t bytes alias that distinct event record. */
    if((const unsigned char *)si!=(const unsigned char *)&uc->uc_sigmask+sizeof(f->frame.mask))return SR_FRAME;
    copy(&f->si,si,sizeof(*si));f->si_saved=1;copy(&f->uc,uc,sizeof(*uc));f->uc_saved=1;
    struct li2_step_frame *s=&f->frame;
    copy(s->greg,uc->uc_mcontext.gregs,sizeof s->greg);copy(&s->mask,&uc->uc_sigmask,8);
    s->fp_address=(uintptr_t)uc->uc_mcontext.fpregs;
    if((s->fp_address&15) || !sr_range((void *)s->fp_address,512))return SR_FRAME;
    const unsigned char *p=(void *)s->fp_address;size_t n=512;
    if(sr_u32(p+464)==UINT32_C(0x46505853)) {
        n=sr_u32(p+468);size_t x=sr_u32(p+480);
        if(n<580 || n>LI2_STEP_FP_BYTES || x<576 || x>n-4 ||
           !sr_range(p,n) || sr_u32(p+n-4)!=UINT32_C(0x46505845))return SR_FRAME;
    }
    s->fp_bytes=n;for(size_t i=0;i<n;i++){s->fp[i]=p[i];s->initialized=i+1;}
    f->complete=1;return 0;
}

static int sr_unchanged(const struct sr_frame *f,const siginfo_t *si,const ucontext_t *uc) {
    return f->complete && sr_range(si,sizeof(*si)) && sr_range(uc,sizeof(*uc)) &&
        equal(si,&f->si,sizeof(*si)) && equal(uc,&f->uc,sizeof(*uc)) &&
        sr_range(uc->uc_mcontext.fpregs,f->frame.fp_bytes) &&
        equal(uc->uc_mcontext.fpregs,f->frame.fp,f->frame.fp_bytes);
}

static void sr_tls(struct sr_frame *f) {
    f->fs_result=raw(SYS_arch_prctl,ARCH_GET_FS,(long)&f->fs,0,0,0,0);
    f->gs_result=raw(SYS_arch_prctl,ARCH_GET_GS,(long)&f->gs,0,0,0,0);
    sr_need(!f->fs_result && !f->gs_result,SR_TLS,0);f->tls_complete=1;
}

static int sr_identity(void) {
    const struct li2_step_session *s=&selected_scalar_region.session;
    return equal(s,&selected_session,sizeof(*s)) && s->initialized && s->self_test_complete &&
        s->pid>0 && s->pid==s->tid && s->sync_query>=0 && (s->sync_query&96)==96 &&
        !s->sync_register && raw(SYS_getpid,0,0,0,0,0,0)==s->pid &&
        raw(SYS_gettid,0,0,0,0,0,0)==s->tid;
}

static int sr_protected(void) {
    return selected_run_protection.context==0 &&
        selected_run_protection.add==selected_run_protect_add &&
        selected_run_protection.contains==selected_run_protect_contains &&
        selected_run_protect_contains(0,(uintptr_t)&selected_scalar_region,sizeof selected_scalar_region)==1 &&
        selected_run_protect_contains(0,selected_scalar_region.arena,SR_BYTES)==1 &&
        selected_run_protect_contains(0,selected_scalar_region.low_arena,SR_BYTES)==1;
}

static int sr_query(uintptr_t entry,int prot,struct li2_private_code_query *q) {
    int e=li2_lifecycle_private_code_query(entry,PAGE,prot,q);
    return e || !q->complete || q->pages_checked!=1 || q->actual_prot!=prot?SR_PUBLICATION:0;
}

static int sr_permission(struct sr_slot *s,int prot,struct sr_permission *p) {
    if(p->started)return SR_STATE;
    p->prot=prot;p->started=1;__asm__ volatile("":::"memory");
    p->result=raw(SYS_mprotect,s->plan.generated,PAGE,prot,0,0,0);p->returned=1;
    p->sync_started=1;__asm__ volatile("":::"memory");
    p->sync_result=raw(SYS_membarrier,32,0,0,0,0,0);p->sync_returned=1;
    int q=sr_query(s->plan.generated,prot,&p->query);
    if(p->result || p->sync_result || q)return SR_PUBLICATION;
    p->complete=1;return 0;
}

static void sr_nx(const struct sr_frame *f,uintptr_t pc) {
    const greg_t *g=f->frame.greg;
    sr_need(f->complete && f->sig==SIGSEGV && f->si.si_signo==SIGSEGV &&
        f->si.si_code==SEGV_ACCERR && !f->si.si_errno && g[REG_TRAPNO]==14 && g[REG_ERR]==21 &&
        (uintptr_t)g[REG_RIP]==pc && (uintptr_t)f->si.si_addr==pc &&
        (uintptr_t)g[REG_CR2]==pc &&
        ((uint64_t)g[REG_CSGSFS]&65535)==0x33 && (uint64_t)g[REG_RSP]<(UINT64_C(1)<<47) &&
        f->frame.mask==selected_scalar_region.session.application_mask,SR_EVENT,f->sig);
}
/* The original helper checks every old step/run/REP/effect/native/rseq owner.
   Add the actual unrolled owner itself; never forge its route or old plan. */
static int sr_quiet(const struct li2_fetch_ref *ref) {
    return uh_quiet(ref) && selected_unrolled.initialized==1 &&
        !selected_unrolled_active && !selected_unrolled_busy && !selected_unrolled_failing &&
        !selected_unrolled.first_error && selected_pending_route!=SELECTED_UNROLLED_HASH &&
        selected_unrolled.entries==selected_unrolled.completed &&
        selected_unrolled.publications==selected_unrolled.used && selected_unrolled.used<=SR_PAGES;
}
static int sr_bytes(const struct sr_slot *s,size_t *observed) {
    const volatile unsigned char *p=(void *)s->plan.generated;
    for(size_t i=0;i<PAGE;i++) {
        if(p[i]!=s->plan.image[i])return SR_PUBLICATION;
        *observed=i+1;
    }
    return 0;
}
static int sr_plan(const struct li2_region_plan *p) {
    sr_need(!selected_scalar_region_decoding,SR_REENTRY,1);
    selected_scalar_region_decoding=1;__asm__ volatile("":::"memory");
    int e=li2_region_plan_validate(p);
    __asm__ volatile("":::"memory");selected_scalar_region_decoding=0;
    selected_initialized();sr_count(&selected_scalar_region.plan_checks);return e;
}
static int sr_rseq(const struct li2_region_plan *p,const ucontext_t *uc) {
    sr_need(!selected_scalar_region_decoding,SR_REENTRY,2);
    selected_scalar_region_decoding=1;__asm__ volatile("":::"memory");
    int e=li2_rseq_check_region(p,uc);
    __asm__ volatile("":::"memory");selected_scalar_region_decoding=0;
    selected_initialized();sr_count(&selected_scalar_region.rseq_checks);return e;
}
/* Terminal association does not recursively re-enter an interrupted decoder.
   These are the exact rows of the fully validated protected immutable plan.
   Interior/tail PCs remain MISS; no association grants resume/completion. */
static int sr_map_actual(const struct sr_slot *s,uintptr_t pc,struct li2_region_pc *out) {
    if(!s->installed || !s->complete || s->plan.version!=LI2_REGION_PLAN_VERSION ||
       s->plan.ready!=1 || !s->plan.maps || s->plan.maps>LI2_REGION_MAPS)
        return LI2_REGION_PLAN_CORRUPT;
#ifdef LI2_SCALAR_REGION_REUSE
    if(!srr_claimed())return LI2_REGION_PLAN_CORRUPT;
#endif
    for(size_t i=0;i<s->plan.maps;i++) {
        const struct li2_region_pc *m=&s->plan.map[i];
        if(m->generated_pc==pc) {copy(out,m,sizeof *out);return LI2_REGION_PLAN_OK;}
    }
    return LI2_REGION_PLAN_MISS;
}
static _Noreturn void selected_scalar_region_abort(unsigned code,long detail) {
    if(!selected_scalar_region.first_error) {
        selected_scalar_region.first_error=code;selected_scalar_region.first_detail=detail;
    }
    if(selected_scalar_region_failing) {
        (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    selected_scalar_region_failing=1;selected_scalar_region_busy=1;li2_maps_phase_fail();
#ifdef LI2_SCALAR_REGION_CAPTURE
    sro_abort_observe();
#endif
    struct sr_record *r=&selected_scalar_region.current;
#ifdef LI2_SCALAR_REGION_REUSE
    srr_abort();
#else
    if(r->slot_present && r->slot<selected_scalar_region.used && !r->cleanup_started) {
        r->cleanup_started=1;__asm__ volatile("":::"memory");
        struct sr_slot *s=&selected_scalar_region.slots[r->slot];
        if(!sr_permission(s,PROT_READ,&r->cleanup))r->cleanup_complete=1;
    }
#endif
#ifdef LI2_SCALAR_REGION_CAPTURE
    sro_abort_after_cleanup();
#endif
    const struct li2_fetch_progress *p=li2_lifecycle_fetch_progress();
    if(p)copy(&r->final_fetch,p,sizeof r->final_fetch);
    li2_lifecycle_abort();report(125,selected_scalar_region.first_error,selected_scalar_region.first_detail);
    (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static _Noreturn void selected_scalar_region_unexpected(int sig,siginfo_t *si,ucontext_t *uc) {
    struct sr_record *r=&selected_scalar_region.current;
    if(!r->unexpected_seen) {
        r->unexpected_seen=1;
        if(selected_scalar_region.unexpected!=UINT64_MAX)++selected_scalar_region.unexpected;
        int e=sr_capture(&r->unexpected,sig,si,uc);
        r->map_result=e?e:LI2_REGION_PLAN_MISS;
        if(!e && !handling && selected_scalar_region_active && r->redirected && !r->completed &&
           r->open.complete && r->slot_present && r->slot<selected_scalar_region.used) {
            const struct sr_slot *s=&selected_scalar_region.slots[r->slot];
            const struct li2_fetch_progress *f=li2_lifecycle_fetch_progress();
            if(
#ifdef LI2_SCALAR_REGION_REUSE
               srr_claimed() &&
#else
               s->identity==(uint64_t)r->slot+1 &&
#endif
               s->publication.complete &&
               s->filled==PAGE && s->verified==PAGE && r->source.ready==1 &&
               r->source.borrow.owner==selected_borrow.owner &&
               r->source.borrow.sequence==selected_borrow.sequence && f && f->held && f->complete &&
               !f->first_error && f->sequence==r->source.borrow.sequence &&
               li2_region_source_key_equal(&s->key,&r->source.key) &&
               s->plan.page==s->key.page.address && s->plan.entry==s->key.entry &&
               s->plan.generated==(s->key.entry<(UINT64_C(1)<<31)?selected_scalar_region.low_arena:
                   selected_scalar_region.arena)+(uintptr_t)r->slot*PAGE)
                r->map_result=sr_map_actual(s,(uintptr_t)r->unexpected.frame.greg[REG_RIP],&r->original);
        }
    }
    selected_scalar_region_abort(SR_EVENT,sig);
}
static int sr_exit_index(const struct li2_region_plan *p,uintptr_t pc) {
    if(p->ready!=1 || !p->exits || p->exits>LI2_REGION_EXITS)return -1;
    for(unsigned i=0;i<p->exits;i++)if(p->exit_pc[i]==pc)return (int)i;
    return -1;
}
/* Runs after the unchanged pure native/rseq guards and BEFORE returning RAW,
   map/event callbacks or any old pending-owner route. */
static void selected_scalar_region_preentry(int sig,siginfo_t *si,ucontext_t *uc) {
#ifdef LI2_SCALAR_REGION_CAPTURE
    sro_preentry(sig,si,uc);
#endif
    sr_event_count(&selected_scalar_region.events);
    unsigned kind=sig==SIGSEGV?0:sig==SIGTRAP?1:sig==SIGILL?2:sig==SIGSYS?3:4;
    sr_event_count(&selected_scalar_region.signals[kind]);
    int routed=selected_pending_route==SELECTED_SCALAR_REGION;
    if(!selected_scalar_region_active && !selected_scalar_region_busy && !routed)return;
    struct sr_record *r=&selected_scalar_region.current;
    if(selected_scalar_region_busy || selected_scalar_region_decoding ||
       !selected_scalar_region_active || handling || !routed || selected_step_pending!=1 ||
       !r->slot_present || r->slot>=selected_scalar_region.used || !r->redirected || r->completed ||
       selected_scalar_region.first_error || !sr_range(si,sizeof(*si)) || !sr_range(uc,sizeof(*uc)))
        selected_scalar_region_unexpected(sig,si,uc);
    const struct sr_slot *s=&selected_scalar_region.slots[r->slot];
    const greg_t *g=uc->uc_mcontext.gregs;uintptr_t pc=(uintptr_t)g[REG_RIP];
    uint64_t mask=0;copy(&mask,&uc->uc_sigmask,sizeof mask);
    if(!s->installed || !s->complete || !r->open.complete || sr_exit_index(&s->plan,pc)<0 ||
       sig!=SIGSEGV || si->si_signo!=SIGSEGV || si->si_code!=SEGV_ACCERR || si->si_errno ||
       g[REG_TRAPNO]!=14 || g[REG_ERR]!=21 || (uintptr_t)si->si_addr!=pc || (uintptr_t)g[REG_CR2]!=pc ||
       ((uint64_t)g[REG_EFL]&(SELECTED_TF|SELECTED_RF))!=SELECTED_RF ||
       ((uint64_t)g[REG_CSGSFS]&65535)!=0x33 || (uint64_t)g[REG_RSP]>=(UINT64_C(1)<<47) ||
       mask!=selected_scalar_region.session.application_mask)
        selected_scalar_region_unexpected(sig,si,uc);
}
static void selected_scalar_region_initialize(void) {
    sr_need(!selected_scalar_region.initialized && !selected_scalar_region_active &&
        !selected_scalar_region_busy,SR_STATE,1);selected_scalar_region_busy=1;
    copy(&selected_scalar_region.session,&selected_session,sizeof selected_session);
    sr_need(sr_identity() && !li2_lifecycle_fetch_interlock() &&
        selected_unrolled.initialized && !selected_unrolled_active && !selected_unrolled_busy,
        SR_STATE,2);
    sr_need(!selected_run_protect_add(0,(uintptr_t)&selected_scalar_region,sizeof selected_scalar_region),SR_STATE,3);
    selected_scalar_region.metadata_registered=1;
    selected_scalar_region.allocation_result=raw(SYS_mmap,0,SR_BYTES,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    long a=selected_scalar_region.allocation_result;
    sr_need(!(a<0 && a>=-4095) && a>0 && !((uintptr_t)a&(PAGE-1)) &&
        (uintptr_t)a<(UINT64_C(1)<<47)-SR_BYTES,SR_PUBLICATION,a);
    selected_scalar_region.arena=(uintptr_t)a;selected_scalar_region.allocated=1;
    sr_need(!selected_run_protect_add(0,(uintptr_t)a,SR_BYTES),SR_STATE,4);
    selected_scalar_region.arena_registered=1;
    selected_scalar_region.low_allocation_result=raw(SYS_mmap,0,SR_BYTES,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT,-1,0);
    long low=selected_scalar_region.low_allocation_result;
    sr_need(!(low<0 && low>=-4095) && low>0 && !((uintptr_t)low&(PAGE-1)) &&
        (uintptr_t)low<=(UINT64_C(1)<<31)-SR_BYTES,SR_PUBLICATION,low);
    selected_scalar_region.low_arena=(uintptr_t)low;selected_scalar_region.low_allocated=1;
    sr_need((uintptr_t)low+SR_BYTES<=(uintptr_t)a || (uintptr_t)a+SR_BYTES<=(uintptr_t)low,SR_PUBLICATION,10);
    sr_need(!selected_run_protect_add(0,(uintptr_t)low,SR_BYTES),SR_STATE,10);
    selected_scalar_region.low_arena_registered=1;sr_need(sr_protected(),SR_STATE,5);
    int e=li2_lifecycle_private_code_query(a,SR_BYTES,PROT_READ|PROT_WRITE,&selected_scalar_region.initial);
    sr_need(!e && selected_scalar_region.initial.complete && selected_scalar_region.initial.pages_checked==SR_PAGES,
        SR_PUBLICATION,e);
    e=li2_lifecycle_private_code_query(low,SR_BYTES,PROT_READ|PROT_WRITE,&selected_scalar_region.low_initial);
    sr_need(!e && selected_scalar_region.low_initial.complete && selected_scalar_region.low_initial.pages_checked==SR_PAGES,
        SR_PUBLICATION,e);
#ifdef LI2_SCALAR_REGION_REUSE
    srr_initialize();
#endif
    selected_scalar_region.initialized=1;selected_scalar_region_busy=0;
#ifdef LI2_SCALAR_REGION_CAPTURE
    sro_initialize();
#endif
}
static uintptr_t sr_entry(uintptr_t pc,size_t slot) {
    uintptr_t arena=pc<(UINT64_C(1)<<31)?selected_scalar_region.low_arena:selected_scalar_region.arena;
    return arena+slot*PAGE;
}
#ifdef LI2_SCALAR_REGION_REUSE
#include "selected_scalar_reuse.inc"
#endif
static int sr_refusal(int result) {
    return result==LI2_REGION_PLAN_MISS?0:result==LI2_REGION_PLAN_BOUNDARY?1:
        result==LI2_REGION_PLAN_GRAPH?2:result==LI2_REGION_PLAN_RELOCATION?3:-1;
}
/* Union only: these are definitely-unchanged masks, not an executed-path
   reconstruction. All affected outputs/undefined flags remain actual. */
static void sr_effects(const struct li2_region_plan *p,struct sr_record *r) {
    sr_need(p->heads && p->heads<=LI2_REGION_HEADS,SR_PLAN,1);
    for(size_t i=0;i<p->heads;i++) {
        const struct li2_region_decoded *d=&p->original[i];
        r->gpr_written|=d->gpr_write;
        r->flags_written|=d->flags_written|d->flags_set|d->flags_cleared|d->flags_undefined;
    }
    sr_need(!(r->gpr_written&~UINT64_C(0xffff)) && !(r->gpr_written&(UINT64_C(1)<<4)) &&
        !(r->flags_written&~UINT64_C(0x8d5)),SR_PLAN,2);
}
static int selected_scalar_region_try(int sig,siginfo_t *si,ucontext_t *uc,uint64_t flags) {
    if(selected_view.length!=15)return 0;
    sr_need(selected_scalar_region.initialized && !selected_scalar_region_active &&
        !selected_scalar_region_busy && !selected_scalar_region.first_error &&
        !selected_step_pending && selected_pending_route==SELECTED_NO_STEP && sr_quiet(&selected_borrow),SR_STATE,6);
    selected_scalar_region_busy=1;__asm__ volatile("":::"memory");sr_count(&selected_scalar_region.candidates);
    struct sr_record *r=&selected_scalar_region.current;sr_zero(r,sizeof *r);
#ifdef LI2_SCALAR_REGION_REUSE
    srr_begin();
#endif
#ifdef LI2_SCALAR_REGION_CAPTURE
    sro_entry_frame(sig,si,uc);
#endif
    sr_need(!sr_capture(&r->before,sig,si,uc),SR_FRAME,0);r->flags=flags;sr_nx(&r->before,selected_view.pc);
    sr_need(!(flags&(SELECTED_TF|SELECTED_RF)) &&
        (uint64_t)r->before.frame.greg[REG_EFL]==(flags|SELECTED_RF),SR_FRAME,1);
    int e=li2_lifecycle_region_source(&selected_borrow,&r->source);sr_need(!e,SR_SOURCE,e);
    if(!r->source.ready) {
        sr_count(&selected_scalar_region.source_misses);sr_need(sr_unchanged(&r->before,si,uc),SR_FRAME,2);
        selected_scalar_region_busy=0;return 0;
    }
    sr_need(r->source.ready==1 && r->source.key.entry==selected_view.pc &&
        r->source.borrow.owner==selected_borrow.owner && r->source.borrow.sequence==selected_borrow.sequence &&
        sr_identity() && sr_protected(),SR_SOURCE,0);sr_tls(&r->before);
#ifdef LI2_SCALAR_REGION_CAPTURE
    sro_source();
#endif
    size_t slot=0;
    while(slot<selected_scalar_region.used &&
          !li2_region_source_key_equal(&selected_scalar_region.slots[slot].key,&r->source.key))++slot;
#ifdef LI2_SCALAR_REGION_REUSE
    int reuse_hit=slot<selected_scalar_region.used;
    if(!reuse_hit) {
        if(slot==SR_PAGES)slot=srr_choose();
#else
    if(slot==selected_scalar_region.used) {
#endif
        if(slot==SR_PAGES) {
            sr_count(&selected_scalar_region.capacity_misses);sr_need(sr_unchanged(&r->before,si,uc),SR_FRAME,3);
            selected_scalar_region_busy=0;return 0;
        }
        uintptr_t entry=sr_entry(r->source.key.entry,slot);
        sr_need(!selected_scalar_region_decoding,SR_REENTRY,3);
        r->build_started=1;selected_scalar_region_decoding=1;__asm__ volatile("":::"memory");
#ifdef LI2_SCALAR_REGION_CAPTURE
        sro_decoder_prefix();
#endif
        e=li2_region_plan_page(r->source.key.page.address,r->source.key.bytes,r->source.key.entry,
            entry,&selected_scalar_region.scratch);
        r->build_result=e;r->build_returned=1;__asm__ volatile("":::"memory");selected_scalar_region_decoding=0;
        selected_initialized();int refusal=sr_refusal(e);
        if(refusal>=0) {
            sr_need(!selected_scalar_region.scratch.ready && !selected_scalar_region.scratch.decoder_result,
                SR_PLAN,e);sr_count(&selected_scalar_region.plan_misses);
            sr_count(&selected_scalar_region.refusals[refusal]);
            sr_need(sr_unchanged(&r->before,si,uc) && sr_quiet(&selected_borrow),SR_FRAME,4);
            selected_scalar_region_busy=0;return 0;
        }
        sr_need(!e && !sr_plan(&selected_scalar_region.scratch),SR_PLAN,e);
        sr_need(!li2_lifecycle_region_validate(&selected_borrow,&r->source,&selected_scalar_region.scratch) &&
            !sr_rseq(&selected_scalar_region.scratch,uc),SR_SOURCE,1);
        struct sr_slot *s=&selected_scalar_region.slots[slot];
#ifdef LI2_SCALAR_REGION_REUSE
        srr_prepare(slot,entry,si,uc);
#endif
        sr_need(!s->installed && !s->complete && !s->identity &&
            (entry+PAGE<=r->source.key.page.address || entry>=r->source.key.page.address+PAGE),SR_PUBLICATION,1);
        copy(&s->key,&r->source.key,sizeof s->key);copy(&s->plan,&selected_scalar_region.scratch,sizeof s->plan);
#ifdef LI2_SCALAR_REGION_REUSE
        s->identity=r->publication_generation;
        if(slot==selected_scalar_region.used)++selected_scalar_region.used;
        r->slot=(unsigned)slot;r->slot_present=1;s->installed=1;
#else
        s->identity=slot+1;r->slot=(unsigned)slot;r->slot_present=1;s->installed=1;++selected_scalar_region.used;
#endif
        selected_pending_route=SELECTED_SCALAR_REGION;selected_step_pending=1;
        sr_need(!sr_query(entry,PROT_READ|PROT_WRITE,&s->writable),SR_PUBLICATION,2);
        volatile unsigned char *p=(void *)entry;
        for(size_t i=0;i<PAGE;i++){p[i]=s->plan.image[i];s->filled=i+1;}
        sr_need(!sr_permission(s,PROT_READ,&s->publication) && !sr_bytes(s,&s->verified),SR_PUBLICATION,3);
        s->complete=1;sr_count(&selected_scalar_region.publications);
#ifdef LI2_SCALAR_REGION_REUSE
        srr_published(slot);
#endif
    } else {
        r->slot=(unsigned)slot;r->slot_present=1;
        selected_pending_route=SELECTED_SCALAR_REGION;selected_step_pending=1;sr_count(&selected_scalar_region.hits);
    }
    struct sr_slot *s=&selected_scalar_region.slots[slot];
#ifdef LI2_SCALAR_REGION_REUSE
    srr_claim(slot,reuse_hit);
#endif
#ifdef LI2_SCALAR_REGION_CAPTURE
    sro_slot(s);
#endif
    sr_need(s->installed && s->complete &&
#ifdef LI2_SCALAR_REGION_REUSE
        srr_claimed() &&
#else
        s->identity==slot+1 &&
#endif
        s->filled==PAGE && s->verified==PAGE &&
        s->publication.complete && s->plan.generated==sr_entry(r->source.key.entry,slot) &&
        li2_region_source_key_equal(&s->key,&r->source.key) && !sr_plan(&s->plan),SR_PUBLICATION,5);
    sr_effects(&s->plan,r);
    sr_need(!sr_query(s->plan.generated,PROT_READ,&r->idle) && !sr_bytes(s,&r->idle_bytes),SR_PUBLICATION,6);
    sr_need(!li2_lifecycle_region_validate(&selected_borrow,&r->source,&s->plan) &&
        !sr_rseq(&s->plan,uc) && sr_quiet(&selected_borrow),SR_SOURCE,3);
#ifdef LI2_SCALAR_REGION_CAPTURE
    sro_before_open(s);
#endif
    sr_need(!sr_permission(s,PROT_READ|PROT_EXEC,&r->open),SR_PUBLICATION,7);
    sr_need(!sr_query(s->plan.generated,PROT_READ|PROT_EXEC,&r->live) && !sr_bytes(s,&r->live_bytes),SR_PUBLICATION,8);
    sr_need(!li2_lifecycle_region_validate(&selected_borrow,&r->source,&s->plan) &&
        !sr_rseq(&s->plan,uc),SR_SOURCE,4);
    selected_initialized();sr_need(sr_unchanged(&r->before,si,uc),SR_FRAME,5);
    sr_count(&selected_scalar_region.entries);selected_scalar_region_active=1;r->redirected=1;
    __asm__ volatile("":::"memory");uc->uc_mcontext.gregs[REG_RIP]=(greg_t)s->plan.generated;
#ifdef LI2_SCALAR_REGION_CAPTURE
    sro_redirected(sig,si,uc);
#endif
    selected_scalar_region_busy=0;return 1;
}
static void selected_scalar_region_exit(int sig,siginfo_t *si,ucontext_t *uc) {
    sr_need(selected_scalar_region_active && !selected_scalar_region_busy && selected_step_pending &&
        selected_pending_route==SELECTED_SCALAR_REGION,SR_STATE,7);
    selected_scalar_region_busy=1;struct sr_record *r=&selected_scalar_region.current;
    sr_need(r->slot_present && r->slot<selected_scalar_region.used && r->redirected,SR_STATE,8);
#ifdef LI2_SCALAR_REGION_REUSE
    sr_need(srr_claimed(),SR_STATE,316);
#endif
    struct sr_slot *s=&selected_scalar_region.slots[r->slot];
    sr_need(!sr_capture(&r->after,sig,si,uc),SR_FRAME,6);
    uintptr_t pc=(uintptr_t)r->after.frame.greg[REG_RIP];int exit=sr_exit_index(&s->plan,pc);
    if(exit<0)selected_scalar_region_unexpected(sig,si,uc);
    sr_nx(&r->after,pc);r->exit_seen=1;r->exit_index=(unsigned)exit;
    sr_need(sr_identity() && sr_protected() && sr_quiet(&selected_borrow),SR_STATE,9);sr_tls(&r->after);
    sr_need(r->before.fs==r->after.fs && r->before.gs==r->after.gs,SR_TLS,1);
    const greg_t *a=r->before.frame.greg,*b=r->after.frame.greg;
    static const unsigned greg[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,
        REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
    for(unsigned i=0;i<16;i++)if(!(r->gpr_written&(UINT64_C(1)<<i)))
        sr_need(a[greg[i]]==b[greg[i]],SR_RESULT,i);
    for(unsigned i=0;i<NGREG;i++) {
        unsigned ordinary=0;for(unsigned j=0;j<16;j++)if(i==greg[j])ordinary=1;
        if(!ordinary && i!=REG_RIP && i!=REG_EFL && i!=REG_CR2)sr_need(a[i]==b[i],SR_RESULT,16+i);
    }
    uint64_t physical=(uint64_t)b[REG_EFL];
    sr_need((physical&(SELECTED_TF|SELECTED_RF))==SELECTED_RF &&
        (physical&~(r->flags_written|SELECTED_RF))==(r->flags&~r->flags_written),SR_RESULT,40);
    sr_need(r->before.frame.mask==r->after.frame.mask &&
        equal(&r->before.uc.uc_stack,&r->after.uc.uc_stack,sizeof(uc->uc_stack)) &&
        r->before.uc.uc_flags==r->after.uc.uc_flags && r->before.uc.uc_link==r->after.uc.uc_link &&
        r->before.frame.fp_bytes==r->after.frame.fp_bytes &&
        equal(r->before.frame.fp,r->after.frame.fp,LI2_STEP_FP_BYTES),SR_RESULT,41);
    sr_need(!sr_plan(&s->plan) && !li2_lifecycle_region_validate(&selected_borrow,&r->source,&s->plan) &&
        !sr_rseq(&s->plan,uc),SR_SOURCE,5);
    sr_need(!sr_permission(s,PROT_READ,&r->close) && !sr_bytes(s,&r->closed_bytes),SR_PUBLICATION,9);
    sr_need(!li2_lifecycle_region_validate(&selected_borrow,&r->source,&s->plan) &&
        sr_unchanged(&r->after,si,uc),SR_SOURCE,6);
    r->release_started=1;r->release_result=li2_lifecycle_fetch_release(&selected_borrow);
    const struct li2_fetch_progress *p=li2_lifecycle_fetch_progress();
    if(p)copy(&r->final_fetch,p,sizeof r->final_fetch);
    sr_need(!r->release_result && p && !p->held && p->complete && !p->first_error &&
        p->sequence==r->source.borrow.sequence,SR_RELEASE,r->release_result);r->release_complete=1;
    sr_need(sr_unchanged(&r->after,si,uc),SR_FRAME,7);
    r->completed=1;sr_count(&selected_scalar_region.completed);sr_count(&selected_scalar_region.exit_counts[exit]);
#ifdef LI2_SCALAR_REGION_CAPTURE
    sro_complete();
#endif
    copy(&selected_scalar_region.last,r,sizeof *r);
    /* Only the original exit RIP is already present. Import every actual
       logical flag, including AF; no GPR, guest data or FP is predicted/reset. */
    selected_logical_flags=physical&~SELECTED_RF;selected_flags_known=1;
    selected_scalar_region_active=0;selected_step_pending=0;selected_pending_route=SELECTED_NO_STEP;
#ifdef LI2_SCALAR_REGION_REUSE
    srr_quiesce(sig,si,uc);
#endif
    __asm__ volatile("":::"memory");selected_scalar_region_busy=0;selected_fetch(sig,si,uc);
}
static void selected_scalar_region_report(unsigned status,unsigned code,long detail) {
#ifdef LI2_SCALAR_REGION_CAPTURE
    sro_finish(status,code,detail);
#endif
#ifdef LI2_SCALAR_REGION_REUSE
    srr_report(status,code,detail);
    struct writer w={.used=0};text(&w,"LI2_SCALAR_REGION {\"version\":2");
#else
    struct writer w={.used=0};text(&w,"LI2_SCALAR_REGION {\"version\":1");
#endif
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",detail<0?0ULL-(uint64_t)detail:(uint64_t)detail);
    field(&w,",\"detail_negative\":",detail<0);
#define SR_FIELD(name) field(&w,",\"" #name "\":",selected_scalar_region.name)
    SR_FIELD(initialized);SR_FIELD(first_error);SR_FIELD(used);SR_FIELD(candidates);SR_FIELD(source_misses);
    SR_FIELD(plan_misses);SR_FIELD(capacity_misses);SR_FIELD(publications);SR_FIELD(hits);SR_FIELD(entries);
    SR_FIELD(completed);SR_FIELD(unexpected);SR_FIELD(events);SR_FIELD(plan_checks);SR_FIELD(rseq_checks);
#undef SR_FIELD
    field(&w,",\"active\":",selected_scalar_region_active);field(&w,",\"busy\":",selected_scalar_region_busy);
    field(&w,",\"decoding\":",selected_scalar_region_decoding);
    selected_repeat_array(&w,",\"signals\":",selected_scalar_region.signals,5);
    selected_repeat_array(&w,",\"refusals\":",selected_scalar_region.refusals,4);
    selected_repeat_array(&w,",\"exit_indices\":",selected_scalar_region.exit_counts,LI2_REGION_EXITS);
    const struct sr_record *r=&selected_scalar_region.current;
    const uint64_t last[]={r->slot_present,r->slot,r->redirected,r->exit_seen,r->completed,r->exit_index,
        r->open.started,r->open.returned,r->open.complete,r->close.started,r->close.returned,r->close.complete,
        r->release_started,r->release_complete,r->cleanup_started,r->cleanup_complete,
        r->before.complete,r->after.complete,r->unexpected_seen,r->unexpected.complete,
        r->original.ready,r->original.kind,r->original.head_index,r->original.source_offset,
        r->idle_bytes,r->live_bytes,r->closed_bytes,r->final_fetch.held,r->final_fetch.complete,
        r->build_started,r->build_returned,(unsigned)r->build_result,r->gpr_written,r->flags_written};
    selected_repeat_array(&w,",\"current\":",last,sizeof last/sizeof last[0]);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
_Static_assert(80*21+1500<=sizeof(((struct writer *)0)->bytes),"bounded scalar-region report");
#ifdef LI2_SCALAR_REGION_CAPTURE
#include "scalar_region_observe.inc"
#endif
