#define _GNU_SOURCE
#include "oneshot.h"
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdatomic.h>

static void copy(void *a,const void *b,size_t n) {
    unsigned char *x=a;const unsigned char *y=b;for(size_t i=0;i<n;i++)x[i]=y[i];
}
static int same(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;return 1;
}
static int zero(const void *a,size_t n) {
    const volatile unsigned char *p=a;for(size_t i=0;i<n;i++)if(p[i])return 0;return 1;
}
static void started(struct li2_oneshot_call *c) {
    atomic_signal_fence(memory_order_seq_cst);c->started=1;
    atomic_signal_fence(memory_order_seq_cst);
}
static void returned(struct li2_oneshot_call *c,long result) {
    c->result=result;atomic_signal_fence(memory_order_seq_cst);c->returned=1;
    atomic_signal_fence(memory_order_seq_cst);
}
static void verified(struct li2_oneshot_call *c) {
    atomic_signal_fence(memory_order_seq_cst);c->verified=1;
    atomic_signal_fence(memory_order_seq_cst);
}
static int complete(const struct li2_oneshot_call *c) {
    return c->started==1 && c->returned==1 && c->verified==1 && !c->reserved && !c->result;
}
static int bad(struct li2_oneshot_owner *o,unsigned code,long detail) {
    li2_admission_oneshot_fail(&o->state,code,detail);return LI2_ONESHOT_TERMINAL;
}
static int phase(struct li2_oneshot_owner *o,unsigned old,unsigned next) {
    int e=li2_admission_oneshot_transition(&o->state,old,next);
    return e?bad(o,(unsigned)e,next):0;
}
static int identity(struct li2_oneshot_owner *o) {
    const struct li2_step_session *s=o->session;
    return s && s->initialized && s->self_test_complete && s->pid>0 && s->pid==s->tid &&
        s->application_mask==LI2_ONESHOT_MASK && !s->sync_register &&
        s->sync_query>=0 && (s->sync_query&96)==96 &&
        o->hooks.raw(SYS_getpid,0,0,0,0,0,0)==s->pid &&
        o->hooks.raw(SYS_gettid,0,0,0,0,0,0)==s->tid;
}
static uint32_t u32(const unsigned char *p) {uint32_t v;copy(&v,p,4);return v;}
static int capture(struct li2_oneshot_owner *o,struct li2_step_frame *f,
                   const siginfo_t *si,const ucontext_t *uc) {
    if(o->hooks.frame_range(o->hooks.context,si,sizeof(*si)) ||
       o->hooks.frame_range(o->hooks.context,uc,sizeof(*uc)))return bad(o,LI2_ONESHOT_FRAME,1);
    for(size_t i=0;i<NGREG;i++)f->greg[i]=uc->uc_mcontext.gregs[i];
    copy(&f->mask,&uc->uc_sigmask,8);f->fp_address=(uintptr_t)uc->uc_mcontext.fpregs;
    f->fp_bytes=0;f->initialized=0;
    const unsigned char *p=(const void *)f->fp_address;
    if(!p || (f->fp_address&15) || o->hooks.frame_range(o->hooks.context,p,512))
        return bad(o,LI2_ONESHOT_FRAME,2);
    size_t n=512;
    if(u32(p+464)==UINT32_C(0x46505853)) {
        n=u32(p+468);size_t x=u32(p+480);
        if(n<580 || n>LI2_STEP_FP_BYTES || x<576 || x>n-4)
            return bad(o,LI2_ONESHOT_FRAME,3);
        if(o->hooks.frame_range(o->hooks.context,p,n) || u32(p+n-4)!=UINT32_C(0x46505845))
            return bad(o,LI2_ONESHOT_FRAME,4);
    }
    f->fp_bytes=n;
    for(size_t i=0;i<n;i++){f->fp[i]=p[i];f->initialized=i+1;}
    return 0;
}
static int page_binding(const struct li2_oneshot_page *a,const struct li2_oneshot_page *b,
                        uint64_t generation) {
    return a->address==b->address && a->allocation==b->allocation &&
        a->generation==generation && a->offset==b->offset;
}
/* Every call retains a distinct actual observation, including partial failures. */
static int observe(struct li2_oneshot_owner *o,unsigned protection) {
    if(o->observations>=8)return bad(o,LI2_ONESHOT_IDENTITY,8);
    unsigned k=o->observations;struct li2_oneshot_call *c=&o->observation_call[k];
    o->observations=k+1;started(c);
    struct li2_oneshot_observation *v=&o->observation[k];
    int e=o->hooks.observe(o->hooks.context,&o->plan,v);returned(c,e);
    if(e)return bad(o,LI2_ONESHOT_IDENTITY,e);
    if(v->pid!=o->session->pid || v->tid!=o->session->tid ||
       v->page_count!=o->plan.page_count || v->landing_protection!=(PROT_READ|PROT_EXEC) ||
       v->landing_private!=1 || v->landing_writable_aliases ||
       v->landing_page!=(o->plan.landing&~UINT64_C(4095)) ||
       v->landing_allocation!=o->plan.landing_allocation ||
       v->landing_generation!=o->plan.landing_generation)
        return bad(o,LI2_ONESHOT_IDENTITY,9);
    for(unsigned i=0;i<o->plan.page_count;i++)
        if(!page_binding(&v->pages[i],&o->plan.pages[i],o->current_generation[i]) ||
           v->protection[i]!=protection || v->private_mapping[i]!=1 ||v->writable_aliases[i])
            return bad(o,LI2_ONESHOT_IDENTITY,(long)i);
    /* Landing is read only after its actual mapping/extent has been authenticated. */
    const volatile unsigned char *p=(const void *)(uintptr_t)o->plan.landing;
    if(p[0]!=0x0f || p[1]!=0x0b)return bad(o,LI2_ONESHOT_LANDING,0);
    o->landing_observed=1;verified(c);
    for(unsigned i=0;i<o->operations;i++) {
        struct li2_oneshot_operation *v=&o->operation[i];
        if(v->kind==1 && v->protection==protection && v->call.returned && !v->call.result)
            verified(&v->call);
    }
    return 0;
}
static int source_equal(struct li2_oneshot_owner *o,int patched) {
    for(unsigned i=0;i<o->plan.page_count;i++) {
        const volatile unsigned char *p=(const void *)(uintptr_t)o->plan.pages[i].address;
        for(size_t j=0;j<LI2_ONESHOT_PAGE;j++) {
            uint64_t at=o->plan.pages[i].address+j;
            unsigned char wanted=o->original_pages[i][j];
            if(patched && at>=o->plan.pc && at-o->plan.pc<5)wanted=o->plan.redirect[at-o->plan.pc];
            if(p[j]!=wanted)return bad(o,LI2_ONESHOT_SOURCE,(long)(i*LI2_ONESHOT_PAGE+j));
        }
    }
    return 0;
}
static struct li2_oneshot_operation *operation(struct li2_oneshot_owner *o,unsigned kind,
                                               unsigned page,unsigned protection) {
    if(o->operations>=LI2_ONESHOT_OPERATIONS){(void)bad(o,LI2_ONESHOT_REUSE,32);return 0;}
    unsigned k=o->operations;struct li2_oneshot_operation *v=&o->operation[k];
    v->kind=kind;v->page=page;v->protection=protection;
    atomic_signal_fence(memory_order_seq_cst);o->operations=k+1;started(&v->call);return v;
}
static int protections(struct li2_oneshot_owner *o,unsigned protection) {
    for(unsigned i=0;i<o->plan.page_count;i++) {
        struct li2_oneshot_operation *v=operation(o,1,i,protection);if(!v)return LI2_ONESHOT_TERMINAL;
        long result=o->hooks.raw(SYS_mprotect,(long)o->plan.pages[i].address,LI2_ONESHOT_PAGE,
                                protection,0,0,0);returned(&v->call,result);
        if(result)return bad(o,LI2_ONESHOT_PROTECT,result);
    }
    return 0;
}
static int sync_core(struct li2_oneshot_owner *o) {
    struct li2_oneshot_operation *v=operation(o,2,0,0);if(!v)return LI2_ONESHOT_TERMINAL;
    long result=o->hooks.raw(SYS_membarrier,32,0,0,0,0,0);returned(&v->call,result);
    if(result)return bad(o,LI2_ONESHOT_SYNC,result);
    verified(&v->call);return 0;
}
static int advance(struct li2_oneshot_owner *o,unsigned restoring) {
    if(restoring>1)return bad(o,LI2_ONESHOT_GENERATION,3);
    struct li2_oneshot_generation *v=&o->generation[restoring];
    if(!zero(v,sizeof(*v)))return bad(o,LI2_ONESHOT_GENERATION,4);
    v->restoring=restoring;
    for(unsigned i=0;i<o->plan.page_count;i++)v->before[i]=o->current_generation[i];
    started(&v->call);
    int e=o->hooks.advance_generation(o->hooks.context,&o->plan,restoring,v);returned(&v->call,e);
    if(e)return bad(o,LI2_ONESHOT_GENERATION,e);
    unsigned mask=(1U<<o->plan.page_count)-1U;
    if(v->restoring!=restoring || v->reserved || v->attempted_mask!=mask ||
       v->completed_mask!=mask)return bad(o,LI2_ONESHOT_GENERATION,5);
    for(unsigned i=0;i<o->plan.page_count;i++) {
        if(v->before[i]!=o->current_generation[i] || v->after[i]<=v->before[i])
            return bad(o,LI2_ONESHOT_GENERATION,(long)i);
    }
    if(o->plan.page_count==1 && (v->before[1] || v->after[1]))return bad(o,LI2_ONESHOT_GENERATION,2);
    for(unsigned i=0;i<o->plan.page_count;i++)o->current_generation[i]=v->after[i];
    verified(&v->call);
    return 0;
}
static int release(struct li2_oneshot_owner *o) {
    struct li2_oneshot_release *v=&o->release;
    if(!zero(v,sizeof(*v)))return bad(o,LI2_ONESHOT_RELEASE,1);
    v->transaction_live=1;started(&v->call);
    int e=o->hooks.release(o->hooks.context,&o->plan,v);returned(&v->call,e);
    if(e || v->transaction_live || v->reserved)return bad(o,LI2_ONESHOT_RELEASE,e?e:2);
    verified(&v->call);
    return 0;
}
static int transfer(struct li2_oneshot_owner *o) {
    struct li2_oneshot_transfer *v=&o->transfer;
    if(!zero(v,sizeof(*v)))return bad(o,LI2_ONESHOT_BIND,1);
    started(&v->call);
    int e=o->hooks.transfer(o->hooks.context,&o->plan,v);returned(&v->call,e);
    if(v->old_authenticated!=1 || v->reserved)return bad(o,LI2_ONESHOT_BIND,2);
    if(e==LI2_ONESHOT_TRANSFER_UNTOUCHED) {
        if(v->old_borrow_live!=1 || v->transaction_live ||
           !zero(&v->old_release,sizeof(v->old_release)) || !zero(&v->acquire,sizeof(v->acquire)))
            return bad(o,LI2_ONESHOT_BIND,3);
        verified(&v->call);return LI2_ONESHOT_REFUSED_UNTOUCHED;
    }
    if(e==LI2_ONESHOT_TRANSFER_RELEASED) {
        if(v->old_borrow_live || v->transaction_live || !complete(&v->old_release) ||
           !zero(&v->acquire,sizeof(v->acquire)))return bad(o,LI2_ONESHOT_BIND,4);
        verified(&v->call);return LI2_ONESHOT_REFUSED_RELEASED;
    }
    if(e!=LI2_ONESHOT_TRANSFER_OWNED || v->old_borrow_live || v->transaction_live!=1 ||
       !complete(&v->old_release) || !complete(&v->acquire))return bad(o,LI2_ONESHOT_BIND,e?e:5);
    verified(&v->call);o->transferred=1;atomic_signal_fence(memory_order_seq_cst);return LI2_ONESHOT_OK;
}
static void write_five(struct li2_oneshot_owner *o,unsigned restoring) {
    volatile uint32_t *attempted=restoring?&o->restore_attempted_mask:&o->write_attempted_mask;
    volatile uint32_t *completed=restoring?&o->restore_completed_mask:&o->write_completed_mask;
    const unsigned char *bytes=restoring?o->plan.original:o->plan.redirect;
    volatile unsigned char *p=(void *)(uintptr_t)o->plan.pc;
    if(restoring)o->restore_started=1;else o->source_write_started=1;
    atomic_signal_fence(memory_order_seq_cst);
    for(unsigned i=0;i<5;i++) {
        uint32_t bit=UINT32_C(1)<<i;
        *attempted=*attempted|bit;atomic_signal_fence(memory_order_seq_cst);
        p[i]=bytes[i];atomic_signal_fence(memory_order_seq_cst);
        *completed=*completed|bit;atomic_signal_fence(memory_order_seq_cst);
    }
}
int li2_oneshot_initialize(struct li2_oneshot_owner *o,const struct li2_step_session *s,
                           const struct li2_oneshot_hooks *h) {
    if(!o || !s || !h || !h->raw || !h->frame_range || !h->transfer ||
       !h->advance_generation || !h->observe || !h->release)return LI2_ONESHOT_ARGUMENT;
    if(!zero(o,sizeof(*o)))return LI2_ONESHOT_REUSE;
    o->session=s;o->hooks=*h;
    if(!identity(o))return LI2_ONESHOT_IDENTITY;
    o->initialized=1;return 0;
}
int li2_oneshot_nx(struct li2_oneshot_owner *o,const struct li2_oneshot_plan *request,
                   int sig,siginfo_t *si,ucontext_t *uc) {
    if(!o || !request || !si || !uc)return LI2_ONESHOT_TERMINAL;
    if(!o->initialized || o->in_handler || o->state.phase!=LI2_ONESHOT_EMPTY)
        return bad(o,LI2_ONESHOT_REENTRY,sig);
    o->in_handler=1;
    int e=li2_admission_oneshot_plan(request,&o->plan);
    if(e) {o->in_handler=0;return e==LI2_ONESHOT_GEOMETRY?LI2_ONESHOT_REFUSED_UNTOUCHED:bad(o,(unsigned)e,0);}
    if(!identity(o) || capture(o,&o->before,si,uc))return bad(o,LI2_ONESHOT_IDENTITY,0);
    const greg_t *g=o->before.greg;
    if(sig!=SIGSEGV || si->si_signo!=SIGSEGV || si->si_code!=SEGV_ACCERR || si->si_errno ||
       (uintptr_t)si->si_addr!=o->plan.pc || (uint64_t)g[REG_RIP]!=o->plan.pc ||
       (uint64_t)g[REG_CR2]!=o->plan.pc || g[REG_TRAPNO]!=14 ||g[REG_ERR]!=21 ||
       ((uint64_t)g[REG_CSGSFS]&0xffff)!=0x33 || o->before.mask!=LI2_ONESHOT_MASK ||
       ((uint64_t)g[REG_EFL]&LI2_STEP_TF) || !((uint64_t)g[REG_EFL]&LI2_STEP_RF))
        return bad(o,LI2_ONESHOT_FRAME,5);
    e=transfer(o);
    if(e) {if(e==LI2_ONESHOT_REFUSED_UNTOUCHED || e==LI2_ONESHOT_REFUSED_RELEASED)o->in_handler=0;return e;}
    for(unsigned i=0;i<o->plan.page_count;i++)o->current_generation[i]=o->plan.pages[i].generation;
    if(observe(o,PROT_READ))return LI2_ONESHOT_TERMINAL;
    for(unsigned i=0;i<o->plan.page_count;i++) {
        const volatile unsigned char *p=(const void *)(uintptr_t)o->plan.pages[i].address;
        for(size_t j=0;j<LI2_ONESHOT_PAGE;j++)o->original_pages[i][j]=p[j];
        o->source_copied=i+1;
    }
    const volatile unsigned char *source=(const void *)(uintptr_t)o->plan.pc;
    for(unsigned i=0;i<5;i++)if(source[i]!=o->plan.original[i])return bad(o,LI2_ONESHOT_SOURCE,i);
    e=li2_admission_oneshot_bind(&o->state,o->plan.sequence);if(e)return bad(o,(unsigned)e,0);
    if(phase(o,LI2_ONESHOT_BOUND,LI2_ONESHOT_WRITING) || advance(o,0) ||
       protections(o,PROT_READ|PROT_WRITE) || observe(o,PROT_READ|PROT_WRITE) || source_equal(o,0))
        return LI2_ONESHOT_TERMINAL;
    write_five(o,0);
    if(source_equal(o,1) || protections(o,PROT_READ|PROT_EXEC) || sync_core(o) ||
       observe(o,PROT_READ|PROT_EXEC) || source_equal(o,1) ||
       phase(o,LI2_ONESHOT_WRITING,LI2_ONESHOT_PUBLISHED))return LI2_ONESHOT_TERMINAL;
    /* Original actual ucontext has not been modified: kernel resumes original PC. */
    o->in_handler=0;return LI2_ONESHOT_OK;
}
int li2_oneshot_ud(struct li2_oneshot_owner *o,int sig,siginfo_t *si,ucontext_t *uc,
                   struct li2_oneshot_handoff *out) {
    if(!o || !si || !uc || !out)return LI2_ONESHOT_TERMINAL;
    if(!o->initialized || o->in_handler || o->state.phase!=LI2_ONESHOT_PUBLISHED)
        return bad(o,LI2_ONESHOT_REENTRY,sig);
    o->in_handler=1;
    if(!identity(o) || capture(o,&o->after,si,uc))return bad(o,LI2_ONESHOT_IDENTITY,1);
    const greg_t *g=o->after.greg;
    if(sig!=SIGILL || si->si_signo!=SIGILL || si->si_code!=ILL_ILLOPN || si->si_errno ||
       (uintptr_t)si->si_addr!=o->plan.landing || (uint64_t)g[REG_RIP]!=o->plan.landing ||
       g[REG_TRAPNO]!=6 || g[REG_ERR] || o->after.mask!=o->before.mask ||
       o->after.fp_bytes!=o->before.fp_bytes || o->after.initialized!=o->after.fp_bytes ||
       o->before.initialized!=o->before.fp_bytes ||
       !same(o->after.fp,o->before.fp,o->before.fp_bytes))return bad(o,LI2_ONESHOT_LANDING,1);
    /* Only RIP and exception vector/error differ. EFLAGS includes actual #PF/#UD
       saved RF; this does not claim intermediate RF survived the E9. CR2 is
       deliberately required exact until an actual separately reviewed result. */
    for(size_t i=0;i<NGREG;i++)if(i!=REG_RIP && i!=REG_TRAPNO && i!=REG_ERR &&
       o->after.greg[i]!=o->before.greg[i])return bad(o,LI2_ONESHOT_FRAME,(long)i);
    if(observe(o,PROT_READ|PROT_EXEC) || source_equal(o,1) ||
       phase(o,LI2_ONESHOT_PUBLISHED,LI2_ONESHOT_LANDED))return LI2_ONESHOT_TERMINAL;
    o->landing_frame=(uintptr_t)uc;
    /* Complete all-pages RX -> all-pages R/NX, including actual fresh observation,
       BEFORE any source RW transition or restoration write. */
    if(phase(o,LI2_ONESHOT_LANDED,LI2_ONESHOT_CLOSING) || protections(o,PROT_READ) ||
       sync_core(o) || observe(o,PROT_READ) || source_equal(o,1) ||
       phase(o,LI2_ONESHOT_CLOSING,LI2_ONESHOT_RESTORING) || advance(o,1) ||
       protections(o,PROT_READ|PROT_WRITE) || observe(o,PROT_READ|PROT_WRITE) || source_equal(o,1))
        return LI2_ONESHOT_TERMINAL;
    write_five(o,1);
    if(source_equal(o,0) || protections(o,PROT_READ) || sync_core(o) ||
       observe(o,PROT_READ) || source_equal(o,0) || release(o) ||
       phase(o,LI2_ONESHOT_RESTORING,LI2_ONESHOT_RESTORED))return LI2_ONESHOT_TERMINAL;
    *out=(struct li2_oneshot_handoff){.kind=o->plan.kind,.sequence=o->plan.sequence,
        .original_pc=o->plan.pc,.original_next_pc=o->plan.next_pc,
        .logical_flags=(uint64_t)o->before.greg[REG_EFL]&~LI2_STEP_RF,.actual_landing_frame=uc};
    o->in_handler=0;return LI2_ONESHOT_OK;
}
void li2_oneshot_abort_close(struct li2_oneshot_owner *o) {
    if(!o || !o->initialized || !o->transferred)return;
    if(!o->state.first_error)(void)bad(o,LI2_ONESHOT_REENTRY,0);
    /* This path is terminal regardless of raw outcomes. It never writes original
       bytes, releases a possibly poisoned transaction or marks restoration. */
    for(unsigned i=0;i<o->plan.page_count;i++) {
        struct li2_oneshot_operation *v=operation(o,3,i,PROT_READ);if(!v)return;
        long result=o->hooks.raw(SYS_mprotect,(long)o->plan.pages[i].address,LI2_ONESHOT_PAGE,
                                PROT_READ,0,0,0);returned(&v->call,result);
    }
    struct li2_oneshot_operation *v=operation(o,4,0,0);if(!v)return;
    long result=o->hooks.raw(SYS_membarrier,32,0,0,0,0,0);returned(&v->call,result);
}
