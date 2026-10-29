#include "register_run.h"
#if defined(LI2_EFFECT_PROVIDER) && defined(LI2_TF_HANDOFF) && defined(LI2_REGISTER_RUN)
#include "tf_chain.h"
#endif
#include <sys/mman.h>
#include <sys/syscall.h>

#define RAW(n,a,b,c,d,e,f) li2_step_raw(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
static const unsigned regs[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,
    REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
static void copy(void *to,const void *from,size_t n) {
    unsigned char *a=to;const unsigned char *b=from;
    for(size_t i=0;i<n;i++)a[i]=b[i];
}
static int same(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;
    for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;
    return 1;
}
static uint32_t u32(const unsigned char *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static int failed(struct li2_run_owner *o,unsigned code,long detail) {
    if(!o->first_error){o->first_error=code;o->first_detail=detail;}
    o->phase=LI2_RUN_FAILED;return (int)o->first_error;
}
_Noreturn void li2_run_abort(struct li2_run_owner *o,unsigned code,long detail) {
#ifdef LI2_MAPS_PHASE_REUSE
    li2_maps_phase_fail();
#endif

    if(o) {
        (void)failed(o,code,detail);
        /* No original page was opened and no publication is reclaimed. The
           retained generated owner stays alive until this process terminates. */
        const struct li2_fetch_progress *p=li2_lifecycle_fetch_progress();
        if(p && o->borrow.sequence && p->sequence==o->borrow.sequence)o->final_fetch=*p;
        if(!o->failure_notified && o->publisher.failure) {
            o->failure_notified=1;
            o->publisher.failure(o->publisher.context,o);
        }
    }
    (void)RAW(SYS_exit_group,125,0,0,0,0,0);
    __builtin_trap();
}
static void require(struct li2_run_owner *o,int yes,unsigned code,long detail) {
    if(!yes)li2_run_abort(o,code,detail);
}
static int session(const struct li2_step_session *s) {
    return s && s->initialized && s->self_test_complete && s->pid>0 && s->pid==s->tid &&
        s->sync_query>=0 && (s->sync_query&96)==96 && !s->sync_register &&
        RAW(SYS_getpid,0,0,0,0,0,0)==s->pid && RAW(SYS_gettid,0,0,0,0,0,0)==s->tid;
}
static int page_same(const struct li2_fetch_page *a,const struct li2_fetch_page *b) {
    return a->address==b->address && a->allocation==b->allocation && a->generation==b->generation &&
        a->offset==b->offset && a->initial_extent==b->initial_extent && a->backing==b->backing &&
        a->object==b->object && a->logical==b->logical && a->closed_prot==b->closed_prot &&
        a->vma_first==b->vma_first && a->vma_end==b->vma_end && a->vma_major==b->vma_major &&
        a->vma_minor==b->vma_minor && a->vma_inode==b->vma_inode && a->vma_offset==b->vma_offset;
}
static int source(struct li2_run_owner *o,int initial) {
    struct li2_fetch_view v={0};
    o->fetch_view_started=1;o->fetch_view_complete=0;
    o->fetch_result=li2_lifecycle_fetch_view(&o->borrow,&v);
    if(o->fetch_result)return LI2_RUN_FETCH;
    if(!v.bytes || !v.pages || !v.backing || !v.length || v.length>15 ||
       v.pc>UINTPTR_MAX-v.length || !v.identity_observed ||
       v.pid!=o->session->pid || v.tid!=o->session->tid)return LI2_RUN_FETCH;
    uintptr_t first=v.pc&~(LI2_STEP_PAGE-1),last=(v.pc+v.length-1)&~(LI2_STEP_PAGE-1);
    size_t pages=first==last?1:2;
    if(v.page_count!=pages || (!initial && pages!=o->page_count))return LI2_RUN_FETCH;
    for(size_t i=0;i<pages;i++) {
        const struct li2_fetch_page *p=&v.pages[i];
        if(p->address!=first+i*LI2_STEP_PAGE || !p->allocation || !p->generation ||
           p->logical!=(PROT_READ|PROT_EXEC) || p->closed_prot!=PROT_READ)return LI2_RUN_FETCH;
        if(!initial && !page_same(&o->pages[i],p))return LI2_RUN_FETCH;
        if(initial){o->pages[i]=*p;o->backing[i]=v.backing[i];o->page_count=i+1;}
        o->fetch_result=li2_lifecycle_fetch_validate(&o->borrow,i,PROT_READ);
        if(o->fetch_result)return LI2_RUN_FETCH;
    }
    if(initial) {
        int result=li2_run_plan_bytes(v.pc,v.bytes,v.length,&o->plan);
        if(result)return result;
    } else if(v.pc!=o->plan.pc || v.length!=o->plan.source_length ||
              !same(v.bytes,o->plan.source,v.length))return LI2_RUN_FETCH;
    o->fetch_view_complete=1;return 0;
}
static int slot(struct li2_run_owner *o,struct li2_run_slot_observation *out,int initial) {
    if(!o->publication || !o->publisher.observe || out->attempted)return LI2_RUN_PUBLICATION_MISSING;
    /* The actual callback must retain attempted and its partial observations.
       A return code without that prefix cannot masquerade as a valid owner. */
    int status=o->publisher.observe(o->publisher.context,o->publication,&o->plan,out);
    out->callback_result=status;
    if(status || out->result || out->attempted!=1 || out->owner_observed!=1 ||
       out->mapping_observed!=1 || out->bytes_observed!=1 || out->complete!=1 ||
       !out->allocation || !out->generation || out->actual_prot!=(PROT_READ|PROT_EXEC) ||
       out->writable_aliases || out->length!=o->plan.generated_length ||
       !out->mapping_first || out->mapping_first>=out->mapping_end ||
       ((out->mapping_first|out->mapping_end)&(LI2_STEP_PAGE-1)) ||
       out->entry<out->mapping_first || out->entry>=out->mapping_end ||
       out->length>out->mapping_end-out->entry ||
       !same(out->bytes,o->plan.generated,out->length))return LI2_RUN_PUBLICATION;
    if(!initial && (out->allocation!=o->armed_slot.allocation || out->generation!=o->armed_slot.generation ||
        out->entry!=o->armed_slot.entry || out->mapping_first!=o->armed_slot.mapping_first ||
        out->mapping_end!=o->armed_slot.mapping_end || out->length!=o->armed_slot.length))return LI2_RUN_PUBLICATION;
    for(size_t i=0;i<o->page_count;i++)if(out->mapping_first<o->pages[i].address+LI2_STEP_PAGE &&
        o->pages[i].address<out->mapping_end)return LI2_RUN_PUBLICATION;
    /* Actual byte read is permitted only after the genuine publisher has
       established live readable RX ownership. No caller scalar grants it. */
    const volatile unsigned char *actual=(const void *)out->entry;
    for(size_t i=0;i<out->length;i++)if(actual[i]!=o->plan.generated[i])return LI2_RUN_PUBLICATION;
    return 0;
}
int li2_run_arm(struct li2_run_owner *o,struct li2_step_session *s,
                const struct li2_fetch_ref *borrow,uint64_t flags,
                const struct li2_run_publisher *publisher,const struct li2_run_publication *publication) {
    if(!o || !s || !borrow)return LI2_RUN_ARGUMENT;
    if(o->phase!=LI2_RUN_EMPTY || o->session || o->first_error)return LI2_RUN_REUSE;
    o->phase=LI2_RUN_PLANNING;o->session=s;o->borrow=*borrow;o->logical_flags=flags;
    if(publisher)o->publisher=*publisher;
    o->publication=publication;
    /* Prototype refuses here until a separately qualified publisher exists.
       No callback, lifecycle read, permission change or frame edit precedes it. */
    if(!publication || !publisher || !publisher->observe)return failed(o,LI2_RUN_PUBLICATION_MISSING,0);
    if(!session(s))return failed(o,LI2_RUN_SESSION,0);
    if(flags&(LI2_STEP_TF|LI2_STEP_RF))return failed(o,LI2_RUN_FLAGS,0);
    int result=source(o,1);
    if(result==LI2_RUN_SLOW){o->phase=LI2_RUN_MISS;return result;}
    if(result)return failed(o,(unsigned)result,result==LI2_RUN_DECODE?(long)o->plan.decoder_result:o->fetch_result);
    result=slot(o,&o->armed_slot,1);
    if(result)return failed(o,(unsigned)result,o->armed_slot.callback_result?o->armed_slot.callback_result:o->armed_slot.result);
    o->phase=LI2_RUN_ARMED;return 0;
}
static void event(struct li2_run_event *out,int sig,const siginfo_t *si) {
    out->observed=1;out->number=sig;
    if(si){out->code=si->si_code;out->error=si->si_errno;out->address=(uintptr_t)si->si_addr;}
}
static void frame(struct li2_run_owner *o,struct li2_step_frame *out,const ucontext_t *uc) {
    require(o,uc && !out->initialized,LI2_RUN_FRAME,0);
    copy(out->greg,uc->uc_mcontext.gregs,sizeof(out->greg));
    copy(&out->mask,&uc->uc_sigmask,sizeof(out->mask));
    out->fp_address=(uintptr_t)uc->uc_mcontext.fpregs;
    require(o,out->fp_address && !(out->fp_address&15),LI2_RUN_FRAME,1);
    const unsigned char *p=(const void *)out->fp_address;
    size_t n=512;
    if(u32(p+464)==UINT32_C(0x46505853)) {
        n=u32(p+468);size_t x=u32(p+480);
        require(o,n>=580 && n<=LI2_STEP_FP_BYTES && x>=576 && x<=n-4 &&
            u32(p+n-4)==UINT32_C(0x46505845),LI2_RUN_FRAME,2);
    }
    out->fp_bytes=n;
    for(size_t i=0;i<n;i++){out->fp[i]=p[i];out->initialized=i+1;}
}
static int unchanged(const struct li2_step_frame *saved,const ucontext_t *uc) {
    uint64_t mask=0;copy(&mask,&uc->uc_sigmask,sizeof(mask));
    return mask==saved->mask && same(saved->greg,uc->uc_mcontext.gregs,sizeof(saved->greg)) &&
        (uintptr_t)uc->uc_mcontext.fpregs==saved->fp_address &&
        same(saved->fp,uc->uc_mcontext.fpregs,saved->fp_bytes);
}
static void nested(struct li2_run_owner *o,int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(o->nested.event.observed)return;
    event(&o->nested.event,sig,si);
    if(uc) {
        copy(o->nested.greg,uc->uc_mcontext.gregs,sizeof(o->nested.greg));
        copy(&o->nested.mask,&uc->uc_sigmask,sizeof(o->nested.mask));
        o->nested.frame_observed=1;
    }
}
static void enter(struct li2_run_owner *o,enum li2_run_phase phase,int sig,
                  siginfo_t *si,ucontext_t *uc,struct li2_run_event *observed,struct li2_step_frame *saved) {
    if(!o)li2_run_abort(0,LI2_RUN_ARGUMENT,0);
    if(o->in_handler){nested(o,sig,si,uc);li2_run_abort(o,LI2_RUN_REENTRY,sig);}
    if(observed->observed){nested(o,sig,si,uc);li2_run_abort(o,LI2_RUN_REUSE,sig);}
    o->in_handler=1;event(observed,sig,si);
    require(o,uc && si,LI2_RUN_FRAME,0);
    frame(o,saved,uc); /* Preserve the actual first event even when foreign. */
    require(o,o->phase==phase && !o->first_error && session(o->session),LI2_RUN_SESSION,o->phase);
    require(o,saved->mask==o->session->application_mask,LI2_RUN_FRAME,3);
}
static void nx(struct li2_run_owner *o,const struct li2_run_event *e,const struct li2_step_frame *f,
               const siginfo_t *si,uintptr_t pc,uintptr_t end) {
    const greg_t *g=f->greg;
    require(o,e->number==SIGSEGV && si->si_signo==SIGSEGV && e->code==SEGV_ACCERR && !e->error &&
        g[REG_TRAPNO]==14 && g[REG_ERR]==21 && (uintptr_t)g[REG_RIP]==pc &&
        ((uint64_t)g[REG_CSGSFS]&UINT64_C(0xffff))==UINT64_C(0x33) &&
        e->address>=pc && e->address<end && (uintptr_t)g[REG_CR2]==e->address,
        LI2_RUN_EVENT,e->number);
    require(o,(uint64_t)g[REG_EFL]==(o->logical_flags|LI2_STEP_RF),LI2_RUN_FLAGS,g[REG_EFL]);
    require(o,(uint64_t)g[REG_RSP]<(UINT64_C(1)<<47),LI2_RUN_FRAME,4);
}
static void closed_query(struct li2_run_owner *o,struct li2_tf_continuation *out) {
    require(o,!out->attempted,LI2_RUN_CONTINUATION,0);
    int result=li2_lifecycle_tf_continuation(&o->borrow,o->plan.stop,out);
    require(o,!result && out->attempted==1 && out->page_observed==1 && out->complete==1 &&
        !out->result && out->pc==o->plan.stop,LI2_RUN_CONTINUATION,result);
}
void li2_run_begin(struct li2_run_owner *o,int sig,siginfo_t *si,ucontext_t *uc) {
    if(!o)li2_run_abort(0,LI2_RUN_ARGUMENT,0);
    enter(o,LI2_RUN_ARMED,sig,si,uc,&o->entry_event,&o->before);
    o->phase=LI2_RUN_ENTERING;
    nx(o,&o->entry_event,&o->before,si,o->plan.pc,o->plan.pc+o->plan.instructions[0].length);
    int result=source(o,0);require(o,!result,(unsigned)result,o->fetch_result);
    closed_query(o,&o->pre_entry);
    result=slot(o,&o->entry_slot,0);require(o,!result,(unsigned)result,o->entry_slot.callback_result?o->entry_slot.callback_result:o->entry_slot.result);
    require(o,unchanged(&o->before,uc),LI2_RUN_FRAME,5);
    /* The only edit. Preserve RF from the genuine NX frame, all other flags,
       complete saved FP, GPRs and application stack. The copied instruction
       naturally clears RF; no TF is injected and no TRACE is manufactured. */
    uc->uc_mcontext.gregs[REG_RIP]=(greg_t)o->entry_slot.entry;
    o->redirected=1;o->phase=LI2_RUN_RUNNING;o->in_handler=0;
}
#if defined(LI2_EFFECT_PROVIDER) && defined(LI2_TF_HANDOFF) && defined(LI2_REGISTER_RUN)
void li2_run_begin_trace(struct li2_run_owner *o,const struct li2_tf_run_entry *origin,
                         int sig,siginfo_t *si,ucontext_t *uc) {
    if(!o)li2_run_abort(0,LI2_RUN_ARGUMENT,0);
    enter(o,LI2_RUN_ARMED,sig,si,uc,&o->entry_event,&o->before);
    o->phase=LI2_RUN_ENTERING;
    int result=li2_tf_chain_run_consume(origin,o->session,&o->borrow,o->plan.pc,
                                       o->logical_flags,sig,si,uc);
    require(o,!result,(unsigned)result,0);
    result=source(o,0);require(o,!result,(unsigned)result,o->fetch_result);
    closed_query(o,&o->pre_entry);
    result=slot(o,&o->entry_slot,0);require(o,!result,(unsigned)result,
        o->entry_slot.callback_result?o->entry_slot.callback_result:o->entry_slot.result);
    require(o,unchanged(&o->before,uc),LI2_RUN_FRAME,8);
    /* Genuine predecessor TRACE has already had only its own TF removed.
       Preserve every remaining frame byte, including its actual CR2. */
    uc->uc_mcontext.gregs[REG_RIP]=(greg_t)o->entry_slot.entry;
    o->redirected=1;o->phase=LI2_RUN_RUNNING;o->in_handler=0;
}
#endif
void li2_run_exit(struct li2_run_owner *o,int sig,siginfo_t *si,ucontext_t *uc) {
    if(!o)li2_run_abort(0,LI2_RUN_ARGUMENT,0);
    enter(o,LI2_RUN_RUNNING,sig,si,uc,&o->exit_event,&o->after);
    o->phase=LI2_RUN_EXIT_CHECKING;
    nx(o,&o->exit_event,&o->after,si,o->plan.stop,o->plan.guard.next_pc);
    o->exit_seen=1;
    int result=source(o,0);require(o,!result,(unsigned)result,o->fetch_result);
    closed_query(o,&o->exit_query);
    result=slot(o,&o->exit_slot,0);require(o,!result,(unsigned)result,o->exit_slot.callback_result?o->exit_slot.callback_result:o->exit_slot.result);
    uint64_t before[16],expected[16];
    for(unsigned i=0;i<16;i++)before[i]=(uint64_t)o->before.greg[regs[i]];
    result=li2_run_expected(&o->plan,before,expected);
    require(o,!result,LI2_RUN_PLAN,result);
    for(unsigned i=0;i<16;i++)require(o,(uint64_t)o->after.greg[regs[i]]==expected[i],LI2_RUN_RESULT,i);
    require(o,o->before.greg[REG_CSGSFS]==o->after.greg[REG_CSGSFS] &&
        o->before.mask==o->after.mask && o->before.fp_bytes==o->after.fp_bytes &&
        same(o->before.fp,o->after.fp,o->before.fp_bytes),LI2_RUN_RESULT,16);
    require(o,unchanged(&o->after,uc),LI2_RUN_FRAME,6);
    o->release_started=1;
    o->release_result=li2_lifecycle_fetch_release(&o->borrow);
    const struct li2_fetch_progress *p=li2_lifecycle_fetch_progress();
    if(p)o->final_fetch=*p;
    require(o,!o->release_result && p && !p->held && p->complete && !p->first_error &&
        p->sequence==o->borrow.sequence,LI2_RUN_RELEASE,o->release_result);
    o->release_complete=1;
    require(o,unchanged(&o->after,uc),LI2_RUN_FRAME,7);
    /* The guard has not executed. Dispatcher must freshly fetch/route it;
       returning this handler directly to the same NX PC would merely refault. */
    o->phase=LI2_RUN_COMPLETE;o->in_handler=0;
}
_Noreturn void li2_run_unexpected(struct li2_run_owner *o,int sig,siginfo_t *si,ucontext_t *uc) {
    if(!o)li2_run_abort(0,LI2_RUN_ARGUMENT,0);
    if(o->in_handler){nested(o,sig,si,uc);li2_run_abort(o,LI2_RUN_REENTRY,sig);}
    o->in_handler=1;
    if(!o->exit_event.observed)event(&o->exit_event,sig,si);
    if(uc && !o->after.initialized)frame(o,&o->after,uc);
    li2_run_abort(o,LI2_RUN_EVENT,sig);
}
