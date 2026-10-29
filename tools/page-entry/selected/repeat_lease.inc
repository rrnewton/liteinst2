/* Included only in the explicit retained-RX profile, after repeat_owner.inc.
   Original repeat/step functions remain the legacy path. This owner retains
   one real opening and borrow; it never invents an intermediate close. */
#include "repeat_lease.h"
#include "repeat_custody.h"

static struct li2_repeat_lease_owner *repeat_lease_actual;
static int repeat_lease_zero(const void *p,size_t n) {
    const unsigned char *b=p;
    for(size_t i=0;i<n;i++)if(b[i])return 0;
    return 1;
}
int li2_repeat_lease_owns_step(const struct li2_step_owner *p) {
    return repeat_lease_actual && p==&repeat_lease_actual->repeat.step;
}
static _Noreturn void repeat_lease_exit(void) {
    (void)RAW(SYS_exit_group,125,0,0,0,0,0);
    __builtin_trap();
}
_Noreturn void li2_repeat_lease_abort(struct li2_repeat_lease_owner *o,unsigned code,long detail) {
    /* A copied/stale owner is never a cleanup address. The actual installed
       prefix remains responsible for every possibly opened source page. */
    if(o!=repeat_lease_actual) {
        li2_repeat_custody_fail(o,code,detail);
        o=repeat_lease_actual;
    }
    if(!o)repeat_lease_exit();
    struct li2_step_owner *p=&o->repeat.step;
    first(p,code,detail);
    if(o->failure_started)repeat_lease_exit();
    o->failure_started=1;__asm__ volatile("":::"memory");
    li2_repeat_custody_fail(o,p->first_error,p->first_detail);
    li2_maps_phase_fail();
    if(p->session && p->session->initialized)revoke_pages(p);
    p->phase=LI2_STEP_FAILED;
    if(p->hooks.failure)p->hooks.failure(p->hooks.context,p);
    repeat_lease_exit();
}
_Noreturn void li2_repeat_lease_abort_step(struct li2_step_owner *p,unsigned code,long detail) {
    if(!li2_repeat_lease_owns_step(p))repeat_lease_exit();
    li2_repeat_lease_abort(repeat_lease_actual,code,detail);
}
static void repeat_lease_custody(struct li2_repeat_lease_owner *o,int result) {
    o->custody_result=result;
    require(&o->repeat.step,!result,LI2_REPEAT_LEASE_CUSTODY,result);
}
static void repeat_lease_borrow(struct li2_repeat_lease_owner *o,unsigned held) {
    const struct li2_fetch_progress *p=li2_lifecycle_fetch_progress();
    o->borrow_held=p->held;
    require(&o->repeat.step,p->sequence==o->borrow.sequence && !p->first_error &&
            o->borrow_held==held,LI2_REPEAT_LEASE_STATE,9);
}
static int repeat_lease_registration(struct li2_repeat_lease_registration *out,
                                     const struct li2_step_session *session) {
    const struct li2_rseq_state *s=li2_rseq_snapshot();
    if(!s || !s->initialized || s->first_error || !session ||
       s->pid!=session->pid || s->tid!=session->tid || s->registered>1 || s->held>1)
        return LI2_REPEAT_LEASE_REGISTRATION;
    if(s->registered) {
        if(s->phase!=LI2_RSEQ_ACTIVE || !s->held || !s->tls_attempted || !s->tls_complete ||
           s->fs_result || s->gs_result || !s->address || s->address>UINTPTR_MAX-16 ||
           !s->epoch || !s->data.attempted || !s->data.complete || s->data.error ||
           s->data.address!=s->address || s->data.page!=s->page ||
           s->data.pid!=s->pid || s->data.tid!=s->tid)
            return LI2_REPEAT_LEASE_REGISTRATION;
    } else if(s->phase!=LI2_RSEQ_IDLE || s->held)return LI2_REPEAT_LEASE_REGISTRATION;
    /* Clear padding too: these exact descriptive fields, not guard counters,
       form the stable registration snapshot for this one held instruction. */
    unsigned char *b=(void *)out;
    for(size_t i=0;i<sizeof(*out);i++)b[i]=0;
    out->initialized=s->initialized;out->registered=s->registered;out->held=s->held;
    out->tls_attempted=s->tls_attempted;out->tls_complete=s->tls_complete;out->phase=s->phase;
    out->pid=s->pid;out->tid=s->tid;out->fs_result=s->fs_result;out->gs_result=s->gs_result;
    out->address=s->address;out->page=s->page;out->length=s->length;out->signature=s->signature;
    out->epoch=s->epoch;out->fs_base=s->fs_base;out->gs_base=s->gs_base;
    copy(&out->data,&s->data,sizeof(out->data));
    return 0;
}
static void repeat_lease_rseq(struct li2_repeat_lease_owner *o,const ucontext_t *uc) {
    struct li2_step_owner *p=&o->repeat.step;
    struct li2_repeat_lease_registration now;
    o->rseq_result=repeat_lease_registration(&now,p->session);
    require(p,!o->rseq_result && equal(&now,&o->registration,sizeof(now)),
            LI2_REPEAT_LEASE_REGISTRATION,1);
    require(p,o->rseq_checks!=UINT64_MAX,LI2_REPEAT_LEASE_OVERFLOW,1);
    ++o->rseq_checks;
    /* Uses genuine current RCX/RDI/DF, including the zero-count case. The
       existing guard supplies overflow/overlap and fresh registered-word
       checks without any TLS observation syscall or new raw exemption. */
    o->rseq_result=li2_rseq_check_instruction(&p->request.decoded,uc);
    require(p,!o->rseq_result,LI2_REPEAT_LEASE_REGISTRATION,o->rseq_result);
    o->rseq_result=repeat_lease_registration(&now,p->session);
    require(p,!o->rseq_result && equal(&now,&o->registration,sizeof(now)),
            LI2_REPEAT_LEASE_REGISTRATION,2);
}
static void repeat_lease_write(struct li2_repeat_lease_owner *o,const ucontext_t *uc) {
    struct li2_step_owner *p=&o->repeat.step;
    const unsigned width=li2_repeat_width(&p->request.decoded);
    require(p,width!=0,LI2_REPEAT_ENCODING,0);
    require(p,o->write_checks!=UINT64_MAX,LI2_REPEAT_LEASE_OVERFLOW,5);
    ++o->write_checks;o->write_first=0;o->write_bytes=0;
    o->write_query_attempted=0;o->write_result=0;
    uint64_t n=(uint64_t)uc->uc_mcontext.gregs[REG_RCX];
    if(!n)return;
    uintptr_t at=(uintptr_t)uc->uc_mcontext.gregs[REG_RDI],first_address=at;
    require(p,n<=UINT64_MAX/width,LI2_REPEAT_LEASE_OVERFLOW,6);
    uint64_t bytes=n*width;
    if((uint64_t)uc->uc_mcontext.gregs[REG_EFL]&UINT64_C(0x400)) {
        require(p,at>=bytes-width && at<=UINTPTR_MAX-width,LI2_REPEAT_LEASE_OVERFLOW,7);
        first_address=at-(bytes-width);
    }
    require(p,first_address<=UINTPTR_MAX-bytes,LI2_REPEAT_LEASE_OVERFLOW,8);
    o->write_first=first_address;o->write_bytes=(size_t)bytes;
    o->write_query_attempted=1;
    o->write_result=li2_repeat_lease_private_intersects(first_address,(size_t)bytes);
    require(p,!o->write_result,LI2_REPEAT_LEASE_WRITE,o->write_result);
}
static void repeat_lease_unchanged(struct li2_repeat_lease_owner *o,const ucontext_t *uc,
                                  uintptr_t address,const ucontext_t *expected,
                                  const struct li2_step_frame *fp,long detail) {
    require(&o->repeat.step,uc && (uintptr_t)uc==address &&
            equal(uc,expected,sizeof(*uc)) && fp->initialized==fp->fp_bytes &&
            fp->fp_bytes && (uintptr_t)uc->uc_mcontext.fpregs==fp->fp_address &&
            equal(uc->uc_mcontext.fpregs,fp->fp,fp->fp_bytes),
            LI2_REPEAT_LEASE_FRAME,detail);
}
int li2_repeat_lease_closed(const struct li2_repeat_lease_owner *o) {
    if(!o)return 0;
    if(!o->attempts)return repeat_lease_zero(o,sizeof(*o));
    const struct li2_repeat_owner *r=&o->repeat;
    const struct li2_step_owner *p=&r->step;
    if(p->phase!=LI2_STEP_COMPLETE || p->first_error || p->in_handler ||
       !p->trace_seen || !o->begin_checked || !o->cold_seeded || o->return_pending ||
       o->failure_started || o->unexpected_observed || o->nested_observed ||
       !r->final || r->remaining || !r->traces || r->closed_cycles!=1 || r->reopened_cycles ||
       o->retained_transfers!=r->traces-1 || !r->continuation_started ||
       !r->continuation_complete || r->continuation_result ||
       !o->close_started || !o->close_complete || !o->release_started ||
       !o->release_complete || o->borrow_held || o->release_result || o->custody_result || o->rseq_result ||
       o->write_result || o->write_first || o->write_bytes || o->write_query_attempted ||
       o->write_checks<2 || o->write_checks-2!=r->traces ||
       o->rseq_checks<2 || o->rseq_checks-2!=r->traces ||
       o->completed!=o->attempts || o->total_closes!=o->completed ||
       o->total_releases!=o->completed || o->total_traces<o->total_retained ||
       o->total_traces-o->total_retained!=o->completed ||
       p->request.page_count!=1 || !p->open_started[0] || !p->opened[0] || p->open_result[0] ||
       !p->revoke_started[0] || !p->revoked[0] || p->revoke_result[0] ||
       p->open_sync || !p->revoke_sync_started || p->revoke_sync)return 0;
    return !p->open_started[1] && !p->opened[1] && !p->open_result[1] &&
           !p->revoke_started[1] && !p->revoked[1] && !p->revoke_result[1];
}
int li2_repeat_lease_arm(struct li2_repeat_lease_owner *o,struct li2_step_session *s,
                         const struct li2_tf_hooks *hooks,const struct li2_step_request *request,
                         const struct li2_fetch_ref *borrow) {
    if(!o || !s || !hooks || !request || !borrow || !hooks->step.authenticate ||
       !hooks->continue_closed)return LI2_STEP_ARGUMENT;
    int error=li2_repeat_custody_reset_ready(o);
    if(error)return error;
    if(!li2_repeat_lease_closed(o))return LI2_REPEAT_LEASE_STATE;
    if(o->attempts==UINT64_MAX || o->completed==UINT64_MAX ||
       o->total_traces==UINT64_MAX || o->total_closes==UINT64_MAX ||
       o->total_releases==UINT64_MAX)return LI2_REPEAT_LEASE_OVERFLOW;
    const uint64_t attempts=o->attempts,completed=o->completed,traces=o->total_traces,
        retained=o->total_retained,closes=o->total_closes,releases=o->total_releases;
    unsigned char *b=(void *)o;
    for(size_t i=0;i<sizeof(*o);i++)b[i]=0;
    o->attempts=attempts+1;o->completed=completed;o->total_traces=traces;
    o->total_retained=retained;o->total_closes=closes;o->total_releases=releases;
    o->borrow=*borrow;
    /* reset_ready authenticates the protected actual owner before this
       pointer is installed. Every inherited abort now uses its real prefix. */
    repeat_lease_actual=o;__asm__ volatile("":::"memory");
    error=li2_repeat_arm(&o->repeat,s,hooks,request);
    if(!error)error=repeat_lease_registration(&o->registration,s);
    if(!error)repeat_lease_borrow(o,1);
    if(!error)error=li2_repeat_custody_bind(o,&o->borrow);
    if(error){first(&o->repeat.step,(unsigned)error,0);o->repeat.step.phase=LI2_STEP_FAILED;}
    return error;
}
static void repeat_lease_return(struct li2_repeat_lease_owner *o,ucontext_t *uc,
                                const struct li2_step_frame *fp) {
    struct li2_step_owner *p=&o->repeat.step;
    /* Reserve the next genuine TRACE observation before allowing execution.
       Completion/close/release counters were reserved at arm. */
    require(p,o->repeat.traces!=UINT64_MAX && o->total_traces!=UINT64_MAX &&
            o->rseq_checks!=UINT64_MAX && o->write_checks!=UINT64_MAX,
            LI2_REPEAT_LEASE_OVERFLOW,2);
    repeat_lease_custody(o,li2_repeat_custody_prepare_return(o,&o->borrow));
    repeat_lease_unchanged(o,uc,o->return_frame_address,&o->return_context,fp,3);
    o->return_pending=1;o->handler_returned=0;
    __asm__ volatile("":::"memory");p->in_handler=0;
}
void li2_repeat_lease_begin(struct li2_repeat_lease_owner *o,int sig,siginfo_t *si,ucontext_t *uc) {
    if(!o || o!=repeat_lease_actual)li2_repeat_lease_abort(o,LI2_REPEAT_LEASE_STATE,3);
    struct li2_step_owner *p=&o->repeat.step;
    if(p->in_handler || o->return_pending)li2_repeat_lease_unexpected(o,sig,si,uc);
    repeat_lease_custody(o,li2_repeat_custody_before_begin(o,&o->borrow));
    enter(p,LI2_STEP_ARMED,sig,si,uc);
    greg_t *g=uc->uc_mcontext.gregs;
    uintptr_t pc=p->request.decoded.pc;
    require(p,sig==SIGSEGV && si->si_code==SEGV_ACCERR && !si->si_errno &&
            (uintptr_t)g[REG_RIP]==pc && g[REG_TRAPNO]==14 && g[REG_ERR]==21 &&
            (uintptr_t)si->si_addr==pc,LI2_STEP_FOREIGN_EVENT,sig);
    require(p,(uint64_t)g[REG_EFL]==(p->request.original_flags|LI2_STEP_RF),LI2_STEP_INPUT_FLAGS,g[REG_EFL]);
    o->entry_frame_address=(uintptr_t)uc;copy(&o->entry_context,uc,sizeof(*uc));
    frame(p,&p->before,uc);
    require(p,equal((const void *)pc,p->request.decoded.bytes,p->request.decoded.length),LI2_STEP_PAGE_BINDING,2);
    o->repeat.initial_count=(uint64_t)p->before.greg[REG_RCX];
    o->repeat.remaining=o->repeat.initial_count;
    repeat_lease_write(o,uc);repeat_lease_rseq(o,uc);
    repeat_lease_unchanged(o,uc,o->entry_frame_address,&o->entry_context,&p->before,4);
    o->begin_checked=1;p->phase=LI2_STEP_OPENING;
    for(size_t i=0;i<p->request.page_count;i++) {
        const struct li2_step_page *page=&p->request.pages[i];
        require(p,!p->hooks.authenticate(p->hooks.context,page,page->closed_prot),LI2_STEP_PAGE_BINDING,(long)i);
        p->open_started[i]=1;__asm__ volatile("":::"memory");
        p->open_result[i]=RAW(SYS_mprotect,page->address,LI2_STEP_PAGE,page->open_prot,0,0,0);
        require(p,!p->open_result[i],LI2_STEP_OPEN,p->open_result[i]);p->opened[i]=1;
        require(p,!p->hooks.authenticate(p->hooks.context,page,page->open_prot),LI2_STEP_PAGE_BINDING,(long)i);
    }
    p->open_sync=RAW(SYS_membarrier,32,0,0,0,0,0);
    require(p,!p->open_sync,LI2_STEP_SYNC_OPEN,p->open_sync);
    repeat_lease_unchanged(o,uc,o->entry_frame_address,&o->entry_context,&p->before,5);
    g[REG_EFL]|=LI2_STEP_TF;p->phase=LI2_STEP_RUNNING;
    o->return_frame_address=(uintptr_t)uc;copy(&o->return_context,&o->entry_context,sizeof(*uc));
    o->return_context.uc_mcontext.gregs[REG_EFL]|=LI2_STEP_TF;
    repeat_lease_custody(o,li2_repeat_custody_seed(o,&o->borrow));
    repeat_lease_borrow(o,1);
    repeat_lease_write(o,uc);repeat_lease_rseq(o,uc);
    repeat_lease_unchanged(o,uc,o->return_frame_address,&o->return_context,&p->before,6);
    o->cold_seeded=1;
    repeat_lease_return(o,uc,&p->before);
}
void li2_repeat_lease_trace(struct li2_repeat_lease_owner *o,int sig,siginfo_t *si,ucontext_t *uc) {
    if(!o || o!=repeat_lease_actual)li2_repeat_lease_abort(o,LI2_REPEAT_LEASE_STATE,4);
    struct li2_repeat_owner *r=&o->repeat;
    struct li2_step_owner *p=&r->step;
    if(p->in_handler || o->return_pending)li2_repeat_lease_unexpected(o,sig,si,uc);
    enter(p,LI2_STEP_RUNNING,sig,si,uc);
    greg_t *g=uc->uc_mcontext.gregs;
    require(p,sig==SIGTRAP && si->si_code==TRAP_TRACE && !si->si_errno &&
            g[REG_TRAPNO]==1 && !g[REG_ERR] &&
            (uintptr_t)si->si_addr==(uintptr_t)g[REG_RIP],LI2_STEP_FOREIGN_EVENT,sig);
    o->trace_frame_address=(uintptr_t)uc;copy(&o->trace_context,uc,sizeof(*uc));
    p->trace_seen=1;frame(p,&p->after,uc);
    r->actual_post_pc=(uintptr_t)g[REG_RIP];r->actual_post_flags=(uint64_t)g[REG_EFL];
    const unsigned width=li2_repeat_width(&p->request.decoded);
    require(p,width!=0,LI2_REPEAT_ENCODING,0);
    require(p,equal((const void *)p->request.decoded.pc,p->request.decoded.bytes,
                    p->request.decoded.length),LI2_STEP_PAGE_BINDING,3);
    uint64_t remaining=(uint64_t)g[REG_RCX];
    require(p,(!r->initial_count && !r->traces && !remaining) ||
            (r->initial_count && remaining<r->remaining),LI2_REPEAT_PROGRESS,0);
    r->remaining=remaining;r->final=!remaining;
    require(p,r->traces!=UINT64_MAX && o->total_traces!=UINT64_MAX,LI2_REPEAT_LEASE_OVERFLOW,3);
    ++r->traces;++o->total_traces;
    require(p,r->actual_post_pc==(r->final?p->request.decoded.next_pc:p->request.decoded.pc),LI2_REPEAT_PROGRESS,1);
    uint64_t flags=p->request.original_flags|LI2_STEP_TF|(r->final?0:LI2_STEP_RF);
    require(p,r->actual_post_flags==flags && g[REG_CSGSFS]==p->before.greg[REG_CSGSFS],LI2_REPEAT_FLAGS,0);
    static const unsigned regs[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,
        REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
    for(unsigned i=0;i<16;i++) {
        uint64_t expected=(uint64_t)p->before.greg[regs[i]];
        if(i==1)expected=remaining;
        else if(i==7) {
            uint64_t bytes=(r->initial_count-remaining)*width;
            expected=p->request.original_flags&UINT64_C(0x400)?expected-bytes:expected+bytes;
        }
        require(p,(uint64_t)g[regs[i]]==expected,LI2_REPEAT_STATE,10+i);
    }
    require(p,(uint64_t)g[REG_RSP]<(UINT64_C(1)<<47),LI2_TF_RSP_DOMAIN,0);
    require(p,p->before.fp_bytes==p->after.fp_bytes &&
            equal(p->before.fp,p->after.fp,p->before.fp_bytes),LI2_REPEAT_STATE,30);
    repeat_lease_custody(o,li2_repeat_custody_validate(o,&o->borrow));
    repeat_lease_borrow(o,1);
    repeat_lease_write(o,uc);repeat_lease_rseq(o,uc);
    repeat_lease_unchanged(o,uc,o->trace_frame_address,&o->trace_context,&p->after,7);
    o->return_frame_address=(uintptr_t)uc;copy(&o->return_context,&o->trace_context,sizeof(*uc));
    if(!r->final) {
        require(p,o->retained_transfers!=UINT64_MAX && o->total_retained!=UINT64_MAX,
                LI2_REPEAT_LEASE_OVERFLOW,4);
        repeat_lease_return(o,uc,&p->after);
        ++o->retained_transfers;++o->total_retained;
        return;
    }
    o->close_started=1;__asm__ volatile("":::"memory");
    repeat_lease_custody(o,li2_repeat_custody_close(o,&o->borrow));
    revoke_pages(p);
    if(p->first_error)li2_repeat_lease_abort(o,p->first_error,p->first_detail);
    repeat_closed_prefix(r);o->close_complete=1;++o->total_closes;
    r->continuation_started=1;
    r->continuation_result=r->hooks.continue_closed(p->hooks.context,r->actual_post_pc);
    require(p,!r->continuation_result,LI2_REPEAT_CONTINUATION,r->continuation_result);
    r->continuation_complete=1;
    o->release_started=1;__asm__ volatile("":::"memory");
    o->release_result=li2_lifecycle_fetch_release(&o->borrow);
    o->borrow_held=li2_lifecycle_fetch_progress()->held;
    require(p,!o->release_result,
            LI2_REPEAT_LEASE_STATE,o->release_result);
    repeat_lease_borrow(o,0);
    o->release_complete=1;++o->total_releases;
    repeat_lease_custody(o,li2_repeat_custody_released(o,&o->borrow));
    repeat_lease_unchanged(o,uc,o->trace_frame_address,&o->trace_context,&p->after,8);
    /* Only the originally injected TF is changed, after genuine closure. */
    g[REG_EFL]&=~LI2_STEP_TF;
    o->return_context.uc_mcontext.gregs[REG_EFL]&=~LI2_STEP_TF;
    p->phase=LI2_STEP_COMPLETE;p->in_handler=0;o->return_pending=0;
    ++o->completed;
    require(p,li2_repeat_lease_closed(o) && !li2_repeat_custody_quiet(o),LI2_REPEAT_LEASE_STATE,5);
}
void li2_repeat_lease_handler_end(struct li2_repeat_lease_owner *o,const ucontext_t *uc) {
    if(!o || o!=repeat_lease_actual)li2_repeat_lease_abort(o,LI2_REPEAT_LEASE_STATE,6);
    struct li2_step_owner *p=&o->repeat.step;
    require(p,p->phase==LI2_STEP_RUNNING && !p->in_handler && o->return_pending==1 &&
            !o->handler_returned && !p->first_error,LI2_REPEAT_LEASE_STATE,7);
    const struct li2_step_frame *fp=o->repeat.traces?&p->after:&p->before;
    repeat_lease_unchanged(o,uc,o->return_frame_address,&o->return_context,fp,9);
    repeat_lease_custody(o,li2_repeat_custody_handler_end(o,&o->borrow));
    repeat_lease_unchanged(o,uc,o->return_frame_address,&o->return_context,fp,10);
    o->handler_returned=1;o->return_pending=0;
}
_Noreturn void li2_repeat_lease_unexpected(struct li2_repeat_lease_owner *o,int sig,
                                          siginfo_t *si,ucontext_t *uc) {
    if(!o || o!=repeat_lease_actual)li2_repeat_lease_abort(o,LI2_REPEAT_LEASE_STATE,8);
    struct li2_step_owner *p=&o->repeat.step;
    if(o->failure_started)repeat_lease_exit();
    const unsigned nested=p->in_handler || o->return_pending || o->unexpected_observed;
    first(p,nested?LI2_STEP_REENTRY:LI2_STEP_FOREIGN_EVENT,sig);
    li2_repeat_custody_fail(o,p->first_error,p->first_detail);
    if(nested) {
        if(o->nested_observed)li2_repeat_lease_abort(o,LI2_STEP_REENTRY,sig);
        o->nested_observed=1;
        if(si) {
            copy(&o->nested_info,si,sizeof(*si));
            __asm__ volatile("":::"memory");o->nested_info_complete=1;
        }
        if(uc) {
            copy(&o->nested_context,uc,sizeof(*uc));
            __asm__ volatile("":::"memory");o->nested_context_complete=1;
        }
    } else {
        o->unexpected_observed=1;o->repeat.unexpected_frame_observed=1;
        if(si) {
            copy(&o->unexpected_info,si,sizeof(*si));
            __asm__ volatile("":::"memory");o->unexpected_info_complete=1;
        }
        if(uc) {
            copy(&o->unexpected_context,uc,sizeof(*uc));
            __asm__ volatile("":::"memory");o->unexpected_context_complete=1;
        }
    }
    /* Keep the prior successful TRACE frame intact. These are observations of
       the real incoming fault/nesting event, never a synthetic TRACE. */
    if(uc)frame(p,nested?&o->nested_frame:&o->unexpected_frame,uc);
    li2_repeat_lease_abort(o,nested?LI2_STEP_REENTRY:LI2_STEP_FOREIGN_EVENT,sig);
}
