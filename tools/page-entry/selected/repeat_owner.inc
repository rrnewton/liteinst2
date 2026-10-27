/* Included after the unchanged step/tf owner implementation. All source-page
   I/O uses the same real syscall bridge and authentication contract. */
#include "repeat_owner.h"

int li2_repeat_candidate(const struct li2_decoded *d) {
    return d && d->abi_version==1 && !d->reserved && d->decode_status==LI2_VALID &&
           d->kind==LI2_NONE && d->code==346 && d->length==3 &&
           d->available>=3 && d->available<=15 && d->pc<=UINTPTR_MAX-3 &&
           d->next_pc==d->pc+3 && d->bytes[0]==0xf3 &&
           d->bytes[1]==0x48 && d->bytes[2]==0xab;
}
int li2_repeat_arm(struct li2_repeat_owner *o,struct li2_step_session *s,
                   const struct li2_tf_hooks *hooks,const struct li2_step_request *request) {
    if(!o || !s || !hooks || !request || !hooks->step.authenticate || !hooks->continue_closed)
        return LI2_STEP_ARGUMENT;
    struct li2_step_owner *p=&o->step;
    if(p->phase!=LI2_STEP_EMPTY || p->session)return LI2_STEP_REUSE;
    p->session=s;p->hooks=hooks->step;p->request=*request;o->hooks=*hooks;
    p->phase=LI2_STEP_ARMED;
    const struct li2_decoded *d=&p->request.decoded;
    unsigned error=0;
    if(!s->initialized || !identity(s))error=LI2_STEP_IDENTITY;
    else if(!s->self_test_complete)error=LI2_STEP_SELFTEST;
    else if(request->original_flags&(LI2_STEP_TF|LI2_STEP_RF))error=LI2_STEP_INPUT_FLAGS;
    else if(!li2_repeat_candidate(d))error=LI2_REPEAT_ENCODING;
    else {
        struct li2_decoded observed;
        if(li2_decoder_decode(d->pc,d->bytes,d->available,&observed) ||
           !equal(&observed,d,sizeof(observed)))error=LI2_REPEAT_ENCODING;
    }
    if(!error) {
        uintptr_t first_page=d->pc&~(LI2_STEP_PAGE-1);
        uintptr_t last_page=(d->next_pc-1)&~(LI2_STEP_PAGE-1);
        size_t count=first_page==last_page?1:2;
        if(request->page_count!=count)error=LI2_STEP_PAGE_BINDING;
        for(size_t i=0;!error && i<count;i++) {
            const struct li2_step_page *page=&request->pages[i];
            if(page->address!=first_page+i*LI2_STEP_PAGE || !page->object || !page->generation ||
               page->closed_prot!=PROT_READ || page->open_prot!=(PROT_READ|PROT_EXEC) ||
               hooks->step.authenticate(hooks->step.context,page,page->closed_prot))
                error=LI2_STEP_PAGE_BINDING;
        }
    }
    if(error){first(p,error,0);p->phase=LI2_STEP_FAILED;}
    return (int)error;
}
void li2_repeat_begin(struct li2_repeat_owner *o,int sig,siginfo_t *si,ucontext_t *uc) {
    li2_step_begin(&o->step,sig,si,uc);
    o->initial_count=(uint64_t)o->step.before.greg[REG_RCX];
    o->remaining=o->initial_count;
}
_Noreturn void li2_repeat_abort(struct li2_repeat_owner *o,unsigned code,long detail) {
    li2_step_abort(&o->step,code,detail);
}
_Noreturn void li2_repeat_unexpected(struct li2_repeat_owner *o,int sig,siginfo_t *si,ucontext_t *uc) {
    struct li2_step_owner *p=&o->step;
    enter(p,LI2_STEP_RUNNING,sig,si,uc);frame(p,&p->after,uc);
    o->unexpected_frame_observed=1;
    li2_step_abort(p,LI2_STEP_FOREIGN_EVENT,sig);
}
static void repeat_closed_prefix(struct li2_repeat_owner *o) {
    struct li2_step_owner *p=&o->step;
    struct li2_repeat_permissions *q=&o->last_closed;
    require(p,p->phase==LI2_STEP_REVOKING && !p->first_error &&
            p->revoke_sync_started && !p->revoke_sync,LI2_REPEAT_STATE,1);
    for(size_t i=0;i<p->request.page_count;i++) {
        require(p,p->open_started[i] && p->opened[i] && !p->open_result[i] &&
                p->revoke_started[i] && p->revoked[i] && !p->revoke_result[i],LI2_REPEAT_STATE,2);
    }
    copy(q->open_started,p->open_started,sizeof(q->open_started));
    copy(q->opened,p->opened,sizeof(q->opened));
    copy(q->revoke_started,p->revoke_started,sizeof(q->revoke_started));
    copy(q->revoked,p->revoked,sizeof(q->revoked));
    copy(q->open_result,p->open_result,sizeof(q->open_result));
    copy(q->revoke_result,p->revoke_result,sizeof(q->revoke_result));
    q->open_sync=p->open_sync;q->revoke_sync=p->revoke_sync;
    q->revoke_sync_started=p->revoke_sync_started;
    require(p,o->closed_cycles!=UINT64_MAX,LI2_REPEAT_OVERFLOW,1);++o->closed_cycles;
}
static void repeat_reopen(struct li2_repeat_owner *o) {
    struct li2_step_owner *p=&o->step;
    require(p,!o->final && o->continuation_complete && o->closed_cycles==o->traces &&
            o->reopened_cycles+1==o->closed_cycles,LI2_REPEAT_STATE,3);
    /* Prior cycle is proved closed and retained above. Fresh prefix ownership
       must precede the first potentially effectful reopening operation. */
    for(size_t i=0;i<2;i++) {
        p->open_started[i]=p->opened[i]=p->revoke_started[i]=p->revoked[i]=0;
        p->open_result[i]=p->revoke_result[i]=0;
    }
    p->open_sync=0;p->revoke_sync=0;p->revoke_sync_started=0;
    p->phase=LI2_STEP_OPENING;
    for(size_t i=0;i<p->request.page_count;i++) {
        const struct li2_step_page *page=&p->request.pages[i];
        require(p,!p->hooks.authenticate(p->hooks.context,page,page->closed_prot),LI2_STEP_PAGE_BINDING,(long)i);
        p->open_started[i]=1;
        p->open_result[i]=RAW(SYS_mprotect,page->address,LI2_STEP_PAGE,page->open_prot,0,0,0);
        require(p,!p->open_result[i],LI2_STEP_OPEN,p->open_result[i]);p->opened[i]=1;
        require(p,!p->hooks.authenticate(p->hooks.context,page,page->open_prot),LI2_STEP_PAGE_BINDING,(long)i);
    }
    p->open_sync=RAW(SYS_membarrier,32,0,0,0,0,0);
    require(p,!p->open_sync,LI2_STEP_SYNC_OPEN,p->open_sync);
    require(p,o->reopened_cycles!=UINT64_MAX,LI2_REPEAT_OVERFLOW,2);++o->reopened_cycles;
}
void li2_repeat_trace(struct li2_repeat_owner *o,int sig,siginfo_t *si,ucontext_t *uc) {
    struct li2_step_owner *p=&o->step;
    enter(p,LI2_STEP_RUNNING,sig,si,uc);
    greg_t *g=uc->uc_mcontext.gregs;
    require(p,sig==SIGTRAP && si->si_code==TRAP_TRACE && !si->si_errno &&
            g[REG_TRAPNO]==1 && !g[REG_ERR] &&
            (uintptr_t)si->si_addr==(uintptr_t)g[REG_RIP],LI2_STEP_FOREIGN_EVENT,sig);
    p->trace_seen=1;frame(p,&p->after,uc);
    o->actual_post_pc=(uintptr_t)g[REG_RIP];o->actual_post_flags=(uint64_t)g[REG_EFL];
    revoke_pages(p);
    if(p->first_error)li2_step_abort(p,p->first_error,p->first_detail);
    require(p,equal((const void *)p->request.decoded.pc,p->request.decoded.bytes,3),LI2_STEP_PAGE_BINDING,3);
    uint64_t remaining=(uint64_t)g[REG_RCX];
    require(p,(!o->initial_count && !o->traces && !remaining) ||
            (o->initial_count && remaining<o->remaining),LI2_REPEAT_PROGRESS,0);
    o->remaining=remaining;o->final=!remaining;
    require(p,o->traces!=UINT64_MAX,LI2_REPEAT_OVERFLOW,0);++o->traces;
    require(p,o->actual_post_pc==(o->final?p->request.decoded.next_pc:p->request.decoded.pc),LI2_REPEAT_PROGRESS,1);
    uint64_t flags=p->request.original_flags|LI2_STEP_TF|(o->final?0:LI2_STEP_RF);
    require(p,o->actual_post_flags==flags && g[REG_CSGSFS]==p->before.greg[REG_CSGSFS],LI2_REPEAT_FLAGS,0);
    static const unsigned regs[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,
        REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
    for(unsigned i=0;i<16;i++) {
        uint64_t expected=(uint64_t)p->before.greg[regs[i]];
        if(i==1)expected=remaining;
        else if(i==7) {
            uint64_t bytes=(o->initial_count-remaining)*UINT64_C(8);
            expected=p->request.original_flags&UINT64_C(0x400)?expected-bytes:expected+bytes;
        }
        require(p,(uint64_t)g[regs[i]]==expected,LI2_REPEAT_STATE,10+i);
    }
    require(p,(uint64_t)g[REG_RSP]<(UINT64_C(1)<<47),LI2_TF_RSP_DOMAIN,0);
    require(p,p->before.fp_bytes==p->after.fp_bytes &&
            equal(p->before.fp,p->after.fp,p->before.fp_bytes),LI2_REPEAT_STATE,30);
    o->continuation_started=1;o->continuation_complete=0;
    o->continuation_result=o->hooks.continue_closed(p->hooks.context,o->actual_post_pc);
    require(p,!o->continuation_result,LI2_REPEAT_CONTINUATION,o->continuation_result);
    o->continuation_complete=1;
    repeat_closed_prefix(o);
    if(!o->final)repeat_reopen(o);
    uint64_t mask=0;copy(&mask,&uc->uc_sigmask,sizeof(mask));
    require(p,mask==p->after.mask && equal(g,p->after.greg,sizeof(p->after.greg)) &&
            (uintptr_t)uc->uc_mcontext.fpregs==p->after.fp_address &&
            equal(uc->uc_mcontext.fpregs,p->after.fp,p->after.fp_bytes),LI2_REPEAT_STATE,31);
    /* The CPU's RCX/RDI/RIP and actual intermediate RF/TF are never repaired.
       On completion remove only the injected TF; leave the source closed. */
    if(o->final){g[REG_EFL]&=~LI2_STEP_TF;p->phase=LI2_STEP_COMPLETE;}
    else p->phase=LI2_STEP_RUNNING;
    p->in_handler=0;
}
