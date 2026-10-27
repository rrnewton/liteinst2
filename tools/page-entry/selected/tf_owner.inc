/* Append to the unchanged step_owner.c translation unit. Reuses its actual
   identity/frame/revoke/first-error helpers; never changes its old trace. */
#include "tf_owner.h"

int li2_tf_arm(struct li2_tf_owner *o,struct li2_step_session *s,
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
    else if(d->abi_version!=1 || d->reserved || d->decode_status!=LI2_VALID ||
            d->kind!=LI2_NONE || !d->length || d->length>15 ||
            d->available<d->length || d->available>15 ||
            d->pc>UINTPTR_MAX-d->length || d->next_pc!=d->pc+d->length)
        error=LI2_TF_CLASSIFICATION;
    else {
        int result=(int)li2_decoder_tf_classify(d->pc,d->bytes,d->available,&o->classification);
        const struct li2_tf_classification *c=&o->classification;
        if(result || c->abi_version!=1 || c->policy!=1 || c->pc!=d->pc ||
           c->next_pc!=d->next_pc || c->code!=d->code || c->length!=d->length ||
           (c->flow!=LI2_TF_FALLTHROUGH && c->flow!=LI2_TF_NEAR_FLOW) ||
           c->family<LI2_TF_INTEGER || c->family>LI2_TF_SIMD)
            error=LI2_TF_CLASSIFICATION;
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

/* Separate canonical XGETBV entry: the complete old entry/open sequence plus
   one actual-register guard. All other instructions use the old function. */
static void tf_xgetbv_begin(struct li2_step_owner *o,int sig,siginfo_t *si,ucontext_t *uc) {
    enter(o,LI2_STEP_ARMED,sig,si,uc);
    greg_t *g=uc->uc_mcontext.gregs;
    uintptr_t pc=o->request.decoded.pc;
    require(o,sig==SIGSEGV && si->si_code==SEGV_ACCERR && !si->si_errno &&
            (uintptr_t)g[REG_RIP]==pc && g[REG_TRAPNO]==14 && g[REG_ERR]==21 &&
            (uintptr_t)si->si_addr==pc,LI2_STEP_FOREIGN_EVENT,sig);
    require(o,(uint64_t)g[REG_EFL]==(o->request.original_flags|LI2_STEP_RF),LI2_STEP_INPUT_FLAGS,g[REG_EFL]);
    frame(o,&o->before,uc);
    require(o,equal((const void *)pc,o->request.decoded.bytes,o->request.decoded.length),LI2_STEP_PAGE_BINDING,2);
    /* Intel specifies ECX, explicitly ignoring RCX[63:32]. Preserve the
       authenticated refused frame and first error; no source page has opened. */
    require(o,(uint32_t)g[REG_RCX]==0,LI2_TF_XCR_INDEX,(long)(uint32_t)g[REG_RCX]);
    o->phase=LI2_STEP_OPENING;
    for(size_t i=0;i<o->request.page_count;i++) {
        const struct li2_step_page *p=&o->request.pages[i];
        require(o,!o->hooks.authenticate(o->hooks.context,p,p->closed_prot),LI2_STEP_PAGE_BINDING,(long)i);
        o->open_started[i]=1;
        o->open_result[i]=RAW(SYS_mprotect,p->address,LI2_STEP_PAGE,p->open_prot,0,0,0);
        require(o,!o->open_result[i],LI2_STEP_OPEN,o->open_result[i]);o->opened[i]=1;
        require(o,!o->hooks.authenticate(o->hooks.context,p,p->open_prot),LI2_STEP_PAGE_BINDING,(long)i);
    }
    o->open_sync=RAW(SYS_membarrier,32,0,0,0,0,0);
    require(o,!o->open_sync,LI2_STEP_SYNC_OPEN,o->open_sync);
    require(o,equal(uc->uc_mcontext.fpregs,o->before.fp,o->before.fp_bytes),LI2_STEP_FRAME,4);
    g[REG_EFL]|=LI2_STEP_TF;
    o->phase=LI2_STEP_RUNNING;o->in_handler=0;
}

void li2_tf_begin(struct li2_tf_owner *o,int sig,siginfo_t *si,ucontext_t *uc) {
    if(o->classification.code==825) {
        tf_xgetbv_begin(&o->step,sig,si,uc);return;
    }
    /* This old function performs no emulated-result check: exact real NX
       entry, immutable source, installed open prefixes, sync, then TF only. */
    li2_step_begin(&o->step,sig,si,uc);
}

_Noreturn void li2_tf_abort(struct li2_tf_owner *o,unsigned code,long detail) {
    li2_step_abort(&o->step,code,detail);
}

_Noreturn void li2_tf_unexpected(struct li2_tf_owner *o,int sig,siginfo_t *si,ucontext_t *uc) {
    struct li2_step_owner *p=&o->step;
    enter(p,LI2_STEP_RUNNING,sig,si,uc);
    frame(p,&p->after,uc);
    o->unexpected_frame_observed=1;
    li2_step_abort(p,LI2_STEP_FOREIGN_EVENT,sig);
}

void li2_tf_trace(struct li2_tf_owner *o,int sig,siginfo_t *si,ucontext_t *uc) {
    struct li2_step_owner *p=&o->step;
    enter(p,LI2_STEP_RUNNING,sig,si,uc);
    greg_t *g=uc->uc_mcontext.gregs;
    require(p,sig==SIGTRAP && si->si_code==TRAP_TRACE && !si->si_errno &&
            g[REG_TRAPNO]==1 && !g[REG_ERR] &&
            (uintptr_t)si->si_addr==(uintptr_t)g[REG_RIP],LI2_STEP_FOREIGN_EVENT,sig);
    p->trace_seen=1;
    o->actual_post_pc=(uintptr_t)g[REG_RIP];
    o->actual_post_flags=(uint64_t)g[REG_EFL];
    frame(p,&p->after,uc);
    revoke_pages(p);
    if(p->first_error)li2_step_abort(p,p->first_error,p->first_detail);
    require(p,equal((const void *)p->request.decoded.pc,p->request.decoded.bytes,
                    p->request.decoded.length),LI2_STEP_PAGE_BINDING,3);
    require(p,(o->actual_post_flags&(LI2_STEP_TF|LI2_STEP_RF))==LI2_STEP_TF &&
            g[REG_CSGSFS]==p->before.greg[REG_CSGSFS],LI2_TF_FRAME,1);
    /* Explicit first-profile envelope, safe on both LA48 and LA57 kernels.
       A CPU instruction may legally produce a different RSP; retain it and
       refuse this signal-return continuation, never repair/normalize it.
       This is not a stack-read, alignment or mapped/writable-stack claim. */
    require(p,(uint64_t)g[REG_RSP]<(UINT64_C(1)<<47),LI2_TF_RSP_DOMAIN,0);
    if(o->classification.flow==LI2_TF_FALLTHROUGH)
        require(p,o->actual_post_pc==p->request.decoded.next_pc,LI2_STEP_FOREIGN_EVENT,2);
    else
        require(p,o->classification.flow==LI2_TF_NEAR_FLOW,LI2_TF_CLASSIFICATION,0);
    /* A branch must not escape into already-executable runtime or another
       untracked region. No instruction/data fetch or target permission change
       is needed to authenticate the actual lifecycle-owned continuation. */
    o->continuation_started=1;
    o->continuation_result=o->hooks.continue_closed(p->hooks.context,o->actual_post_pc);
    require(p,!o->continuation_result,LI2_TF_CONTINUATION,o->continuation_result);
    o->continuation_complete=1;
    uint64_t mask=0;copy(&mask,&uc->uc_sigmask,sizeof(mask));
    require(p,mask==p->after.mask && equal(g,p->after.greg,sizeof(p->after.greg)) &&
            (uintptr_t)uc->uc_mcontext.fpregs==p->after.fp_address &&
            equal(uc->uc_mcontext.fpregs,p->after.fp,p->after.fp_bytes),LI2_TF_FRAME,2);
    /* Preserve every actual CPU result. Only this owner's TF is removed. */
    g[REG_EFL]&=~LI2_STEP_TF;
    p->phase=LI2_STEP_COMPLETE;p->in_handler=0;
}
