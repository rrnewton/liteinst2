/* Separate same-instruction REP owner. Old REP routes/counters stay exact. */
#include "repeat_custody.h"
#if LI2_REPEAT_RX_LEASE != 1 || LI2_RUN_CACHE_REUSE != 1 || LI2_EFFECT_PROVIDER != 1
#error "REP RX lease requires the fixed reusable-cache linked-effect composition"
#endif
/* Fixed linked query: a copied owner cannot replace its private-range guard. */
int li2_repeat_lease_private_intersects(uintptr_t first,size_t bytes) {
    return private_intersects(first,bytes);
}
static void selected_repeat_lease_initialize(void) {
    checked(!selected_repeat_lease_initialized && selected_session.self_test_complete,
            LI2_REPEAT_LEASE_STATE,100);
    int e=li2_repeat_custody_initialize(&selected_repeat_lease,&selected_session,&selected_run_protection);
    checked(!e,LI2_REPEAT_LEASE_CUSTODY,e);
    selected_repeat_lease_initialized=1;
}
static int selected_repeat_lease_closed(void) {
    const struct li2_repeat_lease_owner *o=&selected_repeat_lease;
    if(!selected_repeat_lease_initialized || !li2_repeat_lease_closed(o) ||
       li2_repeat_custody_quiet(o))return 0;
    if(!o->attempts)return !selected_repeat_lease_queries && !selected_repeat_lease_query.attempted;
    const struct li2_tf_continuation *q=&selected_repeat_lease_query;
    return selected_repeat_lease_queries==o->completed && q->attempted==1 &&
        q->page_observed==1 && q->complete==1 && !q->result &&
        q->pc==o->repeat.actual_post_pc;
}
static int selected_repeat_lease_continue(void *context,uintptr_t pc) {
    if(context!=&selected_repeat_lease || selected_repeat_lease_query.attempted ||
       selected_repeat_lease_queries==UINT64_MAX)return LI2_REPEAT_LEASE_STATE;
    ++selected_repeat_lease_queries;
    return li2_lifecycle_tf_continuation(&selected_repeat_lease.borrow,pc,&selected_repeat_lease_query);
}
static int selected_repeat_lease_try(int sig,siginfo_t *si,ucontext_t *uc,uint64_t flags) {
    checked(!selected_selftesting && !selected_step_pending &&
        selected_pending_route==SELECTED_NO_STEP &&
        li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,LI2_REPEAT_LEASE_STATE,101);
    struct li2_step_request request={.decoded=selected_decoded,.original_flags=flags};
    uintptr_t first=selected_decoded.pc&~(PAGE-1),last=(selected_decoded.next_pc-1)&~(PAGE-1);
    request.page_count=first==last?1:2;
    checked(request.page_count<=selected_view.page_count,LI2_REPEAT_LEASE_STATE,102);
    for(size_t i=0;i<request.page_count;i++) {
        const struct li2_fetch_page *p=&selected_view.pages[i];
        request.pages[i]=(struct li2_step_page){p->address,p->allocation,p->generation,
            p->offset,PROT_READ,PROT_READ|PROT_EXEC};
    }
    int eligible=0;
    int e=li2_repeat_custody_eligible(&selected_borrow,&request,&eligible);
    checked(!e,LI2_REPEAT_LEASE_CUSTODY,e);
    checked(eligible==0 || eligible==1,LI2_REPEAT_LEASE_STATE,103);
    if(!eligible)return 0;
    checked(selected_repeat_lease_closed(),LI2_REPEAT_LEASE_STATE,104);
    selected_repeat_lease_query=(struct li2_tf_continuation){0};
    const struct li2_tf_hooks hooks={{&selected_repeat_lease,selected_authenticate,
        selected_step_failure},selected_repeat_lease_continue};
    /* Install the actual cleanup owner before arm or any opening syscall. */
    selected_pending_route=SELECTED_REPEAT_LEASE;selected_step_pending=1;
    e=li2_repeat_lease_arm(&selected_repeat_lease,&selected_session,&hooks,&request,&selected_borrow);
    if(e)li2_repeat_lease_abort(&selected_repeat_lease,(unsigned)e,0);
    selected_initialized();
    li2_repeat_lease_begin(&selected_repeat_lease,sig,si,uc);
    return 1;
}
static void selected_repeat_lease_trace(int sig,siginfo_t *si,ucontext_t *uc) {
    li2_repeat_lease_trace(&selected_repeat_lease,sig,si,uc);
    const struct li2_repeat_lease_owner *o=&selected_repeat_lease;
    const struct li2_repeat_owner *r=&o->repeat;
    const struct li2_step_owner *p=&r->step;
    checked(!p->first_error && !p->in_handler && p->trace_seen && r->traces &&
        !r->reopened_cycles && o->begin_checked && o->cold_seeded &&
        (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==r->actual_post_pc,
        LI2_REPEAT_LEASE_STATE,105);
    if(p->phase==LI2_STEP_RUNNING) {
        checked(!r->final && r->remaining && r->closed_cycles==0 &&
            o->retained_transfers==r->traces && o->return_pending==1 &&
            !o->close_started && !o->release_started &&
            li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY &&
            (uint64_t)uc->uc_mcontext.gregs[REG_EFL]==r->actual_post_flags,
            LI2_REPEAT_LEASE_STATE,106);
        return;
    }
    checked(p->phase==LI2_STEP_COMPLETE && r->final && !r->remaining &&
        r->closed_cycles==1 && o->retained_transfers==r->traces-1 &&
        o->close_complete && o->release_complete && !o->release_result &&
        !li2_lifecycle_fetch_interlock() && selected_repeat_lease_closed(),
        LI2_REPEAT_LEASE_STATE,107);
    selected_logical_flags=(uint64_t)uc->uc_mcontext.gregs[REG_EFL];
    checked(!(selected_logical_flags&(SELECTED_TF|SELECTED_RF)) &&
        selected_logical_flags==(r->actual_post_flags&~SELECTED_TF) &&
        selected_logical_flags==p->request.original_flags,LI2_REPEAT_LEASE_STATE,108);
    selected_flags_known=1;selected_step_pending=0;selected_pending_route=SELECTED_NO_STEP;
}
static void selected_repeat_lease_boundary(void) {
    if(selected_repeat_lease_initialized)li2_repeat_custody_boundary();
}
static void selected_repeat_lease_end(const ucontext_t *uc) {
    if(!selected_repeat_lease_initialized)return;
    if(selected_pending_route==SELECTED_REPEAT_LEASE) {
        checked(selected_step_pending==1,LI2_REPEAT_LEASE_STATE,109);
        li2_repeat_lease_handler_end(&selected_repeat_lease,uc);
    } else checked(selected_repeat_lease_closed(),LI2_REPEAT_LEASE_STATE,110);
}
#include "selected_repeat_lease_report.inc"
