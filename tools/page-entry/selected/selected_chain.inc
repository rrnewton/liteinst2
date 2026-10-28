/* Opt-in controller adapter. Old selected generic bodies are retained under
   #else; these wrappers never count a TRACE entry as an instruction-fetch PF. */
static void selected_chain_failure(const struct li2_tf_chain *c) {
    report(125,c->first_error,c->first_detail);
}
static void selected_generic_begin(int sig,siginfo_t *si,ucontext_t *context,uint64_t flags) {
    checked(!selected_selftesting && !selected_step_pending &&
            selected_pending_route==SELECTED_NO_STEP &&
            li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,649,0);
    selected_pending_route=SELECTED_GENERIC_TF;selected_step_pending=1;
    li2_tf_chain_begin_nx(&selected_chain,&selected_borrow,&selected_decoded,flags,sig,si,context);
    selected_initialized();
}
static void selected_generic_trace(int sig,siginfo_t *si,ucontext_t *context) {
    enum li2_chain_result result=li2_tf_chain_trace(&selected_chain,sig,si,context);
    const struct li2_tf_chain_slot *previous=&selected_chain.slots[selected_chain.active^1];
    selected_logical_flags=previous->owner.actual_post_flags&~SELECTED_TF;
    checked(!(selected_logical_flags&(SELECTED_TF|SELECTED_RF)),656,0);
    uint64_t expected=selected_logical_flags;
    if(result==LI2_CHAIN_RUNNING)expected|=SELECTED_TF;
    checked((uint64_t)context->uc_mcontext.gregs[REG_EFL]==expected,656,1);
    selected_flags_known=1;selected_step_pending=result==LI2_CHAIN_RUNNING;
    selected_pending_route=selected_step_pending?SELECTED_GENERIC_TF:SELECTED_NO_STEP;
    selected_initialized();
}
static void selected_chain_field(struct writer *w,unsigned index,const char *key,uint64_t value) {
    text(w,",\"s");number(w,index);text(w,"_");text(w,key);text(w,"\":");number(w,value);
}
static void selected_chain_slot_report(struct writer *w,unsigned index,const struct li2_tf_chain_slot *s) {
#define CHAIN_FIELD(key,value) selected_chain_field(w,index,key,(uint64_t)(value))
    CHAIN_FIELD("phase",s->phase);CHAIN_FIELD("origin",s->origin);CHAIN_FIELD("fallback",s->fallback);
    CHAIN_FIELD("generation",s->generation);CHAIN_FIELD("event",s->event_id);
    CHAIN_FIELD("pc",s->decoded.pc);CHAIN_FIELD("code",s->decoded.code);CHAIN_FIELD("length",s->decoded.length);
    CHAIN_FIELD("prepare",s->prepare_attempted);CHAIN_FIELD("prepared",s->prepare_complete);CHAIN_FIELD("retry",s->retry);
    CHAIN_FIELD("owner_phase",s->owner.step.phase);CHAIN_FIELD("owner_error",s->owner.step.first_error);
    CHAIN_FIELD("open",s->owner.step.open_started[0]|(s->owner.step.open_started[1]<<1));
    CHAIN_FIELD("opened",s->owner.step.opened[0]|(s->owner.step.opened[1]<<1));
    CHAIN_FIELD("revoke",s->owner.step.revoke_started[0]|(s->owner.step.revoke_started[1]<<1));
    CHAIN_FIELD("revoked",s->owner.step.revoked[0]|(s->owner.step.revoked[1]<<1));
    CHAIN_FIELD("trace",s->owner.step.trace_seen);CHAIN_FIELD("post_pc",s->owner.actual_post_pc);
    CHAIN_FIELD("borrow",s->fetch.ref.sequence);CHAIN_FIELD("held",s->fetch.progress.held);
    CHAIN_FIELD("fetch_error",s->fetch.progress.first_error);CHAIN_FIELD("validations",s->fetch.progress.validation_calls);
    CHAIN_FIELD("query",s->query.attempted);CHAIN_FIELD("queried",s->query.complete);CHAIN_FIELD("query_pc",s->query.pc);
    CHAIN_FIELD("release",s->release.started);CHAIN_FIELD("released",s->release.complete);
    CHAIN_FIELD("unexpected",s->unexpected_frame_observed);
#undef CHAIN_FIELD
}
static void selected_chain_report(unsigned status,unsigned code,long detail) {
    const struct li2_tf_chain *c=&selected_chain;struct writer w={.used=0};
    text(&w,"LI2_CHAIN {\"version\":1,\"scope\":\"opt_in_trace_to_plain\"");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",detail<0?0ULL-(uint64_t)detail:(uint64_t)detail);
    field(&w,",\"detail_negative\":",detail<0);field(&w,",\"active\":",c->active);
    field(&w,",\"pending\":",c->pending);field(&w,",\"error\":",c->first_error);
    field(&w,",\"event\":",c->event_id);field(&w,",\"sequence\":",c->sequence);
    field(&w,",\"attempts\":",c->attempts);field(&w,",\"steps\":",c->steps);
    field(&w,",\"nx_entries\":",c->nx_entries);field(&w,",\"trace_entries\":",c->trace_entries);
    field(&w,",\"fallbacks\":",c->fallbacks);field(&w,",\"preparations\":",c->prepare_attempts);
    field(&w,",\"releases\":",c->releases);field(&w,",\"unexpected\":",c->unexpected_events);
    field(&w,",\"proof_valid\":",__atomic_load_n(&c->entry.valid,__ATOMIC_ACQUIRE));
    for(unsigned i=0;i<2;i++)selected_chain_slot_report(&w,i,&c->slots[i]);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
