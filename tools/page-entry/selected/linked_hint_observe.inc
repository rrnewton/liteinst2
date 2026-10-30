/* Normal-path copy-only observation; only the three explicit negative
   selectors corrupt the actual advisory receipt and call its real lookup. */
static int leto_hint_candidate(void) {
    const struct le_record *r=&selected_linked_epoch.current;
    const struct li2_link_native_hint_progress *p=li2_lifecycle_link_native_hint_progress();
    return leto_ready && !leto_finished && !leto_wire.control[0] && !leto_wire.refault.h[0] &&
        leto_wire.h[25] && leto_wire.entries[0].completed &&
        (leto_wire.h[24]==5 || leto_wire.hint.h[0]) &&
        r->build_started && r->build_returned && r->build_result==LI2_REGION_PLAN_GRAPH &&
        r->source.ready && r->source.key.entry>=UINT64_C(0x200000000) &&
        r->source.key.page.object==leto_wire.h[22] && p->ready && !p->pending &&
        p->receipt.page.address==r->source.key.page.address;
}
static void leto_hint_idle(struct leto_hint_idle *out) {
    const struct li2_native_pair_progress *p=li2_native_pair_progress();
    le_need(p,LE_STATE,160);
#define LETO_HINT_COPY(name) out->name=p->name
    LETO_HINT_COPY(initialized);LETO_HINT_COPY(phase);LETO_HINT_COPY(in_handler);
    LETO_HINT_COPY(first_error);LETO_HINT_COPY(live);LETO_HINT_COPY(entry_pending);
    LETO_HINT_COPY(first_detail);LETO_HINT_COPY(events);LETO_HINT_COPY(seeds);
    LETO_HINT_COPY(extensions);LETO_HINT_COPY(epochs_closed);LETO_HINT_COPY(one_page_closes);
    LETO_HINT_COPY(two_page_closes);LETO_HINT_COPY(policy_closes);LETO_HINT_COPY(capacity_closes);
    LETO_HINT_COPY(refaults);LETO_HINT_COPY(refault_completed);
#undef LETO_HINT_COPY
    leto_copy(&out->rseq,li2_rseq_snapshot(),sizeof out->rseq);
    leto_copy(&out->rseq_native,li2_rseq_native_snapshot(),sizeof out->rseq_native);
    leto_copy(&out->lifecycle,li2_lifecycle_pair_progress(),sizeof out->lifecycle);
    leto_copy(&out->rseq_pair,li2_rseq_pair_progress(),sizeof out->rseq_pair);
}
static void leto_hint_reset(void) {
    unsigned control=(unsigned)leto_wire.hint.h[0];
    le_zero(&leto_wire.hint,sizeof leto_wire.hint);leto_wire.hint.h[0]=control;
}
static void leto_hint_record(void) {
    struct leto_hint *w=&leto_wire.hint;const struct le_record *r=&selected_linked_epoch.current;
    const uint64_t row[]={r->build_started,r->build_returned,(unsigned)r->build_result,
        r->close_complete,r->prepare_complete,r->miss_release_complete,(unsigned)r->miss_release_result,
        r->hint_checked,r->hint_hit,r->hint_publication};
    leto_copy(w->h+10,row,sizeof row);
    leto_copy(&w->after_transfer,li2_tf_chain_span_progress(),sizeof w->after_transfer);
}
static void leto_hint_before(int sig,siginfo_t *si,ucontext_t *uc) {
    struct leto_hint *w=&leto_wire.hint;struct le_record *r=&selected_linked_epoch.current;
    if(w->h[1] || !leto_hint_candidate())return;
    w->h[2]=leto_wire.raw_ingress[0];
    w->h[9]=leto_wire.h[25];
    leto_copy(&w->source,&r->source,sizeof w->source);
    leto_copy(&w->before_transfer,li2_tf_chain_span_progress(),sizeof w->before_transfer);
    leto_copy(&w->fresh,li2_lifecycle_fetch_progress(),sizeof w->fresh);
    const struct li2_tf_chain *c=&selected_chain;
    const uint64_t chain[]={c->initialized,c->first_error,(uint64_t)c->first_detail,
        (unsigned)c->in_handler,(unsigned)c->pending,(unsigned)c->active,c->event_id,c->sequence,
        c->attempts,c->steps,c->nx_entries,c->trace_entries,c->fallbacks,c->prepare_attempts,
        c->releases,c->unexpected_events};
    leto_copy(w->chain,chain,sizeof chain);
    le_need(w->before_transfer.previous<2,LE_STATE,161);
    leto_copy(&w->closed,&c->slots[w->before_transfer.previous],sizeof w->closed);
    leto_copy(&w->before,&r->before,sizeof w->before);leto_hint_idle(&w->idle);
    leto_copy(&w->before_hint,li2_lifecycle_link_native_hint_progress(),sizeof w->before_hint);
    if(w->h[0]) {
        unsigned attempted=0;size_t at=0;uint64_t publication=0;
        int result=li2_lifecycle_link_native_hint_probe(&r->source,r->transfer.serial,
            (unsigned)w->h[0],&attempted,&at,&publication,
            &w->before_hint,&w->changed_hint,&w->after_hint);
        if(!attempted){leto_hint_reset();return;}
        w->h[1]=1;w->h[7]=1;w->h[8]=(unsigned)result;
        w->h[20]=attempted;w->h[21]=at;w->h[22]=(unsigned)result;w->h[23]=publication;
        r->hint_checked=1;r->hint_hit=(unsigned)result;r->hint_publication=publication;
        leto_hint_record();
        /* The actual advisory result is0 on the required path. The terminal
           harness stop is not a native-policy or transfer API failure. */
        le_need(!le_capture(&w->returned,sig,si,uc),LE_FRAME,160);
        selected_linked_epoch_abort(LE_EVENT,0);
    }
}
static void leto_hint_chosen(void) {
    struct leto_hint *w=&leto_wire.hint;const struct le_record *r=&selected_linked_epoch.current;
    if(!w->h[2] || w->h[1] || w->h[2]!=leto_wire.raw_ingress[0])return;
    if(!r->hint_hit){leto_hint_reset();return;}
    w->h[1]=1;w->h[7]=1;w->h[8]=r->hint_hit;
    leto_copy(&w->after_hint,li2_lifecycle_link_native_hint_progress(),sizeof w->after_hint);
    leto_hint_record();
}
static void leto_hint_after(void) {
    struct leto_hint *w=&leto_wire.hint;
    if(w->h[1] && !w->h[0] && w->h[2]==leto_wire.raw_ingress[0])leto_hint_record();
}
static void leto_hint_ingress(int sig,siginfo_t *si,ucontext_t *uc) {
    struct leto_hint *w=&leto_wire.hint;
    if(!leto_ready || !w->h[1] || w->h[0] || !w->h[3] || w->h[4])return;
    w->h[4]=leto_wire.raw_ingress[0];le_need(!le_capture(&w->nx,sig,si,uc),LE_FRAME,161);
}
static void leto_hint_end(int sig,siginfo_t *si,ucontext_t *uc) {
    struct leto_hint *w=&leto_wire.hint;
    if(!leto_ready || !w->h[1] || w->h[0] || w->h[3] || w->h[2]!=leto_wire.raw_ingress[0])return;
    le_need(!le_capture(&w->returned,sig,si,uc),LE_FRAME,162);w->h[3]=leto_wire.raw_ingress[0];
}
static void leto_hint_native(void) {
    struct leto_hint *w=&leto_wire.hint;
    if(!leto_ready || !w->h[1] || w->h[0])return;
    uint64_t event=leto_wire.raw_ingress[0];
    if(w->h[4] && !w->h[5] && w->h[4]==event) {
        leto_owners(&w->admitted,1);w->h[5]=event;
        leto_copy(&w->outcome_hint,li2_lifecycle_link_native_hint_progress(),sizeof w->outcome_hint);return;
    }
    if(w->h[5] && !w->h[6] && li2_native_pair_progress()->epochs_closed>w->admitted.pair.epochs_closed) {
        leto_owners(&w->closed_native,0);w->h[6]=event;
    }
}
static void leto_hint_abort(void) {
    struct leto_hint *w=&leto_wire.hint;
    if(!w->h[1] || !w->h[0])return;
    leto_hint_record();w->h[24]=1;w->h[25]=leto_wire.raw_ingress[0];
}
