/* Normal-path copy-only observation; only the three explicit negative
   selectors corrupt the actual advisory receipt and call its real lookup. */
static int lpef_hint_candidate(void) {
    const struct le_record *r=&selected_linked_epoch.current;
    const struct li2_link_native_hint_progress *p=li2_lifecycle_link_native_hint_progress();
    return lpef_ready && !lpef_finished && !lpef_wire.control[0] && !lpef_wire.refault.h[0] &&
        lpef_wire.h[25] && lpef_wire.entries[0].completed &&
        (lpef_wire.h[24]==5 || lpef_wire.hint.h[0]) &&
        r->build_started && r->build_returned && r->build_result==LI2_REGION_PLAN_GRAPH &&
        r->source.ready && r->source.key.entry>=UINT64_C(0x200000000) &&
        r->source.key.page.object==lpef_wire.h[22] && p->ready && !p->pending &&
        p->receipt.page.address==r->source.key.page.address;
}
static void lpef_hint_idle(struct lpef_hint_idle *out) {
    const struct li2_native_pair_progress *p=li2_native_pair_progress();
    le_need(p!=NULL,LE_STATE,160);
#define LPEF_HINT_COPY(name) out->name=p->name
    LPEF_HINT_COPY(initialized);LPEF_HINT_COPY(phase);LPEF_HINT_COPY(in_handler);
    LPEF_HINT_COPY(first_error);LPEF_HINT_COPY(live);LPEF_HINT_COPY(entry_pending);
    LPEF_HINT_COPY(first_detail);LPEF_HINT_COPY(events);LPEF_HINT_COPY(seeds);
    LPEF_HINT_COPY(extensions);LPEF_HINT_COPY(epochs_closed);LPEF_HINT_COPY(one_page_closes);
    LPEF_HINT_COPY(two_page_closes);LPEF_HINT_COPY(policy_closes);LPEF_HINT_COPY(capacity_closes);
    LPEF_HINT_COPY(refaults);LPEF_HINT_COPY(refault_completed);
#undef LPEF_HINT_COPY
    lpef_copy(&out->rseq,li2_rseq_snapshot(),sizeof out->rseq);
    lpef_copy(&out->rseq_native,li2_rseq_native_snapshot(),sizeof out->rseq_native);
    lpef_copy(&out->lifecycle,li2_lifecycle_pair_progress(),sizeof out->lifecycle);
    lpef_copy(&out->rseq_pair,li2_rseq_pair_progress(),sizeof out->rseq_pair);
}
static void lpef_hint_reset(void) {
    unsigned control=(unsigned)lpef_wire.hint.h[0];
    le_zero(&lpef_wire.hint,sizeof lpef_wire.hint);lpef_wire.hint.h[0]=control;
}
static void lpef_hint_record(void) {
    struct lpef_hint *w=&lpef_wire.hint;const struct le_record *r=&selected_linked_epoch.current;
    const uint64_t row[]={r->build_started,r->build_returned,(unsigned)r->build_result,
        r->close_complete,r->prepare_complete,r->miss_release_complete,(unsigned)r->miss_release_result,
        r->hint_checked,r->hint_hit,r->hint_publication};
    lpef_copy(w->h+10,row,sizeof row);
    lpef_copy(&w->after_transfer,li2_tf_chain_span_progress(),sizeof w->after_transfer);
}
static void lpef_hint_before(int sig,siginfo_t *si,ucontext_t *uc) {
    struct lpef_hint *w=&lpef_wire.hint;struct le_record *r=&selected_linked_epoch.current;
    if(w->h[1] || !lpef_hint_candidate())return;
    w->h[2]=lpef_wire.raw_ingress[0];
    w->h[9]=lpef_wire.h[25];
    lpef_copy(&w->source,&r->source,sizeof w->source);
    lpef_copy(&w->before_transfer,li2_tf_chain_span_progress(),sizeof w->before_transfer);
    lpef_copy(&w->fresh,li2_lifecycle_fetch_progress(),sizeof w->fresh);
    const struct li2_tf_chain *c=&selected_chain;
    const uint64_t chain[]={c->initialized,c->first_error,(uint64_t)c->first_detail,
        (unsigned)c->in_handler,(unsigned)c->pending,(unsigned)c->active,c->event_id,c->sequence,
        c->attempts,c->steps,c->nx_entries,c->trace_entries,c->fallbacks,c->prepare_attempts,
        c->releases,c->unexpected_events};
    lpef_copy(w->chain,chain,sizeof chain);
    le_need(w->before_transfer.previous<2,LE_STATE,161);
    lpef_copy(&w->closed,&c->slots[w->before_transfer.previous],sizeof w->closed);
    lpef_copy(&w->before,&r->before,sizeof w->before);lpef_hint_idle(&w->idle);
    lpef_copy(&w->before_hint,li2_lifecycle_link_native_hint_progress(),sizeof w->before_hint);
    if(w->h[0]) {
        unsigned attempted=0;size_t at=0;uint64_t publication=0;
        int result=li2_lifecycle_link_native_hint_probe(&r->source,r->transfer.serial,
            (unsigned)w->h[0],&attempted,&at,&publication,
            &w->before_hint,&w->changed_hint,&w->after_hint);
        if(!attempted){lpef_hint_reset();return;}
        w->h[1]=1;w->h[7]=1;w->h[8]=(unsigned)result;
        w->h[20]=attempted;w->h[21]=at;w->h[22]=(unsigned)result;w->h[23]=publication;
        r->hint_checked=1;r->hint_hit=(unsigned)result;r->hint_publication=publication;
        lpef_hint_record();
        /* The actual advisory result is0 on the required path. The terminal
           harness stop is not a native-policy or transfer API failure. */
        le_need(!le_capture(&w->returned,sig,si,uc),LE_FRAME,160);
        selected_linked_epoch_abort(LE_EVENT,0);
    }
}
static void lpef_hint_chosen(void) {
    struct lpef_hint *w=&lpef_wire.hint;const struct le_record *r=&selected_linked_epoch.current;
    if(!w->h[2] || w->h[1] || w->h[2]!=lpef_wire.raw_ingress[0])return;
    if(!r->hint_hit){lpef_hint_reset();return;}
    w->h[1]=1;w->h[7]=1;w->h[8]=r->hint_hit;
    lpef_copy(&w->after_hint,li2_lifecycle_link_native_hint_progress(),sizeof w->after_hint);
    lpef_hint_record();
}
static void lpef_hint_after(void) {
    struct lpef_hint *w=&lpef_wire.hint;
    if(w->h[1] && !w->h[0] && w->h[2]==lpef_wire.raw_ingress[0])lpef_hint_record();
}
static void lpef_hint_ingress(int sig,siginfo_t *si,ucontext_t *uc) {
    struct lpef_hint *w=&lpef_wire.hint;
    if(!lpef_ready || !w->h[1] || w->h[0] || !w->h[3] || w->h[4])return;
    w->h[4]=lpef_wire.raw_ingress[0];le_need(!le_capture(&w->nx,sig,si,uc),LE_FRAME,161);
}
static void lpef_hint_end(int sig,siginfo_t *si,ucontext_t *uc) {
    struct lpef_hint *w=&lpef_wire.hint;
    if(!lpef_ready || !w->h[1] || w->h[0] || w->h[3] || w->h[2]!=lpef_wire.raw_ingress[0])return;
    le_need(!le_capture(&w->returned,sig,si,uc),LE_FRAME,162);w->h[3]=lpef_wire.raw_ingress[0];
}
static void lpef_hint_native(void) {
    struct lpef_hint *w=&lpef_wire.hint;
    if(!lpef_ready || !w->h[1] || w->h[0])return;
    uint64_t event=lpef_wire.raw_ingress[0];
    if(w->h[4] && !w->h[5] && w->h[4]==event) {
        lpef_owners(&w->admitted,1);w->h[5]=event;
        lpef_copy(&w->outcome_hint,li2_lifecycle_link_native_hint_progress(),sizeof w->outcome_hint);return;
    }
    if(w->h[5] && !w->h[6] && li2_native_pair_progress()->epochs_closed>w->admitted.pair.epochs_closed) {
        lpef_owners(&w->closed_native,0);w->h[6]=event;
    }
}
static void lpef_hint_abort(void) {
    struct lpef_hint *w=&lpef_wire.hint;
    if(!w->h[1] || !w->h[0])return;
    lpef_hint_record();w->h[24]=1;w->h[25]=lpef_wire.raw_ingress[0];
}
