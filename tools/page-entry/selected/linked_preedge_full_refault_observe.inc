/* Only copies actual state on the normal path. Four explicit qualification
   controls call the real one-use API at a real chosen helper refusal. */
static int lpef_refault_candidate(void) {
    const struct le_record *r=&selected_linked_epoch.current;
    return lpef_ready && !lpef_finished && !lpef_wire.control[0] &&
        lpef_wire.h[25] && lpef_wire.entries[0].completed &&
        (lpef_wire.h[24]==5 || lpef_wire.refault.h[0]) &&
        r->build_started && r->build_returned && r->build_result==LI2_REGION_PLAN_RELOCATION &&
        r->source.ready && r->source.key.entry>=UINT64_C(0x200000000) &&
        r->source.key.page.object==lpef_wire.h[22];
}
static void lpef_refault_save(void) {
    struct lpef_refault *w=&lpef_wire.refault;
    lpef_copy(&w->record,&selected_linked_epoch.current,sizeof w->record);
}
static int lpef_refault_begin(void) {
    struct lpef_refault *w=&lpef_wire.refault;
    if(!lpef_refault_candidate())return 0;
    if(w->h[1]) {
        if(w->h[0]!=1 || !w->h[6] || w->h[8])return 0;
        /* Retain the actual earlier consumed token and successful native close.
           Only its serial is used against the later singlpefn occupation. */
        lpef_copy(&w->prior,&w->record.transfer,sizeof w->prior);
        lpef_copy(&w->prior_close,&w->native_closed.lifecycle.close,sizeof w->prior_close);
        w->h[8]=w->record.transfer.serial;w->h[9]=w->h[2];w->h[10]=w->h[6];
        le_zero(&w->returned,sizeof w->returned);le_zero(&w->nx,sizeof w->nx);
        le_zero(&w->native_admitted,sizeof w->native_admitted);
        le_zero(&w->native_closed,sizeof w->native_closed);
        w->h[3]=w->h[4]=w->h[5]=w->h[6]=0;
    }
    w->h[1]=1;w->h[2]=lpef_wire.raw_ingress[0];
    w->h[11]=selected_linked_epoch.current.transfer.serial;
    lpef_copy(&w->before_transfer,li2_tf_chain_span_progress(),sizeof w->before_transfer);
    lpef_copy(&w->before_fetch,li2_lifecycle_fetch_progress(),sizeof w->before_fetch);
    lpef_copy(&w->closed_chain,&selected_chain,sizeof w->closed_chain);
    lpef_copy(&w->scratch,&selected_linked_epoch.scratch,sizeof w->scratch);
    lpef_owners(&w->native_before,0);lpef_refault_save();return 1;
}
static _Noreturn void lpef_refault_reject(unsigned control,int sig,siginfo_t *si,ucontext_t *uc) {
    struct lpef_refault *w=&lpef_wire.refault;
    le_need(control==w->h[0] && !w->h[12],LE_STATE,150);w->h[12]=1;
    uint64_t serial=selected_linked_epoch.current.transfer.serial;
    if(control==1) {
        le_need(w->h[8] && w->h[8]<serial && w->prior.phase==LI2_ST_REFAULT &&
            w->prior.refaulted && !w->prior.first_error && w->prior_close.complete,
            LE_STATE,151);
        serial=w->h[8];
    }
    if(control==4) {
        /* Real negative stimulus: mutate this actual kernel-saved frame, then
           require the unchanged full-frame API to refuse. No guest return. */
        uc->uc_mcontext.gregs[REG_RAX]^=1;
        le_need(!le_capture(&w->changed,sig,si,uc),LE_FRAME,150);
    }
    w->h[13]=serial;
    int result=li2_tf_chain_span_refault(selected_linked_epoch_ticket,serial,sig,si,uc);
    w->h[14]=1;w->h[15]=(unsigned)result;
    lpef_refault_save();
    /* The real error and actual release prefix remain visible. Never restore
       valid, reset an error, release a fabricated ref, or resume this frame. */
    selected_linked_epoch_abort(LE_EVENT,result);
}
static void lpef_refault_before_release(int sig,siginfo_t *si,ucontext_t *uc) {
    if(lpef_wire.refault.h[0]==3 && lpef_refault_begin())
        lpef_refault_reject(3,sig,si,uc);
}
static void lpef_refault_before(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!lpef_refault_begin())return;
    unsigned control=(unsigned)lpef_wire.refault.h[0];
    if((control==1 && lpef_wire.refault.h[8]) || control==4)
        lpef_refault_reject(control,sig,si,uc);
}
static void lpef_refault_after(int sig,siginfo_t *si,ucontext_t *uc) {
    struct lpef_refault *w=&lpef_wire.refault;
    if(!w->h[1] || w->h[2]!=lpef_wire.raw_ingress[0])return;
    lpef_refault_save();
    if(w->h[0]==2)lpef_refault_reject(2,sig,si,uc);
}
static void lpef_refault_ingress(int sig,siginfo_t *si,ucontext_t *uc) {
    struct lpef_refault *w=&lpef_wire.refault;
    if(!lpef_ready || !w->h[3] || w->h[4] || w->h[12])return;
    w->h[4]=lpef_wire.raw_ingress[0];
    le_need(!le_capture(&w->nx,sig,si,uc),LE_FRAME,151);
}
static void lpef_refault_end(int sig,siginfo_t *si,ucontext_t *uc) {
    struct lpef_refault *w=&lpef_wire.refault;
    if(!lpef_ready || !w->h[1] || w->h[12])return;
    uint64_t event=lpef_wire.raw_ingress[0];
    if(!w->h[3] && event==w->h[2]) {
        le_need(!le_capture(&w->returned,sig,si,uc),LE_FRAME,152);
        w->h[3]=event;return;
    }
}
/* Immediately after the unchanged native-pair dispatcher returns, before any
   ordinary successor can update the actual rseq last-instruction fields. */
static void lpef_refault_native(void) {
    struct lpef_refault *w=&lpef_wire.refault;
    if(!lpef_ready || !w->h[1] || w->h[12])return;
    uint64_t event=lpef_wire.raw_ingress[0];
    if(w->h[4] && !w->h[5] && event==w->h[4]) {
        lpef_owners(&w->native_admitted,1);w->h[5]=event;return;
    }
    if(w->h[5] && !w->h[6]) {
        const struct li2_native_pair_progress *p=li2_native_pair_progress();
        if(p->epochs_closed>w->native_admitted.pair.epochs_closed) {
            lpef_owners(&w->native_closed,0);w->h[6]=event;
        }
    }
}
static void lpef_refault_abort(void) {
    struct lpef_refault *w=&lpef_wire.refault;
    if(w->h[12]) {lpef_refault_save();w->h[16]=1;w->h[17]=lpef_wire.raw_ingress[0];}
}
