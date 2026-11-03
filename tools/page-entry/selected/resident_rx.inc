/* Included after all original physical storage predicates and before storage
   publication/controller. No observer or counter participates in authority. */
static int r3_rx_all(unsigned references) {
    if(references>1 || r3.count!=LI2_R3_CERTIFICATES ||
       r3.planned!=LI2_R3_CERTIFICATES || r3.publications!=LI2_R3_CERTIFICATES ||
       !r3.registry_bound || !r3_registry() || !r3_identity())return 0;
    for(unsigned i=0;i<r3.count;i++) {
        const struct r3_certificate *c=&r3.certificate[i];
        struct li2_sealed_code_query code[3]={0},proof[2]={0};
        if(!c->planned || !c->installed || c->closed || c->active_refs!=references ||
           r3_code_query(i,PROT_READ|PROT_EXEC,code) || r3_proof_query(i,proof) ||
           r3_data_query(i) || r3_bytes(i))return 0;
    }
    return r3_directory_query();
}
static int r3_rx_idle(void) {
    /* Other completed TF work may advance the global fetch sequence after our
       exact release. Retain our actual release, and require no live interlock
       now; never mistake a later fetch's sequence for this execution's pin. */
    const struct li2_fetch_progress *f=&r3.rx_release;
    return r3.initialized==1 && !r3.busy && !r3.active && !r3.first_error &&
        (r3.phase==LI2_R3_IDLE || r3.phase==LI2_R3_DRAINED || r3.phase==LI2_R3_CANCELLED) &&
        selected_pending_route!=SELECTED_RESIDENT_THREE &&
        !li2_r3_rseq_progress()->active && !li2_lifecycle_fetch_interlock() &&
        (!r3.held.owner || (r3.released==1 && f->complete==1 && !f->held &&
          !f->first_error && f->sequence==r3.held.sequence));
}
static int r3_rx_content(unsigned state) {
    return li2_rsl_resident_content_state(&r3.content)==state;
}
int li2_r3_rx_execution_quiet(void) {
    if(!r3_rx_idle())return 0;
    if(r3.rx_lifetime==LI2_R3_RX_UNISSUED)
        return !r3.publications && r3_all_nx();
    if(r3.rx_lifetime==LI2_R3_RX_RETIRED)return r3_all_nx();
    if((r3.rx_lifetime==LI2_R3_RX_RESIDENT && r3_rx_content(LI2_RSG_LIVE)) ||
       (r3.rx_lifetime==LI2_R3_RX_SUSPENDED && r3_rx_content(LI2_RSG_SUSPENDED)))
        return r3_rx_all(0);
    return 0;
}
int li2_r3_rx_execution_closed(const struct li2_r3_token *t) {
    const struct li2_fetch_progress *f=li2_lifecycle_fetch_progress();
    return r3_token(t) && r3.phase==LI2_R3_CLOSING && r3.busy==1 &&
        !r3.active && r3.released==1 && r3.rx_lifetime==LI2_R3_RX_RESIDENT &&
        f->complete==1 && !f->held && !f->first_error && f->sequence==r3.held.sequence &&
        !li2_lifecycle_fetch_interlock() && r3_rx_content(LI2_RSG_LIVE) && r3_rx_all(0);
}
static int r3_rx_entry_storage(void) {
    if(r3.rx_lifetime==LI2_R3_RX_UNISSUED)return !r3.publications && r3_all_nx();
    return r3.rx_lifetime==LI2_R3_RX_RESIDENT &&
        r3_rx_content(LI2_RSG_LIVE) && r3_rx_all(0);
}
static int r3_rx_code_permission(struct r3_certificate *c,int prot) {
    return LI2_R3_RX_CALL(LI2_R3_RX_CODE_PERMISSION,
        raw(SYS_mprotect,c->identity.code,R3_CODE_BYTES,prot,0,0,0));
}
static int r3_rx_sync(void) {
    return LI2_R3_RX_CALL(LI2_R3_RX_PUBLICATION_SYNC,raw(SYS_membarrier,32,0,0,0,0,0));
}
static int r3_rx_reenter(void) {
    if(r3.phase!=LI2_R3_BOUND || r3.busy!=1 || r3.active || r3.consumed!=1 ||
       r3.released || r3.rx_lifetime!=LI2_R3_RX_RESIDENT ||
       !r3_rx_content(LI2_RSG_LIVE) || !r3_rx_all(0) ||
       r3_work.rx.retained_entries==UINT64_MAX)return R3_STATE;
    for(unsigned i=0;i<r3.count;i++)r3.certificate[i].active_refs=1;
    ++r3_work.rx.retained_entries;return 0;
}
/* Called in the original recovery seam, after exact NX frontier and complete
   application-state checks. Fetch/rseq pins end; immutable code stays RX. */
static int r3_rx_release(const ucontext_t *uc) {
    if(r3.phase!=LI2_R3_RECOVERING || r3.busy!=1 || !r3.active || !r3.exit_seen ||
       r3.rx_lifetime!=LI2_R3_RX_RESIDENT || !r3_rx_content(LI2_RSG_LIVE) ||
       !r3_rx_all(1) || r3_work.rx.execution_releases==UINT64_MAX)return R3_STATE;
    r3.phase=LI2_R3_CLOSING;
    if(r3_current(uc) || !r3_directory_query())return R3_SOURCE;
    for(unsigned i=0;i<r3.count;i++)r3.certificate[i].active_refs=0;
    r3.active=0;
    if(li2_lifecycle_fetch_release(&r3.held))return R3_SOURCE;
    r3.rx_release=*li2_lifecycle_fetch_progress();
    if(r3.rx_release.complete!=1 || r3.rx_release.held || r3.rx_release.first_error ||
       r3.rx_release.sequence!=r3.held.sequence)return R3_SOURCE;
    r3.released=1;
    if(li2_r3_rseq_release(&r3.token,uc) || !r3_rx_all(0))return R3_RSEQ;
    ++r3_work.rx.execution_releases;return 0;
}
int li2_r3_rx_suspend(void) {
    if(!r3_rx_idle() || r3.rx_lifetime!=LI2_R3_RX_RESIDENT ||
       !r3_rx_content(LI2_RSG_SUSPENDED) || !r3_rx_all(0) ||
       r3_work.rx.suspensions==UINT64_MAX)return R3_STATE;
    if(r3_permission(PROT_READ|PROT_WRITE))return R3_PUBLICATION;
    r3.rx_lifetime=LI2_R3_RX_SUSPENDED;++r3_work.rx.suspensions;
    return r3_permission(PROT_READ);
}
int li2_r3_rx_resume(void) {
    if(!r3_rx_idle() || r3.rx_lifetime!=LI2_R3_RX_SUSPENDED ||
       !r3_rx_content(LI2_RSG_LIVE) || !r3_rx_all(0) ||
       r3_work.rx.resumptions==UINT64_MAX)return R3_STATE;
    if(r3_permission(PROT_READ|PROT_WRITE))return R3_PUBLICATION;
    r3.rx_lifetime=LI2_R3_RX_RESIDENT;++r3_work.rx.resumptions;
    return r3_permission(PROT_READ);
}
int li2_r3_rx_retire(void) {
    if(!r3.initialized || r3.first_error)return R3_STATE;
    if(r3.rx_lifetime==LI2_R3_RX_UNISSUED)return r3.publications?R3_STATE:0;
    if(!r3_rx_idle() ||
       !((r3.rx_lifetime==LI2_R3_RX_RESIDENT && r3_rx_content(LI2_RSG_LIVE)) ||
         (r3.rx_lifetime==LI2_R3_RX_SUSPENDED && r3_rx_content(LI2_RSG_SUSPENDED))) ||
       !r3_rx_all(0) || r3_work.rx.retirements==UINT64_MAX)return R3_STATE;
    if(r3_permission(PROT_READ|PROT_WRITE))return R3_PUBLICATION;
    /* New entries are denied before the first physical revoke. On any error
       the caller terminates before the original mutator/guest return. */
    r3.rx_lifetime=LI2_R3_RX_REVOKING;
    __asm__ volatile("":::"memory");
    for(unsigned i=0;i<r3.count;i++)
        if(r3_rx_code_permission(&r3.certificate[i],PROT_READ))return R3_PUBLICATION;
    if(r3_rx_sync())return R3_PUBLICATION;
    for(unsigned i=0;i<r3.count;i++) {
        struct r3_certificate *c=&r3.certificate[i];
        le_zero(c->drained,sizeof c->drained);
        if(r3_code_query(i,PROT_READ,c->drained) || r3_bytes(i))return R3_PUBLICATION;
        c->closed=1;
    }
    if(!r3_all_nx())return R3_PUBLICATION;
    r3.rx_lifetime=LI2_R3_RX_RETIRED;++r3_work.rx.retirements;
    return r3_permission(PROT_READ);
}
/* Terminal-only cleanup, never a completion/claim-release path. A bad counter
   cannot prevent the best-effort physical revokes. Complete is recorded only
   after actual full R/NX code, RO proof, data and directory queries succeed.
   Partial publication/refusal keeps the original failure and complete==0. */
void li2_r3_rx_terminal(void) {
    if(!r3.initialized || r3_work.rx.terminal_attempted)return;
    r3_work.rx.terminal_attempted=1;
    unsigned mapped=0;int complete=1;
    if(r3.rx_lifetime!=LI2_R3_RX_RETIRED) {
        for(unsigned i=0;i<LI2_R3_CERTIFICATES;i++) {
            struct r3_certificate *c=&r3.certificate[i];
            if(!c->identity.code_live)continue;
            ++mapped;
            if(li2_r3_rx_observe(LI2_R3_RX_CODE_PERMISSION,0))complete=0;
            long result=raw(SYS_mprotect,c->identity.code,R3_CODE_BYTES,PROT_READ,0,0,0);
            if(result)complete=0;
            else if(li2_r3_rx_observe(LI2_R3_RX_CODE_PERMISSION,1))complete=0;
        }
        if(mapped) {
            if(li2_r3_rx_observe(LI2_R3_RX_PUBLICATION_SYNC,0))complete=0;
            long result=raw(SYS_membarrier,32,0,0,0,0,0);
            if(result)complete=0;
            else if(li2_r3_rx_observe(LI2_R3_RX_PUBLICATION_SYNC,1))complete=0;
        }
    }
    if(r3.count!=LI2_R3_CERTIFICATES || r3.publications!=LI2_R3_CERTIFICATES)complete=0;
    for(unsigned i=0;i<r3.count && i<LI2_R3_CERTIFICATES;i++) {
        struct li2_sealed_code_query code[3]={0},proof[2]={0};
        if(!r3.certificate[i].installed || r3_code_query(i,PROT_READ,code) ||
           r3_proof_query(i,proof) || r3_data_query(i) || r3_bytes(i))complete=0;
    }
    if(!r3_directory_query())complete=0;
    if(complete)r3_work.rx.terminal_closed=1;
}
