/* Included by tf_chain.inc after all old helpers. The active slot and its
   actual permission owner never move on this route, including during commit. */
/* Exactly the initialized frame extent retained by frame(); unused capacity
   is not observed FP state. Keep every scalar/GPR/mask/pointer/extent byte. */
static void lease_frame_copy(struct li2_step_owner *p,struct li2_step_frame *out,
                             const struct li2_step_frame *saved) {
    require(p,saved->fp_address && !(saved->fp_address&15) &&
        saved->fp_bytes>=512 && saved->fp_bytes<=LI2_STEP_FP_BYTES &&
        saved->initialized==saved->fp_bytes,LI2_STEP_FRAME,20);
    copy(out,saved,offsetof(struct li2_step_frame,fp));
    copy(out->fp,saved->fp,saved->fp_bytes);
}
static int lease_plain(const struct li2_decoded *d) {
    return d->decode_status==LI2_VALID && d->kind==LI2_NONE &&
        (d->step_disposition!=LI2_STEP_CANDIDATE ||
         (d->length==2 && d->bytes[0]==0x66 && d->bytes[1]==0x90)) &&
        li2_tf_entry_route(d)==LI2_TF_ENTRY_PLAIN;
}
static int chain_same_page(struct li2_tf_chain *c,int sig,siginfo_t *si,ucontext_t *uc) {
    struct li2_tf_chain_slot *s=chain_slot(c);struct li2_tf_owner *o=&s->owner;
    struct li2_step_owner *p=&o->step;struct li2_tf_same_page *l=&c->lease;
    const struct li2_decoded *d=&p->request.decoded;
    if(!lease_plain(d) || o->classification.flow!=LI2_TF_FALLTHROUGH ||
       p->request.page_count!=1 || s->fetch.page_count!=1 || !uc)return 0;
    uintptr_t page=p->request.pages[0].address,pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    if(d->pc<page || d->next_pc<=d->pc || d->next_pc-page>LI2_STEP_PAGE ||
       pc<page || pc-page>=LI2_STEP_PAGE)return 0;
    chain_need(c,s->phase==LI2_CHAIN_EXECUTING && p->phase==LI2_STEP_RUNNING &&
        !p->trace_seen && !p->revoke_started[0] && !p->revoke_started[1] &&
        !p->revoke_sync_started && p->open_started[0]==1 && p->opened[0]==1 &&
        !p->open_result[0] && !p->open_sync && !p->open_started[1] && !p->opened[1] &&
        !s->release.started && !s->query.attempted && !o->continuation_started &&
        s->fetch.ref.sequence==s->fetch.progress.sequence && s->fetch.progress.held,
        LI2_CHAIN_STATE,20);
    chain_count(c,&l->candidates);l->phase=LI2_LEASE_CHECKING;
    enter(p,LI2_STEP_RUNNING,sig,si,uc);
    greg_t *g=uc->uc_mcontext.gregs;
    require(p,sig==SIGTRAP && si->si_signo==SIGTRAP && si->si_code==TRAP_TRACE &&
        !si->si_errno && g[REG_TRAPNO]==1 && !g[REG_ERR] &&
        (uintptr_t)si->si_addr==pc && pc==d->next_pc,LI2_STEP_FOREIGN_EVENT,sig);
    require(p,((uint64_t)g[REG_EFL]&(LI2_STEP_TF|LI2_STEP_RF))==LI2_STEP_TF &&
        g[REG_CSGSFS]==p->before.greg[REG_CSGSFS] &&
        (uint64_t)g[REG_RSP]<(UINT64_C(1)<<47),LI2_TF_FRAME,20);
    frame(p,&p->after,uc);
    /* Entry progress precedes the fresh stage validation observations. */
    const struct li2_fetch_progress previous_fetch=s->fetch.progress;
    const struct li2_fetch_rx_view *v=0;
#ifdef LI2_TF_SEALED_CUSTODY
    const struct li2_custody_owner custody_owner={.chain=c,.owner=p,.slot=s->index,
        .generation=s->generation,.event=c->event_id};
    int e=li2_lifecycle_fetch_rx_stage_custody(&s->fetch.ref,pc,&custody_owner,&v);
#else
    int e=li2_lifecycle_fetch_rx_stage(&s->fetch.ref,pc,&v);
#endif
    l->transfer=*li2_lifecycle_fetch_rx_progress();chain_observe(&s->fetch);
    chain_need(c,!e && v && v->phase==LI2_RX_STAGED && v->complete &&
        v->before_sequence==s->fetch.ref.sequence && v->pid==c->session->pid &&
        v->tid==c->session->tid && v->pc==pc && v->length && v->length<=15 &&
        v->length<=LI2_STEP_PAGE-(pc-page) && v->page.address==page &&
        v->page.allocation==p->request.pages[0].object &&
        v->page.generation==p->request.pages[0].generation &&
        v->page.offset==p->request.pages[0].offset,LI2_CHAIN_PREPARE,e);
    chain_need(c,chain_frame_equal(&p->after,uc,0),LI2_CHAIN_FRAME,20);
    l->next=(struct li2_decoded){0};
    e=(int)li2_decoder_decode(pc,v->bytes,v->length,&l->next);chain_stats(c);
    const struct li2_decoded *next=&l->next;
    chain_need(c,!e && next->abi_version==1 && !next->reserved && next->pc==pc &&
        next->available==v->length && next->decode_status<=LI2_TRUNCATED,LI2_CHAIN_DECODE,e);
    if(next->decode_status==LI2_VALID)
        chain_need(c,next->length && next->length<=v->length &&
            next->pc<=UINTPTR_MAX-next->length && next->next_pc==pc+next->length &&
            equal(next->bytes,v->bytes,v->length),LI2_CHAIN_DECODE,20);
    int eligible=lease_plain(next);
    if(eligible) {
        l->classification=(struct li2_tf_classification){0};
        e=(int)li2_decoder_tf_classify(pc,v->bytes,v->length,&l->classification);chain_stats(c);
        const struct li2_tf_classification *a=&l->classification;
        chain_need(c,!e && a->abi_version==1 && a->pc==pc && a->next_pc==next->next_pc &&
            a->code==next->code && a->length==next->length && a->policy<=1,
            LI2_CHAIN_DECODE,21);
        eligible=a->policy==1 && a->flow==LI2_TF_FALLTHROUGH;
        if(eligible)chain_need(c,a->family>=LI2_TF_INTEGER && a->family<=LI2_TF_SIMD,
                              LI2_CHAIN_DECODE,22);
    }
    if(!eligible) {
#ifdef LI2_TF_SEALED_CUSTODY
        li2_page_custody_discard(LI2_CUSTODY_MISS);
#endif
        e=li2_lifecycle_fetch_rx_cancel(&s->fetch.ref,v);
        l->transfer=*li2_lifecycle_fetch_rx_progress();
        chain_need(c,!e && chain_frame_equal(&p->after,uc,0),LI2_CHAIN_FRAME,e);
        chain_count(c,&l->misses);l->phase=LI2_LEASE_MISS;
        p->in_handler=0;return 0; /* Original trace now really closes/releases. */
    }
    /* The original per-instruction guard consumes actual post-state, including
       all registers used by the write footprint. No EA/zero-word fact is cached. */
    e=li2_rseq_check_instruction(next,uc);
    chain_need(c,!e && chain_frame_equal(&p->after,uc,0),
               e?(unsigned)e:LI2_CHAIN_FRAME,e?li2_rseq_snapshot()->first_detail:21);
    chain_need(c,l->transfers!=UINT64_MAX &&
        (!l->origin_active || (l->slot==(unsigned)c->active && l->owner_generation==s->generation)),
        LI2_CHAIN_STATE,21);
    if(!l->origin_active) {
        l->opening=p->request;lease_frame_copy(p,&l->opening_frame,&p->before);
        l->slot=(unsigned)c->active;l->owner_generation=s->generation;
        l->origin_event=s->event_id;l->origin_borrow=s->fetch.ref.sequence;
        l->origin_active=1;
    }
    l->previous=p->request;lease_frame_copy(p,&l->previous_before,&p->before);
    l->previous_fetch=previous_fetch;
    l->phase=LI2_LEASE_TRANSFERRING;
    /* request.pages/session/hooks and every actual open/revoke result are
       untouched. Even a nested event between these two ref stores revokes the
       original real page; stale authentication is terminal, never a release. */
#ifdef LI2_TF_SEALED_CUSTODY
    e=li2_lifecycle_fetch_rx_commit_custody(&s->fetch.ref,v,&custody_owner,&s->fetch.ref);
#else
    e=li2_lifecycle_fetch_rx_commit(&s->fetch.ref,v,&s->fetch.ref);
#endif
    l->transfer=*li2_lifecycle_fetch_rx_progress();chain_observe(&s->fetch);
    chain_need(c,!e && l->transfer.phase==LI2_RX_COMMITTED &&
        l->transfer.after_sequence==s->fetch.ref.sequence && s->fetch.progress.held &&
        s->fetch.progress.complete && !s->fetch.progress.first_error &&
        chain_frame_equal(&p->after,uc,0),LI2_CHAIN_PREPARE,e);
    o->actual_post_pc=pc;o->actual_post_flags=(uint64_t)g[REG_EFL];
    p->request.decoded=*next;p->request.original_flags=o->actual_post_flags&~LI2_STEP_TF;
    lease_frame_copy(p,&p->before,&p->after);s->decoded=*next;o->classification=l->classification;
    s->descriptive_classification=l->classification;
    l->completed_event=c->event_id;s->event_id=c->event_id;
    ++l->transfers;chain_stats(c);
    chain_need(c,chain_frame_equal(&p->after,uc,0),LI2_CHAIN_FRAME,22);
    /* TF stays set; no application register, flag, mask or FP byte was edited. */
    l->phase=LI2_LEASE_RUNNING;p->in_handler=0;c->in_handler=0;
#ifdef LI2_TF_SEALED_CUSTODY
    e=li2_lifecycle_fetch_rx_publish_custody(&s->fetch.ref,v,&custody_owner);
    chain_need(c,!e,LI2_CHAIN_PREPARE,e);
#endif
    return 1;
}
static void chain_same_page_closed(struct li2_tf_chain *c,const struct li2_tf_chain_slot *s) {
    struct li2_tf_same_page *l=&c->lease;
    if(!l->origin_active)return;
    chain_need(c,l->slot==s->index && l->owner_generation==s->generation && chain_closed(s),
               LI2_CHAIN_STATE,22);
    chain_count(c,&l->closed_leases);l->origin_active=0;l->phase=LI2_LEASE_CLOSED;
}
