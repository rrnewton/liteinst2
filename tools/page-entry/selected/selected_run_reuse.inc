/* Trusted controller for the distinct reusable-cache profile. The cache's
   private lease, not these diagnostics, authorizes generated execution. */
#if LI2_RUN_CACHE_REUSE != 1 || LI2_EFFECT_PROVIDER != 1 || \
    LI2_ONESHOT_REUSABLE != 1 || LI2_TF_SEALED_CUSTODY != 1 || \
    LI2_TF_SAME_PAGE_LEASE != 1 || LI2_TF_HANDOFF != 1 || \
    LI2_REGISTER_RUN != 1 || LI2_MAPS_PHASE_REUSE != 1 || LI2_NATIVE_PAGES != 1 || \
    LI2_CPUID_NX_ONLY != 1 || LI2_RSEQ_INACTIVE != 1 || LI2_RSEQ_NATIVE != 1 || \
    LI2_RSEQ_NATIVE_BOUNDARY != 1 || LI2_RSEQ_TCGETS_BTRFS != 1 || LI2_RSEQ_TIOCGWINSZ_BTRFS != 1
#error "cache reuse requires the full linked-effect controller composition"
#endif

static int selected_run_reuse_repeat_closed(void) {
    const struct li2_repeat_owner *o=&selected_repeat;
    const struct li2_step_owner *p=&o->step;
    if(p->first_error || p->first_detail || p->in_handler ||
       o->unexpected_frame_observed || selected_repeat_borrow_held)return 0;
    if(p->phase==LI2_STEP_EMPTY)return !p->session && !selected_repeat_attempts;
    if(p->phase!=LI2_STEP_COMPLETE || p->session!=&selected_session ||
       !p->trace_seen || !p->revoke_sync_started || p->revoke_sync || p->open_sync ||
       !o->final || o->remaining || !o->traces || o->closed_cycles!=o->traces ||
       o->reopened_cycles!=o->traces-1 || !o->continuation_started ||
       !o->continuation_complete || o->continuation_result ||
       selected_repeat_queries!=o->traces || !selected_repeat_query.attempted ||
       !selected_repeat_query.page_observed || !selected_repeat_query.complete ||
       selected_repeat_query.result || selected_repeat_query.pc!=o->actual_post_pc ||
       !selected_repeat_release_started || !selected_repeat_release_complete ||
       selected_repeat_release_result || !p->request.page_count || p->request.page_count>2)return 0;
    for(size_t i=0;i<p->request.page_count;i++)
        if(!p->open_started[i] || !p->opened[i] || p->open_result[i] ||
           !p->revoke_started[i] || !p->revoked[i] || p->revoke_result[i])return 0;
    return 1;
}

static int selected_run_reuse_effects_closed(void) {
    const __typeof__(selected_effect_runtime) *e=&selected_effect_runtime;
    if(e->busy || e->first_error || e->first_detail || e->owner.first_error ||
       e->attempts!=e->commits || e->commits!=e->completed ||
       e->native_completed>e->completed || e->scripted_completed!=e->completed-e->native_completed)return 0;
    if(e->attempts) {
        if(e->stage!=8 || e->finished!=1 || e->owner.phase!=LI2_EFFECT_COMMITTED ||
           e->owner.committed!=1)return 0;
    } else if(e->stage || e->finished || e->owner.phase!=LI2_EFFECT_EMPTY)return 0;
    if(!((selected_effect_raw.entered==0 && selected_effect_raw.returned==0) ||
         (selected_effect_raw.entered==1 && selected_effect_raw.returned==1)))return 0;
    const __typeof__(selected_cpuid_nx) *c=&selected_cpuid_nx;
    if(c->hardware_entered!=1 || c->hardware_returned!=1 ||
       (c->phase!=SELECTED_CPUID_NX_EMPTY && c->phase!=SELECTED_CPUID_NX_COMMITTED) ||
       c->attempts!=c->samples || c->samples!=c->commits)return 0;
    /* Phase 6 means controls restored but the effect is not yet committed.
       The actual commit tail sets phase 7; CPUID and scripted clocks keep 0. */
    if((selected_builtin_prefix.phase!=0 && selected_builtin_prefix.phase!=7) ||
       selected_builtin_prefix.enable_result || selected_builtin_prefix.restore_result)return 0;
    if(selected_oneshot_active || selected_oneshot_resetting || selected_oneshot_failing ||
       selected_oneshot_current.state.phase!=LI2_ONESHOT_EMPTY ||
       selected_oneshot_current.state.first_error ||
       selected_oneshot_current_effect_started || selected_oneshot_current_effect_returned ||
       li2_lifecycle_oneshot_interlock())return 0;
    const struct li2_rseq_publication_state *p=li2_rseq_publication_snapshot();
    return p && p->phase==LI2_RP_IDLE && !p->checking && !p->first_error &&
        !p->unsafe_terminal && p->retired<=p->attempts && p->cancelled==p->attempts-p->retired;
}

static int selected_run_reuse_native_closed(void) {
#ifdef LI2_NATIVE_PAIR
    if(!li2_native_pair_quiet())return 0;
#endif
    const struct li2_native_epoch *n=li2_native_epoch_progress();
    const struct li2_native_counts *count=li2_lifecycle_native_counts();
    const struct li2_native_close *c=li2_lifecycle_native_close_progress();
    const struct li2_rseq_native_state *r=li2_rseq_native_snapshot();
    const struct li2_rseq_native_boundary_state *b=li2_rseq_native_boundary_snapshot();
    if(!n || !count || !c || !r || !b || n->phase!=LI2_NATIVE_IDLE ||
       n->first_error || n->in_handler || count->admissions!=count->closed ||
       c->busy || c->first_error || c->cleanup_started ||
       r->phase!=LI2_RN_IDLE || r->first_error || r->checking || r->unsafe_terminal ||
       b->phase!=LI2_RNB_IDLE || b->first_error)return 0;
    return !c->sequence || (c->complete==1 && c->pages==c->attempted &&
        c->pages==c->returned && c->pages==c->closed && c->pages==c->verified);
}

int li2_run_reuse_runtime(enum li2_run_reuse_stage stage,const struct li2_fetch_ref *fresh) {
    int publishing=stage==LI2_REUSE_PUBLISH || stage==LI2_REUSE_REVALIDATE;
    if(!publishing && stage!=LI2_REUSE_QUIESCE)return 1;
    if(handling!=1 || reported || selected_selftesting || !selected_flags_known ||
       selected_run_failing || selected_run_interrupted.event.observed ||
       selected_run_interrupted.frame_observed || selected_run_owner.phase!=LI2_RUN_EMPTY ||
       selected_run_owner.first_error || selected_run_owner.session ||
       !selected_session.initialized || !selected_session.self_test_complete)return 2;
    if(publishing) {
        if(selected_step_pending!=1 || selected_pending_route!=SELECTED_REGISTER_RUN ||
           !fresh || fresh->owner!=selected_borrow.owner ||
           fresh->sequence!=selected_borrow.sequence)return 3;
    } else if(fresh || selected_step_pending || selected_pending_route!=SELECTED_NO_STEP)return 4;
    if(li2_lifecycle_run_reuse_quiet(fresh))return 5;
    const ucontext_t *uc=selected_run_reuse_frame;
    if(selected_oneshot_frame_range(0,uc,sizeof(*uc)))return 6;
    uint64_t mask=0;copy(&mask,&uc->uc_sigmask,sizeof mask);
    if(mask!=selected_session.application_mask)return 7;
    if(publishing && ((uintptr_t)uc->uc_mcontext.gregs[REG_RIP]!=selected_run_plan.pc ||
       selected_run_plan.pc!=selected_view.pc))return 8;
    if(selected_step.phase!=LI2_STEP_EMPTY || selected_step.session ||
       selected_step.first_error || selected_step.in_handler ||
       !selected_run_reuse_repeat_closed())return 9;
#ifdef LI2_REPEAT_RX_LEASE
    if(!selected_repeat_lease_closed())return 20;
#endif
    const struct li2_tf_run_entry *origin=0;
    if(publishing && selected_run_trace_origin) {
        if(selected_run_trace_busy!=1 || selected_run_trace_active)return 10;
        origin=selected_run_trace_origin;
    } else if(selected_run_trace_busy || selected_run_trace_active || selected_run_trace_origin)return 11;
    if(li2_tf_chain_run_reuse_quiet(&selected_chain,origin))return 12;
    const struct li2_page_custody_stats *custody=li2_page_custody_snapshot();
    const struct li2_fetch_rx_view *rx=li2_lifecycle_fetch_rx_progress();
    if(!custody || custody->phase!=LI2_CUSTODY_EMPTY || !rx || rx->result ||
       (rx->phase!=LI2_RX_EMPTY &&
        (!rx->complete || (rx->phase!=LI2_RX_COMMITTED && rx->phase!=LI2_RX_CANCELLED))))return 13;
    if(!selected_run_reuse_native_closed())return 14;
    if(!selected_run_reuse_effects_closed())return 15;
    const struct li2_rseq_state *rseq=li2_rseq_snapshot();
    if(!rseq || !rseq->initialized || rseq->first_error ||
       rseq->pid!=selected_session.pid || rseq->tid!=selected_session.tid)return 16;
    if(rseq->registered) {
        if(rseq->registered!=1 || rseq->held!=1 || rseq->phase!=LI2_RSEQ_ACTIVE ||
           !rseq->tls_complete || !rseq->address || rseq->address>UINTPTR_MAX-16 ||
           *(const volatile uint64_t *)(rseq->address+8))return 17;
    } else if(rseq->held || rseq->phase!=LI2_RSEQ_IDLE)return 18;
    const struct li2_tcgets_state *io=li2_rseq_tcgets_snapshot();
    if(!io || !io->initialized || io->first_error ||
       (io->phase!=LI2_TCGETS_IDLE && io->phase!=LI2_TCGETS_COMPLETE) ||
       io->issued!=io->returned || io->returned!=io->completed)return 19;
    /* Both calls use the current actual frame and current descriptive plan.
       This rechecks the pinned zero word and every copied footprint after
       retirement permission work. It does not compare any old frame/epoch. */
    if(publishing) {
        int result=li2_rseq_check_run(&selected_run_plan,uc);
        if(result)return result;
    }
    return 0;
}

void li2_run_reuse_runtime_failure(const struct li2_run_owner *owner) {
    selected_run_failure(0,owner);
}

static void selected_run_reuse_query(struct writer *w,const char *name,
                                      const struct li2_private_code_query *q) {
    const uint64_t row[]={q->attempted,q->complete,q->first,q->end,
        q->pages_checked,selected_repeat_abs(q->expected_prot),q->expected_prot<0,
        selected_repeat_abs(q->actual_prot),q->actual_prot<0,
        selected_repeat_abs(q->result),q->result<0,
        selected_repeat_abs(q->detail),q->detail<0};
    selected_repeat_array(w,name,row,sizeof row/sizeof row[0]);
}

/* Version 2 LI2_RUN above retains its field meanings but has generation-aware
   publication copies. This separate row describes reuse and retirement; no
   immutable slot+1 timing/reader is used for this profile. */
static void selected_run_reuse_report(unsigned status,unsigned code,long detail) {
    struct li2_run_reuse_observation s={0};
    int result=li2_run_reuse_snapshot(selected_run_cache,&s);
    struct writer w={.used=0};
    text(&w,"LI2_RUN_REUSE {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",selected_repeat_abs(detail));
    field(&w,",\"detail_negative\":",detail<0);
    field(&w,",\"snapshot_result_abs\":",selected_repeat_abs(result));
    field(&w,",\"snapshot_result_negative\":",result<0);
    const uint64_t state[]={s.generation,s.completions,s.retirements,s.cursor,
        s.lookup,s.lease,s.reset_pending};
    selected_repeat_array(&w,",\"state\":",state,sizeof state/sizeof state[0]);
    selected_repeat_array(&w,",\"current\":",s.current.opaque,4);
    const struct li2_run_owner *done=&selected_run_history.last_complete;
    const uint64_t completed[]={selected_run_history.completed_runs,selected_run_history.copied_instructions,
        done->armed_slot.allocation,done->armed_slot.generation,done->armed_slot.entry,
        done->borrow.sequence,done->plan.pc,done->plan.stop};
    selected_repeat_array(&w,",\"last_completed\":",completed,sizeof completed/sizeof completed[0]);
    const struct li2_run_retirement *r=&s.retirement;
    selected_repeat_array(&w,",\"retired_handle\":",r->old_handle.opaque,4);
    const uint64_t retirement[]={r->phase,r->completion,r->attempt,r->entry,
        r->consumed,r->rx_checked,r->revoke_started,r->revoke_complete,r->sync_started,
        r->writable_started,r->writable_complete,r->cleanup_started,r->cleanup_complete,
        selected_repeat_abs(r->revoke_result),r->revoke_result<0,
        selected_repeat_abs(r->sync_result),r->sync_result<0,
        selected_repeat_abs(r->writable_result),r->writable_result<0,
        selected_repeat_abs(r->cleanup_result),r->cleanup_result<0,
        selected_repeat_abs(r->cleanup_sync_result),r->cleanup_sync_result<0,
        r->first_error,selected_repeat_abs(r->first_detail),r->first_detail<0,
        r->verified_bytes};
    selected_repeat_array(&w,",\"retirement\":",retirement,sizeof retirement/sizeof retirement[0]);
    selected_run_reuse_query(&w,",\"rx\":",&r->rx);
    selected_run_reuse_query(&w,",\"revoked\":",&r->revoked);
    selected_run_reuse_query(&w,",\"writable\":",&r->writable);
    selected_run_reuse_query(&w,",\"cleanup\":",&r->cleanup);
    text(&w,"}\n");
    (void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
