/* Bounded descriptive row. Old rows keep physical page/old-owner meanings;
   this row alone describes the new two-page epochs. All arrays are ordered. */
static void np_report_array(struct writer *w,const char *key,const uint64_t *values,size_t n) {
    text(w,key);text(w,"[");
    for(size_t i=0;i<n;i++){if(i)text(w,",");number(w,values[i]);}
    text(w,"]");
}
#ifdef LI2_COST_PROFILE
static void selected_cost_report(unsigned status,unsigned code,long detail,
                                 const struct li2_native_pair_cost *c,
                                 const struct li2_maps_stats *m) {
    /* Both snapshots precede the first terminal report write. No hot-path
       clock/syscall is added. This new row never qualifies the old rows. */
    struct writer w={0};text(&w,"LI2_COST {\"version\":1,\"scope\":\"native_pair_existing_admission_clocks\"");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_negative\":",detail<0);
    field(&w,",\"detail_abs\":",detail<0?0ULL-(uint64_t)detail:(uint64_t)detail);
    field(&w,",\"clock_id\":",4);
    const uint64_t admission[]={c->initialized,c->valid,c->busy,c->overflow,
        c->count,c->sum_ns,c->min_ns,c->max_ns};
    const uint64_t maps[]={m->fresh_calls,m->acquisitions,m->reuses,m->invalidations,
        m->handler_id,m->mutation_epoch,m->active,m->valid,m->poisoned,m->reserved};
    _Static_assert(18*21+512<4096,"bounded diagnostic counter row");
    np_report_array(&w,",\"admission\":",admission,sizeof admission/sizeof admission[0]);
    np_report_array(&w,",\"maps\":",maps,sizeof maps/sizeof maps[0]);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
#endif
static void selected_native_pair_report(unsigned status,unsigned code,long detail) {
    const struct li2_native_pair_progress *p=li2_native_pair_progress();
    const struct li2_native_pair_lifecycle *l=li2_lifecycle_pair_progress();
    const struct li2_rseq_pair_progress *r=li2_rseq_pair_progress();
    const struct li2_native_close *c=li2_lifecycle_native_close_progress();
    /* 163 scalars at maximum uint64 width plus punctuation/keys < 4096. */
    _Static_assert(163*21+600<4096,"native pair report bound");
    struct writer w={0};text(&w,"LI2_NATIVE_PAIR {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_negative\":",detail<0);
    field(&w,",\"detail_abs\":",detail<0?0ULL-(uint64_t)detail:(uint64_t)detail);
    uint64_t control[]={p->initialized,p->phase,p->in_handler,p->first_error,
        p->first_detail<0,p->first_detail<0?0ULL-(uint64_t)p->first_detail:(uint64_t)p->first_detail,
        p->live,p->entry_pending,p->first_observed,p->second_observed,p->close_reason,
        (uint64_t)p->pid,(uint64_t)p->tid};
    np_report_array(&w,",\"control\":",control,sizeof(control)/sizeof(*control));
    uint64_t counts[]={p->events,p->seeds,p->extensions,p->epochs_closed,p->one_page_closes,
        p->two_page_closes,p->policy_closes,p->capacity_closes,p->refaults,p->refault_completed};
    np_report_array(&w,",\"counts\":",counts,sizeof(counts)/sizeof(*counts));
    uint64_t event[]={(uint64_t)p->signal_number,(uint64_t)p->signal_code,(uint64_t)p->signal_errno,
        p->pc,p->signal_address,p->logical_flags};
    np_report_array(&w,",\"last_nx\":",event,sizeof(event)/sizeof(*event));
    uint64_t life[]={l->initialized,l->busy,l->live,l->first_error,l->first_detail<0,
        l->first_detail<0?0ULL-(uint64_t)l->first_detail:(uint64_t)l->first_detail,
        l->sequence,l->allocation_epoch,l->generation_epoch,l->transactions_epoch,l->records_epoch,
        l->attempts,l->published,l->closed_pages,l->close_calls,l->candidate,l->candidate_policy,
        l->candidate_eligible,l->opening,l->post_verified};
    np_report_array(&w,",\"lifecycle\":",life,sizeof(life)/sizeof(*life));
    text(&w,",\"slots\":[");
    for(size_t i=0;i<2;i++) {
        const struct li2_native_pair_slot *s=&l->slots[i];
        uint64_t slot[]={s->prepared,s->published,s->slot,s->pc,s->page.address,s->page.allocation,
            s->page.generation,s->page.offset,s->page.object,s->page.backing,s->page.logical,s->page.closed_prot,
            s->window_before,s->window_after,s->window_bytes,s->window_initialized,s->policy,
            (uint64_t)s->backing.retained_fd,(uint64_t)s->backing.seals,s->backing.seals_observed,
            s->backing.stat_observed,(uint64_t)s->backing.stat_result,(uint64_t)s->backing.stat.st_dev,
            (uint64_t)s->backing.stat.st_ino,(uint64_t)s->backing.stat.st_size,(uint64_t)s->backing.stat.st_mode};
        np_report_array(&w,i?",":"",slot,sizeof(slot)/sizeof(*slot));
    }
    text(&w,"]");
    uint64_t rs[]={r->initialized,r->registered,r->active,r->checking,r->entry_checked,r->first_error,
        r->first_detail<0,r->first_detail<0?0ULL-(uint64_t)r->first_detail:(uint64_t)r->first_detail,
        r->unsafe_terminal,(uint64_t)r->pid,(uint64_t)r->tid,r->attempts,r->published,r->preentries,
        r->entries,r->refreshes,r->closed,r->registration_epoch,r->address,r->page,r->length,r->signature,
        r->word_before,r->word_entry,r->word_after,r->fs_before,r->gs_before,r->fs_after,r->gs_after,
        r->fs_selector_entry,r->gs_selector_entry,r->fs_selector_after,r->gs_selector_after};
    np_report_array(&w,",\"rseq\":",rs,sizeof(rs)/sizeof(*rs));
    uint64_t pin_before[]={r->before.allocation,r->before.generation,r->before.offset,
        r->before.attempted,r->before.complete,r->before.error};
    uint64_t pin_after[]={r->after.allocation,r->after.generation,r->after.offset,
        r->after.attempted,r->after.complete,r->after.error};
    np_report_array(&w,",\"pin_before\":",pin_before,sizeof(pin_before)/sizeof(*pin_before));
    np_report_array(&w,",\"pin_after\":",pin_after,sizeof(pin_after)/sizeof(*pin_after));
    uint64_t close[]={c->sequence,c->pages,c->attempted,c->returned,c->closed,c->verified,c->busy,
        c->complete,c->first_error,c->cleanup_started,c->cleanup_complete};
    np_report_array(&w,",\"close\":",close,sizeof(close)/sizeof(*close));
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
