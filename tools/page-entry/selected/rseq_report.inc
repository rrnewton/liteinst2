/* Separate explicit-profile report. Existing LOADER/CHAIN/RUN/REPEAT keys and
   acceptance contracts are unchanged. No field authorizes target execution. */
_Static_assert(2846<=sizeof(((struct writer *)0)->bytes),"bounded rseq report");
static uint64_t rseq_abs(long n) { return n<0?0ULL-(uint64_t)n:(uint64_t)n; }
static void rseq_array(struct writer *w,const char *key,const uint64_t *v,size_t n) {
    text(w,key);text(w,"[");
    for(size_t i=0;i<n;i++){if(i)text(w,",");number(w,v[i]);}
    text(w,"]");
}
static void rseq_data_report(struct writer *w,const char *key,const struct li2_rseq_data *d) {
    const uint64_t v[]={d->address,d->page,d->allocation,d->generation,d->offset,
        (uint64_t)d->pid,(uint64_t)d->tid,d->attempted,d->complete,d->error,
        rseq_abs(d->detail),d->detail<0,
        rseq_abs(d->maps.fd),d->maps.fd<0,
        rseq_abs(d->maps.last_read),d->maps.last_read<0,
        rseq_abs(d->maps.close_result),d->maps.close_result<0,
        d->maps.bytes,d->maps.rows,d->maps.opened,d->maps.close_started,d->maps.closed,
#ifdef LI2_MAPS_PHASE_REUSE
        d->maps.observation.acquisition_id,d->maps.observation.handler_id,
        d->maps.observation.mutation_epoch,d->maps.observation.kind,d->maps.observation.io_performed
#else
        0,0,0,0,0 /* This build has no shared acquisition-observation ABI. */
#endif
    };
    rseq_array(w,key,v,sizeof(v)/sizeof(v[0]));
}
static void selected_rseq_report(unsigned status,unsigned code,long detail) {
    struct writer w={.used=0};const struct li2_rseq_state *s=li2_rseq_snapshot();
    const struct li2_rseq_transaction *t=&s->transaction;
    text(&w,"LI2_RSEQ {\"version\":1,\"scope\":\"registered_inactive_prototype\"");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",rseq_abs(detail));field(&w,",\"detail_negative\":",detail<0);
#ifdef LI2_MAPS_PHASE_REUSE
    field(&w,",\"maps_profile\":",1);
#else
    field(&w,",\"maps_profile\":",0);
#endif
    const uint64_t owner[]={s->initialized,s->registered,s->held,(unsigned)s->phase,s->first_error,
        rseq_abs(s->first_detail),s->first_detail<0,(uint64_t)s->pid,(uint64_t)s->tid,
        s->address,s->page,s->length,s->signature,s->epoch};
    const uint64_t tls[]={s->tls_attempted,s->tls_complete,rseq_abs(s->fs_result),s->fs_result<0,
        rseq_abs(s->gs_result),s->gs_result<0,s->fs_base,s->gs_base};
    const uint64_t counts[]={s->calls,s->registrations,s->unregistrations,s->kernel_errors,
        s->instruction_checks,s->range_checks,s->repeat_checks,s->run_checks,s->syscall_checks};
    const uint64_t last[]={s->last_pc,s->last_code,s->last_policy,s->last_first,s->last_end};
    const struct li2_write_footprint *f=&s->last_footprint;
    const uint64_t footprint[]={f->abi_version,f->pc,f->next_pc,f->code,f->length,f->policy,f->first,f->end};
    const uint64_t transaction[]={t->attempted,t->issued,t->returned,t->prior_registered,
        rseq_abs(t->result),t->result<0,t->input_word_observed,t->input_word};
    const uint64_t args[]={(uint64_t)t->args[0],(uint64_t)t->args[1],(uint64_t)t->args[2],
        (uint64_t)t->args[3],(uint64_t)t->args[4],(uint64_t)t->args[5]};
    const uint64_t identity[]={s->data.complete,s->data.allocation,s->data.generation,s->data.offset};
    rseq_array(&w,",\"owner\":",owner,sizeof(owner)/sizeof(owner[0]));
    rseq_array(&w,",\"tls\":",tls,sizeof(tls)/sizeof(tls[0]));
    rseq_array(&w,",\"counts\":",counts,sizeof(counts)/sizeof(counts[0]));
    rseq_array(&w,",\"last\":",last,sizeof(last)/sizeof(last[0]));
    rseq_array(&w,",\"footprint\":",footprint,sizeof(footprint)/sizeof(footprint[0]));
    rseq_array(&w,",\"transaction\":",transaction,sizeof(transaction)/sizeof(transaction[0]));
    rseq_array(&w,",\"args\":",args,sizeof(args)/sizeof(args[0]));
    rseq_array(&w,",\"identity\":",identity,sizeof(identity)/sizeof(identity[0]));
    rseq_data_report(&w,",\"before\":",&t->before);
    rseq_data_report(&w,",\"after\":",&t->after);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
