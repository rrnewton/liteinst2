/* Separate protocol: old registered-native and inactive-owner rows remain
   exact. Complete first/second close maps records stay in the private owner. */
_Static_assert(3748<=sizeof(((struct writer *)0)->bytes),"bounded boundary report");
static void boundary_close_report(struct writer *w,const char *key,const struct li2_native_close *c) {
    const uint64_t v[]={c->sequence,c->allocation_epoch,c->generation_epoch,c->transactions_epoch,
        c->records_epoch,c->pages,c->attempted,c->returned,c->closed,c->verified,c->last_address,
        (uint64_t)c->pid,(uint64_t)c->tid,rseq_abs(c->last_result),c->last_result<0,
        rseq_abs(c->sync_result),c->sync_result<0,c->first_error,c->first_error_address,
        rseq_abs(c->first_detail),c->first_detail<0,c->busy,c->complete,c->sync_started,c->sync_returned,
        c->cleanup_started,c->cleanup_complete,c->cleanup_attempted,c->cleanup_returned,
        rseq_abs(c->cleanup_first_result),c->cleanup_first_result<0,
        rseq_abs(c->cleanup_sync_result),c->cleanup_sync_result<0};
    rseq_array(w,key,v,sizeof(v)/sizeof(v[0]));
}
static void selected_rseq_boundary_report(unsigned status,unsigned code,long detail) {
    const struct li2_rseq_native_boundary_state *s=li2_rseq_native_boundary_snapshot();
    struct writer w={.used=0};
    text(&w,"LI2_RSEQ_BOUNDARY {\"version\":1,\"scope\":\"registered_current_pc_refault\"");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",rseq_abs(detail));field(&w,",\"detail_negative\":",detail<0);
    field(&w,",\"phase\":",(uint64_t)s->phase);field(&w,",\"first_error\":",s->first_error);
    field(&w,",\"first_detail_abs\":",rseq_abs(s->first_detail));
    field(&w,",\"first_detail_negative\":",s->first_detail<0);
    field(&w,",\"entry_checked\":",s->entry_checked);
    const uint64_t counts[]={s->attempts,s->preentries,s->entries,s->observations,s->tls_refreshes,s->completed};
    const uint64_t identity[]={(uint64_t)s->pid,(uint64_t)s->tid,s->address,s->page,s->length,s->signature,
        s->registration_epoch,s->native_admissions,s->native_closed};
    const uint64_t geometry[]={s->pc,s->fault_address,s->admitted_page};
    const uint64_t words[]={s->word_first,s->word_entry,s->word_after};
    const uint64_t tls[]={s->fs_first,s->gs_first,s->fs_second,s->gs_second,
        s->fs_selector_first,s->gs_selector_first,s->fs_selector_entry,s->gs_selector_entry,
        s->fs_selector_after,s->gs_selector_after};
    rseq_array(&w,",\"counts\":",counts,sizeof(counts)/sizeof(counts[0]));
    rseq_array(&w,",\"identity\":",identity,sizeof(identity)/sizeof(identity[0]));
    rseq_array(&w,",\"geometry\":",geometry,sizeof(geometry)/sizeof(geometry[0]));
    rseq_array(&w,",\"words\":",words,sizeof(words)/sizeof(words[0]));
    rseq_array(&w,",\"tls\":",tls,sizeof(tls)/sizeof(tls[0]));
    rseq_data_report(&w,",\"first_data\":",&s->first_data);
    rseq_data_report(&w,",\"second_data\":",&s->second_data);
    boundary_close_report(&w,",\"first_close\":",&s->first_close);
    boundary_close_report(&w,",\"second_close\":",&s->second_close);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
