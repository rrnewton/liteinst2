/* The unchanged LI2_RSEQ row describes the inactive instruction/syscall
   owner. This separate row identifies and closes the opt-in native epochs;
   zero at an epoch boundary never claims nonpublication during execution. */
static void selected_rseq_native_report(unsigned status,unsigned code,long detail) {
    const struct li2_rseq_native_state *s=li2_rseq_native_snapshot();
    struct writer w={.used=0};
    text(&w,"LI2_RSEQ_NATIVE {\"version\":1,\"scope\":\"registered_native_epochs\"");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",rseq_abs(detail));field(&w,",\"detail_negative\":",detail<0);
    field(&w,",\"first_detail_abs\":",rseq_abs(s->first_detail));
    field(&w,",\"first_detail_negative\":",s->first_detail<0);
    field(&w,",\"phase\":",(uint64_t)s->phase);
    field(&w,",\"first_error\":",(uint64_t)s->first_error);
    field(&w,",\"unsafe_terminal\":",(uint64_t)s->unsafe_terminal);
    field(&w,",\"entry_checked\":",(uint64_t)s->entry_checked);
    field(&w,",\"checking\":",(uint64_t)s->checking);
    field(&w,",\"attempts\":",(uint64_t)s->attempts);
    field(&w,",\"admissions\":",(uint64_t)s->admissions);
    field(&w,",\"preentries\":",(uint64_t)s->preentries);
    field(&w,",\"entries\":",(uint64_t)s->entries);
    field(&w,",\"closed\":",(uint64_t)s->closed);
    field(&w,",\"tls_refreshes\":",(uint64_t)s->tls_refreshes);
    field(&w,",\"pid\":",(uint64_t)s->pid);
    field(&w,",\"tid\":",(uint64_t)s->tid);
    field(&w,",\"pc\":",(uint64_t)s->pc);
    field(&w,",\"address\":",(uint64_t)s->address);
    field(&w,",\"page\":",(uint64_t)s->page);
    field(&w,",\"registration_epoch\":",(uint64_t)s->registration_epoch);
    field(&w,",\"length\":",(uint64_t)s->length);
    field(&w,",\"signature\":",(uint64_t)s->signature);
    field(&w,",\"native_admissions_before\":",(uint64_t)s->native_admissions_before);
    field(&w,",\"native_closed_before\":",(uint64_t)s->native_closed_before);
    field(&w,",\"word_before\":",(uint64_t)s->word_before);
    field(&w,",\"word_entry\":",(uint64_t)s->word_entry);
    field(&w,",\"word_after\":",(uint64_t)s->word_after);
    field(&w,",\"fs_before\":",(uint64_t)s->fs_before);
    field(&w,",\"gs_before\":",(uint64_t)s->gs_before);
    field(&w,",\"fs_after\":",(uint64_t)s->fs_after);
    field(&w,",\"gs_after\":",(uint64_t)s->gs_after);
    field(&w,",\"fs_selector_entry\":",(uint64_t)s->fs_selector_entry);
    field(&w,",\"gs_selector_entry\":",(uint64_t)s->gs_selector_entry);
    field(&w,",\"fs_selector_after\":",(uint64_t)s->fs_selector_after);
    field(&w,",\"gs_selector_after\":",(uint64_t)s->gs_selector_after);
    rseq_data_report(&w,",\"before\":",&s->before);
    rseq_data_report(&w,",\"after\":",&s->after);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
