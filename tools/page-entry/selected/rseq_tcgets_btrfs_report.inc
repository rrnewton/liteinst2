/* A separate opt-in row; no old report is renamed or declared successful.
   completed means this gate validated the actual result, before frame commit. */
static void selected_tcgets_report(unsigned status,unsigned code,long detail) {
    const struct li2_tcgets_state *s=li2_rseq_tcgets_snapshot();struct writer w={.used=0};
#ifdef LI2_RSEQ_TIOCGWINSZ_BTRFS
    text(&w,"LI2_RSEQ_BTRFS_TTY_QUERY {\"version\":1,\"scope\":\"trusted_parent_capture_btrfs_tcgets_tiocgwinsz_v1\"");
#else
    text(&w,"LI2_RSEQ_TCGETS {\"version\":1,\"scope\":\"trusted_parent_capture_btrfs_tcgets_v1\"");
#endif
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",rseq_abs(detail));field(&w,",\"detail_negative\":",detail<0);
    const uint64_t prefix[]={s->initialized,s->invalidated,(uint64_t)s->phase,s->first_error,
        rseq_abs(s->first_detail),s->first_detail<0,(uint64_t)s->invalidated_number,
        s->attempts,s->permitted,s->issued,s->returned,s->completed,s->queries,
        s->registration_epoch,s->syscall_check};
    const uint64_t launch[]={s->launch.device,s->launch.inode,s->launch.mount_id,
        s->launch.major,s->launch.minor,s->launch.mode,(uint64_t)s->launch.flags};
    const uint64_t current[]={s->current.device,s->current.inode,s->current.mount_id,
        s->current.major,s->current.minor,s->current.mode,(uint64_t)s->current.flags};
    const uint64_t query[]={s->query_attempted,s->query_returned,(uint64_t)s->query_number,
        rseq_abs(s->query_result),s->query_result<0,rseq_abs(s->result),s->result<0};
    const uint64_t mount[]={s->mount_opened,s->mount_eof,s->mount_close_started,s->mount_closed,
        s->mount_complete,rseq_abs(s->mount_fd),s->mount_fd<0,
        rseq_abs(s->mount_close_result),s->mount_close_result<0,s->mount_bytes,s->mount_rows,s->mount_matches};
    rseq_array(&w,",\"prefix\":",prefix,sizeof(prefix)/sizeof(prefix[0]));
    rseq_array(&w,",\"launch\":",launch,sizeof(launch)/sizeof(launch[0]));
    rseq_array(&w,",\"current\":",current,sizeof(current)/sizeof(current[0]));
    rseq_array(&w,",\"query\":",query,sizeof(query)/sizeof(query[0]));
    rseq_array(&w,",\"mount\":",mount,sizeof(mount)/sizeof(mount[0]));
#ifdef LI2_RSEQ_TIOCGWINSZ_BTRFS
    const uint64_t commands[]={s->command_completed[0],s->command_completed[1],(uint64_t)s->args[1]};
    rseq_array(&w,",\"commands\":",commands,sizeof(commands)/sizeof(commands[0]));
#endif
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
