/* Included last by lifecycle_loader.c. Read actual module-owned state only;
   do not call raw, hooks, validators that mutate progress, or cleanup paths. */
#if LI2_RUN_CACHE_REUSE != 1
#error "run cache reuse requires its explicit lifecycle interlock"
#endif
int li2_lifecycle_run_reuse_quiet(const struct li2_fetch_ref *expected) {
    if(!active || tx.guard ||
       (tx.phase!=IDLE && tx.phase!=REVOKED && tx.phase!=ADMITTED))
        return LI2_FETCH_STATE;
    if(fetch.progress.first_error)return (int)fetch.progress.first_error;
    if(expected) {
        int e=fetch_ref(expected);if(e)return e; /* Pure identity/held checks. */
        if(!expected->sequence || !fetch.progress.identity_observed ||
           fetch.pid<=0 || fetch.pid!=fetch.tid ||
           allocation_id!=fetch.allocation_epoch || generation!=fetch.generation_epoch ||
           used!=fetch.records_epoch || counts.transactions!=fetch.transactions_epoch ||
           tx.phase!=fetch.phase_epoch)return LI2_FETCH_IDENTITY;
    } else if(fetch.progress.held)return LI2_FETCH_BUSY;
#ifdef LI2_ONESHOT_PUBLICATION
    if(oneshot_held)return LI2_FETCH_BUSY;
#ifdef LI2_ONESHOT_REUSABLE
    if(li2_lifecycle_oneshot_interlock())return LI2_FETCH_BUSY;
    if(os_reuse.completed>os_reuse.prepared ||
       os_reuse.prepared-os_reuse.completed!=os_reuse.refused)return LI2_FETCH_STATE;
#else
    if(os_used>LI2_ONESHOT_LIFECYCLE_SLOTS)return LI2_FETCH_STATE;
    for(size_t i=0;i<os_used;i++) {
        const struct li2_oneshot_lifecycle_progress *p=&os_slots[i].progress;
        if(p->first_error)return (int)p->first_error;
        if(p->held || (p->prepared && !p->released))return LI2_FETCH_BUSY;
    }
#endif
#endif
#ifdef LI2_NATIVE_PAGES
    if(native_counts.admissions!=native_counts.closed || native_close.busy)
        return LI2_FETCH_BUSY;
    if(native_close.first_error)return (int)native_close.first_error;
    if(native_close.cleanup_started || (native_close.sequence &&
       (!native_close.complete || native_close.pages!=native_close.attempted ||
        native_close.pages!=native_close.returned || native_close.pages!=native_close.closed ||
        native_close.pages!=native_close.verified)))return LI2_FETCH_STATE;
#endif
#ifdef LI2_TF_SAME_PAGE_LEASE
    if(rx_view.result)return rx_view.result;
    if(rx_view.phase!=LI2_RX_EMPTY && rx_view.phase!=LI2_RX_COMMITTED &&
       rx_view.phase!=LI2_RX_CANCELLED)return LI2_FETCH_BUSY;
    if(rx_view.phase!=LI2_RX_EMPTY && !rx_view.complete)return LI2_FETCH_STATE;
#ifdef LI2_TF_SEALED_CUSTODY
    if(__atomic_load_n(&custody_stats.phase,__ATOMIC_ACQUIRE)!=LI2_CUSTODY_EMPTY)
        return LI2_FETCH_STATE;
#endif
#endif
    return 0;
}
