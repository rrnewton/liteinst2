/* Private opt-in draft: generation renewal for one already-exclusive source
   transaction. The finite profile retains its original retire+append body.
   No source store, permission change, rseq permit or new execution authority. */
#if LI2_ONESHOT_REUSABLE != 1 || !defined(LI2_ONESHOT_PUBLICATION) || \
    !defined(LI2_MAPS_PHASE_REUSE) || !defined(LI2_TF_SEALED_CUSTODY)
#error "reusable generation renewal requires its complete publication profile"
#endif
static int os_reusable_renew(struct li2_oneshot_lifecycle *s,unsigned i,
                              struct li2_oneshot_generation *out) {
    if(!s || !out)return LI2_ONESHOT_ARGUMENT;
    if(i>=s->page_count || s->page_count>2 ||
       !s->progress.prepared || s->progress.held!=1 || s->progress.released ||
       s->progress.first_error || oneshot_held!=(unsigned)(s-os_slots)+1 ||
       fetch.progress.held || tx.guard || native_close.busy || native_close.first_error ||
       native_counts.admissions!=native_counts.closed ||
       counts.generations!=generation || counts.retained_records!=used ||
       generation==UINT64_MAX)
        return os_error(s,LI2_ONESHOT_GENERATION,60);
    struct owned_page *p=current(s->checked.pages[i].address);
    if(!p || p<records || p>=records+used ||
       !os_source_record(s,i,p) || p->backing!=SEALED ||
       p->actual!=PROT_READ || p->logical!=(PROT_READ|PROT_EXEC) || p->admitted ||
       out->before[i]!=p->generation)
        return os_error(s,LI2_ONESHOT_GENERATION,61+i);
    /* The caller just completed os_fresh/os_pages/source_bytes under this same
       exclusive owner. Independently reject any surviving native admission. */
    for(size_t n=0;n<used;n++)
        if(records[n].live && records[n].admitted)
            return os_error(s,LI2_ONESHOT_GENERATION,63);
    uint32_t bit=UINT32_C(1)<<i;
    out->attempted_mask|=bit;atomic_signal_fence(memory_order_seq_cst);
    li2_page_custody_discard(LI2_CUSTODY_EFFECT);
    if(li2_page_custody_snapshot()->phase!=LI2_CUSTODY_EMPTY)
        return os_error(s,LI2_ONESHOT_GENERATION,64);
    li2_maps_phase_end();
    struct li2_maps_stats maps;
    li2_maps_stats_read(&maps);
    if(maps.active || maps.valid || maps.poisoned)
        return os_error(s,LI2_ONESHOT_GENERATION,65);
    __atomic_store_n(&alias_query_memo.valid,0,__ATOMIC_RELEASE);
    native_blocked[(size_t)(p-records)]=0;
    atomic_signal_fence(memory_order_seq_cst);
    /* Allocation and record location remain fixed, but no old generation can
       match a new borrow/run/plan. Historical fetch/RX payloads are not erased
       or rewritten as current authority. No page-record capacity is consumed. */
    p->generation=++generation;
    ++counts.generations;
    s->current_generation[i]=p->generation;
    s->current_protection[i]=p->actual;
    out->after[i]=p->generation;atomic_signal_fence(memory_order_seq_cst);
    out->completed_mask|=bit;
    return 0;
}
