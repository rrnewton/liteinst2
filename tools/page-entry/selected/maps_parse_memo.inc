/* Pure complete-input parsing memo. Every caller has already performed the
   original fresh open/read-to-EOF/successful-close sequence. This is not a
   mapping, identity, permission, or current-ticket cache. */
#if !defined(LI2_MAPS_PARSE_MEMO) || LI2_MAPS_PARSE_MEMO != 1
#error "explicit complete-input maps parser memo required"
#endif
_Static_assert(__atomic_always_lock_free(4,0),"signal-safe parse memo flags");
_Static_assert(sizeof(struct map_row)==56,"literal raw parser row");
static struct maps_parse_memo {
    unsigned busy,valid;
    size_t bytes,count;
    unsigned char input[MAP_BYTES];
    struct map_row raw[MAP_ROWS];
} maps_parse_memo;
_Static_assert(sizeof maps_parse_memo==376856,"bounded parser-only BSS");
struct maps_parse_scope { unsigned owned; };
#ifdef LI2_MAPS_PARSE_MEMO_TEST
static uint64_t maps_parse_memo_hits,maps_parse_memo_misses,maps_parse_memo_saves;
#endif
static void maps_parse_end(struct maps_parse_scope *scope) {
    if(scope->owned) {
        scope->owned=0;
        __atomic_store_n(&maps_parse_memo.busy,0,__ATOMIC_RELEASE);
    }
}
static int maps_parse_begin(struct maps_parse_scope *scope,size_t length,
                            struct li2_fetch_map_progress *p,struct check_error *e) {
    unsigned idle=0;
    if(!__atomic_compare_exchange_n(&maps_parse_memo.busy,&idle,1,0,
                                    __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        return -check_error(e,LI2_FETCH_BUSY,0);
    scope->owned=1;
    unsigned valid=__atomic_load_n(&maps_parse_memo.valid,__ATOMIC_ACQUIRE);
    if(valid>1 || (valid && (maps_parse_memo.bytes>MAP_BYTES ||
                             maps_parse_memo.count>MAP_ROWS))) {
        __atomic_store_n(&maps_parse_memo.valid,0,__ATOMIC_RELEASE);
        return -check_error(e,LI2_FETCH_STATE,0);
    }
    if(valid && length==maps_parse_memo.bytes &&
       equal(maps_bytes,maps_parse_memo.input,length)) {
        /* rows is subsequently normalized/projected. Keep the saved raw
           table separate, and leave the old parser's unused tail untouched. */
        copy(rows,maps_parse_memo.raw,maps_parse_memo.count*sizeof rows[0]);
        row_count=maps_parse_memo.count;p->rows=row_count;
#ifdef LI2_MAPS_PARSE_MEMO_TEST
        ++maps_parse_memo_hits;
#endif
        return 1;
    }
    /* No interrupted replacement or failed parse is a publishable result.
       scope cleanup releases busy on every original parser-error return. */
    __atomic_store_n(&maps_parse_memo.valid,0,__ATOMIC_RELEASE);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
#ifdef LI2_MAPS_PARSE_MEMO_TEST
    ++maps_parse_memo_misses;
#endif
    return 0;
}
static void maps_parse_save(size_t length) {
    /* The original successful parser established both bounds. copy/equal are
       the existing no-RAW bridge helpers; the active profile binds their
       bounded general-register fast implementations. No callback or lock. */
    copy(maps_parse_memo.input,maps_bytes,length);
    copy(maps_parse_memo.raw,rows,row_count*sizeof rows[0]);
    maps_parse_memo.bytes=length;maps_parse_memo.count=row_count;
#ifdef LI2_MAPS_PARSE_MEMO_TEST
    ++maps_parse_memo_saves;
#endif
    __atomic_store_n(&maps_parse_memo.valid,1,__ATOMIC_RELEASE);
}
