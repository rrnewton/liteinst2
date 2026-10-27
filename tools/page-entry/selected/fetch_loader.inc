/* Included only by lifecycle_loader.c: shares its exact fallible predicates,
   retained owners and already-bounded maps scratch. No permission operations. */
struct li2_fetch {
    struct li2_fetch_progress progress;
    uintptr_t pc;
    size_t requested,page_count;
    long pid,tid;
    uint64_t allocation_epoch,generation_epoch,transactions_epoch;
    size_t records_epoch;
    unsigned phase_epoch;
    struct owned_page original[2];
    struct li2_fetch_page pages[2];
    struct li2_fetch_backing backing[2],last_backing;
    unsigned char bytes[15];
};
static struct li2_fetch fetch;
static uint64_t fetch_sequence;

static int fetch_error(unsigned code,long detail) {
    if (!fetch.progress.first_error) {
        fetch.progress.first_error=code; fetch.progress.first_detail=detail;
    }
    return (int)fetch.progress.first_error;
}
static int fetch_check_error(const struct check_error *e) {
    return fetch_error(e->code,e->detail);
}
static int fetch_ref(const struct li2_fetch_ref *ref) {
    if (!ref || ref->owner!=&fetch || !fetch.progress.held || ref->sequence!=fetch.progress.sequence)
        return LI2_FETCH_STALE;
    if (fetch.progress.first_error) return (int)fetch.progress.first_error;
    if (!fetch.progress.complete) return LI2_FETCH_STATE;
    return 0;
}
static int fetch_identity(void) {
    long pid=RAW(SYS_getpid,0,0,0,0,0,0),tid=RAW(SYS_gettid,0,0,0,0,0,0);
    if (pid!=fetch.pid || tid!=fetch.tid || !active || tx.guard ||
        allocation_id!=fetch.allocation_epoch || generation!=fetch.generation_epoch ||
        used!=fetch.records_epoch || counts.transactions!=fetch.transactions_epoch ||
        tx.phase!=fetch.phase_epoch)
        return fetch_error(LI2_FETCH_IDENTITY,0);
    return 0;
}
static int fetch_owned_equal(const struct owned_page *a,const struct owned_page *b) {
    return a && a->address==b->address && a->allocation==b->allocation &&
        a->generation==b->generation && a->offset==b->offset && a->initial_extent==b->initial_extent &&
        a->backing==b->backing && a->object==b->object && a->logical==b->logical &&
        a->actual==b->actual && a->live==b->live && a->admitted==b->admitted;
}
static int fetch_backing_check(const struct owned_page *p,struct li2_fetch_backing *observed) {
    *observed=(struct li2_fetch_backing){.retained_fd=-1};
    if (p->backing==ANONYMOUS) return 0;
    if (p->backing!=SEALED || p->object>=object_count) return fetch_error(LI2_FETCH_BACKING,0);
    const struct object *o=&objects[p->object];
    observed->retained_fd=o->retained_fd;
    observed->seals=RAW(SYS_fcntl,o->retained_fd,F_GET_SEALS,0,0,0,0);
    observed->seals_observed=1;
    if (observed->seals<0 || (observed->seals&SEALS)!=SEALS)
        return fetch_error(LI2_FETCH_BACKING,observed->seals);
    observed->stat_result=RAW(SYS_fstat,o->retained_fd,&observed->stat,0,0,0,0);
    observed->stat_observed=1;
    if (observed->stat_result) return fetch_error(LI2_FETCH_BACKING,observed->stat_result);
    const struct stat *st=&observed->stat;
    if (st->st_dev!=o->stat.st_dev || st->st_ino!=o->stat.st_ino ||
        st->st_size!=o->stat.st_size || st->st_mode!=o->stat.st_mode)
        return fetch_error(LI2_FETCH_BACKING,0);
    /* A VMA alone does not make a file page beyond EOF readable (SIGBUS).
       Seals keep this actual file extent stable. The final partial page is
       readable through its zero tail; a wholly beyond-EOF page is refused. */
    if (st->st_size<=0 || (uint64_t)st->st_size>UINT64_MAX-(PAGE-1) ||
        p->offset>=(((uint64_t)st->st_size+PAGE-1)&~(PAGE-1)))
        return fetch_error(LI2_FETCH_BACKING,0);
    return 0;
}
static int fetch_initial_page(size_t index,uintptr_t address) {
    const struct owned_page *p=current(address);
    const struct map_row *r=mapping(address);
    if (!p || !p->live || !p->allocation || !p->generation || p->admitted ||
        p->logical!=(PROT_READ|PROT_EXEC) || p->actual!=PROT_READ ||
        (p->backing==SEALED && p->object>=object_count)) return fetch_error(LI2_FETCH_PAGE,(long)index);
    struct check_error error={0};
    if (verify_page_checked(p,r,&error)) return fetch_check_error(&error);
    if (r->prot!=PROT_READ) return fetch_error(LI2_FETCH_PAGE,(long)index);
    if (p->backing==SEALED && alias_check_checked(p->object,p->offset,PAGE,p->logical,
                                                p->address,p->address+PAGE,&error))
        return fetch_check_error(&error);
    /* Install actual original header before the next fallible descriptor read. */
    fetch.original[index]=*p;
    fetch.pages[index]=(struct li2_fetch_page){
        .address=p->address,.allocation=p->allocation,.generation=p->generation,
        .offset=p->offset,.initial_extent=p->initial_extent,.backing=p->backing,
        .object=p->object,.logical=p->logical,.closed_prot=p->actual,
        .vma_first=r->first,.vma_end=r->end,.vma_major=r->major,
        .vma_minor=r->minor,.vma_inode=r->inode,.vma_offset=r->offset
    };
    fetch.progress.pages_copied=index+1;
    return fetch_backing_check(p,&fetch.backing[index]);
}
int li2_lifecycle_fetch_prepare(uintptr_t pc,size_t bytes,struct li2_fetch_ref *out) {
    if (!out || !bytes || bytes>15 || pc>UINTPTR_MAX-bytes) return LI2_FETCH_ARGUMENT;
    if (fetch.progress.held) return LI2_FETCH_BUSY;
    if (!active || tx.guard || (tx.phase!=IDLE && tx.phase!=REVOKED && tx.phase!=ADMITTED) ||
        fetch_sequence==UINT64_MAX) return LI2_FETCH_STATE;
    fetch=(struct li2_fetch){.progress={.held=1,.sequence=++fetch_sequence},.pc=pc,.requested=bytes};
    *out=(struct li2_fetch_ref){&fetch,fetch.progress.sequence};
    fetch.allocation_epoch=allocation_id; fetch.generation_epoch=generation;
    fetch.transactions_epoch=counts.transactions; fetch.records_epoch=used; fetch.phase_epoch=tx.phase;
    fetch.pid=RAW(SYS_getpid,0,0,0,0,0,0); fetch.tid=RAW(SYS_gettid,0,0,0,0,0,0);
    fetch.progress.identity_observed=1;
    if (fetch.pid<=0 || fetch.pid!=fetch.tid) return fetch_error(LI2_FETCH_IDENTITY,0);
    uintptr_t first=pc&~(PAGE-1),last=(pc+bytes-1)&~(PAGE-1);
    fetch.page_count=first==last?1:2;
    struct check_error error={0};
    if (read_maps_checked(&error,&fetch.progress.preparation)) return fetch_check_error(&error);
    for (size_t i=0;i<fetch.page_count;i++) {
        int result=fetch_initial_page(i,first+i*PAGE);
        if (result) return result;
    }
    /* Source reads happen only after every containing page and retained backing
       is authenticated. Singleton + the mandatory mutation interlock keeps
       this mapped/readable source stable throughout copy and the borrow. */
    const volatile unsigned char *source=(const void *)pc;
    for (size_t i=0;i<bytes;i++) { fetch.bytes[i]=source[i]; fetch.progress.bytes_copied=i+1; }
    fetch.progress.complete=1;
    return 0;
}
void li2_lifecycle_fetch_partial_view(struct li2_fetch_view *out) {
    if (!out) return;
    *out=(struct li2_fetch_view){.pc=fetch.pc,
        .bytes=fetch.progress.bytes_copied?fetch.bytes:0,.length=fetch.progress.bytes_copied,
        .page_count=fetch.progress.pages_copied,.pages=fetch.progress.pages_copied?fetch.pages:0,
        .backing=fetch.progress.pages_copied?fetch.backing:0,
        .last_backing=fetch.progress.last_backing_observed?&fetch.last_backing:0,
        .pid=fetch.pid,.tid=fetch.tid,.identity_observed=fetch.progress.identity_observed};
}
int li2_lifecycle_fetch_view(const struct li2_fetch_ref *ref,struct li2_fetch_view *out) {
    if (!out) return LI2_FETCH_ARGUMENT;
    int error=fetch_ref(ref); if (error) return error;
    li2_lifecycle_fetch_partial_view(out);
    return 0;
}
int li2_lifecycle_fetch_validate(const struct li2_fetch_ref *ref,size_t index,int expected_prot) {
    int result=fetch_ref(ref); if (result) return result;
    if (index>=fetch.page_count || (expected_prot!=PROT_READ && expected_prot!=(PROT_READ|PROT_EXEC)))
        return fetch_error(LI2_FETCH_ARGUMENT,(long)index);
    if (fetch.progress.validation_calls==UINT64_MAX) return fetch_error(LI2_FETCH_STATE,0);
    ++fetch.progress.validation_calls;
    if ((result=fetch_identity())) return result;
    struct check_error error={0};
    if (read_maps_checked(&error,&fetch.progress.validation)) return fetch_check_error(&error);
    /* All page identities are checked on every callback. Only the requested
       page's temporary protection is compared; the sole step owner retains
       its exact successful/open/revoke prefix for the other page. */
    for (size_t i=0;i<fetch.page_count;i++) {
        const struct owned_page *saved=&fetch.original[i],*p=current(saved->address);
        const struct map_row *r=mapping(saved->address);
        if (!fetch_owned_equal(p,saved)) return fetch_error(LI2_FETCH_STALE,(long)i);
        if (verify_page_checked(p,r,&error)) return fetch_check_error(&error);
        if ((r->prot!=PROT_READ && r->prot!=(PROT_READ|PROT_EXEC)) ||
            (i==index && r->prot!=(unsigned)expected_prot)) return fetch_error(LI2_FETCH_PAGE,(long)i);
        if (p->backing==SEALED && alias_check_checked(p->object,p->offset,PAGE,p->logical,
                                                    p->address,p->address+PAGE,&error))
            return fetch_check_error(&error);
        fetch.progress.last_backing_page=i; fetch.progress.last_backing_observed=1;
        if ((result=fetch_backing_check(p,&fetch.last_backing))) return result;
    }
    const volatile unsigned char *source=(const void *)fetch.pc;
    for (size_t i=0;i<fetch.requested;i++) if (source[i]!=fetch.bytes[i]) return fetch_error(LI2_FETCH_SOURCE,(long)i);
    return 0;
}
int li2_lifecycle_fetch_release(const struct li2_fetch_ref *ref) {
    int result=fetch_ref(ref); if (result) return result;
    for (size_t i=0;i<fetch.page_count;i++)
        if ((result=li2_lifecycle_fetch_validate(ref,i,PROT_READ))) return result;
    /* No payload is cleared. A later prepare may reuse this fixed owner only
       after the caller has ended the old borrow and copied claimed evidence. */
    fetch.progress.held=0;
    return 0;
}
int li2_lifecycle_fetch_interlock(void) { return fetch.progress.held?LI2_FETCH_BUSY:0; }
const struct li2_fetch_progress *li2_lifecycle_fetch_progress(void) { return &fetch.progress; }
