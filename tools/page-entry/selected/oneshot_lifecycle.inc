/* Opt-in admission-owned transaction. Included after the existing fetch/native
   owners so their predicates and retained source records remain authoritative.
   No allocator, source store, mprotect, or supplied permission-success flag. */
#if !defined(LI2_NATIVE_PAGES) || !defined(LI2_RSEQ_INACTIVE)
#error "one-shot first profile requires native-page close and actual rseq owner"
#endif
#include <stdatomic.h>

struct os_landing {
    volatile unsigned attempted,complete;
    unsigned image_kind,object;
    uintptr_t pc,page;
    uint64_t allocation,generation;
    long pid,tid;
    struct li2_fetch_map_progress maps;
    struct check_error error;
};
struct li2_oneshot_lifecycle {
    struct li2_oneshot_lifecycle_progress progress;
    struct li2_fetch_ref borrow;
    struct li2_oneshot_plan checked;
    struct owned_page original[2];
    struct li2_fetch_progress released_fetch;
    unsigned landing_index,page_count;
    uint64_t current_generation[2];
    unsigned current_protection[2];
    unsigned char original_bytes[2][PAGE];
};
static struct os_landing os_landings[2];
static struct li2_oneshot_lifecycle os_slots[LI2_ONESHOT_LIFECYCLE_SLOTS];
static size_t os_used;

static int os_error(struct li2_oneshot_lifecycle *s,unsigned code,long detail) {
    if(!s->progress.first_error) {
        s->progress.first_detail=detail;atomic_signal_fence(memory_order_seq_cst);
        s->progress.first_error=code;
    }
    return (int)s->progress.first_error;
}
static void os_start(struct li2_oneshot_call *p) {
    atomic_signal_fence(memory_order_seq_cst);p->started=1;
    atomic_signal_fence(memory_order_seq_cst);
}
static void os_return(struct li2_oneshot_call *p,long result) {
    p->result=result;atomic_signal_fence(memory_order_seq_cst);p->returned=1;
    atomic_signal_fence(memory_order_seq_cst);
}
static void os_verified(struct li2_oneshot_call *p) {
    atomic_signal_fence(memory_order_seq_cst);p->verified=1;
    atomic_signal_fence(memory_order_seq_cst);
}
static int os_private(uintptr_t first,size_t bytes) {
    if(!bytes || first>UINTPTR_MAX-bytes || !hooks.protected_range)return 0;
    /* The existing hook answers intersection, not full containment. Querying
       each one-byte extent proves coverage by its actual registered union. */
    for(size_t i=0;i<bytes;i++)if(hooks.protected_range(first+i,1)!=1)return 0;
    return 1;
}
static int os_unregistered(void) {
    const struct li2_rseq_state *r=li2_rseq_snapshot();
    return r && r->initialized && !r->registered && !r->held &&
        !r->first_error && r->phase==LI2_RSEQ_IDLE;
}
static struct li2_oneshot_lifecycle *os_context(void *context) {
    for(size_t i=0;i<os_used;i++)if(context==&os_slots[i])
        return os_slots[i].progress.prepared?&os_slots[i]:0;
    return 0;
}
const struct li2_oneshot_lifecycle_progress *li2_lifecycle_oneshot_progress(const void *context) {
    struct li2_oneshot_lifecycle *s=os_context((void *)context);return s?&s->progress:0;
}
static int os_identity(struct li2_oneshot_lifecycle *s,int held) {
    if(s->progress.first_error)return (int)s->progress.first_error;
    if(!active || !hooks.raw || tx.guard || !os_unregistered() ||
       oneshot_held!=(held?(unsigned)(s-os_slots)+1:0) ||
       s->progress.held!=(unsigned)held || s->progress.released ||
       allocation_id!=s->progress.allocation_epoch || generation!=s->progress.generation_epoch ||
       used!=s->progress.records_epoch || counts.transactions!=s->progress.transactions_epoch ||
       tx.phase!=s->progress.phase_epoch ||
       RAW(SYS_getpid,0,0,0,0,0,0)!=s->progress.pid ||
       RAW(SYS_gettid,0,0,0,0,0,0)!=s->progress.tid)
        return os_error(s,LI2_ONESHOT_IDENTITY,0);
    return 0;
}
static int os_fresh(struct li2_oneshot_lifecycle *s) {
    unsigned i=s->progress.maps_started;
    if(i>=LI2_ONESHOT_LIFECYCLE_MAPS)return os_error(s,LI2_ONESHOT_REUSE,i);
#ifdef LI2_MAPS_PHASE_REUSE
    li2_maps_phase_end();
#endif
    s->progress.maps_started=i+1;atomic_signal_fence(memory_order_seq_cst);
    struct check_error e={0};int result=read_maps_checked(&e,&s->progress.maps[i]);
    atomic_signal_fence(memory_order_seq_cst);s->progress.maps_returned=i+1;
    if(result)return os_error(s,e.code,e.detail);
#ifdef LI2_MAPS_PHASE_REUSE
    if(s->progress.maps[i].observation.kind!=LI2_MAPS_DIRECT ||
       s->progress.maps[i].observation.io_performed!=1)
        return os_error(s,LI2_ONESHOT_IDENTITY,1);
#endif
    return 0;
}
static int os_landing_check(const struct os_landing *l,struct check_error *e) {
    const struct map_row *r=mapping(l->page);
    if(!l->complete || !l->allocation || !l->generation || current(l->page) ||
       !r || r->first>l->page || r->end-l->page<PAGE ||
       r->prot!=(PROT_READ|PROT_EXEC) || !r->private || r->inode || r->major ||
       r->minor || r->offset || !os_private(l->page,PAGE))
        return check_error(e,LI2_ONESHOT_LANDING,1);
    const volatile unsigned char *p=(const void *)l->pc;
    if(p[0]!=0x0f || p[1]!=0x0b)return check_error(e,LI2_ONESHOT_LANDING,2);
    return 0;
}
int li2_lifecycle_oneshot_register_landing(unsigned kind,uintptr_t pc) {
    if((kind!=IMAGE_MAIN && kind!=IMAGE_INTERPRETER) || !active || tx.guard ||
       oneshot_held || fetch.progress.held || os_used || !os_unregistered() ||
       pc<LI2_ONESHOT_MIN_EXEC || pc>UINTPTR_MAX-2 ||
       (pc&~(PAGE-1))>UINTPTR_MAX-PAGE || (pc&(PAGE-1))>PAGE-2)
        return LI2_ONESHOT_ARGUMENT;
    if(!os_private((uintptr_t)os_slots,sizeof(os_slots)) ||
       !os_private((uintptr_t)os_landings,sizeof(os_landings)))return LI2_ONESHOT_BIND;
    struct os_landing *l=&os_landings[kind-1];
    if(l->attempted)return LI2_ONESHOT_REUSE;
    l->image_kind=kind;l->pc=pc;l->page=pc&~(PAGE-1);
    l->attempted=1;atomic_signal_fence(memory_order_seq_cst);
    size_t found=OBJECTS;
    for(size_t i=0;i<object_count;i++)if(objects[i].initial_kind==kind) {
        if(found!=OBJECTS)return check_error(&l->error,LI2_ONESHOT_IDENTITY,2);
        found=i;
    }
    if(found==OBJECTS)return check_error(&l->error,LI2_ONESHOT_IDENTITY,3);
    l->object=(unsigned)found;
    l->pid=RAW(SYS_getpid,0,0,0,0,0,0);l->tid=RAW(SYS_gettid,0,0,0,0,0,0);
    if(l->pid<=0 || l->pid!=l->tid)return check_error(&l->error,LI2_ONESHOT_IDENTITY,4);
#ifdef LI2_MAPS_PHASE_REUSE
    li2_maps_phase_end();
#endif
    if(read_maps_checked(&l->error,&l->maps))return (int)l->error.code;
    const struct map_row *r=mapping(l->page);
    if(current(l->page) || !r || r->end-l->page<PAGE || !r->private ||
       r->prot!=(PROT_READ|PROT_EXEC) || r->inode || r->major || r->minor || r->offset ||
       !os_private(l->page,PAGE))return check_error(&l->error,LI2_ONESHOT_LANDING,3);
    const volatile unsigned char *p=(const void *)pc;
    if(p[0]!=0x0f || p[1]!=0x0b)return check_error(&l->error,LI2_ONESHOT_LANDING,4);
    /* Identity belongs to this fixed private landing registry, never an app
       allocation or an old core publication receipt. Mapping mutation is
       excluded by its actual protected range for the rest of process life. */
    l->allocation=kind;l->generation=1;
    atomic_signal_fence(memory_order_seq_cst);l->complete=1;return 0;
}
static int os_source_record(const struct li2_oneshot_lifecycle *s,unsigned i,
                             const struct owned_page *p) {
    const struct owned_page *a=&s->original[i];
    return p && p->live && p->address==a->address && p->allocation==a->allocation &&
        p->generation==s->current_generation[i] && p->actual==s->current_protection[i] &&
        p->offset==a->offset && p->initial_extent==a->initial_extent &&
        p->backing==SEALED && p->object==a->object && p->logical==(PROT_READ|PROT_EXEC) &&
        !p->admitted;
}
static int os_pages(struct li2_oneshot_lifecycle *s,unsigned prot) {
    struct check_error e={0};
    for(unsigned i=0;i<s->page_count;i++) {
        struct owned_page *p=current(s->checked.pages[i].address);
        const struct map_row *r=mapping(s->checked.pages[i].address);
        if(!os_source_record(s,i,p) || !r || r->prot!=prot)
            return os_error(s,LI2_ONESHOT_IDENTITY,10+i);
        if(verify_page_checked(p,r,&e) ||
           alias_check_checked(p->object,p->offset,PAGE,PROT_READ|PROT_WRITE|PROT_EXEC,
                               p->address,p->address+PAGE,&e))return os_error(s,e.code,e.detail);
    }
    /* No other application page may execute during the temporal certificate.
       Runtime, landing and vDSO mappings have separate protected ownership. */
    for(size_t i=0;i<used;i++) {
        const struct owned_page *p=&records[i];if(!p->live || !(p->logical&PROT_EXEC))continue;
        unsigned source=0;for(unsigned j=0;j<s->page_count;j++)
            if(p->address==s->checked.pages[j].address)source=1;
        if(source)continue;
        const struct map_row *r=mapping(p->address);
        if(p->logical!=(PROT_READ|PROT_EXEC) || p->admitted || p->actual!=PROT_READ ||
           !r || r->prot!=PROT_READ ||
           verify_page_checked(p,r,&e))return os_error(s,e.code?e.code:LI2_ONESHOT_IDENTITY,20);
    }
    if(native_counts.admissions!=native_counts.closed)return os_error(s,LI2_ONESHOT_IDENTITY,21);
    if(os_landing_check(&os_landings[s->landing_index],&e))return os_error(s,e.code,e.detail);
    return 0;
}
static int os_source_bytes(struct li2_oneshot_lifecycle *s,unsigned patched) {
    for(unsigned i=0;i<s->page_count;i++) {
        const volatile unsigned char *p=(const void *)s->checked.pages[i].address;
        for(size_t j=0;j<PAGE;j++) {
            uint64_t at=s->checked.pages[i].address+j;
            unsigned char wanted=s->original_bytes[i][j];
            if(patched && at>=s->checked.pc && at-s->checked.pc<5)
                wanted=s->checked.redirect[at-s->checked.pc];
            if(p[j]!=wanted)return os_error(s,LI2_ONESHOT_SOURCE,(long)(i*PAGE+j));
        }
    }
    return 0;
}
static int os_original_backing(struct li2_oneshot_lifecycle *s,unsigned i) {
    const struct owned_page *p=&s->original[i];const struct object *o=&objects[p->object];
    struct li2_fetch_backing *b=&s->progress.backing[i];
    b->retained_fd=o->retained_fd;
    b->seals=RAW(SYS_fcntl,o->retained_fd,F_GET_SEALS,0,0,0,0);b->seals_observed=1;
    if(b->seals<0 || (b->seals&SEALS)!=SEALS)return os_error(s,LI2_ONESHOT_BIND,b->seals);
    b->stat_result=RAW(SYS_fstat,o->retained_fd,&b->stat,0,0,0,0);b->stat_observed=1;
    if(b->stat_result || b->stat.st_size<=0 || b->stat.st_dev!=o->stat.st_dev || b->stat.st_ino!=o->stat.st_ino ||
       b->stat.st_size!=o->stat.st_size || b->stat.st_mode!=o->stat.st_mode ||
       p->offset>(uint64_t)b->stat.st_size || PAGE>(uint64_t)b->stat.st_size-p->offset ||
       p->offset>o->initial_source_size || PAGE>o->initial_source_size-p->offset)
        return os_error(s,LI2_ONESHOT_BIND,30+i);
    uintptr_t source=(uintptr_t)o->initial_source+p->offset;
    const struct map_row *r=mapping(source);
    if(source<(uintptr_t)o->initial_source || source>UINTPTR_MAX-PAGE ||
       !r || r->end-source<PAGE || r->prot!=PROT_READ || !r->private ||
       !os_private(source,PAGE))return os_error(s,LI2_ONESHOT_BIND,32+i);
    s->progress.backing_started[i]=1;atomic_signal_fence(memory_order_seq_cst);
    long got=RAW(SYS_pread64,o->retained_fd,s->original_bytes[i],PAGE,p->offset,0,0);
    s->progress.backing_result[i]=got;atomic_signal_fence(memory_order_seq_cst);
    s->progress.backing_returned[i]=1;
    if(got!=(long)PAGE || !equal(s->original_bytes[i],(const void *)source,PAGE))
        return os_error(s,LI2_ONESHOT_SOURCE,got);
    atomic_signal_fence(memory_order_seq_cst);s->progress.backing_verified[i]=1;return 0;
}
int li2_lifecycle_oneshot_prepare(const struct li2_fetch_ref *ref,unsigned kind,
                                 struct li2_oneshot_plan *out,struct li2_oneshot_lifecycle **context) {
    if(!ref || !out || !context || (kind!=LI2_ONESHOT_SYSCALL && kind!=LI2_ONESHOT_RDTSC))
        return LI2_ONESHOT_ARGUMENT;
    *context=0;
    if(oneshot_held || !active || tx.guard || !os_unregistered())return LI2_ONESHOT_REENTRY;
    if(os_used && ref->sequence<=os_slots[os_used-1].borrow.sequence)return LI2_ONESHOT_REENTRY;
    struct li2_fetch_view v={0};int error=li2_lifecycle_fetch_view(ref,&v);if(error)return error;
    if(!v.bytes || !v.pages || !v.backing || !v.identity_observed || v.pid<=0 || v.pid!=v.tid ||
       v.pc>UINTPTR_MAX-5)return LI2_ONESHOT_BIND;
    if(v.length<5 || os_used==LI2_ONESHOT_LIFECYCLE_SLOTS)return LI2_ONESHOT_REFUSED_UNTOUCHED;
    unsigned pages=((v.pc&~(PAGE-1))==((v.pc+4)&~(PAGE-1)))?1:2;
    if(v.page_count<pages)return LI2_ONESHOT_BIND;
    unsigned object=v.pages[0].object;
    if(object>=object_count || (objects[object].initial_kind!=IMAGE_MAIN &&
       objects[object].initial_kind!=IMAGE_INTERPRETER))return LI2_ONESHOT_REFUSED_UNTOUCHED;
    unsigned li=objects[object].initial_kind-1;
    const struct os_landing *l=&os_landings[li];
    if(!l->complete || l->object!=object)return LI2_ONESHOT_REFUSED_UNTOUCHED;
    struct li2_oneshot_plan request={.abi_version=LI2_ONESHOT_ABI,.kind=kind,
        .sequence=os_used+1,.pc=v.pc,.next_pc=v.pc+2,.landing=l->pc,
        .landing_allocation=l->allocation,.landing_generation=l->generation,.page_count=pages};
    for(unsigned i=0;i<pages;i++) {
        const struct li2_fetch_page *p=&v.pages[i];
        /* Main carrier PHDR bytes were deliberately reconstructed at boot;
           the first page is not a byte-identical original-file projection.
           This first capability excludes it before consuming the old borrow. */
        if(objects[object].initial_kind==IMAGE_MAIN && !p->offset)
            return LI2_ONESHOT_REFUSED_UNTOUCHED;
        if(p->backing!=SEALED || p->object!=object || p->offset>objects[object].initial_source_size ||
           PAGE>objects[object].initial_source_size-p->offset ||
           p->offset>(uint64_t)objects[object].stat.st_size ||
           PAGE>(uint64_t)objects[object].stat.st_size-p->offset)
            return LI2_ONESHOT_REFUSED_UNTOUCHED;
        request.pages[i]=(struct li2_oneshot_page){p->address,p->allocation,p->generation,p->offset};
    }
    for(unsigned i=0;i<5;i++)request.original[i]=v.bytes[i];
    struct li2_oneshot_plan checked;
    error=li2_admission_oneshot_plan(&request,&checked);
    if(error)return error==LI2_ONESHOT_GEOMETRY?LI2_ONESHOT_REFUSED_UNTOUCHED:error;
    struct li2_oneshot_lifecycle *s=&os_slots[os_used];
    s->borrow=*ref;s->checked=checked;s->landing_index=li;s->page_count=pages;
    s->progress.sequence=checked.sequence;s->progress.pid=v.pid;s->progress.tid=v.tid;
    s->progress.allocation_epoch=allocation_id;s->progress.generation_epoch=generation;
    s->progress.records_epoch=used;s->progress.transactions_epoch=counts.transactions;
    s->progress.phase_epoch=tx.phase;
    for(unsigned i=0;i<pages;i++) {
        const struct owned_page *p=current(checked.pages[i].address);
        if(!p || p->generation!=checked.pages[i].generation || p->allocation!=checked.pages[i].allocation ||
           p->offset!=checked.pages[i].offset || p->object!=object || !p->live)return LI2_ONESHOT_BIND;
        s->original[i]=*p;
        s->current_generation[i]=p->generation;s->current_protection[i]=p->actual;
    }
    *out=request;*context=s;atomic_signal_fence(memory_order_seq_cst);
    s->progress.prepared=1;++os_used;return 0;
}
static int os_plan(struct li2_oneshot_lifecycle *s,const struct li2_oneshot_plan *p,int held) {
    if(!s || !p)return LI2_ONESHOT_ARGUMENT;
    if(!equal(p,&s->checked,sizeof(*p)))return os_error(s,LI2_ONESHOT_BIND,40);
    return os_identity(s,held);
}
int li2_lifecycle_oneshot_transfer(void *context,const struct li2_oneshot_plan *p,
                                  struct li2_oneshot_transfer *v) {
    struct li2_oneshot_lifecycle *s=os_context(context);int error=os_plan(s,p,0);
    if(error || !v)return error?error:LI2_ONESHOT_ARGUMENT;
    struct li2_fetch_view view={0};error=li2_lifecycle_fetch_view(&s->borrow,&view);
    if(error || view.pc!=p->pc || view.length<5 || !equal(view.bytes,p->original,5))
        return os_error(s,LI2_ONESHOT_BIND,error);
    for(size_t i=0;i<view.page_count;i++) {
        error=li2_lifecycle_fetch_validate(&s->borrow,i,PROT_READ);
        if(error)return os_error(s,LI2_ONESHOT_BIND,error);
    }
    v->old_borrow_live=1;atomic_signal_fence(memory_order_seq_cst);v->old_authenticated=1;
    if(os_fresh(s) || os_pages(s,PROT_READ))return (int)s->progress.first_error;
    for(unsigned i=0;i<s->page_count;i++)if(os_original_backing(s,i))return (int)s->progress.first_error;
    if(os_source_bytes(s,0))return (int)s->progress.first_error;
    if(used>RECORDS-2*s->page_count || generation>UINT64_MAX-2*s->page_count)
        return LI2_ONESHOT_TRANSFER_UNTOUCHED;
    os_start(&v->old_release);error=li2_lifecycle_fetch_release(&s->borrow);os_return(&v->old_release,error);
    s->released_fetch=*li2_lifecycle_fetch_progress();
    if(error || s->released_fetch.held)return os_error(s,LI2_ONESHOT_RELEASE,error);
    v->old_borrow_live=0;os_verified(&v->old_release);
    os_start(&v->acquire);
    if(fetch.progress.held || oneshot_held || os_identity(s,0)) {
        error=s->progress.first_error?(int)s->progress.first_error:LI2_ONESHOT_REENTRY;
        os_return(&v->acquire,error);return os_error(s,LI2_ONESHOT_BIND,error);
    }
    /* Install all immutable binding fields before publishing global ownership.
       Acquisition-started is retained even if a reserved event interrupts. */
    s->progress.held=1;atomic_signal_fence(memory_order_seq_cst);
    oneshot_held=(unsigned)(s-os_slots)+1;atomic_signal_fence(memory_order_seq_cst);
    v->transaction_live=1;
    if(os_fresh(s) || os_pages(s,PROT_READ) || os_source_bytes(s,0)) {
        os_return(&v->acquire,s->progress.first_error);return (int)s->progress.first_error;
    }
    os_return(&v->acquire,0);os_verified(&v->acquire);return LI2_ONESHOT_TRANSFER_OWNED;
}
int li2_lifecycle_oneshot_advance(void *context,const struct li2_oneshot_plan *p,unsigned restoring,
                                 struct li2_oneshot_generation *out) {
    struct li2_oneshot_lifecycle *s=os_context(context);int error=os_plan(s,p,1);
    if(error || !out)return error?error:LI2_ONESHOT_ARGUMENT;
    if(restoring>1 || out->restoring!=restoring || s->progress.generation_steps!=restoring ||
       s->progress.observations!=(restoring?5U:1U) || used>RECORDS-s->page_count ||
       generation>UINT64_MAX-s->page_count || fetch.progress.held)
        return os_error(s,LI2_ONESHOT_GENERATION,1);
    if(os_fresh(s) || os_pages(s,PROT_READ) || os_source_bytes(s,restoring))
        return (int)s->progress.first_error;
#ifdef LI2_MAPS_PHASE_REUSE
    li2_maps_phase_end();
#endif
    for(unsigned i=0;i<s->page_count;i++) {
        struct owned_page *old=current(p->pages[i].address);
        if(!old || out->before[i]!=old->generation || old->actual!=PROT_READ)
            return os_error(s,LI2_ONESHOT_GENERATION,2+i);
        struct owned_page saved=*old;uint32_t bit=UINT32_C(1)<<i;
        out->attempted_mask|=bit;atomic_signal_fence(memory_order_seq_cst);
        retire(old);append(saved.address,saved.allocation,saved.offset,saved.backing,saved.object,
                           saved.logical,PROT_READ);
        struct owned_page *now=current(saved.address);now->initial_extent=saved.initial_extent;
        s->current_generation[i]=now->generation;s->current_protection[i]=now->actual;
        out->after[i]=now->generation;atomic_signal_fence(memory_order_seq_cst);
        out->completed_mask|=bit;atomic_signal_fence(memory_order_seq_cst);
    }
    /* Exact retire+append makes old fetch epochs/source-page tuples stale.
       Run cache hits compare these generations; native_blocked is indexed by
       append-only record and the fresh record has no old negative-cache entry. */
    s->progress.generation_epoch=generation;s->progress.records_epoch=used;
    atomic_signal_fence(memory_order_seq_cst);s->progress.generation_steps=restoring+1;
    return 0;
}
int li2_lifecycle_oneshot_observe(void *context,const struct li2_oneshot_plan *p,
                                 struct li2_oneshot_observation *out) {
    static const unsigned protections[7]={PROT_READ,PROT_READ|PROT_WRITE,PROT_READ|PROT_EXEC,
        PROT_READ|PROT_EXEC,PROT_READ,PROT_READ|PROT_WRITE,PROT_READ};
    static const unsigned generations[7]={0,1,1,1,1,2,2};
    static const unsigned patched[7]={0,0,1,1,1,1,0};
    struct li2_oneshot_lifecycle *s=os_context(context);int error=os_plan(s,p,1);
    if(error || !out)return error?error:LI2_ONESHOT_ARGUMENT;
    unsigned n=s->progress.observations;
    if(n>=7 || s->progress.generation_steps!=generations[n])return os_error(s,LI2_ONESHOT_IDENTITY,50);
    if(os_fresh(s) || os_pages(s,protections[n]) || os_source_bytes(s,patched[n]))
        return (int)s->progress.first_error;
    out->page_count=s->page_count;out->pid=s->progress.pid;out->tid=s->progress.tid;
    for(unsigned i=0;i<s->page_count;i++) {
        struct owned_page *q=current(p->pages[i].address);
        q->actual=protections[n];
        s->current_protection[i]=protections[n];
        out->pages[i]=(struct li2_oneshot_page){q->address,q->allocation,q->generation,q->offset};
        out->protection[i]=protections[n];out->private_mapping[i]=1;out->writable_aliases[i]=0;
    }
    const struct os_landing *l=&os_landings[s->landing_index];
    out->landing_page=l->page;out->landing_allocation=l->allocation;out->landing_generation=l->generation;
    out->landing_protection=PROT_READ|PROT_EXEC;out->landing_private=1;out->landing_writable_aliases=0;
    atomic_signal_fence(memory_order_seq_cst);s->progress.observations=n+1;return 0;
}
int li2_lifecycle_oneshot_release(void *context,const struct li2_oneshot_plan *p,
                                 struct li2_oneshot_release *out) {
    struct li2_oneshot_lifecycle *s=os_context(context);int error=os_plan(s,p,1);
    if(error || !out)return error?error:LI2_ONESHOT_ARGUMENT;
    if(s->progress.observations!=7 || s->progress.generation_steps!=2 || fetch.progress.held ||
       out->transaction_live!=1)return os_error(s,LI2_ONESHOT_RELEASE,1);
    if(os_fresh(s) || os_pages(s,PROT_READ) || os_source_bytes(s,0))return (int)s->progress.first_error;
    for(unsigned i=0;i<s->page_count;i++)if(current(p->pages[i].address)->actual!=PROT_READ)
        return os_error(s,LI2_ONESHOT_RELEASE,2);
    /* Caller only dispatches the selected effect after the C owner separately
       publishes RESTORED, then freshly prepares the original instruction. */
    s->progress.held=0;s->progress.released=1;atomic_signal_fence(memory_order_seq_cst);
    oneshot_held=0;atomic_signal_fence(memory_order_seq_cst);out->transaction_live=0;return 0;
}
int li2_lifecycle_fetch_prepare(uintptr_t pc,size_t bytes,struct li2_fetch_ref *out) {
    if(oneshot_held)return LI2_FETCH_BUSY;
    return li2_lifecycle_fetch_prepare_unpatched(pc,bytes,out);
}
int li2_lifecycle_fetch_interlock(void) {
    return oneshot_held?LI2_FETCH_BUSY:li2_lifecycle_fetch_interlock_unpatched();
}
