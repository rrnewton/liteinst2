/* Included instead of the finite prepare body. Permission/store/observation
   callbacks below remain the common actual transaction implementation. */
#include "oneshot_reusable.h"
static struct li2_oneshot_reuse_stats os_reuse;
static struct li2_oneshot_lifecycle os_last_complete,os_last_refused;
static uint64_t os_landing_serial;
const struct li2_oneshot_reuse_stats *li2_lifecycle_oneshot_reuse_snapshot(void) { return &os_reuse; }
const struct li2_oneshot_lifecycle_progress *li2_lifecycle_oneshot_last_complete(void) {
    return &os_last_complete.progress;
}
const struct li2_oneshot_lifecycle_progress *li2_lifecycle_oneshot_last_refused(void) {
    return &os_last_refused.progress;
}
int li2_lifecycle_oneshot_interlock(void) {
    return oneshot_held || os_slots[0].progress.prepared || os_slots[0].progress.first_error ||
        (os_reuse.reset_started && !os_reuse.reset_complete)?LI2_FETCH_BUSY:0;
}
static int os_range(unsigned object,uint64_t allocation,uintptr_t *first,uintptr_t *end) {
    *first=UINTPTR_MAX;*end=0;
    for(size_t i=0;i<used;i++) {
        const struct owned_page *p=&records[i];
        if(!p->live || p->object!=object || p->allocation!=allocation || !(p->logical&PROT_EXEC))continue;
        if(p->backing!=SEALED || p->logical!=(PROT_READ|PROT_EXEC) ||
           p->actual!=PROT_READ || p->admitted || p->address>UINTPTR_MAX-PAGE)return 0;
        if(p->address<*first)*first=p->address;
        if(p->address+PAGE>*end)*end=p->address+PAGE;
    }
    return *first<*end;
}
int li2_lifecycle_oneshot_landing_query(const struct li2_fetch_ref *ref,struct li2_oneshot_site *out) {
    if(!out || !os_private((uintptr_t)out,sizeof(*out)) ||
       li2_lifecycle_oneshot_interlock())return LI2_ONESHOT_ARGUMENT;
    *out=(struct li2_oneshot_site){0};
    struct li2_fetch_view v={0};int e=li2_lifecycle_fetch_view(ref,&v);if(e)return e;
    if(!v.bytes || !v.pages || !v.backing || !v.identity_observed ||
       v.pid<=0 || v.pid!=v.tid || v.pc>UINTPTR_MAX-5)return LI2_ONESHOT_BIND;
    if(v.length<5)return LI2_ONESHOT_REFUSED_UNTOUCHED;
    size_t pages=(v.pc&~(PAGE-1))==((v.pc+4)&~(PAGE-1))?1:2;
    if(v.page_count<pages)return LI2_ONESHOT_BIND;
    unsigned object=v.pages[0].object;uint64_t allocation=v.pages[0].allocation;
    if(object>=object_count || !allocation)return LI2_ONESHOT_REFUSED_UNTOUCHED;
    for(size_t i=0;i<pages;i++) {
        if(v.pages[i].backing!=SEALED || v.pages[i].object!=object ||
           v.pages[i].allocation!=allocation)return LI2_ONESHOT_REFUSED_UNTOUCHED;
        e=li2_lifecycle_fetch_validate(ref,i,PROT_READ);if(e)return e;
    }
    uintptr_t first,end;
    if(!os_range(object,allocation,&first,&end))return LI2_ONESHOT_BIND;
    const struct os_landing *l=&os_landings[object];
    out->object_id=(uint64_t)object+1;out->allocation=allocation;
    out->first=first;out->end=end;out->pc=v.pc;
    if(l->complete) {
        out->landing=l->pc;
        out->bound=l->object==object && l->source_allocation==allocation &&
            l->source_first==first && l->source_end==end;
    } else if(l->attempted)return LI2_ONESHOT_REENTRY;
    return 0;
}
int li2_lifecycle_oneshot_register_object_landing(const struct li2_oneshot_site *site,uintptr_t pc) {
    if(!site || !os_private((uintptr_t)site,sizeof(*site)) || !site->object_id ||
       site->object_id>object_count || site->reserved || !site->allocation ||
       !active || tx.guard || li2_lifecycle_fetch_interlock() ||
       li2_lifecycle_oneshot_interlock() || pc<LI2_ONESHOT_MIN_EXEC || pc>UINTPTR_MAX-2 ||
       (pc&(PAGE-1))>PAGE-2 || (pc&~(PAGE-1))>UINTPTR_MAX-PAGE ||
       native_counts.admissions!=native_counts.closed || native_close.busy || native_close.first_error)
        return LI2_ONESHOT_ARGUMENT;
    if(!os_private((uintptr_t)os_slots,sizeof(os_slots)) ||
       !os_private((uintptr_t)os_landings,sizeof(os_landings)) ||
       !os_private((uintptr_t)&os_last_complete,sizeof(os_last_complete)) ||
       !os_private((uintptr_t)&os_last_refused,sizeof(os_last_refused)))return LI2_ONESHOT_BIND;
    unsigned object=(unsigned)(site->object_id-1);uintptr_t first,end;
    if(!os_range(object,site->allocation,&first,&end) || first!=site->first || end!=site->end ||
       site->pc<first || site->pc>end-5)return LI2_ONESHOT_BIND;
    const struct owned_page *source=current(site->pc&~(PAGE-1));
    if(!source || source->object!=object || source->allocation!=site->allocation)
        return LI2_ONESHOT_BIND;
    struct os_landing *l=&os_landings[object];
    if(l->attempted && (!l->complete || l->pc!=pc || l->object!=object))
        return LI2_ONESHOT_REFUSED_UNTOUCHED;
    if(!l->attempted && os_landing_serial==UINT64_MAX)return LI2_ONESHOT_REUSE;
    li2_maps_phase_end();
    struct check_error error={0};struct li2_fetch_map_progress maps={0};
    if(read_maps_checked(&error,&maps))return (int)error.code;
    for(size_t i=0;i<used;i++) {
        const struct owned_page *p=&records[i];
        if(p->live && p->object==object && p->allocation==site->allocation && (p->logical&PROT_EXEC))
            if(verify_page_checked(p,mapping(p->address),&error))return (int)error.code;
    }
    struct os_landing candidate={.attempted=1,.complete=1,.object=object,
        .pc=pc,.page=pc&~(PAGE-1),.allocation=l->complete?l->allocation:os_landing_serial+1,
        .generation=1,.pid=RAW(SYS_getpid,0,0,0,0,0,0),.tid=RAW(SYS_gettid,0,0,0,0,0,0),
        .maps=maps,.source_allocation=site->allocation,.source_first=first,.source_end=end};
    if(candidate.pid<=0 || candidate.pid!=candidate.tid ||
       (l->complete && (l->pid!=candidate.pid || l->tid!=candidate.tid)))return LI2_ONESHOT_IDENTITY;
    if(os_landing_check(&candidate,&error))return (int)error.code;
    /* A new landing gets a never-reused identity. Rebinding keeps that exact
       protected mapping/identity; the old mapping is never freed or relabelled. */
    unsigned fresh=!l->attempted;
    l->attempted=1;atomic_signal_fence(memory_order_seq_cst);l->complete=0;
    *l=candidate;if(fresh)++os_landing_serial;
    atomic_signal_fence(memory_order_seq_cst);l->complete=1;return 0;
}
int li2_lifecycle_oneshot_prepare(const struct li2_fetch_ref *ref,unsigned kind,
                                 struct li2_oneshot_plan *out,struct li2_oneshot_lifecycle **context) {
    if(!ref || !out || !context ||
       (kind!=LI2_ONESHOT_SYSCALL && kind!=LI2_ONESHOT_RDTSC && kind!=3))return LI2_ONESHOT_ARGUMENT;
    *context=0;
    if(!active || tx.guard || li2_lifecycle_oneshot_interlock() ||
       os_reuse.prepared==UINT64_MAX || os_reuse.completed>os_reuse.prepared ||
       os_reuse.prepared-os_reuse.completed!=os_reuse.refused ||
       ref->sequence<=os_reuse.last_fetch_sequence)
        return LI2_ONESHOT_REENTRY;
    struct li2_oneshot_site site={0};int error=li2_lifecycle_oneshot_landing_query(ref,&site);
    if(error)return error;
    if(!site.bound)return LI2_ONESHOT_REFUSED_UNTOUCHED;
    struct li2_fetch_view v={0};error=li2_lifecycle_fetch_view(ref,&v);if(error)return error;
    unsigned object=(unsigned)(site.object_id-1),pages=((v.pc&~(PAGE-1))==((v.pc+4)&~(PAGE-1)))?1:2;
    const struct os_landing *l=&os_landings[object];
    struct li2_oneshot_plan request={.abi_version=LI2_ONESHOT_ABI,.kind=kind,
        .sequence=os_reuse.prepared+1,.pc=v.pc,.next_pc=v.pc+2,.landing=l->pc,
        .landing_allocation=l->allocation,.landing_generation=l->generation,.page_count=pages};
    for(unsigned i=0;i<pages;i++) {
        const struct li2_fetch_page *p=&v.pages[i];const struct object *o=&objects[object];
        /* The reconstructed main carrier header is still explicitly outside
           this byte-identical source publication contract. */
        if(o->initial_kind==IMAGE_MAIN && !p->offset)return LI2_ONESHOT_REFUSED_UNTOUCHED;
        if(p->backing!=SEALED || p->object!=object || p->allocation!=site.allocation ||
           o->stat.st_size<=0 || p->offset>(uint64_t)o->stat.st_size ||
           PAGE>(uint64_t)o->stat.st_size-p->offset)return LI2_ONESHOT_REFUSED_UNTOUCHED;
        request.pages[i]=(struct li2_oneshot_page){p->address,p->allocation,p->generation,p->offset};
    }
    for(unsigned i=0;i<5;i++)request.original[i]=v.bytes[i];
    struct li2_oneshot_plan checked;
    error=li2_admission_oneshot_plan(&request,&checked);
    if(error)return error==LI2_ONESHOT_GEOMETRY?LI2_ONESHOT_REFUSED_UNTOUCHED:error;
    struct li2_oneshot_lifecycle *s=&os_slots[0];
    s->borrow=*ref;s->checked=checked;s->landing_index=object;s->page_count=pages;
    s->progress.sequence=checked.sequence;s->progress.pid=v.pid;s->progress.tid=v.tid;
    s->progress.allocation_epoch=allocation_id;s->progress.generation_epoch=generation;
    s->progress.records_epoch=used;s->progress.transactions_epoch=counts.transactions;s->progress.phase_epoch=tx.phase;
    for(unsigned i=0;i<pages;i++) {
        const struct owned_page *p=current(checked.pages[i].address);
        if(!p || !p->live || p->generation!=checked.pages[i].generation ||
           p->allocation!=checked.pages[i].allocation || p->offset!=checked.pages[i].offset ||
           p->object!=object)return os_error(s,LI2_ONESHOT_BIND,70+i);
        s->original[i]=*p;s->current_generation[i]=p->generation;s->current_protection[i]=p->actual;
    }
    *out=request;*context=s;os_used=1;
    os_reuse.last_fetch_sequence=ref->sequence;++os_reuse.prepared;
    atomic_signal_fence(memory_order_seq_cst);s->progress.prepared=1;return 0;
}
static int os_call_complete(const struct li2_oneshot_call *p) {
    return p->started==1 && p->returned==1 && p->verified==1 && !p->result && !p->reserved;
}
static int os_zero(const void *v,size_t bytes) {
    const unsigned char *p=v;for(size_t i=0;i<bytes;i++)if(p[i])return 0;return 1;
}
static int os_retirement_domain(struct li2_oneshot_lifecycle *s,const struct li2_oneshot_owner *o) {
    return s==&os_slots[0] && s->progress.prepared==1 && !s->progress.first_error &&
        !oneshot_held && !fetch.progress.held && !tx.guard &&
        !native_close.busy && !native_close.first_error && native_counts.admissions==native_counts.closed &&
        os_private((uintptr_t)o,sizeof(*o)) && o->initialized==1 && !o->in_handler &&
        !o->state.first_error && o->hooks.context==s &&
        o->hooks.transfer==li2_lifecycle_oneshot_transfer &&
        o->hooks.advance_generation==li2_lifecycle_oneshot_advance &&
        o->hooks.observe==li2_lifecycle_oneshot_observe &&
        o->hooks.release==li2_lifecycle_oneshot_release &&
        equal(&o->plan,&s->checked,sizeof(o->plan)) &&
        !(os_reuse.reset_started && !os_reuse.reset_complete) &&
        os_reuse.prepared>os_reuse.completed &&
        os_reuse.prepared-os_reuse.completed-1==os_reuse.refused;
}
static void os_clear_attempt(struct li2_oneshot_lifecycle *s,int completed) {
    /* Root keeps its active/pending gate until this call returns, and copies
       the full C owner before clearing it. An interrupted reset is terminal.
       No query, callback, fallible operation or permission change follows. */
    os_reuse.reset_started=1;os_reuse.reset_complete=0;atomic_signal_fence(memory_order_seq_cst);
    if(completed) {
        os_last_complete=*s;++os_reuse.completed;
        os_reuse.last_completed_sequence=s->checked.sequence;
    } else {os_last_refused=*s;++os_reuse.refused;}
    unsigned char *bytes=(void *)s;for(size_t i=0;i<sizeof(*s);i++)bytes[i]=0;
    atomic_signal_fence(memory_order_seq_cst);os_reuse.reset_complete=1;
}
int li2_lifecycle_oneshot_retire(void *context,const struct li2_oneshot_owner *o,
                                const struct li2_effect_owner *effect) {
    struct li2_oneshot_lifecycle *s=os_context(context);
    if(!s || !o || !effect)return LI2_ONESHOT_ARGUMENT;
    if(!os_retirement_domain(s,o) || !os_private((uintptr_t)effect,sizeof(*effect)) ||
       o->state.phase!=LI2_ONESHOT_COMPLETED || o->state.sequence!=s->checked.sequence ||
       o->state.mutation_started!=1 || o->state.published!=1 || o->state.restored!=1 ||
       o->transferred!=1 || o->write_attempted_mask!=31 || o->write_completed_mask!=31 ||
       o->restore_attempted_mask!=31 || o->restore_completed_mask!=31 ||
       !os_call_complete(&o->release.call) || o->release.transaction_live ||
       !os_call_complete(&o->transfer.old_release) || !os_call_complete(&o->transfer.acquire) ||
       s->progress.held || s->progress.released!=1 || s->progress.observations!=7 ||
       s->progress.generation_steps!=2 || s->progress.maps_started!=s->progress.maps_returned ||
       effect->phase!=LI2_EFFECT_COMMITTED || effect->committed!=1 || effect->first_error ||
       !effect->input.sequence || effect->input.before.pc!=s->checked.pc ||
       effect->input.decoded.pc!=s->checked.pc || effect->input.decoded.next_pc!=s->checked.next_pc ||
       effect->input.decoded.length!=2 || effect->input.decoded.available<2 ||
       !equal(effect->input.decoded.bytes,s->checked.original,2) ||
       ((uint64_t)o->before.greg[REG_EFL]!=(effect->input.before.logical_flags|LI2_STEP_RF)) ||
       !fetch.progress.complete || fetch.progress.first_error || fetch.pc!=s->checked.pc ||
       fetch.progress.sequence<=s->borrow.sequence || os_reuse.completed==UINT64_MAX)
        return os_error(s,LI2_ONESHOT_REUSE,80);
    unsigned wanted=s->checked.kind==LI2_ONESHOT_SYSCALL?LI2_SYSCALL:
        s->checked.kind==LI2_ONESHOT_RDTSC?LI2_RDTSC:LI2_CPUID;
    if(effect->input.decoded.kind!=wanted || effect->input.source_count!=fetch.page_count)
        return os_error(s,LI2_ONESHOT_REUSE,81);
    /* These are the actual post-restoration/pre-effect borrow facts. Compare
       their immutable identities, not a stale pre-effect global epoch after
       an authorized mapping/rseq syscall has completed. */
    for(size_t i=0;i<fetch.page_count;i++) {
        const struct li2_fetch_page *p=&fetch.pages[i];
        const struct li2_effect_source *q=&effect->input.source[i];
        if(q->page!=p->address || q->allocation!=p->allocation || q->generation!=p->generation ||
           q->offset!=p->offset || q->backing!=p->backing || q->reserved ||
           q->object_id!=(p->backing==SEALED?(uint64_t)p->object+1:0))
            return os_error(s,LI2_ONESHOT_REUSE,82+i);
        for(unsigned j=0;j<s->page_count;j++)if(p->address==s->original[j].address)
            if(p->allocation!=s->original[j].allocation || p->generation!=s->current_generation[j] ||
               p->offset!=s->original[j].offset || p->object!=s->original[j].object)
                return os_error(s,LI2_ONESHOT_REUSE,84+j);
    }
    li2_page_custody_discard(LI2_CUSTODY_EFFECT);li2_maps_phase_end();
    if(li2_page_custody_snapshot()->phase!=LI2_CUSTODY_EMPTY)
        return os_error(s,LI2_ONESHOT_REUSE,86);
    int e=li2_rseq_publication_retire(o);if(e)return os_error(s,LI2_ONESHOT_REUSE,e);
    os_clear_attempt(s,1);return 0;
}
int li2_lifecycle_oneshot_cancel(void *context,const struct li2_oneshot_owner *o,int refusal) {
    struct li2_oneshot_lifecycle *s=os_context(context);
    if(!s || !o)return LI2_ONESHOT_ARGUMENT;
    const struct li2_oneshot_transfer *t=&o->transfer;
    if(!os_retirement_domain(s,o) || !os_zero(&o->state,sizeof(o->state)) ||
       o->transferred || o->source_copied || o->landing_observed || o->source_write_started ||
       o->write_attempted_mask || o->write_completed_mask || o->restore_started ||
       o->restore_attempted_mask || o->restore_completed_mask || o->operations || o->observations ||
       !os_zero(o->generation,sizeof(o->generation)) || !os_zero(&o->release,sizeof(o->release)) ||
       !os_zero(&t->acquire,sizeof(t->acquire)) || t->transaction_live || t->old_authenticated!=1 ||
       t->call.started!=1 || t->call.returned!=1 || t->call.verified!=1 || t->call.reserved ||
       s->progress.held || s->progress.released || s->progress.observations || s->progress.generation_steps ||
       !fetch.progress.complete || fetch.progress.first_error || fetch.progress.sequence!=s->borrow.sequence ||
       fetch.pc!=s->checked.pc || fetch.requested<5 || !equal(fetch.bytes,s->checked.original,5) ||
       os_reuse.refused==UINT64_MAX)return os_error(s,LI2_ONESHOT_REUSE,90);
    if(refusal==LI2_ONESHOT_REFUSED_UNTOUCHED) {
        if(t->call.result!=LI2_ONESHOT_TRANSFER_UNTOUCHED || t->old_borrow_live!=1 ||
           !os_zero(&t->old_release,sizeof(t->old_release)))return os_error(s,LI2_ONESHOT_REUSE,91);
    } else if(refusal==LI2_ONESHOT_REFUSED_RELEASED) {
        if(t->call.result!=LI2_ONESHOT_TRANSFER_RELEASED || t->old_borrow_live ||
           !os_call_complete(&t->old_release) ||
           !equal(&s->released_fetch,&fetch.progress,sizeof(fetch.progress)))
            return os_error(s,LI2_ONESHOT_REUSE,92);
    } else return os_error(s,LI2_ONESHOT_REUSE,93);
    /* Actual caller release revalidated this exact still-original fetch.
       The retained transfer's old_borrow_live bit describes its earlier
       refusal boundary and is intentionally not rewritten as current. */
    if(os_identity(s,0))return (int)s->progress.first_error;
    li2_page_custody_discard(LI2_CUSTODY_EFFECT);li2_maps_phase_end();
    if(li2_page_custody_snapshot()->phase!=LI2_CUSTODY_EMPTY)
        return os_error(s,LI2_ONESHOT_REUSE,94);
    int e=li2_rseq_publication_cancel_bound(s->checked.sequence,s->checked.pc);
    if(e)return os_error(s,LI2_ONESHOT_REUSE,e);
    os_clear_attempt(s,0);return 0;
}
