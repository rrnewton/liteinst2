/* Reusable exact-entry publication. The source is restored before any selected
   effect; dormant return PCs and source reads retain their original meaning. */
#include "oneshot_reusable.h"
#if LI2_ONESHOT_REUSABLE != 1 || LI2_EFFECT_PROVIDER != 1
#error "reusable publication requires the linked selected-effect owner"
#endif
static int selected_oneshot_frame_range(void *unused,const void *p,size_t n) {
    (void)unused;uintptr_t a=(uintptr_t)p,first=(uintptr_t)fork_gate_stack.ss_sp;
    return !p || !n || first>UINTPTR_MAX-fork_gate_stack.ss_size ||
        a<first || a>first+fork_gate_stack.ss_size || n>first+fork_gate_stack.ss_size-a;
}
static void selected_oneshot_clear_route(void) {
    selected_step_pending=0;selected_pending_route=SELECTED_NO_STEP;
}
static _Noreturn void selected_oneshot_abort(unsigned code,long detail) {
    if(!selected_oneshot_failing) {
        selected_oneshot_failing=1;li2_maps_phase_fail();
        struct li2_oneshot_owner *o=selected_oneshot_active;
        if(o && o->state.phase!=LI2_ONESHOT_RESTORED && o->state.phase!=LI2_ONESHOT_COMPLETED) {
            li2_admission_oneshot_fail(&o->state,code,detail);
            li2_oneshot_abort_close(o);
        }
        li2_lifecycle_abort();report(125,code,detail);
    }
    (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static void selected_oneshot_count(uint64_t *count) {
    checked(*count!=UINT64_MAX,1710,0);++*count;
}
static unsigned selected_oneshot_kind(void) {
    if(selected_decoded.length!=2 || selected_decoded.bytes[0]!=0x0f)return 0;
    if(selected_decoded.kind==LI2_SYSCALL && selected_decoded.bytes[1]==0x05)return LI2_ONESHOT_SYSCALL;
    if(selected_decoded.kind==LI2_RDTSC && selected_decoded.bytes[1]==0x31)return LI2_ONESHOT_RDTSC;
    if(selected_decoded.kind==LI2_CPUID && selected_decoded.bytes[1]==0xa2)return LI2_ONESHOT_CPUID;
    return 0;
}
static void selected_oneshot_same_original(const struct li2_decoded *original,unsigned kind) {
    checked(selected_oneshot_kind()==kind && selected_decoded.pc==original->pc &&
        selected_decoded.next_pc==original->next_pc && selected_decoded.code==original->code &&
        selected_decoded.kind==original->kind && selected_decoded.length==original->length &&
        selected_decoded.destination==original->destination &&
        selected_decoded.width_bits==original->width_bits &&
        selected_decoded.step_disposition==original->step_disposition &&
        equal(selected_decoded.bytes,original->bytes,original->length),1711,0);
}
static void selected_oneshot_reprepare(const struct li2_decoded *original,unsigned kind) {
    selected_prepare(original->pc);selected_oneshot_same_original(original,kind);
    /* The redirect borrows five original bytes even though the effect is two.
       Only a genuine known-code extent can extend this source borrow. */
    if(selected_view.length<5 && li2_lifecycle_known_code(original->pc,5)) {
        selected_release();
        checked(!li2_lifecycle_fetch_prepare(original->pc,5,&selected_borrow),1712,0);
        checked(!li2_lifecycle_fetch_view(&selected_borrow,&selected_view),1712,1);
        checked(!li2_decoder_decode(original->pc,selected_view.bytes,selected_view.length,&selected_decoded),1712,2);
        selected_oneshot_same_original(original,kind);
    }
}
/* Lazy landing work occurs only after authenticated old-fetch release and
   closure of every native source epoch. Protected landing mappings never move. */
static uintptr_t selected_oneshot_stage_near(uintptr_t pc) {
    uintptr_t base=pc&~(PAGE-1),landing=0;
    if(base<LI2_ONESHOT_MIN_EXEC || base>UINTPTR_MAX-PAGE)return 0;
    for(unsigned i=1;i<=16 && !landing;i++) {
        uint64_t distance=(uint64_t)((i+1)/2)*UINT64_C(0x4000000);
        uintptr_t wanted=0;
        if(i&1) {if(base<=UINTPTR_MAX-distance-PAGE)wanted=base+distance;}
        else if(base>=LI2_ONESHOT_MIN_EXEC+distance)wanted=base-distance;
        if(wanted<LI2_ONESHOT_MIN_EXEC || wanted>UINTPTR_MAX-PAGE)continue;
        long result=raw(SYS_mmap,wanted,PAGE,PROT_READ|PROT_WRITE,
            MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
        if(result<0)continue;
        if((uintptr_t)result!=wanted) {
            checked(!raw(SYS_munmap,result,PAGE,0,0,0,0),1713,result);continue;
        }
        landing=wanted;
    }
    if(!landing)return 0;
    protect(landing,PAGE);
    volatile unsigned char *bytes=(void *)landing;
    for(size_t i=0;i<PAGE;i++)bytes[i]=0xcc;
    bytes[0]=0x0f;bytes[1]=0x0b;
    checked(!raw(SYS_mprotect,landing,PAGE,PROT_READ|PROT_EXEC,0,0,0),1714,0);
    checked(!raw(SYS_membarrier,32,0,0,0,0,0),1714,1);
    return landing;
}
static void selected_oneshot_reset_current(unsigned completed) {
    /* The backend already proved complete retirement or exact untouched
       cancellation. During the copy/reset a nested reserved event is terminal. */
    checked(selected_oneshot_resetting && selected_oneshot_active==&selected_oneshot_current &&
        !li2_lifecycle_fetch_interlock() && !li2_lifecycle_oneshot_interlock(),1715,0);
    if(completed)copy(&selected_oneshot_last,&selected_oneshot_current,sizeof(selected_oneshot_last));
    else copy(&selected_oneshot_last_refused,&selected_oneshot_current,sizeof(selected_oneshot_last_refused));
    selected_oneshot_current=(struct li2_oneshot_owner){0};
    selected_oneshot_current_effect_started=selected_oneshot_current_effect_returned=0;
    selected_oneshot_active=0;selected_oneshot_clear_route();
    __asm__ volatile("":::"memory");selected_oneshot_resetting=0;
}
static int selected_oneshot_try(int sig,siginfo_t *si,ucontext_t *uc) {
    unsigned kind=selected_oneshot_kind();
    if(!kind || (uintptr_t)si->si_addr!=selected_decoded.pc)return 0;
    checked(!selected_oneshot_active && !selected_oneshot_resetting &&
        selected_oneshot_current.state.phase==LI2_ONESHOT_EMPTY &&
        !selected_step_pending && selected_pending_route==SELECTED_NO_STEP &&
        !li2_lifecycle_oneshot_interlock() &&
        li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,1716,0);
    checked(!selected_oneshot_frame_range(0,si,sizeof(*si)) &&
        !selected_oneshot_frame_range(0,uc,sizeof(*uc)),1716,1);
    const struct li2_decoded original=selected_decoded;
    if(selected_view.length<5) {
        if(!li2_lifecycle_known_code(original.pc,5))return 0;
        selected_release();selected_oneshot_reprepare(&original,kind);
    }
    struct li2_oneshot_site site={0};
    int e=li2_lifecycle_oneshot_landing_query(&selected_borrow,&site);
    if(e==LI2_ONESHOT_REFUSED_UNTOUCHED)return 0;
    checked(!e && site.object_id && site.allocation && site.pc==original.pc,1717,e);
    selected_pending_route=SELECTED_ONESHOT;selected_step_pending=1;
    selected_release();li2_maps_phase_end();li2_lifecycle_native_close();
    if(!site.bound) {
        uintptr_t landing=site.landing?site.landing:selected_oneshot_stage_near(original.pc);
        if(!landing) {
            selected_oneshot_clear_route();selected_oneshot_reprepare(&original,kind);return 0;
        }
        e=li2_lifecycle_oneshot_register_object_landing(&site,landing);checked(!e,1718,e);
    }
    e=li2_rseq_publication_prepare(original.pc);checked(!e,1719,e);
    selected_oneshot_reprepare(&original,kind);
    struct li2_oneshot_lifecycle *backend=0;
    e=li2_lifecycle_oneshot_prepare(&selected_borrow,kind,&selected_oneshot_request,&backend);
    if(e==LI2_ONESHOT_REFUSED_UNTOUCHED) {
        checked(!backend && li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,1720,e);
        selected_release();
        e=li2_rseq_publication_cancel_unbound(original.pc);checked(!e,1720,e);
        selected_oneshot_clear_route();selected_oneshot_reprepare(&original,kind);return 0;
    }
    checked(!e && backend,1721,e);
    e=li2_rseq_publication_bind(&selected_oneshot_request);checked(!e,1721,e);
    struct li2_oneshot_owner *o=&selected_oneshot_current;
    selected_oneshot_active=o;selected_oneshot_count(&selected_oneshot_counts.attempted);
    const struct li2_oneshot_hooks hooks={backend,raw,selected_oneshot_frame_range,
        li2_lifecycle_oneshot_transfer,li2_lifecycle_oneshot_advance,
        li2_lifecycle_oneshot_observe,li2_lifecycle_oneshot_release};
    e=li2_oneshot_initialize(o,&selected_session,&hooks);checked(!e,1722,e);
    e=li2_oneshot_nx(o,&selected_oneshot_request,sig,si,uc);
    if(e==LI2_ONESHOT_REFUSED_UNTOUCHED || e==LI2_ONESHOT_REFUSED_RELEASED) {
        int refusal=e;
        checked(!o->transferred && !o->state.mutation_started && !o->state.published,1723,e);
        if(e==LI2_ONESHOT_REFUSED_UNTOUCHED) {
            checked(li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,1723,1);
            selected_release();
        } else checked(!li2_lifecycle_fetch_interlock(),1723,2);
        selected_oneshot_resetting=1;__asm__ volatile("":::"memory");
        e=li2_lifecycle_oneshot_cancel(backend,o,refusal);checked(!e,1724,e);
        selected_oneshot_count(&selected_oneshot_counts.refused);
        selected_oneshot_reset_current(0);selected_oneshot_reprepare(&original,kind);return 0;
    }
    checked(!e && o->state.phase==LI2_ONESHOT_PUBLISHED &&
        o->state.published && !o->state.first_error && !o->in_handler &&
        o->write_attempted_mask==31 && o->write_completed_mask==31 &&
        (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==original.pc,1725,e);
    e=li2_rseq_publication_publish(o);checked(!e,1725,e);
    selected_oneshot_count(&selected_oneshot_counts.published);
    selected_oneshot_count(kind==LI2_ONESHOT_CPUID?&selected_oneshot_counts.cpuid:
        kind==LI2_ONESHOT_RDTSC?&selected_oneshot_counts.rdtsc:&selected_oneshot_counts.syscall);
    return 1;
}
static void selected_oneshot_landed(int sig,siginfo_t *si,ucontext_t *uc) {
    struct li2_oneshot_owner *o=selected_oneshot_active;
    checked(o==&selected_oneshot_current && !selected_oneshot_resetting &&
        selected_step_pending && selected_pending_route==SELECTED_ONESHOT &&
        !selected_oneshot_frame_range(0,si,sizeof(*si)) &&
        !selected_oneshot_frame_range(0,uc,sizeof(*uc)),1726,0);
    int e=li2_rseq_publication_landed(o,sig,si,uc);checked(!e,1726,e);
    e=li2_oneshot_ud(o,sig,si,uc,&selected_oneshot_handoff);
    checked(!e && o->state.phase==LI2_ONESHOT_RESTORED && o->state.restored &&
        !o->state.first_error && !o->in_handler && o->restore_attempted_mask==31 &&
        o->restore_completed_mask==31 && !li2_lifecycle_fetch_interlock(),1727,e);
    e=li2_rseq_publication_restored(o);checked(!e,1727,e);
    selected_oneshot_count(&selected_oneshot_counts.restored);
    const struct li2_oneshot_handoff *h=&selected_oneshot_handoff;
    checked(h->actual_landing_frame==uc && h->sequence==o->plan.sequence &&
        h->kind==o->plan.kind && !h->reserved && h->original_pc==o->plan.pc &&
        h->original_next_pc==o->plan.next_pc && selected_flags_known &&
        h->logical_flags==selected_logical_flags,1728,0);
    selected_prepare(h->original_pc);
    checked(selected_oneshot_kind()==h->kind && selected_decoded.pc==h->original_pc &&
        selected_decoded.next_pc==h->original_next_pc && equal(selected_decoded.bytes,o->plan.original,2),1728,1);
    selected_oneshot_clear_route();
    checked(!selected_oneshot_current_effect_started && !selected_oneshot_current_effect_returned,1729,0);
    selected_oneshot_current_effect_started=1;selected_oneshot_count(&selected_oneshot_counts.effect_started);
    if(h->kind==LI2_ONESHOT_SYSCALL)selected_owned_syscall(uc,h->logical_flags);
    else {
        checked(selected_effect_complete(0,uc,h->logical_flags),1729,1);
        selected_release();selected_effect_finish();
    }
    selected_oneshot_current_effect_returned=1;selected_oneshot_count(&selected_oneshot_counts.effect_returned);
    checked((uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==h->original_next_pc &&
        !li2_lifecycle_fetch_interlock() && !selected_step_pending &&
        selected_effect_runtime.finished && selected_effect_runtime.owner.phase==LI2_EFFECT_COMMITTED,1730,0);
    e=li2_admission_oneshot_transition(&o->state,LI2_ONESHOT_RESTORED,LI2_ONESHOT_COMPLETED);
    checked(!e,1730,e);selected_oneshot_count(&selected_oneshot_counts.completed);
    selected_oneshot_resetting=1;__asm__ volatile("":::"memory");
    e=li2_lifecycle_oneshot_retire(o->hooks.context,o,&selected_effect_runtime.owner);checked(!e,1731,e);
    selected_oneshot_count(&selected_oneshot_counts.retired);selected_oneshot_reset_current(1);
}
static void selected_oneshot_stage(void) {
    /* Static singleton storage only; actual object landings are staged lazily. */
    volatile unsigned char *p=(void *)&selected_oneshot_current;
    for(size_t i=0;i<sizeof(selected_oneshot_current);i++)p[i]=0;
    p=(void *)&selected_oneshot_last;
    for(size_t i=0;i<sizeof(selected_oneshot_last);i++)p[i]=0;
    p=(void *)&selected_oneshot_last_refused;
    for(size_t i=0;i<sizeof(selected_oneshot_last_refused);i++)p[i]=0;
}
static void selected_oneshot_report(unsigned status,unsigned code,long detail) {
    struct writer w={.used=0};const struct selected_oneshot_counts *c=&selected_oneshot_counts;
    text(&w,"LI2_ONESHOT {\"version\":2,\"scope\":\"singleton_reusable_sealed_temporary_e9\"");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",detail<0?0ULL-(uint64_t)detail:(uint64_t)detail);
    field(&w,",\"detail_negative\":",detail<0);field(&w,",\"attempted\":",c->attempted);
    field(&w,",\"published\":",c->published);field(&w,",\"restored\":",c->restored);
    field(&w,",\"completed\":",c->completed);field(&w,",\"retired\":",c->retired);
    field(&w,",\"refused\":",c->refused);field(&w,",\"cpuid_patches\":",c->cpuid);
    field(&w,",\"syscall_patches\":",c->syscall);field(&w,",\"rdtsc_patches\":",c->rdtsc);
    field(&w,",\"effect_started\":",c->effect_started);field(&w,",\"effect_returned\":",c->effect_returned);
    field(&w,",\"active_phase\":",selected_oneshot_active?selected_oneshot_active->state.phase:0);
    field(&w,",\"resetting\":",selected_oneshot_resetting);
    field(&w,",\"last_completed_sequence\":",selected_oneshot_last.plan.sequence);
    field(&w,",\"last_refused_sequence\":",selected_oneshot_last_refused.plan.sequence);
    const struct li2_oneshot_reuse_stats *b=li2_lifecycle_oneshot_reuse_snapshot();
    field(&w,",\"backend_prepared\":",b->prepared);field(&w,",\"backend_completed\":",b->completed);
    const struct li2_rseq_publication_state *r=li2_rseq_publication_snapshot();
    field(&w,",\"rseq_phase\":",r->phase);field(&w,",\"rseq_error\":",r->first_error);
    field(&w,",\"rseq_attempts\":",r->attempts);field(&w,",\"rseq_retired\":",r->retired);
    struct li2_lifecycle_counts lc;li2_lifecycle_snapshot(&lc);
    field(&w,",\"retained_records\":",lc.retained_records);field(&w,",\"generations\":",lc.generations);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
