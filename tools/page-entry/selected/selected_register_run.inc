/* Separate opt-in controller. The reference all-NX build does not include this
   file. Only a genuine published register run changes the application's RIP. */
static int selected_run_protect_add(void *unused,uintptr_t first,size_t bytes) {
    (void)unused;
    if(!bytes || first>UINTPTR_MAX-bytes || protected_count>=RANGES)
        return LI2_CACHE_PROTECTION;
    protected[protected_count++]=(struct li2_fork_range){first,first+bytes};
    return 0;
}
static int selected_run_protect_contains(void *unused,uintptr_t first,size_t bytes) {
    (void)unused;
    if(!bytes || first>UINTPTR_MAX-bytes)return 0;
    for(size_t i=0;i<protected_count;i++)
        if(protected[i].first<=first && first+bytes<=protected[i].end)return 1;
    return 0;
}
static const struct li2_run_protection selected_run_protection={
    0,selected_run_protect_add,selected_run_protect_contains
};
#ifdef LI2_RUN_TIMING
#include "selected_run_timing.inc"
#endif
static void selected_run_initialize(void) {
    checked(!selected_run_protect_add(0,(uintptr_t)&selected_run_owner,sizeof selected_run_owner),760,0);
    checked(!selected_run_protect_add(0,(uintptr_t)&selected_run_history,sizeof selected_run_history),760,1);
    int error=li2_run_cache_initialize(&selected_session,&selected_run_protection,&selected_run_cache);
    checked(!error,761,error);
#ifdef LI2_RUN_TIMING
    selected_run_time_initialize();
#endif
}
static void selected_run_failure(void *unused,const struct li2_run_owner *owner) {
    (void)unused;report(125,owner->first_error,owner->first_detail);
}
static _Noreturn void selected_run_abort(unsigned code,long detail) {
#ifdef LI2_RUN_TIMING
    li2_run_timing_fail(&selected_run_timing,code,detail);
#endif
#ifdef LI2_MAPS_PHASE_REUSE
    li2_maps_phase_fail();
#endif

    if(selected_run_failing) {
        /* A secondary event during cleanup must never restart that cleanup. */
        (void)li2_run_cache_interrupt(selected_run_cache,code,detail);
        (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    selected_run_failing=1;
    (void)li2_run_cache_interrupt(selected_run_cache,code,detail);
    if(selected_run_owner.phase!=LI2_RUN_EMPTY)
        li2_run_abort(&selected_run_owner,code,detail);
    report(125,code,detail);
    (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static _Noreturn void selected_run_unexpected(int sig,siginfo_t *si,ucontext_t *uc) {
#ifdef LI2_RUN_TIMING
    li2_run_timing_fail(&selected_run_timing,LI2_TIME_INTERRUPTED,sig);
#endif
#ifdef LI2_MAPS_PHASE_REUSE
    li2_maps_phase_fail();
#endif

    if(!selected_run_interrupted.event.observed) {
        struct li2_run_nested *n=&selected_run_interrupted;
        n->event.observed=1;n->event.number=sig;
        if(si){n->event.code=si->si_code;n->event.error=si->si_errno;n->event.address=(uintptr_t)si->si_addr;}
        if(uc) {
            copy(n->greg,uc->uc_mcontext.gregs,sizeof n->greg);
            copy(&n->mask,&uc->uc_sigmask,sizeof n->mask);n->frame_observed=1;
        }
    }
    if(selected_run_failing)selected_run_abort(LI2_RUN_REENTRY,sig);
    /* During publication the cache owns cleanup. After arm the run owner also
       retains the actual unexpected signal frame before terminal failure. */
    if(selected_run_owner.phase!=LI2_RUN_EMPTY) {
        selected_run_failing=1;
        (void)li2_run_cache_interrupt(selected_run_cache,LI2_RUN_EVENT,sig);
        li2_run_unexpected(&selected_run_owner,sig,si,uc);
    }
    selected_run_abort(LI2_RUN_EVENT,sig);
}
static int selected_run_try(int sig,siginfo_t *si,ucontext_t *uc,uint64_t flags) {
    checked(!selected_selftesting && !selected_step_pending &&
            selected_pending_route==SELECTED_NO_STEP &&
            selected_run_owner.phase==LI2_RUN_EMPTY &&
            li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,762,0);
    /* No speculative fetch: only the already-owned complete source window.
       A closed complete guard and at least two eligible instructions are needed. */
    int error=li2_run_plan_bytes(selected_view.pc,selected_view.bytes,selected_view.length,
                                &selected_run_plan);
    if(error==LI2_RUN_SLOW) {
        checked(selected_run_plan_misses!=UINT64_MAX,763,0);
        ++selected_run_plan_misses;
#if defined(LI2_EFFECT_PROVIDER) && defined(LI2_TF_HANDOFF) && defined(LI2_REGISTER_RUN)
        if(selected_run_trace_origin) {
            checked(selected_run_trace_plan_misses!=UINT64_MAX,LI2_CHAIN_OVERFLOW,21);
            ++selected_run_trace_plan_misses;
        }
#endif
        return 0;
    }
    checked(!error,764,error);
#ifdef LI2_RSEQ_INACTIVE
    int rseq_error=li2_rseq_check_run(&selected_run_plan,uc);
    checked(!rseq_error,(unsigned)rseq_error,li2_rseq_snapshot()->first_detail);
#endif
    selected_run_publication=0;
    selected_pending_route=SELECTED_REGISTER_RUN;selected_step_pending=1;
    __asm__ volatile("" ::: "memory");
#ifdef LI2_RUN_TIMING
    int time_error=li2_run_timing_begin(&selected_run_timing,&selected_run_plan,
                                      &selected_borrow,&selected_view);
    if(time_error)selected_run_abort((unsigned)time_error,selected_run_timing.first_detail);
#endif
    error=li2_run_cache_publish(selected_run_cache,&selected_borrow,&selected_run_plan,
                               &selected_run_publication);
#ifdef LI2_RUN_TIMING
    if(!error || error==LI2_RUN_SLOW) {
        time_error=li2_run_timing_published(&selected_run_timing,error,
            li2_run_cache_diagnostic(selected_run_cache),
            li2_run_publication_progress(selected_run_cache,selected_run_publication));
        if(time_error)selected_run_abort((unsigned)time_error,selected_run_timing.first_detail);
    } else li2_run_timing_fail(&selected_run_timing,(unsigned)error,0);
#endif
    if(error==LI2_RUN_SLOW) {
        /* Only actual capacity exhaustion before a publication attempt grants
           this branch. No owner is armed/reset and the real borrow stays held. */
        const struct li2_run_cache_diagnostic *d=li2_run_cache_diagnostic(selected_run_cache);
        checked(d && d->phase==LI2_CACHE_READY && !d->first_error &&
                d->slots_used==LI2_RUN_CACHE_PAGES && d->complete_slots==LI2_RUN_CACHE_PAGES &&
                d->last_attempt.miss_before_publication && !selected_run_publication &&
                selected_run_owner.phase==LI2_RUN_EMPTY &&
                li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,765,0);
#if defined(LI2_EFFECT_PROVIDER) && defined(LI2_TF_HANDOFF) && defined(LI2_REGISTER_RUN)
        if(selected_run_trace_origin) {
            checked(selected_run_trace_full_misses!=UINT64_MAX,LI2_CHAIN_OVERFLOW,22);
            ++selected_run_trace_full_misses;
        }
#endif
        selected_step_pending=0;selected_pending_route=SELECTED_NO_STEP;return 0;
    }
    if(error)selected_run_abort((unsigned)error,0);
    const struct li2_run_publisher publisher={selected_run_cache,
        li2_run_publication_observe,selected_run_failure};
    error=li2_run_arm(&selected_run_owner,&selected_session,&selected_borrow,flags,
                     &publisher,selected_run_publication);
    if(error)selected_run_abort((unsigned)error,0);
    selected_initialized();
#if defined(LI2_EFFECT_PROVIDER) && defined(LI2_TF_HANDOFF) && defined(LI2_REGISTER_RUN)
    if(selected_run_trace_origin) {
        li2_run_begin_trace(&selected_run_owner,selected_run_trace_origin,sig,si,uc);
        return 1;
    }
#endif
    li2_run_begin(&selected_run_owner,sig,si,uc);return 1;
}
#if defined(LI2_EFFECT_PROVIDER) && defined(LI2_TF_HANDOFF) && defined(LI2_REGISTER_RUN)
static void selected_run_trace_try(int sig,siginfo_t *si,ucontext_t *uc,uint64_t flags) {
    checked(!selected_run_trace_busy && !selected_run_trace_active && !selected_run_trace_origin &&
        !selected_selftesting && !selected_step_pending &&
        selected_pending_route==SELECTED_NO_STEP && selected_run_owner.phase==LI2_RUN_EMPTY &&
        !li2_lifecycle_fetch_interlock(),LI2_CHAIN_STATE,20);
    selected_run_trace_busy=1;
    selected_run_trace_origin=li2_tf_chain_run_entry(&selected_chain);
    checked(selected_run_trace_origin && selected_run_trace_candidates!=UINT64_MAX,
            LI2_CHAIN_ORIGIN,22);
    ++selected_run_trace_candidates;
    const struct li2_chain_fetch *closed=&selected_chain.slots[selected_chain.active].fetch;
    struct li2_run_plan descriptive={0};
    int plan_result=li2_run_plan_bytes(closed->pc,closed->bytes,closed->length,&descriptive);
    if(plan_result==LI2_RUN_SLOW) {
        /* A copied, closed window is sufficient only to decline this attempt.
           No borrow, source opening or cached publication follows this branch. */
        int error=li2_tf_chain_run_skip(selected_run_trace_origin,sig,si,uc);
        if(error)selected_run_abort((unsigned)error,0);
        checked(selected_run_trace_preflight_misses!=UINT64_MAX,LI2_CHAIN_OVERFLOW,23);
        ++selected_run_trace_preflight_misses;
        selected_run_trace_origin=0;selected_run_trace_busy=0;return;
    }
    if(plan_result)selected_run_abort((unsigned)plan_result,0);
    checked(selected_run_trace_attempts!=UINT64_MAX,LI2_CHAIN_OVERFLOW,24);
    ++selected_run_trace_attempts;
    /* The chain's two real releases stay retained. This is the same fresh
       prepare that the next NX ingress used to perform, with no source opening. */
    selected_prepare((uintptr_t)uc->uc_mcontext.gregs[REG_RIP]);
#ifdef LI2_RSEQ_INACTIVE
    int rseq_error=li2_rseq_check_instruction(&selected_decoded,uc);
    checked(!rseq_error,(unsigned)rseq_error,li2_rseq_snapshot()->first_detail);
#endif
    if(selected_run_try(sig,si,uc,flags)) {
        checked(selected_run_trace_entries!=UINT64_MAX,LI2_CHAIN_OVERFLOW,20);
        ++selected_run_trace_entries;selected_run_trace_active=1;
    } else {
        /* Only exact planner/capacity SLOW can reach here. Authenticate and
           consume the proof even on this miss, then release the fresh borrow.
           Returning the unedited real frame naturally produces the old NX. */
        int error=li2_tf_chain_run_consume(selected_run_trace_origin,&selected_session,
            &selected_borrow,selected_decoded.pc,flags,sig,si,uc);
        if(error)selected_run_abort((unsigned)error,0);
        selected_release();
        error=li2_tf_chain_run_released(selected_run_trace_origin,&selected_borrow,sig,si,uc);
        if(error)selected_run_abort((unsigned)error,0);
    }
    selected_run_trace_origin=0;selected_run_trace_busy=0;
}
#endif

static void selected_run_exit(int sig,siginfo_t *si,ucontext_t *uc) {
    li2_run_exit(&selected_run_owner,sig,si,uc);
    int error=li2_run_complete_reset(&selected_run_owner,&selected_run_history,
                                    &selected_run_protection,uc);
    if(error)selected_run_abort((unsigned)error,0);
    checked(selected_run_history.reset_complete && !selected_run_history.first_error &&
            selected_run_owner.phase==LI2_RUN_EMPTY && !li2_lifecycle_fetch_interlock(),766,0);
#if defined(LI2_EFFECT_PROVIDER) && defined(LI2_TF_HANDOFF) && defined(LI2_REGISTER_RUN)
    if(selected_run_trace_active) {
        checked(selected_run_history.last_complete.entry_event.number==SIGTRAP &&
                selected_run_history.last_complete.entry_event.code==TRAP_TRACE &&
                selected_run_trace_completed!=UINT64_MAX,LI2_CHAIN_STATE,21);
        ++selected_run_trace_completed;selected_run_trace_active=0;
    }
#endif
#ifdef LI2_RUN_TIMING
    error=li2_run_timing_complete(&selected_run_timing,&selected_run_history);
    if(error)selected_run_abort((unsigned)error,selected_run_timing.first_detail);
#endif
    selected_logical_flags=selected_run_history.last_complete.logical_flags;
    selected_flags_known=1;selected_step_pending=0;selected_pending_route=SELECTED_NO_STEP;
    /* The actual guard has not executed; route this same real NX event with
       a new genuine borrow. No synthetic TRACE, direct guard resume or chaining. */
    selected_fetch(sig,si,uc);
}
static void selected_run_before_syscall(long number,const long args[6]) {
    int error=li2_run_cache_before_syscall(selected_run_cache,number,args);
    checked(!error,767,error);
    if(number!=SYS_brk || !args[0])return;
    /* Guard every other runtime-private range as well as the cache's own arena.
       brk shrink can unmap a replacement in a hole; ordinary overlap checks on
       mmap/mprotect/munmap alone do not cover that kernel operation. */
    struct li2_run_brk_observation *b=&selected_run_private_brk;
    *b=(struct li2_run_brk_observation){.attempted=1,.requested=(uintptr_t)args[0]};
    b->query_result=raw(SYS_brk,0,0,0,0,0,0);b->observed=(uintptr_t)b->query_result;
    if((b->query_result<0 && b->query_result>=-4095) || b->observed>UINTPTR_MAX-(PAGE-1)) {
        b->result=LI2_CACHE_BRK;fail(768,b->query_result);
    }
    if(b->requested<b->observed) {
        b->first=(b->requested+PAGE-1)&~(PAGE-1);b->end=(b->observed+PAGE-1)&~(PAGE-1);
        if(b->first<b->end && intersects(b->first,b->end-b->first)) {
            b->result=LI2_CACHE_BRK;fail(769,number);
        }
    }
    b->complete=1;
}
_Static_assert(3286<=sizeof(((struct writer *)0)->bytes),"bounded register-run report");
static void selected_run_report(unsigned status,unsigned code,long detail) {
    struct writer w={.used=0};
    const struct li2_run_cache_diagnostic *d=li2_run_cache_diagnostic(selected_run_cache);
    const struct li2_run_publication_progress *p=li2_run_publication_progress(selected_run_cache,selected_run_publication);
    const struct li2_run_owner *o=&selected_run_history.last_complete;
    text(&w,"LI2_RUN {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",selected_repeat_abs(detail));field(&w,",\"detail_negative\":",detail<0);
    field(&w,",\"cache_present\":",d!=0);field(&w,",\"publication_present\":",p!=0);
    field(&w,",\"plan_misses\":",selected_run_plan_misses);
    field(&w,",\"completed_runs\":",selected_run_history.completed_runs);
    field(&w,",\"copied_instructions\":",selected_run_history.copied_instructions);
    field(&w,",\"pending\":",selected_step_pending);field(&w,",\"route\":",selected_pending_route);
    if(d) {
        const struct li2_run_cache_initialization *i=&d->initialization;
        const uint64_t cache[]={d->phase,d->first_error,selected_repeat_abs(d->first_detail),d->first_detail<0,
            d->slots_used,d->complete_slots,d->attempts,d->hits,d->full_misses,d->interrupted,d->interrupted_again,
            d->interrupted_code,selected_repeat_abs(d->interrupted_detail),d->interrupted_detail<0};
        selected_repeat_array(&w,",\"cache\":",cache,sizeof cache/sizeof cache[0]);
        const uint64_t init[]={i->metadata_started,i->metadata_complete,i->allocation_started,i->allocated,
            i->arena_protection_started,i->arena_protection_complete,i->complete,i->arena,i->arena_bytes,i->metadata_bytes,
            selected_repeat_abs(i->allocation_result),i->allocation_result<0,
            selected_repeat_abs(i->metadata_result),i->metadata_result<0,
            selected_repeat_abs(i->arena_protection_result),i->arena_protection_result<0,
            i->mapping.attempted,i->mapping.complete,i->mapping.pages_checked};
        selected_repeat_array(&w,",\"initialization\":",init,sizeof init/sizeof init[0]);
        const struct li2_run_publish_attempt *a=&d->last_attempt;
        const uint64_t attempt[]={a->ordinal,a->borrow_sequence,a->installed,a->source_complete,a->plan_complete,
            a->hit,a->miss_before_publication,a->complete,a->first_error,selected_repeat_abs(a->first_detail),a->first_detail<0,
            a->pages_validated,a->slot,a->fetch.held,a->fetch.complete,a->fetch.first_error};
        selected_repeat_array(&w,",\"attempt\":",attempt,sizeof attempt/sizeof attempt[0]);
    }
    if(p) {
        const uint64_t publication[]={p->phase,p->first_error,selected_repeat_abs(p->first_detail),p->first_detail<0,
            p->allocation,p->generation,p->borrow_sequence,p->entry,p->fill_bytes,p->code_bytes,p->verified_bytes,
            p->rw_checked,p->rx_started,p->rx_complete,p->sync_started,p->sync_complete,
            selected_repeat_abs(p->rx_result),p->rx_result<0,selected_repeat_abs(p->sync_result),p->sync_result<0,
            p->cleanup_started,p->cleanup_complete,p->cleanup_sync_started,
            selected_repeat_abs(p->cleanup_result),p->cleanup_result<0,
            selected_repeat_abs(p->cleanup_sync_result),p->cleanup_sync_result<0,
            p->before.attempted,p->before.complete,p->after.attempted,p->after.complete,
            p->cleanup.attempted,p->cleanup.complete};
        selected_repeat_array(&w,",\"publication\":",publication,sizeof publication/sizeof publication[0]);
    }
    const uint64_t complete[]={selected_run_history.reset_started,selected_run_history.reset_complete,
        selected_run_history.first_error,selected_repeat_abs(selected_run_history.first_detail),selected_run_history.first_detail<0,
        o->phase,o->plan.pc,o->plan.stop,o->plan.instruction_count,o->entry_event.observed,o->exit_event.observed,
        o->redirected,o->exit_seen,o->pre_entry.complete,o->exit_query.complete,o->release_started,o->release_complete,
        o->final_fetch.held,o->final_fetch.complete,o->final_fetch.sequence};
    selected_repeat_array(&w,",\"last_complete\":",complete,sizeof complete/sizeof complete[0]);
    const uint64_t interrupted[]={selected_run_interrupted.event.observed,selected_repeat_abs(selected_run_interrupted.event.number),
        selected_run_interrupted.event.number<0,selected_repeat_abs(selected_run_interrupted.event.code),
        selected_run_interrupted.event.code<0,selected_run_interrupted.event.address,
        selected_run_interrupted.frame_observed,selected_run_interrupted.greg[REG_RIP],selected_run_interrupted.mask};
    selected_repeat_array(&w,",\"interrupted\":",interrupted,sizeof interrupted/sizeof interrupted[0]);
    const struct li2_run_owner *current=&selected_run_owner;
    const uint64_t active[]={current->phase,current->first_error,selected_repeat_abs(current->first_detail),
        current->first_detail<0,current->borrow.sequence,current->plan.pc,current->plan.stop,
        current->redirected,current->exit_seen,current->release_complete};
    selected_repeat_array(&w,",\"active\":",active,sizeof active/sizeof active[0]);
    const struct li2_run_brk_observation *b=&selected_run_private_brk;
    const uint64_t brk[]={b->attempted,b->complete,b->requested,b->observed,b->first,b->end,
        selected_repeat_abs(b->query_result),b->query_result<0,selected_repeat_abs(b->result),b->result<0};
    selected_repeat_array(&w,",\"private_brk\":",brk,sizeof brk/sizeof brk[0]);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}

#if defined(LI2_EFFECT_PROVIDER) && defined(LI2_TF_HANDOFF) && defined(LI2_REGISTER_RUN)
/* Additional effect-profile row; old RUN/CHAIN counters keep their meanings. */
static void selected_run_trace_report(unsigned status,unsigned code,long detail) {
    struct writer w={.used=0};
    text(&w,"LI2_TRACE_RUN {\"version\":1,\"scope\":\"genuine_trace_to_register_run\"");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",selected_repeat_abs(detail));field(&w,",\"detail_negative\":",detail<0);
    field(&w,",\"candidates\":",selected_run_trace_candidates);
    field(&w,",\"preflight_misses\":",selected_run_trace_preflight_misses);
    field(&w,",\"attempts\":",selected_run_trace_attempts);field(&w,",\"entries\":",selected_run_trace_entries);
    field(&w,",\"plan_misses\":",selected_run_trace_plan_misses);field(&w,",\"full_misses\":",selected_run_trace_full_misses);
    field(&w,",\"completed\":",selected_run_trace_completed);field(&w,",\"busy\":",selected_run_trace_busy);
    field(&w,",\"active\":",selected_run_trace_active);
    field(&w,",\"proof_available\":",li2_tf_chain_run_entry(&selected_chain)!=0);
    field(&w,",\"pending\":",selected_step_pending);field(&w,",\"route\":",selected_pending_route);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
#endif
