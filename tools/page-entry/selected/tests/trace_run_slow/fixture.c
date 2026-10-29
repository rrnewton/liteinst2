/* The complete first-slice fixture is included with only its main/dump
   definitions renamed. Its old cases and comparators are not changed. */
#include "trace_run_slow_support.inc"

struct slow_fill {
    unsigned started,complete;
    uint64_t ordinal;
    struct li2_fetch_ref ref;
    struct li2_fetch_page pages[2];
    struct li2_fetch_backing backing[2];
    struct li2_fetch_progress prepared,released;
    struct li2_run_plan plan;
    struct li2_run_publication_progress publication;
    struct li2_run_slot_observation inspected;
    struct li2_run_cache_diagnostic cache;
};
struct slow_record {
    uint64_t magic,version,bytes,mode,complete;
    uint64_t fill_started,fill_completed,preflight_started,fresh_started;
    uint64_t publish_started,consume_started,skip_started,release_started,release_complete,release_verified;
    uint64_t decision_complete,natural_nx,source_closed_checked;
    int preflight_result,publish_result,consume_result,skip_result,release_result,verify_result;
    uintptr_t publication_pointer;
    struct li2_fetch_progress before_fetch,after_fetch;
    struct li2_run_cache_diagnostic before_cache,after_cache;
    struct li2_run_plan descriptive;
    struct tr_snapshot consumed_frame;
    struct slow_fill fills[64];
};
static struct slow_record slow;
static int tr_dump(void) {
    slow.magic=UINT64_C(0x31574f4c5352324c);slow.version=1;slow.bytes=sizeof(slow);
    return tr_dump_base()&&write_all(3,&slow,sizeof(slow));
}
static void slow_fill_cache(void) {
    for(unsigned i=0;i<64;i++) {
        struct slow_fill *f=&slow.fills[i];f->started=1;f->ordinal=i;++slow.fill_started;
        tr_fetch(tr.mapping+512+i*16);f->ref=tr_ref;f->prepared=*li2_lifecycle_fetch_progress();
        need(tr_view.page_count==1&&tr_view.length==15,500);
        f->pages[0]=tr_view.pages[0];f->backing[0]=tr_view.backing[0];
        need(!li2_run_plan_bytes(tr_view.pc,tr_view.bytes,tr_view.length,&f->plan)&&
             f->plan.instruction_count==2&&f->plan.run_length==7,501);
        const struct li2_run_publication *p=0;
        need(!li2_run_cache_publish(tr_cache,&tr_ref,&f->plan,&p)&&p,502);
        const struct li2_run_publication_progress *q=li2_run_publication_progress(tr_cache,p);
        need(q&&q->phase==LI2_PUBLICATION_COMPLETE,503);f->publication=*q;
        need(!li2_run_publication_observe(tr_cache,p,&f->plan,&f->inspected),504);
        need(!li2_lifecycle_fetch_release(&tr_ref),505);f->released=*li2_lifecycle_fetch_progress();
        f->cache=*li2_run_cache_diagnostic(tr_cache);
        need(!f->released.held&&f->released.complete&&!f->released.first_error&&
             f->released.sequence==f->ref.sequence&&f->cache.slots_used==i+1&&
             f->cache.complete_slots==i+1&&f->cache.attempts==i+1&&!f->cache.hits&&
             !f->cache.full_misses&&!f->cache.first_error,506);
        f->complete=1;++slow.fill_completed;
    }
    /* These are real completed publications, not executed/completed runs. */
    need(!tr.completed_runs&&!tr.history.completed_runs&&tr_owner.phase==LI2_RUN_EMPTY,507);
}
static void slow_decide(int sig,siginfo_t *si,ucontext_t *uc) {
    struct tr_lane *l=&tr.lanes[0];
    tr_origin=li2_tf_chain_run_entry(&tr_chain);need(tr_origin!=0,508);
    const struct li2_tf_run_origin *o=li2_tf_chain_run_snapshot(&tr_chain);need(o!=0,509);l->offered=*o;
    tr_snap(&l->closed,sig,si,uc);l->closed_chain=tr_chain;
    slow.before_fetch=*li2_lifecycle_fetch_progress();slow.before_cache=*li2_run_cache_diagnostic(tr_cache);
    const struct li2_chain_fetch *q=&tr_chain.slots[tr_chain.active].fetch;
    slow.preflight_started=1;
    slow.preflight_result=li2_run_plan_bytes(q->pc,q->bytes,q->length,&slow.descriptive);
    if(!slow.mode) {
        need(slow.preflight_result==LI2_RUN_SLOW&&!li2_lifecycle_fetch_interlock(),510);
        slow.skip_started=1;++tr.consume_calls;
        slow.skip_result=li2_tf_chain_run_skip(tr_origin,sig,si,uc);need(!slow.skip_result,511);
    } else {
        need(!slow.preflight_result,512);slow.fresh_started=1;tr_fetch(tr.run_pc);
        l->fresh=*li2_lifecycle_fetch_progress();
        need(!li2_run_plan_bytes(tr.run_pc,tr_view.bytes,tr_view.length,&l->plan)&&
             !memcmp(&l->plan,&slow.descriptive,sizeof(l->plan)),513);
        slow.publish_started=1;tr_publication=0;
        slow.publish_result=li2_run_cache_publish(tr_cache,&tr_ref,&l->plan,&tr_publication);
        slow.publication_pointer=(uintptr_t)tr_publication;l->published=*li2_run_cache_diagnostic(tr_cache);
        need(slow.publish_result==LI2_RUN_SLOW&&!tr_publication&&
             l->published.slots_used==64&&l->published.complete_slots==64&&
             l->published.last_attempt.miss_before_publication&&l->published.full_misses==1&&
             !l->published.first_error&&tr_owner.phase==LI2_RUN_EMPTY,514);
        slow.consume_started=1;++tr.consume_calls;
        slow.consume_result=li2_tf_chain_run_consume(tr_origin,&session,&tr_ref,tr.run_pc,
            (uint64_t)uc->uc_mcontext.gregs[REG_EFL],sig,si,uc);need(!slow.consume_result,515);
        tr_snap(&slow.consumed_frame,sig,si,uc);
        slow.release_started=1;slow.release_result=li2_lifecycle_fetch_release(&tr_ref);
        need(!slow.release_result,516);slow.release_complete=1;
        slow.verify_result=li2_tf_chain_run_released(tr_origin,&tr_ref,sig,si,uc);
        need(!slow.verify_result,517);slow.release_verified=1;
    }
    o=li2_tf_chain_run_snapshot(&tr_chain);need(o!=0,518);l->consumed=*o;
    slow.after_fetch=*li2_lifecycle_fetch_progress();slow.after_cache=*li2_run_cache_diagnostic(tr_cache);
    tr_snap(&l->input,sig,si,uc);
    need(!memcmp(&l->closed,&l->input,sizeof(l->input))&&!li2_lifecycle_fetch_interlock()&&
         !tr_chain.pending&&tr_owner.phase==LI2_RUN_EMPTY,519);
    slow.decision_complete=1;tr_source_closed();slow.source_closed_checked=1;
    /* No RIP/flags edit: return from this genuine TRACE to the original NX PC. */
}
static void slow_handler(int sig,siginfo_t *si,void *frame_) {
    ucontext_t *uc=frame_;li2_tf_chain_event_boundary(&tr_chain);
    need(!tr_handling&&si&&uc,520);tr_handling=1;
    if(tr_native_mode)tr_native_handler(sig,si,uc);
    else {
        struct tr_lane *l=&tr.lanes[0];greg_t *g=uc->uc_mcontext.gregs;
        ++l->events;if(sig==SIGSEGV)++l->nx;if(sig==SIGTRAP&&si->si_code==TRAP_TRACE)++l->trace_events;
        if(slow.decision_complete) {
            need(!slow.natural_nx&&nx(sig,si,g,tr.run_pc)&&(uint64_t)g[REG_EFL]==(UINT64_C(0xa96)|LI2_STEP_RF),521);
            tr_snap(&l->after,sig,si,uc);slow.natural_nx=1;
            need(!li2_lifecycle_fetch_interlock()&&!tr_chain.pending&&tr_owner.phase==LI2_RUN_EMPTY,522);
            l->final_fetch=*li2_lifecycle_fetch_progress();l->finished=*li2_run_cache_diagnostic(tr_cache);
            tr_source_closed();g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
        } else if(tr_chain.pending) {
            tr_snap(&l->trace,sig,si,uc);
            if(sig!=SIGTRAP||si->si_code!=TRAP_TRACE)li2_tf_chain_unexpected(&tr_chain,sig,si,uc);
            need(li2_tf_chain_trace(&tr_chain,sig,si,uc)==LI2_CHAIN_NX_FALLBACK&&
                 tr_chain.slots[tr_chain.active].fallback==LI2_CHAIN_OLD_STEP&&!tr_chain.pending,523);
            slow_decide(sig,si,uc);
        } else {
            need(!tr_phase&&nx(sig,si,g,tr.pc),524);tr_phase=1;tr_snap(&l->before,sig,si,uc);
            tr_fetch(tr.pc);li2_tf_chain_begin_nx(&tr_chain,&tr_ref,&tr_decoded,fixture_flags,sig,si,uc);
        }
        ++l->returns;
    }
    fixture_vector_clobber();li2_tf_chain_handler_end(&tr_chain);tr_handling=0;
}
static void slow_install(void) {
    struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} a;
    a.handler=slow_handler;a.flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL;a.restorer=step_restorer;a.mask=mask;
    need(!RAW(SYS_rt_sigaction,SIGSEGV,&a,0,8,0,0)&&!RAW(SYS_rt_sigaction,SIGTRAP,&a,0,8,0,0)&&
         !RAW(SYS_rt_sigaction,SIGSYS,&a,0,8,0,0),525);
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(tr)+sizeof(samples[0])+sizeof(slow)<16*1024*1024,"whole SLOW oracle below16MiB");
    const char *const *env=(const void *)(stack+3);unsigned found=0;
    static const char key[]="LI2_TRACE_RUN_SLOW=";const size_t n=sizeof(key)-1;
    need(stack[0]==1,526);
    for(size_t i=0;env[i];i++)if(length(env[i])>=n&&!memcmp(env[i],key,n)) {
        need(!found&&length(env[i])==n+1&&env[i][n]>='0'&&env[i][n]<='1'&&!env[i][n+1],527);
        slow.mode=(unsigned)(env[i][n]-'0');++found;
    }
    need(found==1,528);tr_mode=7+(unsigned)slow.mode;setup(stack);
    size_t done=0,failed=0;uint32_t rc=0;
    need(!li2_tf_refusal_controls(&done,&failed,&rc,&refused_last)&&done==47&&failed==SIZE_MAX&&!rc,529);tr.old_refusals=done;
    prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,530);tr.startup_pairs=1;
    need(!li2_tf_chain_init(&tr_chain,&session,tr_chain_failure)&&
         !li2_run_cache_initialize(&session,&tr_protection,&tr_cache)&&!li2_decoder_stats(&tr.initial_stats),531);
    tr.pid=(uint64_t)session.pid;tr.tid=(uint64_t)session.tid;tr.uid=(uint64_t)RAW(SYS_getuid,0,0,0,0,0,0);
    long base=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(base>0,532);
    tr.mapping=(uintptr_t)base+PAGE;tr.pc=tr.mapping+128;tr.run_pc=tr.pc+4;tr.guard=tr.run_pc+(slow.mode?7:5);
    tr.subject_address=subject;tr.data_address=data_page;tr.fault_address=data_fault;
    memset(tr.literal,0xcc,CODE_BYTES);
    const unsigned char pred[]={0x48,0x83,0xc0,1},one[]={0xb8,0x78,0x56,0x34,0x12,0x01,0xc0};
    const unsigned char two[]={0xb8,0x78,0x56,0x34,0x12,0x89,0xc1,0x01,0xc0};
    memcpy(tr.literal+128,pred,sizeof(pred));memcpy(tr.literal+132,slow.mode?two:one,slow.mode?sizeof(two):sizeof(one));
    if(slow.mode)for(unsigned i=0;i<64;i++) {
        unsigned char *p=tr.literal+512+i*16;memcpy(p,two,sizeof(two));
        p[1]=(unsigned char)(i+1);p[2]=p[3]=p[4]=0;
    }
    slow_install();tr_reference(0);tr_replace(tr.literal);tr_source_closed();
    if(slow.mode)slow_fill_cache();
    tr_native_mode=0;tr_which=0;tr_phase=0;tr.lanes[0].started=1;
    tr_inputs(0);fixture_target=tr.pc;fixture_enter();
    struct tr_lane *l=&tr.lanes[0];
    l->live[0]=fixture_live_before;l->live[1]=fixture_live_after;
    memcpy(l->fp[0],fixture_fp_before,xsave_bytes);memcpy(l->fp[1],fixture_fp_after,xsave_bytes);
    need(slow.decision_complete&&slow.natural_nx&&l->events==3&&l->returns==3&&l->nx==2&&l->trace_events==1&&
         !l->complete&&!l->reset&&!tr.completed_runs&&!tr.history.completed_runs,533);
    tr_equal(&l->before.state,&tr.native[0].before.state);
    tr_equal(&l->trace.state,&tr.native[0].after.state);tr_equal(&l->after.state,&tr.native[0].after.state);
    need((uint64_t)l->after.state.frame.greg[REG_RAX]==UINT64_C(0x8000000000000000)&&
         (uint64_t)l->after.state.frame.greg[REG_EFL]==(UINT64_C(0xa96)|LI2_STEP_RF),534);
    for(unsigned e=0;e<2;e++) {
        const struct live *v=&l->live[e];const struct state *s=e?&l->after.state:&l->before.state;
        need(v->started==v->complete&&v->complete==1&&!v->reserved&&v->rflags==(e?UINT64_C(0xa96):UINT64_C(0x247)),535);
        for(unsigned i=0;i<16;i++)need(v->gpr[i]==(uint64_t)s->frame.greg[regs[i]],536);
        need(!memcmp(v->selectors,tr.native[0].live[e].selectors,sizeof(v->selectors))&&
             !memcmp(l->fp[e],tr.native[0].fp[e],FP_CAPACITY),537);
    }
    need(!li2_decoder_stats(&tr.final_stats)&&!memcmp(&tr.initial_stats,&tr.final_stats,sizeof(tr.initial_stats)),538);
    slow.complete=1;tr.complete=1;need(tr_dump(),539);
    output(slow.mode?"LI2_TRACE_RUN_SLOW_PASS mode=1 publications=64 fresh=1\n":"LI2_TRACE_RUN_SLOW_PASS mode=0 publications=0 fresh=0\n");
    return 0;
}
