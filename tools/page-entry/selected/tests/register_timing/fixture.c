/* Actual handler publication, same-site miss plus ten hits. The unchanged
   register oracle supplies every native/returned-state and literal predicate. */
#define _GNU_SOURCE
#include "register_run_timing.h"
static void timing_enter(void);
static void timing_capture(void *);
static void timing_nested(int,siginfo_t *,void *);
static void timing_completed(void);
static int timing_append(void);
#include "timing_support.inc"
#ifndef TIMING_CONTROL
#error TIMING_CONTROL required
#endif
struct timing_fixture_record {
    uint64_t magic,version,bytes,mode,entries,publish_returns,completions;
    uint64_t interrupt_issued,nested_seen,complete;
    struct state entry,nested;
    struct li2_run_timing observation;
    long expected_pid,expected_uid;
    unsigned signal_observed;
    int signal_number,signal_signo,signal_code,signal_errno,signal_pid;
    unsigned signal_uid;
};
static struct timing_fixture_record li2_timing_record;
static unsigned expected_timing_hit;
static void timing_capture(void *frame) {
    capture(&li2_timing_record.entry,(ucontext_t *)frame);
    capture(&running->state.step_before,(ucontext_t *)frame);
}
static int timing_append(void) {
    struct timing_fixture_record *r=&li2_timing_record;
    r->magic=UINT64_C(0x31454d495432494c);r->version=1;r->bytes=sizeof(*r);r->mode=TIMING_CONTROL;
    li2_run_timing_finish(&r->observation,(result.fixture_failure||result.owner_failure)?125:0);
    return write_all(3,r,sizeof(*r));
}
static void timing_nested(int sig,siginfo_t *si,void *frame) {
    struct timing_fixture_record *r=&li2_timing_record;
    ++r->nested_seen;r->signal_number=sig;
    if(si) {
        r->signal_signo=si->si_signo;r->signal_code=si->si_code;r->signal_errno=si->si_errno;
        r->signal_pid=si->si_pid;r->signal_uid=si->si_uid;
        __atomic_store_n(&r->signal_observed,1,__ATOMIC_RELEASE);
    }
    if(frame)capture(&r->nested,(ucontext_t *)frame);
    li2_run_timing_fail(&r->observation,LI2_TIME_INTERRUPTED,sig);
    li2_maps_phase_fail();
    need(r->signal_observed&&sig==SIGSEGV&&r->signal_signo==SIGSEGV&&
         r->signal_code==SI_TKILL&&!r->signal_errno&&r->signal_pid==r->expected_pid&&
         r->expected_pid==session.pid&&r->signal_uid==(unsigned)r->expected_uid,833);
}
static void timing_enter(void) {
    struct run_record *r=running;struct sample *s=&r->state;
    ++li2_timing_record.entries;
    borrow(s);
    need(!li2_run_plan_bytes(s->pc,(const void *)s->pc,s->length,&r->plan)&&
         r->plan.stop==s->expected_post&&r->plan.run_length==6&&
         r->plan.instruction_count==2&&r->plan.source_length==8&&
         !memcmp(r->plan.source,(const void *)s->pc,s->length),810);
    struct li2_fetch_view view;
    need(!li2_lifecycle_fetch_view(&s->ref,&view),811);
    r->history_before=tail.history.completed_runs;r->copied_before=tail.history.copied_instructions;
    publication=0;publishing=1;
    int error=li2_run_timing_begin(&li2_timing_record.observation,&r->plan,&s->ref,&view);
    if(error)die((unsigned)error);
    int status=li2_run_cache_publish(cache,&s->ref,&r->plan,&publication);
    r->published=*li2_run_cache_diagnostic(cache);r->publication_address=(uintptr_t)publication;
    need(!status&&publication&&r->published.phase==LI2_CACHE_READY&&!r->published.first_error&&
         r->published.last_attempt.complete&&r->published.last_attempt.source_complete&&
         r->published.last_attempt.plan_complete&&r->published.last_attempt.pages_validated==s->count&&
         r->published.last_attempt.borrow_sequence==s->ref.sequence&&
         r->published.last_attempt.hit==expected_timing_hit&&!r->published.last_attempt.miss_before_publication,812);
    const struct li2_run_publication_progress *p=li2_run_publication_progress(cache,publication);
    need(p!=0,813);r->publication=*p;
    error=li2_run_timing_published(&li2_timing_record.observation,status,&r->published,p);
    if(error)die((unsigned)error);
    ++li2_timing_record.publish_returns;
    if(TIMING_CONTROL==2) {
        li2_timing_record.interrupt_issued=1;
        long result_=RAW(SYS_tgkill,session.pid,session.tid,SIGSEGV,0,0,0);
        (void)result_;die(814); /* A returned delivery is never accepted. */
    }
    publishing=0;
    const struct li2_run_publisher provider={cache,li2_run_publication_observe,run_failure};
    need(!li2_run_arm(&tail.active,&session,&s->ref,s->initial_flags,&provider,publication),815);
}
static void timing_completed(void) {
    int error=li2_run_timing_complete(&li2_timing_record.observation,&tail.history);
    if(error)die((unsigned)error);
    ++li2_timing_record.completions;
}
static void timed_run(struct run_record *r,unsigned hit) {
    struct sample *s=&r->state;running=r;current=s;inputs(s);fixture_target=s->pc;
    expected_timing_hit=hit;route=1;r->route=1;fixture_enter();
    r->history_after=tail.history.completed_runs;r->copied_after=tail.history.copied_instructions;
    r->finished=*li2_run_cache_diagnostic(cache);
    const struct li2_private_code_query *q=li2_run_publication_last_query(cache,publication);
    need(q!=0,816);r->last_query=*q;
    ++header.published_runs;if(hit)++header.hit_runs;header.generated_trace_events+=r->trace_events;
    s->live[2]=fixture_live_before;s->live[3]=fixture_live_after;
    memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[3],fixture_fp_after,xsave_bytes);
    compare_run(r); /* Original complete comparison, no timing normalization. */
}
int fixture_main(unsigned long *stack) {
    _Static_assert(TIMING_CONTROL>=0&&TIMING_CONTROL<=2,"three finite commands");
    _Static_assert(sizeof(header)+sizeof(samples[0])+sizeof(li2_register_records)+sizeof(capacities)+
        sizeof(tail)+sizeof(li2_timing_record)<16*1024*1024,"unchanged 16 MiB file bound");
    header.magic=UINT64_C(0x314e55525232494c);header.version=1;header.group=4;
    setup(stack);size_t done=0,failed=0;uint32_t decoder=0;
    li2_timing_record.expected_pid=session.pid;li2_timing_record.expected_uid=RAW(SYS_getuid,0,0,0,0,0,0);
    need(li2_timing_record.expected_pid>0&&li2_timing_record.expected_uid>=0&&
         (uint64_t)li2_timing_record.expected_uid<=UINT32_MAX,834);
    need(!li2_tf_refusal_controls(&done,&failed,&decoder,&refused_last)&&done==47&&failed==SIZE_MAX&&!decoder,817);
    header.refusals=done;prepare_case(&samples[0],0);run_pair(&samples[0]);
    need(session.self_test_complete&&samples[0].checked&&result.completed==1,818);
    need(!li2_run_cache_initialize(&session,&protection,&cache)&&cache,819);
    need(contains(0,(uintptr_t)&tail.active,sizeof(tail.active))&&
         contains(0,(uintptr_t)&tail.history,sizeof(tail.history)),820);
    install_register_handler();need(!li2_decoder_stats(&tail.decoder_before)&&tail.decoder_before.phase==2,821);
    unsigned count=TIMING_CONTROL?1:11;
    prepare_run(&li2_register_records[0],3);
    for(unsigned i=1;i<count;i++){li2_register_records[i]=li2_register_records[0];li2_register_records[i].repetition=i;}
    for(unsigned i=0;i<count;i++)native_run(&li2_register_records[i]);
    restore_source(&li2_register_records[0]);
    for(unsigned i=1;i<count;i++)memcpy(li2_register_records[i].state.source,li2_register_records[i].literal_source,CODE_BYTES);
    struct sample *s=&li2_register_records[0].state;
    struct li2_run_plan plan;
    need(!li2_run_plan_bytes(s->pc,(const void *)s->pc,s->length,&plan),822);
    struct li2_time_config config={.mode=LI2_TIME_MEASURE,
        .key={.offset=s->pc-s->mapping,.source_length=plan.source_length,.run_length=plan.run_length,
              .instructions=plan.instruction_count,.guard_length=plan.guard.length,.guard_code=plan.guard.code}};
    memcpy(config.key.source,plan.source,plan.source_length);
    digest((const unsigned char *)s->mapping,CODE_BYTES,config.image_hash);
    need(!li2_run_timing_init(&li2_timing_record.observation,&config,s->mapping,s->mapping+CODE_BYTES,
        s->mapping,config.image_hash,&protection),823);
#if TIMING_CONTROL==1
    need(!li2_run_timing_test_bad_clock(&li2_timing_record.observation),824);
#endif
    for(unsigned i=0;i<count;i++)timed_run(&li2_register_records[i],i!=0);
    need(TIMING_CONTROL==0&&header.completed_records==11&&header.native_references==11&&
         header.published_runs==11&&header.hit_runs==10&&!header.fallback_runs&&header.source_restorations==1&&
         !header.generated_trace_events&&!header.fallback_trace_events&&tail.history.completed_runs==11,825);
    const struct li2_run_cache_diagnostic *d=li2_run_cache_diagnostic(cache);
    need(d->phase==LI2_CACHE_READY&&!d->first_error&&d->slots_used==1&&d->complete_slots==1&&
         d->attempts==11&&d->hits==10&&!d->full_misses,826);
    need(!li2_decoder_stats(&tail.decoder_after)&&!memcmp(&tail.decoder_before,&tail.decoder_after,sizeof(tail.decoder_before)),827);
    need(!li2_lifecycle_fetch_interlock()&&zero(&tail.active,sizeof(tail.active)),828);
    li2_run_timing_finish(&li2_timing_record.observation,0);
    need(li2_timing_record.observation.qualified&&li2_timing_record.observation.samples_complete==11&&
         li2_timing_record.observation.clock_calls==33&&li2_timing_record.entries==11&&
         li2_timing_record.publish_returns==11&&li2_timing_record.completions==11&&
         !li2_timing_record.interrupt_issued&&!li2_timing_record.nested_seen,829);
    li2_timing_record.complete=1;header.complete=1;need(register_dump(),830);
    output("LI2_REGISTER_TIMING_PASS pairs=11 miss=1 hit=10 samples=11 clocks=33 refusal=47 trace=0\n");
    return 0;
}
