/* Actual original-address native prefix versus immutable private RX publication.
   The native lane alone replaces the first guard byte by INT3, restores the
   entire literal source through lifecycle, then the generated lane stops at
   the original NX guard. Neither lane executes or claims the guard itself. */
static int register_dump(void);
#define fixture_main unchanged_generic_fixture_main
#include "run_support.inc"
#undef fixture_main
#include "register_run_reset.h"
#include "cases.h"
#include "sha256.h"

#ifndef REGISTER_GROUP
#error REGISTER_GROUP required
#endif
#define RECORDS_KEPT 6U
#define CAPACITY_CYCLES 64U
struct run_record {
    struct sample state;
    struct li2_run_plan plan;
    struct li2_run_owner owner;
    struct li2_run_cache_diagnostic published,finished;
    struct li2_run_publication_progress publication;
    struct li2_private_code_query last_query;
    struct li2_fetch_page native_pages[2];
    unsigned char native_source[CODE_BYTES],literal_source[CODE_BYTES];
    uintptr_t publication_address;
    uint64_t history_before,history_after,copied_before,copied_after;
    unsigned case_index,repetition,route,started,checked,reset_complete;
    unsigned nx_entries,nx_exits,trap_events,trace_events;
};
struct capacity_record {
    uint64_t ordinal,pc,stop,source_allocation,source_generation;
    uint64_t slot,publication_allocation,publication_generation,entry;
    uint64_t slots_used,complete_slots,attempts,hits,full_misses,completed_runs;
    uint64_t native_generation,checked,reset_complete,nx_entries,nx_exits;
    unsigned char full_record_sha256[32];
};
struct register_header {
    uint64_t magic,version,header_bytes,group,record_bytes,records_kept;
    uint64_t startup_bytes,capacity_row_bytes,capacity_rows,tail_bytes;
    uint64_t completed_records,completed_capacity,native_references;
    uint64_t published_runs,hit_runs,fallback_runs,source_restorations;
    uint64_t generated_trace_events,fallback_trace_events;
    uint64_t refusals,xcr0,xsave_bytes,fixture_failure,owner_failure;
    uint64_t owner_detail_abs,owner_detail_negative,complete;
};
struct register_tail {
    struct li2_run_owner active;
    struct li2_run_completion_history history;
    struct li2_run_cache_diagnostic cache;
    struct li2_step_owner fallback[2];
    struct li2_tf_continuation fallback_query;
    struct li2_fetch_progress fallback_releases[2];
    struct li2_decoder_stats decoder_before,decoder_after;
};
static struct run_record li2_register_records[RECORDS_KEPT],*running;
static struct capacity_record capacities[CAPACITY_CYCLES];
static struct register_header header;
static struct register_tail tail;
static struct li2_run_cache *cache;
static const struct li2_run_publication *publication;
static struct sample fallback_source;
static unsigned fallback_index,reference_phase,route;
static volatile sig_atomic_t register_handling,publishing;

static int register_dump(void) {
    header.header_bytes=sizeof(header);header.record_bytes=sizeof(li2_register_records[0]);
    header.records_kept=RECORDS_KEPT;header.startup_bytes=sizeof(samples[0]);
    header.capacity_row_bytes=sizeof(capacities[0]);header.capacity_rows=CAPACITY_CYCLES;
    header.tail_bytes=sizeof(tail);header.xcr0=fixture_xcr0;header.xsave_bytes=xsave_bytes;
    header.fixture_failure=result.fixture_failure;header.owner_failure=result.owner_failure;
    header.owner_detail_abs=result.owner_detail_abs;header.owner_detail_negative=result.owner_detail_negative;
    if(cache)tail.cache=*li2_run_cache_diagnostic(cache);
    return write_all(3,&header,sizeof(header))&&write_all(3,&samples[0],sizeof(samples[0]))&&
        write_all(3,li2_register_records,sizeof(li2_register_records))&&write_all(3,capacities,sizeof(capacities))&&
        write_all(3,&tail,sizeof(tail));
}
static int contains(void *context,uintptr_t first,size_t bytes) {
    (void)context;if(!bytes||first>UINTPTR_MAX-bytes)return 0;
    for(size_t i=0;i<protected_count;i++)
        if(first>=protected[i].first&&first+bytes<=protected[i].end)return 1;
    return 0;
}
static int protect_add(void *context,uintptr_t first,size_t bytes) {
    if(contains(context,first,bytes))return 0;
    if(!bytes||first>UINTPTR_MAX-bytes||protected_count>=128)return 1;
    protected[protected_count].first=first;protected[protected_count].end=first+bytes;
    ++protected_count;return 0;
}
static const struct li2_run_protection protection={0,protect_add,contains};
static void run_failure(void *context,const struct li2_run_owner *owner) {
    (void)context;result.owner_failure=owner->first_error;
    result.owner_detail_abs=owner->first_detail<0?0ULL-(uint64_t)owner->first_detail:(uint64_t)owner->first_detail;
    result.owner_detail_negative=owner->first_detail<0;
    if(running)running->owner=*owner;
    (void)register_dump();
}
static void fallback_failure(void *context,const struct li2_step_owner *owner) {
    (void)context;result.owner_failure=owner->first_error;
    result.owner_detail_abs=owner->first_detail<0?0ULL-(uint64_t)owner->first_detail:(uint64_t)owner->first_detail;
    result.owner_detail_negative=owner->first_detail<0;(void)register_dump();
}
static int zero(const void *p,size_t n) {
    const unsigned char *b=p;for(size_t i=0;i<n;i++)if(b[i])return 0;return 1;
}
static int fetch_released(const struct li2_fetch_progress *p,const struct li2_fetch_ref *ref) {
    return p->complete&&!p->held&&!p->first_error&&p->sequence==ref->sequence;
}
static void source_closed(struct run_record *r) {
    struct sample *s=&r->state;
    need(!memcmp((const void *)s->mapping,r->literal_source,CODE_BYTES),300);
    for(size_t i=0;i<CODE_BYTES/PAGE;i++)need(actual_protection(s->mapping+i*PAGE,0)==PROT_READ,301);
}
static void fallback_arm(unsigned index) {
    struct sample *s=&running->state;
    memset(&fallback_source,0,sizeof(fallback_source));
    fallback_source.mapping=s->mapping;fallback_source.pc=s->pc+index;
    fallback_source.length=1;fallback_source.count=1;
    memcpy(fallback_source.source,running->literal_source,CODE_BYTES);borrow(&fallback_source);
    need(!li2_decoder_decode(fallback_source.pc,(const void *)fallback_source.pc,1,&fallback_source.decoded)&&
         fallback_source.decoded.length==1&&fallback_source.decoded.bytes[0]==0x90,302);
    struct li2_step_request req={.decoded=fallback_source.decoded,.page_count=1,.original_flags=s->initial_flags};
    req.pages[0]=(struct li2_step_page){fallback_source.pages[0].address,
        fallback_source.pages[0].allocation,fallback_source.pages[0].generation,
        fallback_source.pages[0].offset,PROT_READ,PROT_READ|PROT_EXEC};
    const struct li2_step_hooks hooks={&fallback_source,authenticate,fallback_failure};
    need(!li2_step_arm(&tail.fallback[index],&session,&hooks,&req,0),303);
}
static void register_handler(int sig,siginfo_t *si,void *frame_) {
    if(register_handling||publishing) {
        if(cache)(void)li2_run_cache_interrupt(cache,LI2_CACHE_REENTRY,sig);
        if(tail.active.phase!=LI2_RUN_EMPTY)li2_run_unexpected(&tail.active,sig,si,frame_);
        die(304);
    }
    register_handling=1;need(running&&si&&frame_,305);
    struct run_record *r=running;struct sample *s=&r->state;ucontext_t *uc=frame_;
    greg_t *g=uc->uc_mcontext.gregs;
    if(sig==SIGTRAP){++r->trap_events;if(si->si_code==TRAP_TRACE)++r->trace_events;}
    if(route==0) {
        if(!reference_phase) {
            need(nx(sig,si,g,s->pc)&&(uint64_t)g[REG_EFL]==(fixture_flags|LI2_STEP_RF),306);
            capture(&s->native_before,uc);permissions(s,PROT_READ|PROT_EXEC);reference_phase=1;
        } else {
            need(reference_phase==1&&sig==SIGTRAP&&si->si_code==SI_KERNEL&&!si->si_errno&&
                 si->si_signo==SIGTRAP&&g[REG_TRAPNO]==3&&!g[REG_ERR]&&
                 (uintptr_t)g[REG_RIP]==s->expected_post+1&&
                 (uint64_t)g[REG_EFL]==fixture_flags,307);
            capture(&s->native_after,uc);permissions(s,PROT_READ);reference_phase=2;
            s->native_complete=1;g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
        }
    } else if(route==1) {
        if(tail.active.phase==LI2_RUN_ARMED) {
            capture(&s->step_before,uc);++r->nx_entries;
            li2_run_begin(&tail.active,sig,si,uc);
        } else if(tail.active.phase==LI2_RUN_RUNNING) {
            li2_run_exit(&tail.active,sig,si,uc);++r->nx_exits;
            capture(&s->step_endpoint,uc);s->step_endpoint_seen=1;r->owner=tail.active;
            need(!li2_run_complete_reset(&tail.active,&tail.history,&protection,uc),308);
            need(zero(&tail.active,sizeof(tail.active))&&tail.history.reset_complete&&
                 !tail.history.first_error&&!memcmp(&tail.history.last_complete,&r->owner,sizeof(r->owner)),309);
            r->reset_complete=1;g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
        } else li2_run_unexpected(&tail.active,sig,si,uc);
    } else if(route==2) {
        struct li2_step_owner *o=&tail.fallback[fallback_index];
        if(o->phase==LI2_STEP_ARMED) {
            need(fallback_index==0&&nx(sig,si,g,s->pc),310);
            capture(&s->step_before,uc);++r->nx_entries;li2_step_begin(o,sig,si,uc);
        } else if(o->phase==LI2_STEP_RUNNING) {
            li2_step_trace(o,sig,si,uc);
        } else if(o->phase==LI2_STEP_COMPLETE) {
            need(nx(sig,si,g,s->pc+fallback_index+1)&&
                 (uint64_t)g[REG_EFL]==(s->initial_flags|LI2_STEP_RF),311);
            need(!li2_lifecycle_fetch_release(&fallback_source.ref),312);
            tail.fallback_releases[fallback_index]=*li2_lifecycle_fetch_progress();
            need(fetch_released(&tail.fallback_releases[fallback_index],&fallback_source.ref),313);
            if(!fallback_index) {
                fallback_index=1;fallback_arm(1);li2_step_begin(&tail.fallback[1],sig,si,uc);
            } else {
                /* Fresh real borrow/query of the still-NX original complete guard. */
                struct li2_fetch_ref guard={0};
                need(!li2_lifecycle_fetch_prepare(s->expected_post,2,&guard)&&
                     !li2_lifecycle_tf_continuation(&guard,s->expected_post,&tail.fallback_query)&&
                     tail.fallback_query.complete,314);
                capture(&s->step_endpoint,uc);s->step_endpoint_seen=1;++r->nx_exits;
                need(!li2_lifecycle_fetch_release(&guard),315);s->step_fetch=*li2_lifecycle_fetch_progress();
                need(fetch_released(&s->step_fetch,&guard),316);source_closed(r);
                g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
            }
        } else li2_step_abort(o,LI2_STEP_FOREIGN_EVENT,sig);
    } else die(317);
    fixture_vector_clobber();register_handling=0;
}
static void install_register_handler(void) {
    struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} action;
    action.handler=register_handler;action.flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL;
    action.restorer=step_restorer;action.mask=mask;
    need(!RAW(SYS_rt_sigaction,SIGSEGV,&action,0,8,0,0)&&
         !RAW(SYS_rt_sigaction,SIGTRAP,&action,0,8,0,0)&&
         !RAW(SYS_rt_sigaction,SIGSYS,&action,0,8,0,0),318);
}
static void prepare_run(struct run_record *r,unsigned case_index) {
    need(case_index<LI2_RUN_FIXTURE_CASE_COUNT,319);
    const struct li2_run_fixture_case *c=&li2_run_fixture_cases[case_index];
    struct sample *s=&r->state;r->case_index=case_index;r->started=1;
    s->id=100+case_index;s->length=c->length;s->endpoint_int3=1;
    long reserved=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reserved>0,320);s->mapping=(uintptr_t)reserved+PAGE;s->pc=s->mapping+c->page_offset;
    s->expected_post=s->pc+c->run_bytes;
    s->count=((s->pc+s->length-1)&~(PAGE-1))==(s->pc&~(PAGE-1))?1:2;
    memset(r->literal_source,0xcc,CODE_BYTES);memcpy(r->literal_source+c->page_offset,c->bytes,c->length);
    memcpy(r->native_source,r->literal_source,CODE_BYTES);
    r->native_source[c->page_offset+c->run_bytes]=0xcc;
    memcpy(s->source,r->native_source,CODE_BYTES);
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),321);
    memcpy((void *)s->mapping,s->source,CODE_BYTES);
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),322);
}
static void native_run(struct run_record *r) {
    struct sample *s=&r->state;running=r;current=s;fixture_target=s->pc;inputs(s);borrow(s);
    for(size_t i=0;i<s->count;i++)r->native_pages[i]=s->pages[i];
    route=0;reference_phase=0;fixture_enter();
    s->initial_flags=fixture_flags;s->post_flags=(uint64_t)s->native_after.frame.greg[REG_EFL];
    s->live[0]=fixture_live_before;s->live[1]=fixture_live_after;
    memcpy(s->actual_fp[0],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[1],fixture_fp_after,xsave_bytes);
    need(s->native_complete&&reference_phase==2&&s->post_flags==s->initial_flags&&
         !(s->initial_flags&(LI2_STEP_RF|LI2_STEP_TF))&&r->trap_events==1&&!r->trace_events,323);
    need(!memcmp((const void *)s->mapping,r->native_source,CODE_BYTES)&&
         !li2_lifecycle_fetch_release(&s->ref),324);s->native_fetch=*li2_lifecycle_fetch_progress();
    need(fetch_released(&s->native_fetch,&s->ref),325);++header.native_references;
}
static void restore_source(struct run_record *r) {
    struct sample *s=&r->state;
    need(!li2_lifecycle_fetch_interlock(),326);
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),327);
    memcpy((void *)s->mapping,r->literal_source,CODE_BYTES);
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),328);
    memcpy(s->source,r->literal_source,CODE_BYTES);source_closed(r);++header.source_restorations;
}
static void compare_run(struct run_record *r) {
    struct sample *s=&r->state;need(s->native_complete&&s->step_endpoint_seen&&r->nx_entries==1&&r->nx_exits==1,329);
    uint64_t expected[16];
    for(unsigned i=0;i<16;i++)expected[i]=(uint64_t)s->native_before.frame.greg[regs[i]];
    switch(r->case_index) {
    case 1:expected[0]=(expected[0]&~UINT64_C(0xffff))|0x1234;
           expected[1]=(expected[1]&~UINT64_C(0xffff))|0x1234;break;
    case 2:case 5:expected[0]=0x12345678;expected[1]=0x12345678;break;
    case 3:expected[1]=expected[0];expected[10]=expected[0];break;
    case 4:expected[0]=expected[4];expected[1]=expected[4];break;
    case 6:expected[1]=expected[0];break;
    default:break;
    }
    for(unsigned i=0;i<16;i++) {
        need(s->native_before.frame.greg[regs[i]]==s->step_before.frame.greg[regs[i]],330);
        need((uint64_t)s->native_after.frame.greg[regs[i]]==expected[i]&&
             (uint64_t)s->step_endpoint.frame.greg[regs[i]]==expected[i],331);
    }
    need((uint64_t)s->native_before.frame.greg[REG_EFL]==(s->initial_flags|LI2_STEP_RF)&&
         (uint64_t)s->native_after.frame.greg[REG_EFL]==s->initial_flags&&
         (uint64_t)s->step_before.frame.greg[REG_EFL]==(s->initial_flags|LI2_STEP_RF)&&
         (uint64_t)s->step_endpoint.frame.greg[REG_EFL]==(s->initial_flags|LI2_STEP_RF),332);
    need((uintptr_t)s->native_after.frame.greg[REG_RIP]==s->expected_post+1&&
         s->native_after.frame.greg[REG_TRAPNO]==3&&!s->native_after.frame.greg[REG_ERR]&&
         (uintptr_t)s->step_endpoint.frame.greg[REG_RIP]==s->expected_post&&
         s->step_endpoint.frame.greg[REG_TRAPNO]==14&&s->step_endpoint.frame.greg[REG_ERR]==21,333);
    const struct state *states[4]={&s->native_before,&s->native_after,&s->step_before,&s->step_endpoint};
    for(unsigned i=0;i<4;i++) {
        compare_memory(states[0],states[i],334);
        need(states[i]->fs==states[0]->fs&&states[i]->gs==states[0]->gs,335);
        const struct li2_step_frame *f=&states[i]->frame;
        need(f->initialized==f->fp_bytes&&f->fp_bytes==states[0]->frame.fp_bytes&&
             f->mask==mask&&f->greg[REG_CSGSFS]==states[0]->frame.greg[REG_CSGSFS]&&
             !memcmp(f->fp,states[0]->frame.fp,f->fp_bytes),336);
        const struct live *l=&s->live[i];
        need(l->started==1&&l->complete==1&&!l->reserved&&l->rflags==s->initial_flags,337);
        for(unsigned j=0;j<16;j++)need(l->gpr[j]==(uint64_t)f->greg[regs[j]],338);
        for(unsigned j=0;j<6;j++)need(l->selectors[j]==s->live[0].selectors[j],339);
        need(l->selectors[0]==((uint64_t)f->greg[REG_CSGSFS]&0xffff)&&
             l->selectors[1]==((uint64_t)f->greg[REG_CSGSFS]>>48),340);
        need(!memcmp(s->actual_fp[0],s->actual_fp[i],xsave_bytes),341);
    }
    if(r->route==1) {
        const struct li2_run_owner *o=&r->owner;
        need(o->phase==LI2_RUN_COMPLETE&&!o->first_error&&!o->in_handler&&!o->failure_notified&&
             o->redirected==1&&o->exit_seen==1&&!o->nested.event.observed,342);
        need(o->entry_event.observed==1&&o->exit_event.observed==1&&o->entry_event.number==SIGSEGV&&
             o->exit_event.number==SIGSEGV&&o->entry_event.code==SEGV_ACCERR&&o->exit_event.code==SEGV_ACCERR&&
             !o->entry_event.error&&!o->exit_event.error,343);
        need(!memcmp(o->before.greg,s->step_before.frame.greg,sizeof(o->before.greg))&&
             !memcmp(o->after.greg,s->step_endpoint.frame.greg,sizeof(o->after.greg)),344);
        const struct li2_step_frame *f[2]={&o->before,&o->after};
        for(unsigned i=0;i<2;i++)need(f[i]->initialized==f[i]->fp_bytes&&f[i]->fp_bytes==states[0]->frame.fp_bytes&&
            f[i]->mask==mask&&!memcmp(f[i]->fp,states[0]->frame.fp,f[i]->fp_bytes),345);
        need(o->pre_entry.complete&&o->pre_entry.attempted&&o->pre_entry.page_observed&&!o->pre_entry.result&&
             o->exit_query.complete&&o->exit_query.attempted&&o->exit_query.page_observed&&!o->exit_query.result&&
             o->pre_entry.pc==s->expected_post&&o->exit_query.pc==s->expected_post&&
             o->release_started&&o->release_complete&&!o->release_result&&fetch_released(&o->final_fetch,&o->borrow),346);
        need(r->reset_complete&&r->history_after==r->history_before+1&&
             r->copied_after==r->copied_before+r->plan.instruction_count&&r->trace_events==0&&r->trap_events==1,347);
        need(r->publication.phase==LI2_PUBLICATION_COMPLETE&&!r->publication.first_error&&
             r->publication.fill_bytes==PAGE&&r->publication.code_bytes==r->plan.generated_length&&
             r->publication.verified_bytes==PAGE&&r->publication.rw_checked&&r->publication.rx_started&&
             r->publication.rx_complete&&!r->publication.rx_result&&r->publication.sync_started&&
             r->publication.sync_complete&&!r->publication.sync_result&&!r->publication.cleanup_started,348);
        need(r->last_query.complete&&r->last_query.pages_checked==1&&
             r->last_query.actual_prot==(PROT_READ|PROT_EXEC)&&
             actual_protection(r->publication.entry,0)==(PROT_READ|PROT_EXEC),349);
        for(size_t i=0;i<PAGE;i++)need(((const unsigned char *)r->publication.entry)[i]==
            (i<r->plan.generated_length?r->plan.generated[i]:0xcc),350);
    } else {
        need(r->route==2&&r->case_index==0&&r->trace_events==2&&r->trap_events==3&&
             !r->reset_complete&&zero(&r->owner,sizeof(r->owner)),352);
        for(unsigned i=0;i<2;i++) {
            const struct li2_step_owner *o=&tail.fallback[i];
            need(o->phase==LI2_STEP_COMPLETE&&!o->first_error&&o->trace_seen&&
                 o->open_started[0]&&o->opened[0]&&o->revoke_started[0]&&o->revoked[0]&&
                 !o->open_result[0]&&!o->revoke_result[0]&&!o->open_sync&&!o->revoke_sync&&
                 o->revoke_sync_started&&(uintptr_t)o->after.greg[REG_RIP]==s->pc+i+1&&
                 (uint64_t)o->after.greg[REG_EFL]==(s->initial_flags|LI2_STEP_TF),353);
            for(unsigned j=0;j<16;j++)need((uint64_t)o->before.greg[regs[j]]==expected[j]&&
                (uint64_t)o->after.greg[regs[j]]==expected[j],354);
            need(o->before.fp_bytes==states[0]->frame.fp_bytes&&o->after.fp_bytes==states[0]->frame.fp_bytes&&
                 !memcmp(o->before.fp,states[0]->frame.fp,o->before.fp_bytes)&&
                 !memcmp(o->after.fp,states[0]->frame.fp,o->after.fp_bytes),355);
        }
    }
    for(size_t i=0;i<s->count;i++)need(s->pages[i].generation!=r->native_pages[i].generation&&
        s->pages[i].allocation==r->native_pages[i].allocation,351);
    need(!memcmp(s->source,r->literal_source,CODE_BYTES)&&
         !memcmp(r->native_source,r->literal_source,(size_t)(s->expected_post-s->mapping))&&
         r->native_source[s->expected_post-s->mapping]==0xcc&&
         !memcmp(r->native_source+(s->expected_post-s->mapping)+1,
                 r->literal_source+(s->expected_post-s->mapping)+1,
                 CODE_BYTES-(size_t)(s->expected_post-s->mapping)-1),356);
    source_closed(r);r->checked=1;s->checked=1;++header.completed_records;
}
static int publish_run(struct run_record *r,int expected_hit,int permit_full) {
    struct sample *s=&r->state;running=r;current=s;inputs(s);fixture_target=s->pc;borrow(s);
    need(!li2_run_plan_bytes(s->pc,(const void *)s->pc,s->length,&r->plan)&&
         r->plan.stop==s->expected_post&&r->plan.run_length==li2_run_fixture_cases[r->case_index].run_bytes&&
         r->plan.instruction_count==li2_run_fixture_cases[r->case_index].copied_instructions&&
         r->plan.source_length==s->length&&!memcmp(r->plan.source,(const void *)s->pc,s->length),357);
    uint64_t before=tail.history.completed_runs;
    r->history_before=before;r->copied_before=tail.history.copied_instructions;
    publication=0;publishing=1;
    int status=li2_run_cache_publish(cache,&s->ref,&r->plan,&publication);
    publishing=0;r->published=*li2_run_cache_diagnostic(cache);
    r->publication_address=(uintptr_t)publication;
    need(r->published.last_attempt.source_complete&&r->published.last_attempt.plan_complete&&
         r->published.last_attempt.pages_validated==s->count&&
         r->published.last_attempt.borrow_sequence==s->ref.sequence&&
         r->published.last_attempt.fetch.held&&r->published.last_attempt.fetch.complete&&
         !r->published.last_attempt.fetch.first_error,382);
    if(status==LI2_RUN_SLOW) {
        need(permit_full&&!publication&&r->published.phase==LI2_CACHE_READY&&!r->published.first_error&&
             r->published.slots_used==64&&r->published.complete_slots==64&&
             r->published.last_attempt.complete&&r->published.last_attempt.miss_before_publication&&
             r->published.last_attempt.slot==64&&!r->published.last_attempt.hit,358);
        need(!li2_lifecycle_fetch_release(&s->ref)&&fetch_released(li2_lifecycle_fetch_progress(),&s->ref),359);
        route=2;r->route=2;fallback_index=0;fallback_arm(0);fixture_enter();
        r->finished=*li2_run_cache_diagnostic(cache);
        need(!memcmp(&r->finished,&r->published,sizeof(r->finished))&&tail.history.completed_runs==before,360);
        ++header.fallback_runs;header.fallback_trace_events+=r->trace_events;
    } else {
        need(!status&&!permit_full&&publication&&r->published.phase==LI2_CACHE_READY&&
             !r->published.first_error&&r->published.last_attempt.complete&&
             r->published.last_attempt.hit==(unsigned)expected_hit&&!r->published.last_attempt.miss_before_publication,361);
        const struct li2_run_publication_progress *p=li2_run_publication_progress(cache,publication);
        need(p!=0,362);r->publication=*p;
        const struct li2_run_publisher provider={cache,li2_run_publication_observe,run_failure};
        need(!li2_run_arm(&tail.active,&session,&s->ref,s->initial_flags,&provider,publication),363);
        route=1;r->route=1;fixture_enter();
        r->history_after=tail.history.completed_runs;r->copied_after=tail.history.copied_instructions;
        r->finished=*li2_run_cache_diagnostic(cache);
        const struct li2_private_code_query *q=li2_run_publication_last_query(cache,publication);
        need(q!=0,364);r->last_query=*q;
        ++header.published_runs;if(expected_hit)++header.hit_runs;
        header.generated_trace_events+=r->trace_events;
    }
    s->live[2]=fixture_live_before;s->live[3]=fixture_live_after;
    memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[3],fixture_fp_after,xsave_bytes);
    compare_run(r);return status;
}
static void positive_case(unsigned id,unsigned slot) {
    struct run_record *a=&li2_register_records[slot],*b=&li2_register_records[slot+1];
    prepare_run(a,id);*b=*a;b->repetition=1;
    native_run(a);native_run(b);restore_source(a);memcpy(b->state.source,b->literal_source,CODE_BYTES);
    need(!publish_run(a,0,0)&&!publish_run(b,1,0),365);
    need(a->publication_address==b->publication_address&&a->publication.entry==b->publication.entry&&
         a->publication.generation==b->publication.generation&&
         a->finished.slots_used==b->finished.slots_used&&
         b->finished.hits==a->finished.hits+1,366);
    for(size_t i=0;i<a->state.count;i++)need(!memcmp(&a->state.pages[i],&b->state.pages[i],sizeof(a->state.pages[i])),367);
}
static void save_capacity(struct run_record *r,unsigned ordinal) {
    struct capacity_record *c=&capacities[ordinal];
    *c=(struct capacity_record){.ordinal=ordinal,.pc=r->state.pc,.stop=r->state.expected_post,
        .source_allocation=r->state.pages[0].allocation,.source_generation=r->state.pages[0].generation,
        .slot=r->published.last_attempt.slot,.publication_allocation=r->publication.allocation,
        .publication_generation=r->publication.generation,.entry=r->publication.entry,
        .slots_used=r->finished.slots_used,.complete_slots=r->finished.complete_slots,
        .attempts=r->finished.attempts,.hits=r->finished.hits,.full_misses=r->finished.full_misses,
        .completed_runs=r->history_after,.native_generation=r->native_pages[0].generation,
        .checked=r->checked,.reset_complete=r->reset_complete,.nx_entries=r->nx_entries,.nx_exits=r->nx_exits};
    need(c->slot==ordinal&&c->slots_used==ordinal+1&&c->complete_slots==ordinal+1&&
         c->attempts==ordinal+1&&!c->hits&&!c->full_misses&&c->completed_runs==ordinal+1,368);
    digest((const unsigned char *)r,sizeof(*r),c->full_record_sha256);++header.completed_capacity;
}
static void capacity(void) {
    for(unsigned i=0;i<64;i++) {
        struct run_record *r=&li2_register_records[i==0?0:i==63?1:2];memset(r,0,sizeof(*r));
        prepare_run(r,0);native_run(r);restore_source(r);need(!publish_run(r,0,0),369);save_capacity(r,i);
    }
    struct run_record *slow=&li2_register_records[3];prepare_run(slow,0);native_run(slow);restore_source(slow);
    need(publish_run(slow,0,1)==LI2_RUN_SLOW&&slow->finished.attempts==65&&
         slow->finished.full_misses==1&&slow->finished.hits==0,370);
    struct run_record *hit=&li2_register_records[4];
    hit->state=li2_register_records[0].state;hit->case_index=0;hit->repetition=1;hit->started=1;
    memcpy(hit->native_source,li2_register_records[0].native_source,CODE_BYTES);
    memcpy(hit->literal_source,li2_register_records[0].literal_source,CODE_BYTES);
    memcpy(hit->native_pages,li2_register_records[0].native_pages,sizeof(hit->native_pages));
    /* The independent native reference was captured before this source's sole
       restoration/publication. Reuse its immutable capture, not its execution
       credit. Fresh actual cache entry/exit and a fresh borrow follow. */
    hit->trap_events=li2_register_records[0].trap_events; /* Retain the actual reference observation. */
    hit->state.step_endpoint_seen=0;hit->state.checked=0;
    memset(&hit->state.step_before,0,sizeof(hit->state.step_before));
    memset(&hit->state.step_endpoint,0,sizeof(hit->state.step_endpoint));
    need(!publish_run(hit,1,0)&&hit->publication_address==li2_register_records[0].publication_address&&
         hit->finished.slots_used==64&&hit->finished.complete_slots==64&&hit->finished.attempts==66&&
         hit->finished.hits==1&&hit->finished.full_misses==1&&tail.history.completed_runs==65,371);
    need(header.completed_capacity==64&&header.completed_records==66&&header.native_references==65&&
         header.published_runs==65&&header.hit_runs==1&&header.fallback_runs==1&&
         header.source_restorations==65&&!header.generated_trace_events&&header.fallback_trace_events==2,372);
}
int fixture_main(unsigned long *stack) {
    _Static_assert(REGISTER_GROUP>=0&&REGISTER_GROUP<=3,"closed group");
    _Static_assert(sizeof(header)+sizeof(samples[0])+sizeof(li2_register_records)+sizeof(capacities)+sizeof(tail)<16*1024*1024,
                   "bounded complete private output");
    header.magic=UINT64_C(0x314e55525232494c);header.version=1;header.group=REGISTER_GROUP;
    setup(stack);size_t done=0,failed=0;uint32_t decoder=0;
    need(!li2_tf_refusal_controls(&done,&failed,&decoder,&refused_last)&&done==47&&failed==SIZE_MAX&&!decoder,373);
    header.refusals=done;prepare_case(&samples[0],0);run_pair(&samples[0]);
    need(session.self_test_complete&&samples[0].checked&&result.completed==1,374);
    need(!li2_run_cache_initialize(&session,&protection,&cache)&&cache,375);
    need(contains(0,(uintptr_t)&tail.active,sizeof(tail.active))&&
         contains(0,(uintptr_t)&tail.history,sizeof(tail.history)),376);
    install_register_handler();need(!li2_decoder_stats(&tail.decoder_before)&&tail.decoder_before.phase==2,377);
    if(REGISTER_GROUP<3) {
        for(unsigned i=0;i<3;i++)positive_case(REGISTER_GROUP*3+i,i*2);
        const struct li2_run_cache_diagnostic *d=li2_run_cache_diagnostic(cache);
        need(header.completed_records==6&&header.native_references==6&&header.published_runs==6&&
             header.hit_runs==3&&!header.fallback_runs&&header.source_restorations==3&&
             !header.generated_trace_events&&!header.fallback_trace_events&&tail.history.completed_runs==6&&
             d->phase==LI2_CACHE_READY&&!d->first_error&&d->slots_used==3&&d->complete_slots==3&&
             d->attempts==6&&d->hits==3&&!d->full_misses,378);
    } else capacity();
    need(!li2_decoder_stats(&tail.decoder_after)&&!memcmp(&tail.decoder_before,&tail.decoder_after,sizeof(tail.decoder_before)),379);
    need(!li2_lifecycle_fetch_interlock()&&zero(&tail.active,sizeof(tail.active)),380);
    header.complete=1;need(register_dump(),381);
    output(REGISTER_GROUP<3?"LI2_REGISTER_RUN_PASS cases=3 records=6 native=6 miss=3 hit=3 trace=0\n":
           "LI2_REGISTER_CAPACITY_PASS slots=64 published=65 hit=1 fallback=1 fallback_trace=2\n");
    return 0;
}
