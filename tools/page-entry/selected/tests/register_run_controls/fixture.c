/* Finite terminal controls. Supplied raw failures are explicitly recorded;
   actual mappings/signals/kernel outcomes are never replaced by success. */
static _Noreturn void control_lifecycle_fail(unsigned,long);
#include "control_support.inc"
#include <errno.h>

enum control_kind { CORRUPT_HIT,NON_RX_HIT,WRONG_PLAN,RELEASED_BORROW,
    WRONG_PUBLICATION,SOURCE_MUTATION,PREMATURE_RESET,FAILED_RESET,
    PROTECTED_MPROTECT,BRK_HOLE,RAW_RX_ERROR,RAW_SYNC_ERROR,NESTED_WRITING,RAW_ALLOC_ERROR,CONTROL_COUNT };
static const char *const control_names[]={"corrupt-hit","non-rx-hit","wrong-plan","released-borrow",
    "wrong-publication","source-mutation","premature-reset","failed-reset","protected-mprotect",
    "brk-hole","raw-rx-error","raw-sync-error","nested-writing","raw-allocation-error"};
struct raw_event {
    long number,args[6],actual_args[6],actual_result,returned_result;
    unsigned issued,complete,failure_injected,placement_redirected,signal_sent;
};
struct control_record {
    uint64_t magic,version,bytes,mode,expected_error,expected_failure_verified;
    uint64_t raw_calls,injections,signals,publication_started,publication_returned;
    long operation_result,primary_error,secondary_error,secondary_detail;
    long mutation_results[4],break_before,break_grown,break_after;
    long guarded_number,guarded_args[6],guard_error,guard_returned,signal_sender_pid,signal_sender_uid;
    uintptr_t hole,entry;
    unsigned char original_byte,changed_byte;
    struct li2_run_event actual_event;
    struct state actual_frame;
    struct li2_run_owner owner_before_reset,owner_after_reset;
    struct li2_run_publication_progress publication_before,publication_after;
    struct li2_run_cache_diagnostic cache_before,cache_after;
    struct li2_fetch_progress fetch_before,fetch_after;
    struct li2_run_plan supplied_plan;
    struct li2_run_slot_observation rejected_slot;
    struct raw_event raw[128];
};
static struct control_record ctl;
static unsigned injected_once,signal_once;

static int register_dump(void) {
    ctl.bytes=sizeof(ctl);
    if(cache)ctl.cache_after=*li2_run_cache_diagnostic(cache);
    ctl.fetch_after=*li2_lifecycle_fetch_progress();
    if(cache&&publication) {
        const struct li2_run_publication_progress *p=li2_run_publication_progress(cache,publication);
        if(p)ctl.publication_after=*p;
    }
    return positive_dump()&&write_all(3,&ctl,sizeof(ctl));
}
static _Noreturn void expected(unsigned code) {
    need(code==ctl.expected_error&&!result.fixture_failure&&!header.complete,500);
    need(tail.decoder_before.phase==2&&!li2_decoder_stats(&tail.decoder_after)&&
         !memcmp(&tail.decoder_before,&tail.decoder_after,sizeof(tail.decoder_before)),558);
    ctl.primary_error=code;ctl.expected_failure_verified=1;
    need(register_dump(),501);output("LI2_REGISTER_EXPECTED_FAILURE ");output(control_names[ctl.mode]);output("\n");
    (void)RAW(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static void closed_original(void) {
    if(running)for(size_t i=0;i<running->state.count;i++)
        need(actual_protection(running->state.pages[i].address,0)==PROT_READ,502);
}
static void publication_failed(unsigned code,long detail) {
    const struct li2_run_publication_progress *p=li2_run_publication_progress(cache,publication);
    const struct li2_run_cache_diagnostic *d=li2_run_cache_diagnostic(cache);
    need(p&&p->phase==LI2_PUBLICATION_FAILED&&p->entry&&p->first_error==code&&p->first_detail==detail&&
         p->cleanup_started&&p->cleanup_complete&&!p->cleanup_result&&p->cleanup_sync_started&&
         !p->cleanup_sync_result&&p->cleanup.complete&&p->cleanup.pages_checked==1&&
         actual_protection(p->entry,0)==PROT_READ,503);
    need(d->phase==LI2_CACHE_FAILED&&d->first_error==code&&d->first_detail==detail&&
         d->slots_used==1&&!d->complete_slots&&d->last_attempt.first_error==code&&
         d->last_attempt.first_detail==detail&&!d->last_attempt.complete,504);
    need(li2_lifecycle_fetch_progress()->held&&li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,505);
    closed_original();ctl.publication_after=*p;
}
/* Only register_run_publish.c is linked to this named raw adapter. Every
   unmodified call reaches the real gateway. A negative injection issues no
   substituted kernel operation and is distinct from an observed kernel error. */
long li2_control_raw(long n,long a,long b,long c,long d,long e,long f) {
    need(ctl.raw_calls<128,506);struct raw_event *o=&ctl.raw[ctl.raw_calls++];
    *o=(struct raw_event){.number=n,.args={a,b,c,d,e,f},.actual_args={a,b,c,d,e,f}};
    if(ctl.mode==RAW_ALLOC_ERROR&&!injected_once&&n==SYS_mmap&&b==LI2_RUN_CACHE_BYTES) {
        need(a==0&&c==(PROT_READ|PROT_WRITE)&&d==(MAP_PRIVATE|MAP_ANONYMOUS)&&e==-1&&!f,507);
        injected_once=1;++ctl.injections;o->failure_injected=1;o->returned_result=-ENOMEM;o->complete=1;return -ENOMEM;
    }
    if(ctl.mode==BRK_HOLE&&n==SYS_mmap&&b==LI2_RUN_CACHE_BYTES) {
        need(!injected_once&&ctl.hole&&a==0&&c==(PROT_READ|PROT_WRITE)&&
             d==(MAP_PRIVATE|MAP_ANONYMOUS)&&e==-1&&!f,508);
        injected_once=1;o->placement_redirected=1;
        o->actual_args[0]=(long)ctl.hole;o->actual_args[3]|=MAP_FIXED_NOREPLACE;
    }
    const struct li2_run_publication_progress *p=cache&&publication?
        li2_run_publication_progress(cache,publication):0;
    if(p&&p->phase==LI2_PUBLICATION_WRITING&&!injected_once&&
       ((ctl.mode==RAW_RX_ERROR&&n==SYS_mprotect&&a==(long)p->entry&&b==PAGE&&c==(PROT_READ|PROT_EXEC))||
        (ctl.mode==RAW_SYNC_ERROR&&n==SYS_membarrier&&a==32&&p->rx_complete))) {
        injected_once=1;++ctl.injections;o->failure_injected=1;
        o->returned_result=ctl.mode==RAW_RX_ERROR?-EACCES:-EIO;o->complete=1;return o->returned_result;
    }
    if(ctl.mode==NESTED_WRITING&&!signal_once&&p&&p->phase==LI2_PUBLICATION_WRITING&&
       n==SYS_mprotect&&a==(long)p->entry&&b==PAGE&&c==(PROT_READ|PROT_EXEC)) {
        need(p->allocation&&p->generation&&p->borrow_sequence&&p->fill_bytes==PAGE&&
             p->code_bytes==running->plan.generated_length,509);
        signal_once=1;++ctl.signals;o->signal_sent=1;ctl.publication_before=*p;
        /* Real same-thread kernel delivery while the original call is pending.
           The actual handler must terminate; this mprotect never gets issued. */
        long sent=RAW(SYS_tgkill,session.pid,session.tid,SIGTRAP,0,0,0);
        o->returned_result=sent;die(510);
    }
    o->issued=1;o->actual_result=li2_step_raw(n,o->actual_args[0],o->actual_args[1],o->actual_args[2],
                                           o->actual_args[3],o->actual_args[4],o->actual_args[5]);
    o->returned_result=o->actual_result;o->complete=1;return o->returned_result;
}
static _Noreturn void control_lifecycle_fail(unsigned code,long detail) {
    if(ctl.mode!=PROTECTED_MPROTECT||code!=155||detail)lifecycle_fail(code,detail);
    need(publication&&ctl.entry&&actual_protection(ctl.entry,0)==(PROT_READ|PROT_EXEC)&&
         !li2_lifecycle_fetch_interlock(),511);
    ctl.guard_error=code;ctl.secondary_detail=detail;
    ctl.cache_after=*li2_run_cache_diagnostic(cache);
    need(!memcmp(&ctl.cache_after,&ctl.cache_before,sizeof(ctl.cache_before)),512);
    closed_original();expected(code);
}
static void control_handler(int sig,siginfo_t *si,void *frame_) {
    if(ctl.mode==NESTED_WRITING&&publishing) {
        need(!register_handling&&signal_once&&si&&frame_&&sig==SIGTRAP&&
             si->si_signo==SIGTRAP&&si->si_code==SI_TKILL&&!si->si_errno&&
             si->si_pid==session.pid&&si->si_uid==(unsigned)RAW(SYS_getuid,0,0,0,0,0,0),513);
        ctl.signal_sender_pid=si->si_pid;ctl.signal_sender_uid=si->si_uid;
        ctl.actual_event=(struct li2_run_event){.number=sig,.code=si->si_code,.error=si->si_errno,
            .address=0,.observed=1}; /* SI_TKILL has sender identity, not fault address. */
        capture(&ctl.actual_frame,frame_);
        ctl.operation_result=li2_run_cache_interrupt(cache,LI2_CACHE_REENTRY,sig);
        need(ctl.operation_result==LI2_CACHE_REENTRY&&!ctl.publication_returned,514);
        publication_failed(LI2_CACHE_REENTRY,sig);
        need(ctl.publication_before.entry==ctl.publication_after.entry&&
             ctl.publication_before.allocation==ctl.publication_after.allocation&&
             ctl.publication_before.generation==ctl.publication_after.generation&&
             ctl.publication_before.borrow_sequence==ctl.publication_after.borrow_sequence&&
             !ctl.publication_after.rx_complete&&!ctl.publication_after.sync_started,515);
        expected(LI2_CACHE_REENTRY);
    }
    if((ctl.mode==PREMATURE_RESET||ctl.mode==FAILED_RESET)&&route==3) {
        ucontext_t *uc=frame_;
        need(si&&uc&&nx(sig,si,uc->uc_mcontext.gregs,running->state.pc)&&
             (uint64_t)uc->uc_mcontext.gregs[REG_EFL]==(fixture_flags|LI2_STEP_RF),516);
        ctl.actual_event=(struct li2_run_event){.number=sig,.code=si->si_code,.error=si->si_errno,
            .address=(uintptr_t)si->si_addr,.observed=1};
        capture(&ctl.actual_frame,uc);ctl.owner_before_reset=tail.active;
        ctl.secondary_error=li2_run_complete_reset(&tail.active,&tail.history,&protection,uc);
        ctl.secondary_detail=tail.history.first_detail;ctl.owner_after_reset=tail.active;
        need(ctl.secondary_error==LI2_CACHE_RESET&&tail.history.first_error==LI2_CACHE_RESET&&
             ctl.secondary_detail==3&&!tail.history.reset_started&&!tail.history.reset_complete&&
             !tail.history.completed_runs&&!tail.history.copied_instructions&&
             !memcmp(&ctl.owner_before_reset,&ctl.owner_after_reset,sizeof(tail.active)),517);
        uint64_t observed_mask=0;memcpy(&observed_mask,&uc->uc_sigmask,sizeof(observed_mask));
        need(!memcmp(uc->uc_mcontext.gregs,ctl.actual_frame.frame.greg,sizeof(ctl.actual_frame.frame.greg))&&
             observed_mask==ctl.actual_frame.frame.mask&&
             (uintptr_t)uc->uc_mcontext.fpregs==ctl.actual_frame.frame.fp_address&&
             !memcmp(uc->uc_mcontext.fpregs,ctl.actual_frame.frame.fp,ctl.actual_frame.frame.fp_bytes),555);
        need((ctl.mode==PREMATURE_RESET&&tail.active.phase==LI2_RUN_ARMED&&!tail.active.first_error)||
             (ctl.mode==FAILED_RESET&&tail.active.phase==LI2_RUN_FAILED&&tail.active.first_error==LI2_RUN_PUBLICATION),518);
        closed_original();expected((unsigned)ctl.expected_error);
    }
    register_handler(sig,si,frame_);
}
static void install_control_handler(void) {
    struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} action;
    action.handler=control_handler;action.flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL;
    action.restorer=step_restorer;action.mask=mask;
    need(!RAW(SYS_rt_sigaction,SIGSEGV,&action,0,8,0,0)&&
         !RAW(SYS_rt_sigaction,SIGTRAP,&action,0,8,0,0)&&
         !RAW(SYS_rt_sigaction,SIGSYS,&action,0,8,0,0),519);
}
static void actual_heap_hole(void) {
    ctl.break_before=RAW(SYS_brk,0,0,0,0,0,0);
    need(ctl.break_before>0&&(uintptr_t)ctl.break_before<UINTPTR_MAX-LI2_RUN_CACHE_BYTES-3*PAGE,520);
    ctl.hole=((uintptr_t)ctl.break_before+PAGE-1)&~(PAGE-1);
    uintptr_t end=ctl.hole+LI2_RUN_CACHE_BYTES+PAGE;
    ctl.break_grown=RAW(SYS_brk,end,0,0,0,0,0);need(ctl.break_grown==(long)end,521);
    ctl.mutation_results[0]=RAW(SYS_munmap,ctl.hole,LI2_RUN_CACHE_BYTES,0,0,0,0);
    need(!ctl.mutation_results[0],522);
}
static void fresh_source(void) {
    struct run_record *r=&li2_register_records[0];prepare_run(r,0);native_run(r);restore_source(r);
    running=r;current=&r->state;borrow(&r->state);
    need(!li2_run_plan_bytes(r->state.pc,(const void *)r->state.pc,r->state.length,&r->plan),523);
    ctl.supplied_plan=r->plan;ctl.fetch_before=*li2_lifecycle_fetch_progress();
}
static int publish(void) {
    ctl.publication_started=1;publishing=1;
    int rc=li2_run_cache_publish(cache,&running->state.ref,&ctl.supplied_plan,&publication);
    publishing=0;ctl.publication_returned=1;ctl.operation_result=rc;return rc;
}
static void publish_valid(void) {
    need(!publish()&&publication,524);
    const struct li2_run_publication_progress *p=li2_run_publication_progress(cache,publication);
    need(p&&p->phase==LI2_PUBLICATION_COMPLETE&&!p->first_error&&p->fill_bytes==PAGE&&
         p->verified_bytes==PAGE&&p->code_bytes==running->plan.generated_length&&
         p->rx_complete&&p->sync_complete&&!p->rx_result&&!p->sync_result,525);
    ctl.publication_before=*p;ctl.entry=p->entry;
    need(actual_protection(ctl.entry,0)==(PROT_READ|PROT_EXEC),526);
}
static void reborrow(void) {
    need(!li2_lifecycle_fetch_release(&running->state.ref),527);
    borrow(&running->state);ctl.fetch_before=*li2_lifecycle_fetch_progress();
}
static void failed_cache(unsigned code,long detail,unsigned slots) {
    const struct li2_run_cache_diagnostic *d=li2_run_cache_diagnostic(cache);
    need(d->phase==LI2_CACHE_FAILED&&d->first_error==code&&d->first_detail==detail&&
         d->slots_used==slots&&d->complete_slots==slots&&
         !d->last_attempt.complete&&d->last_attempt.first_error==code&&
         d->last_attempt.first_detail==detail,528);
    closed_original();expected(code);
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(header)+sizeof(samples[0])+sizeof(li2_register_records)+sizeof(capacities)+sizeof(tail)+sizeof(ctl)<16*1024*1024,
                   "bounded failure record including original full fixture prefix");
    need(stack[0]<128,556);
    const char *const *argv=(const void *)(stack+1),*const *env=argv+stack[0]+1;
    const char *name=0;unsigned hits=0;
    for(size_t i=0;env[i];i++) {
        need(i<1024,529);const char key[]="LI2_REGISTER_CONTROL=";
        if(length(env[i])>=sizeof(key)-1&&!memcmp(env[i],key,sizeof(key)-1)){name=env[i]+sizeof(key)-1;++hits;}
    }
    need(hits==1&&name,530);unsigned index=0;while(index<CONTROL_COUNT&&!same(name,control_names[index]))++index;
    need(index<CONTROL_COUNT,531);ctl.mode=index;ctl.magic=UINT64_C(0x314c52544332494c);ctl.version=1;
    static const unsigned errors[CONTROL_COUNT]={LI2_CACHE_BYTES,LI2_CACHE_QUERY,LI2_CACHE_PLAN,LI2_CACHE_SOURCE,
        LI2_RUN_PUBLICATION,LI2_CACHE_SOURCE,LI2_CACHE_RESET,LI2_RUN_PUBLICATION,155,LI2_CACHE_BRK,
        LI2_CACHE_RX,LI2_CACHE_SYNC,LI2_CACHE_REENTRY,LI2_CACHE_ALLOCATION};
    ctl.expected_error=errors[index];header.magic=UINT64_C(0x314e55525232494c);header.version=1;header.group=4;
    setup(stack);size_t done=0,failed=0;uint32_t decoder=0;
    need(!li2_tf_refusal_controls(&done,&failed,&decoder,&refused_last)&&done==47&&failed==SIZE_MAX&&!decoder,532);
    header.refusals=done;prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,533);
    need(!li2_decoder_stats(&tail.decoder_before)&&tail.decoder_before.phase==2,559);
    install_control_handler();
    need(!protect_add(0,(uintptr_t)&tail.active,sizeof(tail.active))&&
         !protect_add(0,(uintptr_t)&tail.history,sizeof(tail.history)),557);
    if(index==BRK_HOLE)actual_heap_hole();
    int init=li2_run_cache_initialize(&session,&protection,&cache);
    if(index==RAW_ALLOC_ERROR) {
        const struct li2_run_cache_diagnostic *d=li2_run_cache_diagnostic(cache);
        need(init==LI2_CACHE_ALLOCATION&&d->phase==LI2_CACHE_FAILED&&d->first_error==LI2_CACHE_ALLOCATION&&
             d->first_detail==-ENOMEM&&d->initialization.metadata_complete&&d->initialization.allocation_started&&
             d->initialization.allocation_result==-ENOMEM&&!d->initialization.allocated&&
             !d->initialization.arena_protection_started&&!d->initialization.complete&&
             !d->slots_used&&!d->attempts&&ctl.injections==1,534);expected(LI2_CACHE_ALLOCATION);
    }
    need(!init&&cache,535);
    if(index==BRK_HOLE) {
        const struct li2_run_cache_diagnostic *d=li2_run_cache_diagnostic(cache);
        need(d->initialization.arena==ctl.hole&&d->initialization.mapping.complete&&
             d->initialization.mapping.pages_checked==64&&actual_protection(ctl.hole,0)==(PROT_READ|PROT_WRITE),536);
        ctl.guarded_number=SYS_brk;ctl.guarded_args[0]=ctl.break_before;
        ctl.operation_result=li2_run_cache_before_syscall(cache,ctl.guarded_number,ctl.guarded_args);
        ctl.guard_returned=1;
        ctl.break_after=RAW(SYS_brk,0,0,0,0,0,0);d=li2_run_cache_diagnostic(cache);
        need(ctl.operation_result==LI2_CACHE_BRK&&d->first_error==LI2_CACHE_BRK&&d->first_detail==SYS_brk&&
             d->last_brk.attempted&&!d->last_brk.complete&&d->last_brk.result==LI2_CACHE_BRK&&
             d->last_brk.requested==(uintptr_t)ctl.break_before&&d->last_brk.observed==(uintptr_t)ctl.break_grown&&
             ctl.break_after==ctl.break_grown&&actual_protection(ctl.hole,0)==(PROT_READ|PROT_WRITE),537);
        expected(LI2_CACHE_BRK);
    }
    fresh_source();
    if(index==WRONG_PLAN){ctl.supplied_plan.generated[0]^=1;need(publish()==LI2_CACHE_PLAN&&!publication,538);failed_cache(LI2_CACHE_PLAN,0,0);}
    if(index==RELEASED_BORROW){need(!li2_lifecycle_fetch_release(&running->state.ref),539);
        need(publish()==LI2_CACHE_SOURCE&&!publication&&!li2_lifecycle_fetch_progress()->held,540);
        failed_cache(LI2_CACHE_SOURCE,LI2_FETCH_STALE,0);}
    if(index==SOURCE_MUTATION) {
        uintptr_t first=running->state.pc&~(PAGE-1);ctl.original_byte=*(unsigned char *)running->state.pc;
        ctl.mutation_results[0]=RAW(SYS_mprotect,first,PAGE,PROT_READ|PROT_WRITE,0,0,0);need(!ctl.mutation_results[0],541);
        *(volatile unsigned char *)running->state.pc=ctl.original_byte^1;ctl.changed_byte=*(unsigned char *)running->state.pc;
        ctl.mutation_results[1]=RAW(SYS_mprotect,first,PAGE,PROT_READ,0,0,0);
        ctl.mutation_results[2]=RAW(SYS_membarrier,32,0,0,0,0,0);
        need(!ctl.mutation_results[1]&&!ctl.mutation_results[2]&&ctl.changed_byte==(unsigned char)(ctl.original_byte^1),542);
        need(publish()==LI2_CACHE_SOURCE&&!publication&&li2_lifecycle_fetch_progress()->first_error==LI2_FETCH_SOURCE,543);
        failed_cache(LI2_CACHE_SOURCE,LI2_FETCH_SOURCE,0);
    }
    if(index==RAW_RX_ERROR||index==RAW_SYNC_ERROR||index==NESTED_WRITING) {
        int rc=publish();need(index!=NESTED_WRITING&&rc==(int)ctl.expected_error&&ctl.injections==1,544);
        publication_failed((unsigned)ctl.expected_error,index==RAW_RX_ERROR?-EACCES:-EIO);
        need(ctl.publication_after.rx_started&&
             (index==RAW_RX_ERROR?(!ctl.publication_after.rx_complete&&ctl.publication_after.rx_result==-EACCES):
              (ctl.publication_after.rx_complete&&!ctl.publication_after.rx_result&&
               ctl.publication_after.sync_started&&!ctl.publication_after.sync_complete&&ctl.publication_after.sync_result==-EIO)),545);
        expected((unsigned)ctl.expected_error);
    }
    publish_valid();
    if(index==CORRUPT_HIT||index==NON_RX_HIT) {
        reborrow();ctl.mutation_results[0]=RAW(SYS_mprotect,ctl.entry,PAGE,index==CORRUPT_HIT?(PROT_READ|PROT_WRITE):PROT_READ,0,0,0);
        need(!ctl.mutation_results[0],546);
        if(index==CORRUPT_HIT) {
            ctl.original_byte=*(unsigned char *)ctl.entry;*(volatile unsigned char *)ctl.entry=ctl.original_byte^1;
            ctl.changed_byte=*(unsigned char *)ctl.entry;
            ctl.mutation_results[1]=RAW(SYS_mprotect,ctl.entry,PAGE,PROT_READ|PROT_EXEC,0,0,0);
            ctl.mutation_results[2]=RAW(SYS_membarrier,32,0,0,0,0,0);
            need(!ctl.mutation_results[1]&&!ctl.mutation_results[2]&&ctl.changed_byte==(unsigned char)(ctl.original_byte^1),547);
        }
        const struct li2_run_publication *old=publication;
        need(publish()==(int)ctl.expected_error&&!publication,548);publication=old;
        need(li2_run_cache_diagnostic(cache)->last_attempt.hit&&
             !li2_run_cache_diagnostic(cache)->hits&&actual_protection(ctl.entry,0)==
             (index==CORRUPT_HIT?(PROT_READ|PROT_EXEC):PROT_READ),549);
        failed_cache((unsigned)ctl.expected_error,index==CORRUPT_HIT?0:LI2_FETCH_PAGE,1);
    }
    if(index==PROTECTED_MPROTECT) {
        need(!li2_lifecycle_fetch_release(&running->state.ref),550);
        ctl.cache_before=*li2_run_cache_diagnostic(cache);
        ctl.guarded_number=SYS_mprotect;ctl.guarded_args[0]=(long)ctl.entry;
        ctl.guarded_args[1]=PAGE;ctl.guarded_args[2]=PROT_READ|PROT_WRITE;long out=0;
        (void)li2_lifecycle_dispatch(ctl.guarded_number,ctl.guarded_args,&out);ctl.guard_returned=1;die(551);
    }
    const struct li2_run_publisher provider={cache,li2_run_publication_observe,run_failure};
    const struct li2_run_publication *supplied=publication;
    if(index==WRONG_PUBLICATION||index==FAILED_RESET)
        supplied=(const struct li2_run_publication *)(uintptr_t)ctl.entry; /* real RX address, never an owner */
    int armed=li2_run_arm(&tail.active,&session,&running->state.ref,running->state.initial_flags,&provider,supplied);
    ctl.operation_result=armed;
    if(index==WRONG_PUBLICATION||index==FAILED_RESET) {
        need(armed==LI2_RUN_PUBLICATION&&tail.active.phase==LI2_RUN_FAILED&&
             tail.active.first_error==LI2_RUN_PUBLICATION&&!tail.active.redirected&&
             !tail.active.entry_event.observed&&tail.active.armed_slot.attempted&&
             !tail.active.armed_slot.owner_observed&&tail.active.armed_slot.callback_result==LI2_CACHE_QUERY,552);
        ctl.primary_error=armed;if(index==WRONG_PUBLICATION){closed_original();expected(LI2_RUN_PUBLICATION);}
    } else need(index==PREMATURE_RESET&&!armed&&tail.active.phase==LI2_RUN_ARMED,553);
    route=3;inputs(&running->state);fixture_target=running->state.pc;fixture_enter();die(554);
}
