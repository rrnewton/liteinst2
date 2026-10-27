/* Standalone native REP owner fixture; no connected production join.
   The inherited baseline and all 47 generic refusals remain unchanged. */
#include "repeat_owner.h"
#define fixture_main li2_unchanged_generic_fixture_main
#include "tests/generic/fixture.c"
#undef fixture_main

#define REPEAT_PAIRS 6
#define REPEAT_TRACES 4
enum repeat_phase { REPEAT_EMPTY, REPEAT_ARMED, REPEAT_RUNNING,
                    REPEAT_FINAL_TRACE, REPEAT_ENDPOINT, REPEAT_VERIFIED };
struct repeat_permission {
    uint64_t attempted, complete;
    long result;
    uint64_t validation_attempted;
    long validation_result;
    uint64_t sync_attempted;
    long sync_result;
};
struct repeat_event {
    long signal_number, signal_code, signal_errno;
    uintptr_t signal_address;
    uint64_t captured, remaining, progress, final;
    struct state state;
    struct li2_tf_continuation continuation;
    uint64_t continuation_calls, owner_observed, owner_returned;
    int continuation_result;
    struct li2_repeat_owner owner_after;
};
struct repeat_case {
    uintptr_t mapping, pc, next_pc;
    uint64_t count, direction, logical_flags, seed[16], phase;
    uint64_t native_completed, endpoint_seen, trace_count, checked;
    uint64_t classifier_checked, source_equal, source_closed, target_closed;
    struct li2_decoded decoded;
    struct li2_tf_classification refused;
    struct li2_fetch_page pages[2];
    struct li2_fetch_progress native_borrow, repeat_borrow;
    unsigned char source[CODE_BYTES];
    struct state before[2], after[2];
    struct live live[4];
    unsigned char actual_fp[4][FP_CAPACITY] __attribute__((aligned(64)));
    struct repeat_permission native_open, native_close;
    uint64_t arm_attempted, begin_returned, native_fault;
    int arm_result;
    struct li2_repeat_owner owner, begun_owner;
    struct repeat_event traces[REPEAT_TRACES];
};
struct repeat_header {
    uint64_t magic, version, header_bytes, case_bytes, event_bytes, selftest_bytes;
    uint64_t pairs, completed, traces, old_refusals, stosq_refusals;
    uint64_t xcr0, xsave_bytes, first_error, active_index, active_lane;
    uint64_t unexpected_observed, emergency_revoke_attempted;
    long emergency_revoke_result;
    uint64_t emergency_sync_attempted;
    long emergency_sync_result;
    uint64_t control, expected_failure_verified, owner_failure;
    uint64_t owner_detail_abs, owner_detail_negative;
};
static struct repeat_case repeats[REPEAT_PAIRS], *repeat_current;
static struct repeat_event unexpected;
static struct repeat_header repeat_result;
static unsigned repeat_lane, repeat_handling, repeat_failing, repeat_open_possible;
static struct sample *repeat_source;
static struct repeat_event *repeat_active_event;
static unsigned repeat_control;

static int repeat_dump(void) {
    repeat_result.header_bytes=sizeof(repeat_result);
    repeat_result.case_bytes=sizeof(struct repeat_case);
    repeat_result.event_bytes=sizeof(struct repeat_event);
    repeat_result.selftest_bytes=sizeof(struct sample);
    return write_all(3,&repeat_result,sizeof(repeat_result)) &&
           write_all(3,&samples[0],sizeof(samples[0])) &&
           write_all(3,repeats,sizeof(repeats)) &&
           write_all(3,&unexpected,sizeof(unexpected));
}
static _Noreturn void repeat_die(unsigned error) {
    if(!repeat_result.first_error)repeat_result.first_error=error;
    if(!repeat_failing++) {
        if(repeat_open_possible && repeat_source) {
            repeat_result.emergency_revoke_attempted=1;
            repeat_result.emergency_revoke_result=RAW(SYS_mprotect,
                repeat_source->pc&~(PAGE-1),PAGE,PROT_READ,0,0,0);
            repeat_result.emergency_sync_attempted=1;
            repeat_result.emergency_sync_result=RAW(SYS_membarrier,32,0,0,0,0,0);
        }
        (void)repeat_dump();output("LI2_REPEAT_OWNER_FAILURE ");number(error);
    }
    (void)RAW(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static void rneed(int yes,unsigned error) {if(!yes)repeat_die(error);}
/* Same actual kernel frame layout as the baseline capture helper, with this
   probe's own retained-failure destination. No frame is synthesized. */
static void repeat_capture(struct state *out,const ucontext_t *uc) {
    memcpy(out->frame.greg,uc->uc_mcontext.gregs,sizeof(out->frame.greg));
    memcpy(&out->frame.mask,&uc->uc_sigmask,8);
    out->frame.fp_address=(uintptr_t)uc->uc_mcontext.fpregs;
    rneed(out->frame.fp_address && !(out->frame.fp_address&15),400);
    const unsigned char *fp=(const void *)out->frame.fp_address;size_t n=512;
    if(u32(fp+464)==UINT32_C(0x46505853)) {
        n=u32(fp+468);size_t x=u32(fp+480);
        rneed(n>=580 && n<=FP_CAPACITY && x>=576 && x<=n-4 &&
              u32(fp+n-4)==UINT32_C(0x46505845),401);
    }
    out->frame.fp_bytes=n;
    for(size_t i=0;i<n;i++){out->frame.fp[i]=fp[i];out->frame.initialized=i+1;}
    memcpy(out->stack,(const void *)subject,SUBJECT_BYTES);
    memcpy(out->data,(const void *)data_page,DATA_BYTES);
    rneed(!RAW(SYS_arch_prctl,ARCH_GET_FS,&out->fs,0,0,0,0) &&
          !RAW(SYS_arch_prctl,ARCH_GET_GS,&out->gs,0,0,0,0),402);
}
static void repeat_event_capture(struct repeat_event *event,int sig,
                                 const siginfo_t *si,const ucontext_t *uc) {
    event->signal_number=sig;event->signal_code=si->si_code;
    event->signal_errno=si->si_errno;event->signal_address=(uintptr_t)si->si_addr;
    repeat_capture(&event->state,uc);event->captured=1;
}
static void repeat_permission(struct repeat_permission *p,int prot) {
    rneed(!p->attempted && repeat_source && repeat_source->count==1,403);
    if(prot==(PROT_READ|PROT_EXEC))repeat_open_possible=1;
    p->attempted=1;
    p->result=RAW(SYS_mprotect,repeat_source->pages[0].address,PAGE,prot,0,0,0);
    rneed(!p->result,404);
    p->validation_attempted=1;
    p->validation_result=li2_lifecycle_fetch_validate(&repeat_source->ref,0,prot);
    rneed(!p->validation_result && actual_protection(repeat_source->pc,0)==prot,405);
    p->sync_attempted=1;p->sync_result=RAW(SYS_membarrier,32,0,0,0,0,0);
    rneed(!p->sync_result,406);p->complete=1;
    if(prot==PROT_READ)repeat_open_possible=0;
}
static void repeat_frame_unchanged(const struct state *saved,const ucontext_t *uc,
                                  uint64_t expected_flags) {
    const greg_t *g=uc->uc_mcontext.gregs;
    for(size_t i=0;i<NGREG;i++)if(i!=REG_EFL)
        rneed(g[i]==saved->frame.greg[i],407);
    uint64_t actual_mask=0;memcpy(&actual_mask,&uc->uc_sigmask,8);
    rneed((uint64_t)g[REG_EFL]==expected_flags && actual_mask==saved->frame.mask &&
          (uintptr_t)uc->uc_mcontext.fpregs==saved->frame.fp_address &&
          !memcmp(uc->uc_mcontext.fpregs,saved->frame.fp,saved->frame.fp_bytes),408);
}
/* Independent literal STOSQ effects at every observed prefix; the native
   final lane is an additional reference, not the source of this expectation. */
static void repeat_effects(const struct repeat_case *r,const struct state *state,
                           const struct state *before,uint64_t progress) {
    rneed(progress<=r->count,409);
    for(unsigned i=0;i<16;i++) {
        uint64_t expected=r->seed[i];
        if(i==1)expected=r->count-progress;
        if(i==7)expected=r->direction?r->seed[7]-8*progress:r->seed[7]+8*progress;
        rneed((uint64_t)state->frame.greg[regs[i]]==expected,410);
    }
    rneed(!memcmp(state->stack,before->stack,SUBJECT_BYTES),411);
    for(size_t i=0;i<DATA_BYTES;i++) {
        unsigned char expected=before->data[i];
        for(uint64_t j=0;j<progress;j++) {
            uintptr_t address=r->direction?r->seed[7]-8*j:r->seed[7]+8*j;
            size_t offset=(size_t)(address-data_page);
            if(i>=offset && i<offset+8)expected=(unsigned char)(r->seed[0]>>(8*(i-offset)));
        }
        rneed(state->data[i]==expected,412);
    }
    rneed(state->frame.fp_bytes==before->frame.fp_bytes &&
          !memcmp(state->frame.fp,before->frame.fp,state->frame.fp_bytes) &&
          state->fs==before->fs && state->gs==before->gs &&
          state->frame.mask==mask && state->frame.greg[REG_CSGSFS]==before->frame.greg[REG_CSGSFS],413);
}
/* The real continuation API owns an attempted output. Every actual TRACE
   gets its own zero-initialized retained event, never a recycled sample slot. */
static int repeat_continue_closed(void *context,uintptr_t pc) {
    struct sample *s=context;struct repeat_event *event=repeat_active_event;
    if(s!=repeat_source || !event || event->continuation_calls)return LI2_FETCH_ARGUMENT;
    ++event->continuation_calls;
    event->continuation_result=li2_lifecycle_tf_continuation(&s->ref,pc,&event->continuation);
    return event->continuation_result;
}
static void repeat_owner_failure(void *context,const struct li2_step_owner *owner) {
    struct repeat_case *r=repeat_current;
    rneed(r && context==repeat_source && owner==&r->owner.step,450);
    repeat_result.owner_failure=owner->first_error;
    repeat_result.owner_detail_abs=owner->first_detail<0?0ULL-(uint64_t)owner->first_detail:(uint64_t)owner->first_detail;
    repeat_result.owner_detail_negative=owner->first_detail<0;
    if(repeat_active_event) {
        repeat_active_event->owner_after=r->owner;
        repeat_active_event->owner_observed=1;
    }
    if(repeat_control==1 && r->native_fault) {
        /* This is an actual first-store protection fault in both lanes.
           Native's redirected observer is diagnostic, not a completed REP. */
        rneed(repeat_lane==1 && r->count==1 && !r->direction &&
              !r->native_completed && !r->endpoint_seen && !r->checked &&
              owner->phase==LI2_STEP_FAILED && owner->first_error==LI2_STEP_FOREIGN_EVENT &&
              owner->first_detail==SIGSEGV && r->owner.unexpected_frame_observed &&
              !owner->trace_seen && !r->owner.traces && !r->trace_count &&
              r->owner.initial_count==1 && r->owner.remaining==1 && !r->owner.final &&
              !r->owner.closed_cycles && !r->owner.reopened_cycles &&
              !r->owner.continuation_started && !r->owner.continuation_complete,451);
        rneed(owner->signal_number==SIGSEGV && owner->signal_code==SEGV_ACCERR &&
              !owner->signal_errno && owner->signal_address==r->seed[7] &&
              owner->after.greg[REG_RIP]==(greg_t)r->pc && owner->after.greg[REG_TRAPNO]==14 &&
              owner->after.greg[REG_ERR]==7 && owner->after.mask==mask,452);
        for(size_t i=0;i<NGREG;i++)if(i!=REG_EFL)
            rneed(owner->after.greg[i]==r->after[0].frame.greg[i],453);
        rneed((uint64_t)owner->after.greg[REG_EFL]==
                  ((uint64_t)r->after[0].frame.greg[REG_EFL]|LI2_STEP_TF) &&
              owner->after.fp_bytes==r->after[0].frame.fp_bytes &&
              !memcmp(owner->after.fp,r->after[0].frame.fp,owner->after.fp_bytes),454);
        rneed(unexpected.captured && repeat_result.unexpected_observed &&
              !memcmp(owner->after.greg,unexpected.state.frame.greg,sizeof(owner->after.greg)) &&
              owner->after.fp_address==unexpected.state.frame.fp_address &&
              owner->after.fp_bytes==unexpected.state.frame.fp_bytes &&
              !memcmp(owner->after.fp,unexpected.state.frame.fp,owner->after.fp_bytes),455);
        repeat_effects(r,&unexpected.state,&r->before[1],0);
        rneed(!memcmp(unexpected.state.stack,r->after[0].stack,SUBJECT_BYTES) &&
              !memcmp(unexpected.state.data,r->after[0].data,DATA_BYTES) &&
              unexpected.state.fs==r->after[0].fs && unexpected.state.gs==r->after[0].gs &&
              unexpected.state.frame.mask==r->after[0].frame.mask &&
              !memcmp((const void *)subject,unexpected.state.stack,SUBJECT_BYTES) &&
              !memcmp((const void *)data_page,unexpected.state.data,DATA_BYTES),456);
        rneed(owner->request.page_count==1 && owner->open_started[0] && owner->opened[0] &&
              !owner->open_result[0] && owner->revoke_started[0] && owner->revoked[0] &&
              !owner->revoke_result[0] && !owner->open_sync && owner->revoke_sync_started &&
              !owner->revoke_sync && !owner->open_started[1] && !owner->revoke_started[1] &&
              !li2_lifecycle_fetch_validate(&repeat_source->ref,0,PROT_READ) &&
              actual_protection(r->pc,0)==PROT_READ && actual_protection(r->next_pc,0)==PROT_READ &&
              actual_protection(data_page,0)==PROT_READ &&
              !memcmp((const void *)r->mapping,r->source,CODE_BYTES),457);
        r->repeat_borrow=*li2_lifecycle_fetch_progress();
        rneed(r->repeat_borrow.complete && r->repeat_borrow.held &&
              r->native_borrow.complete && !r->native_borrow.held &&
              !memcmp(&r->pages[0],&r->pages[1],sizeof(r->pages[0])),458);
        r->live[2]=fixture_live_before;memcpy(r->actual_fp[2],fixture_fp_before,xsave_bytes);
        for(unsigned k=0;k<3;k++) {
            const struct state *state=k==0?&r->before[0]:k==1?&r->after[0]:&r->before[1];
            rneed(r->live[k].started && r->live[k].complete && !r->live[k].reserved &&
                  r->live[k].rflags==r->logical_flags,459);
            for(unsigned i=0;i<16;i++)rneed(r->live[k].gpr[i]==(uint64_t)state->frame.greg[regs[i]],460);
            for(unsigned i=0;i<6;i++)rneed(r->live[k].selectors[i]==r->live[0].selectors[i],461);
            rneed(!memcmp(r->actual_fp[0],r->actual_fp[k],xsave_bytes),462);
        }
        repeat_open_possible=0;repeat_result.expected_failure_verified=1;
        rneed(repeat_dump(),463);output("LI2_REPEAT_OWNER_EXPECTED_FAILURE ");number(owner->first_error);
    } else {
        (void)repeat_dump();output("LI2_REPEAT_OWNER_UNEXPECTED_FAILURE ");number(owner->first_error);
    }
    /* The real owner's abort path exits125 after this callback returns. */
}
static void repeat_arm_actual(struct repeat_case *r,struct sample *s) {
    struct li2_step_request request={.decoded=r->decoded,.page_count=s->count,
        .original_flags=fixture_input_flags};
    for(size_t i=0;i<s->count;i++)request.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
    struct li2_tf_hooks hooks={{s,authenticate,repeat_owner_failure},repeat_continue_closed};
    r->arm_attempted=1;r->arm_result=li2_repeat_arm(&r->owner,&session,&hooks,&request);
    if(r->arm_result)li2_repeat_abort(&r->owner,(unsigned)r->arm_result,0);
    rneed(r->owner.step.phase==LI2_STEP_ARMED && !r->owner.step.first_error,464);
}
static void repeat_handler(int sig,siginfo_t *si,void *context) {
    if(!repeat_current || !si || !context)repeat_die(414);
    ucontext_t *uc=context;greg_t *g=uc->uc_mcontext.gregs;
    struct repeat_case *r=repeat_current;
    if(repeat_handling) {
        repeat_result.unexpected_observed=1;
        repeat_event_capture(&unexpected,sig,si,uc);repeat_die(415);
    }
    repeat_handling=1;
    uint64_t actual_mask=0;memcpy(&actual_mask,&uc->uc_sigmask,8);
    if(actual_mask!=mask || RAW(SYS_getpid,0,0,0,0,0,0)!=session.pid ||
       RAW(SYS_gettid,0,0,0,0,0,0)!=session.tid ||
       ((uint64_t)g[REG_CSGSFS]&0xffff)!=0x33)goto unexpected_event;
    if(r->phase==REPEAT_ARMED) {
        if(!nx(sig,si,g,r->pc) || (uint64_t)g[REG_EFL]!=(fixture_flags|LI2_STEP_RF))goto unexpected_event;
        rneed(fixture_flags==fixture_input_flags && !(fixture_flags&(LI2_STEP_TF|LI2_STEP_RF)),416);
        r->logical_flags=fixture_flags;
        repeat_capture(&r->before[repeat_lane],uc);
        struct li2_decoded observed;
        rneed(!li2_decoder_decode(r->pc,(const void *)r->pc,3,&observed) &&
              !memcmp(&observed,&r->decoded,sizeof(observed)),417);
        if(repeat_lane) {
            repeat_open_possible=1;
            li2_repeat_begin(&r->owner,sig,si,uc);
            r->begun_owner=r->owner;r->begin_returned=1;
            rneed(r->owner.step.phase==LI2_STEP_RUNNING && !r->owner.step.first_error &&
                  r->owner.initial_count==r->count && r->owner.remaining==r->count &&
                  !memcmp(r->owner.step.before.greg,r->before[1].frame.greg,sizeof(r->owner.step.before.greg)) &&
                  r->owner.step.before.fp_address==r->before[1].frame.fp_address &&
                  r->owner.step.before.fp_bytes==r->before[1].frame.fp_bytes &&
                  !memcmp(r->owner.step.before.fp,r->before[1].frame.fp,r->before[1].frame.fp_bytes),465);
            rneed(!memcmp((const void *)subject,r->before[1].stack,SUBJECT_BYTES) &&
                  !memcmp((const void *)data_page,r->before[1].data,DATA_BYTES),477);
        } else repeat_permission(&r->native_open,PROT_READ|PROT_EXEC);
        fixture_vector_clobber();
        repeat_frame_unchanged(&r->before[repeat_lane],uc,
            r->logical_flags|LI2_STEP_RF|(repeat_lane?LI2_STEP_TF:0));
        r->phase=REPEAT_RUNNING;
    } else if(!repeat_lane && r->phase==REPEAT_RUNNING) {
        if(repeat_control==1) {
            if(sig!=SIGSEGV || si->si_code!=SEGV_ACCERR || si->si_errno ||
               (uintptr_t)si->si_addr!=r->seed[7] || (uintptr_t)g[REG_RIP]!=r->pc ||
               g[REG_TRAPNO]!=14 || g[REG_ERR]!=7)goto unexpected_event;
            repeat_capture(&r->after[0],uc);repeat_permission(&r->native_close,PROT_READ);
            rneed((uint64_t)g[REG_EFL]==(r->logical_flags|LI2_STEP_RF),466);
            repeat_effects(r,&r->after[0],&r->before[0],0);
            r->native_fault=1;r->phase=REPEAT_ENDPOINT;
            fixture_vector_clobber();repeat_frame_unchanged(&r->after[0],uc,r->logical_flags|LI2_STEP_RF);
            g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
            repeat_handling=0;return;
        }
        if(!nx(sig,si,g,r->next_pc))goto unexpected_event;
        repeat_capture(&r->after[0],uc);
        repeat_permission(&r->native_close,PROT_READ);
        rneed((uint64_t)g[REG_EFL]==(r->logical_flags|LI2_STEP_RF),418);
        repeat_effects(r,&r->after[0],&r->before[0],r->count);
        r->native_completed=1;r->phase=REPEAT_ENDPOINT;
        fixture_vector_clobber();repeat_frame_unchanged(&r->after[0],uc,r->logical_flags|LI2_STEP_RF);
        g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
    } else if(repeat_lane && r->phase==REPEAT_RUNNING) {
        if(sig!=SIGTRAP || si->si_code!=TRAP_TRACE || si->si_errno ||
           g[REG_TRAPNO]!=1 || g[REG_ERR] || (uintptr_t)si->si_addr!=(uintptr_t)g[REG_RIP])goto unexpected_event;
        rneed(r->trace_count<REPEAT_TRACES,419);
        struct repeat_event *event=&r->traces[r->trace_count++];++repeat_result.traces;
        repeat_event_capture(event,sig,si,uc);
        event->remaining=(uint64_t)g[REG_RCX];rneed(event->remaining<=r->count,420);
        event->progress=r->count-event->remaining;
        uint64_t previous=r->trace_count==1?0:r->traces[r->trace_count-2].progress;
        rneed((!r->count && r->trace_count==1 && !event->progress) || event->progress>previous,421);
        event->final=!event->remaining;
        uintptr_t expected_pc=event->final?r->next_pc:r->pc;
        uint64_t expected_flags=r->logical_flags|LI2_STEP_TF|(event->final?0:LI2_STEP_RF);
        rneed((uintptr_t)g[REG_RIP]==expected_pc && (uint64_t)g[REG_EFL]==expected_flags,422);
        repeat_effects(r,&event->state,&r->before[1],event->progress);
        repeat_active_event=event;
        li2_repeat_trace(&r->owner,sig,si,uc);
        event->owner_after=r->owner;event->owner_observed=1;event->owner_returned=1;
        repeat_active_event=0;
        rneed(event->continuation_calls==1 && !event->continuation_result &&
              event->continuation.complete && event->continuation.page_observed &&
              event->continuation.pc==expected_pc && event->continuation.page.closed_prot==PROT_READ,423);
        const struct li2_repeat_owner *o=&event->owner_after;
        rneed(!o->step.first_error && !o->step.in_handler && o->traces==r->trace_count &&
              o->closed_cycles==r->trace_count && o->reopened_cycles==r->trace_count-event->final &&
              o->remaining==event->remaining && o->final==event->final &&
              o->actual_post_pc==expected_pc && o->actual_post_flags==expected_flags &&
              o->continuation_started && o->continuation_complete && !o->continuation_result &&
              !memcmp(o->step.after.greg,event->state.frame.greg,sizeof(o->step.after.greg)) &&
              o->step.after.fp_address==event->state.frame.fp_address &&
              o->step.after.fp_bytes==event->state.frame.fp_bytes &&
              !memcmp(o->step.after.fp,event->state.frame.fp,o->step.after.fp_bytes),467);
        const struct li2_repeat_permissions *closed=&o->last_closed;
        rneed(closed->open_started[0] && closed->opened[0] && !closed->open_result[0] &&
              closed->revoke_started[0] && closed->revoked[0] && !closed->revoke_result[0] &&
              !closed->open_sync && closed->revoke_sync_started && !closed->revoke_sync &&
              !closed->open_started[1] && !closed->revoke_started[1],468);
        if(event->final) {
            rneed(o->step.phase==LI2_STEP_COMPLETE && o->step.revoked[0] &&
                  !li2_lifecycle_fetch_validate(&repeat_source->ref,0,PROT_READ),469);
            r->phase=REPEAT_FINAL_TRACE;repeat_open_possible=0;
        } else {
            rneed(o->step.phase==LI2_STEP_RUNNING && o->step.open_started[0] && o->step.opened[0] &&
                  !o->step.open_result[0] && !o->step.open_sync && !o->step.revoke_started[0] &&
                  !o->step.revoke_sync_started &&
                  !li2_lifecycle_fetch_validate(&repeat_source->ref,0,PROT_READ|PROT_EXEC),470);
        }
        rneed(actual_protection(r->pc,0)==(event->final?PROT_READ:PROT_READ|PROT_EXEC) &&
              actual_protection(r->next_pc,0)==PROT_READ,471);
        rneed(!memcmp((const void *)subject,event->state.stack,SUBJECT_BYTES) &&
              !memcmp((const void *)data_page,event->state.data,DATA_BYTES),478);
        fixture_vector_clobber();
        repeat_frame_unchanged(&event->state,uc,event->final?r->logical_flags:expected_flags);
    } else if(repeat_lane && r->phase==REPEAT_FINAL_TRACE) {
        if(!nx(sig,si,g,r->next_pc) || (uint64_t)g[REG_EFL]!=(r->logical_flags|LI2_STEP_RF))goto unexpected_event;
        repeat_capture(&r->after[1],uc);
        rneed(!li2_lifecycle_fetch_validate(&repeat_source->ref,0,PROT_READ) &&
              actual_protection(r->next_pc,0)==PROT_READ,424);
        r->endpoint_seen=1;r->phase=REPEAT_ENDPOINT;
        fixture_vector_clobber();repeat_frame_unchanged(&r->after[1],uc,r->logical_flags|LI2_STEP_RF);
        g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
    } else goto unexpected_event;
    repeat_handling=0;return;
unexpected_event:
    repeat_result.unexpected_observed=1;repeat_event_capture(&unexpected,sig,si,uc);
    if(repeat_lane && r->owner.step.phase==LI2_STEP_RUNNING)
        li2_repeat_unexpected(&r->owner,sig,si,uc);
    repeat_die(425);
}
static void repeat_prepare(unsigned index) {
    struct sample *s=&samples[index+1];struct repeat_case *r=&repeats[index];
    static const uint64_t counts[3]={0,1,3};static const unsigned char bytes[3]={0xf3,0x48,0xab};
    s->id=1000+index;s->length=3;s->count=1;
    long area=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    rneed(area>0,426);s->mapping=(uintptr_t)area+PAGE;
    rneed(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),427);
    memset(s->source,0xcc,CODE_BYTES);memcpy(s->source+PAGE-3,bytes,3);
    memcpy((void *)s->mapping,s->source,CODE_BYTES);
    s->pc=s->mapping+PAGE-3;s->expected_post=s->pc+3;
    rneed(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),428);
    rneed(!li2_decoder_decode(s->pc,(const void *)s->pc,3,&s->decoded) &&
          s->decoded.decode_status==LI2_VALID && s->decoded.kind==LI2_NONE &&
          s->decoded.code==346 && s->decoded.length==3 && s->decoded.next_pc==s->pc+3,429);
    rneed(!li2_decoder_tf_classify(s->pc,(const void *)s->pc,3,&r->refused) &&
          r->refused.abi_version==1 && r->refused.pc==s->pc &&
          !r->refused.policy && !r->refused.flow && !r->refused.family,430);
    r->classifier_checked=1;++repeat_result.stosq_refusals;
    r->mapping=s->mapping;r->pc=s->pc;r->next_pc=s->pc+3;r->decoded=s->decoded;
    r->count=counts[index%3];r->direction=index/3;memcpy(r->source,s->source,CODE_BYTES);
}
static void repeat_inputs(struct repeat_case *r,struct sample *s) {
    inputs(s);fixture_seed[0]=UINT64_C(0x0123456789abcdef);fixture_seed[1]=r->count;
    fixture_seed[6]=data_page+1024;fixture_seed[7]=data_page+512;
    fixture_input_flags=UINT64_C(0x247)|(r->direction?UINT64_C(0x400):0);
    memcpy(r->seed,fixture_seed,sizeof(r->seed));
}
static void repeat_borrow(struct repeat_case *r,struct sample *s) {
    rneed(!li2_lifecycle_fetch_prepare(s->pc,3,&s->ref),431);
    struct li2_fetch_view view;
    rneed(!li2_lifecycle_fetch_view(&s->ref,&view) && view.pc==s->pc && view.length==3 &&
          view.page_count==1 && view.identity_observed && view.pid==session.pid && view.tid==session.tid &&
          !memcmp(view.bytes,r->decoded.bytes,3),432);
    s->pages[0]=view.pages[0];r->pages[repeat_lane]=view.pages[0];
}
static void repeat_compare(struct repeat_case *r) {
    rneed(r->native_completed && r->endpoint_seen && r->phase==REPEAT_ENDPOINT &&
          r->trace_count && r->trace_count<=(r->count?r->count:1),433);
    rneed(!memcmp(&r->pages[0],&r->pages[1],sizeof(r->pages[0])) &&
          r->native_borrow.complete && !r->native_borrow.held &&
          r->repeat_borrow.complete && !r->repeat_borrow.held,447);
    const struct state *states[4]={&r->before[0],&r->after[0],&r->before[1],&r->after[1]};
    for(unsigned k=0;k<2;k++) {
        const struct state *a=states[k],*b=states[k+2];
        for(unsigned i=0;i<16;i++)rneed(a->frame.greg[regs[i]]==b->frame.greg[regs[i]],434);
        rneed(!memcmp(a->frame.greg,b->frame.greg,sizeof(a->frame.greg)) &&
              !memcmp(a->stack,b->stack,SUBJECT_BYTES) && !memcmp(a->data,b->data,DATA_BYTES) &&
              a->frame.fp_bytes==b->frame.fp_bytes && !memcmp(a->frame.fp,b->frame.fp,a->frame.fp_bytes),435);
    }
    for(unsigned k=0;k<4;k++) {
        const struct state *st=states[k];const struct live *live=&r->live[k];
        rneed(st->frame.mask==mask && st->fs==states[0]->fs && st->gs==states[0]->gs &&
              st->frame.greg[REG_CSGSFS]==states[0]->frame.greg[REG_CSGSFS] &&
              st->frame.initialized==st->frame.fp_bytes &&
              live->started==1 && live->complete==1 && !live->reserved &&
              live->rflags==r->logical_flags,436);
        for(unsigned i=0;i<16;i++)rneed(live->gpr[i]==(uint64_t)st->frame.greg[regs[i]],437);
        for(unsigned i=0;i<6;i++)rneed(live->selectors[i]==r->live[0].selectors[i],438);
        rneed(live->selectors[0]==((uint64_t)st->frame.greg[REG_CSGSFS]&0xffff) &&
              live->selectors[1]==((uint64_t)st->frame.greg[REG_CSGSFS]>>48),439);
        rneed(!memcmp(r->actual_fp[0],r->actual_fp[k],xsave_bytes),440);
    }
    repeat_effects(r,&r->after[1],&r->before[1],r->count);
    r->source_equal=!memcmp((const void *)r->mapping,r->source,CODE_BYTES);
    r->source_closed=actual_protection(r->pc,0)==PROT_READ;
    r->target_closed=actual_protection(r->next_pc,0)==PROT_READ;
    rneed(r->source_equal && r->source_closed && r->target_closed,441);
    r->checked=1;r->phase=REPEAT_VERIFIED;++repeat_result.completed;
}
static void repeat_pair(unsigned index) {
    struct repeat_case *r=&repeats[index];struct sample *s=&samples[index+1];
    repeat_current=r;repeat_source=s;current=s;fixture_target=s->pc;
    repeat_result.active_index=index;
    for(repeat_lane=0;repeat_lane<2;repeat_lane++) {
        repeat_result.active_lane=repeat_lane;
        if(repeat_control)rneed(!RAW(SYS_mprotect,data_page,PAGE,PROT_READ|PROT_WRITE,0,0,0),472);
        repeat_inputs(r,s);
        if(repeat_control)rneed(!RAW(SYS_mprotect,data_page,PAGE,PROT_READ,0,0,0),473);
        repeat_borrow(r,s);
        if(repeat_lane)repeat_arm_actual(r,s);
        r->phase=REPEAT_ARMED;fixture_enter();
        rneed(r->phase==REPEAT_ENDPOINT,442);
        unsigned at=repeat_lane*2;r->live[at]=fixture_live_before;r->live[at+1]=fixture_live_after;
        memcpy(r->actual_fp[at],fixture_fp_before,xsave_bytes);
        memcpy(r->actual_fp[at+1],fixture_fp_after,xsave_bytes);
        rneed(!li2_lifecycle_fetch_release(&s->ref),443);
        if(!repeat_lane)r->native_borrow=*li2_lifecycle_fetch_progress();
        else r->repeat_borrow=*li2_lifecycle_fetch_progress();
    }
    rneed(!repeat_control,474);
    repeat_compare(r);
    rneed(r->arm_attempted && !r->arm_result && r->begin_returned &&
          r->owner.step.phase==LI2_STEP_COMPLETE && r->owner.final &&
          !r->owner.remaining && r->owner.traces==r->trace_count,475);
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(struct li2_repeat_owner)<=140*1024,"fixed owner record bound");
    _Static_assert(sizeof(repeat_result)+sizeof(samples[0])+sizeof(repeats)+sizeof(unexpected)<16*1024*1024,
                   "bounded complete repeat observation record");
    repeat_result.magic=UINT64_C(0x315045525449324c);repeat_result.version=2;repeat_result.pairs=REPEAT_PAIRS;
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=PAIRS;
    need(stack[0]==1,444);
    const char *const *argv=(const void *)(stack+1),*const *env=argv+stack[0]+1;
    const char control_key[]="LI2_REPEAT_WRITE_FAULT=";
    size_t environment_count=0;
    while(env[environment_count]) {
        need(environment_count<1024,444);
        const char *value=env[environment_count++];size_t at=0;
        while(at<sizeof(control_key)-1 && value[at]==control_key[at])++at;
        if(at==sizeof(control_key)-1) {
            need(!repeat_control && same(value+at,"1"),444);repeat_control=1;
        }
    }
    repeat_result.control=repeat_control;setup(stack);
    size_t completed=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&completed,&failed,&decoder_result,&refused_last);
    result.refusals=completed;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc && completed==li2_tf_refusal_count() && completed==47,130);
    repeat_result.old_refusals=completed;
    prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    repeat_result.xcr0=fixture_xcr0;repeat_result.xsave_bytes=xsave_bytes;
    for(unsigned i=0;i<REPEAT_PAIRS;i++)repeat_prepare(i);
    struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;
            void (*restorer)(void);uint64_t mask;} action={repeat_handler,
            SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL,step_restorer,mask};
    rneed(!RAW(SYS_rt_sigaction,SIGSEGV,&action,0,8,0,0) &&
          !RAW(SYS_rt_sigaction,SIGTRAP,&action,0,8,0,0) &&
          !RAW(SYS_rt_sigaction,SIGSYS,&action,0,8,0,0),445);
    if(repeat_control) {repeat_pair(1);repeat_die(476);}
    for(unsigned i=0;i<REPEAT_PAIRS;i++)repeat_pair(i);
    rneed(repeat_result.completed==REPEAT_PAIRS && !repeat_open_possible &&
          !li2_lifecycle_fetch_interlock() && repeat_dump(),446);
    output("LI2_REPEAT_OWNER_PASS pairs=6 counts=0,1,3 directions=0,1 old_refusals=47 stosq_refusals=6 selftest=1 traces=");
    number(repeat_result.traces);return 0;
}
