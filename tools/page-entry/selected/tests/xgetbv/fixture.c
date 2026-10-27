/* Additive XCR0 oracle. Every original helper and full-state comparator remains
   unchanged; the original generic, integer, padding and REP suites still run. */
#define fixture_main li2_unchanged_generic_fixture_main
#include "tests/generic/fixture.c"
#undef fixture_main

#define XGETBV_PAIRS 7
_Static_assert(PAIRS==21 && XGETBV_PAIRS<PAIRS,"unchanged bounded capture layout");
static unsigned xgetbv_control;
static uint64_t xgetbv_index;
static const unsigned char xgetbv_bytes[]={0x0f,0x01,0xd0};

static void xgetbv_inputs(struct sample *s) {
    inputs(s);fixture_seed[1]=xgetbv_index;
}
static void xgetbv_prepare(struct sample *s,unsigned id,unsigned tail) {
    need(tail>=1&&tail<=3,500);s->id=id;s->length=3;
    long reserved=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reserved>0,501);s->mapping=(uintptr_t)reserved+PAGE;
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),502);
    memset(s->source,0xcc,sizeof(s->source));size_t offset=PAGE-tail;
    s->pc=s->mapping+offset;s->expected_post=s->pc+3;
    s->endpoint_int3=tail<3;s->count=tail<3?2:1;
    memcpy(s->source+offset,xgetbv_bytes,3);memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),503);
    need(!li2_decoder_decode(s->pc,(const void *)s->pc,3,&s->decoded)&&
         s->decoded.decode_status==LI2_VALID&&s->decoded.kind==LI2_NONE&&
         s->decoded.code==825&&s->decoded.length==3&&
         !memcmp(s->decoded.bytes,xgetbv_bytes,3),504);
}
static void xgetbv_effects(struct sample *s) {
    const struct li2_step_owner *o=&s->owner.step;
    need(s->owner.classification.policy==1&&s->owner.classification.code==825&&
         s->owner.classification.flow==LI2_TF_FALLTHROUGH&&
         s->owner.classification.family==LI2_TF_INTEGER&&s->length==3&&
         s->expected_post==s->pc+3&&!memcmp(s->decoded.bytes,xgetbv_bytes,3),505);
    need(!(uint32_t)xgetbv_index&&
         (uint64_t)s->native_before.frame.greg[REG_RCX]==xgetbv_index&&
         (uint64_t)s->step_before.frame.greg[REG_RCX]==xgetbv_index&&
         ((uint64_t)s->native_before.frame.greg[REG_RAX]>>32)&&
         ((uint64_t)s->native_before.frame.greg[REG_RDX]>>32),506);
    /* The expected bits are the literal actual XCR0 read during setup, not a
       fabricated FP mask. Both 32-bit destinations must zero-extend. */
    for(unsigned i=0;i<16;i++) {
        uint64_t expected=(uint64_t)s->native_before.frame.greg[regs[i]];
        if(i==0)expected=(uint32_t)fixture_xcr0;
        else if(i==2)expected=(uint32_t)(fixture_xcr0>>32);
        need((uint64_t)s->native_after.frame.greg[regs[i]]==expected&&
             (uint64_t)o->after.greg[regs[i]]==expected&&
             (uint64_t)s->step_endpoint.frame.greg[regs[i]]==expected,507);
    }
    need(s->initial_flags==s->post_flags,508);
    compare_memory(&s->native_before,&s->native_after,509);
    compare_memory(&s->step_before,&s->step_endpoint,510);
    need(!memcmp(s->native_before.frame.fp,s->native_after.frame.fp,s->native_before.frame.fp_bytes)&&
         !memcmp(s->step_before.frame.fp,s->step_endpoint.frame.fp,s->step_before.frame.fp_bytes)&&
         !memcmp(o->before.fp,o->after.fp,o->before.fp_bytes),511);
    need(!memcmp(s->actual_fp[0],s->actual_fp[1],xsave_bytes)&&
         !memcmp(s->actual_fp[2],s->actual_fp[3],xsave_bytes),512);
    for(unsigned i=0;i<2;i++) {
        const struct live *a=&s->live[2*i],*b=&s->live[2*i+1];
        need(a->rflags==b->rflags&&b->gpr[0]==(uint32_t)fixture_xcr0&&
             b->gpr[2]==(uint32_t)(fixture_xcr0>>32),513);
        for(unsigned r=0;r<16;r++)if(r!=0&&r!=2)need(a->gpr[r]==b->gpr[r],514);
    }
    for(size_t i=0;i<s->count;i++)need(actual_protection(s->pages[i].address,0)==PROT_READ,515);
    need(actual_protection(s->expected_post,0)==PROT_READ&&s->continuation.complete,516);
}
/* Same pair protocol, with actual RCX seeds and additional literal effects. */
static void xgetbv_pair(struct sample *s) {
    current=s;fixture_target=s->pc;xgetbv_inputs(s);borrow(s);lane=0;native_phase=0;fixture_enter();
    s->initial_flags=fixture_flags;s->live[0]=fixture_live_before;s->live[1]=fixture_live_after;
    memcpy(s->actual_fp[0],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[1],fixture_fp_after,xsave_bytes);
    need(s->native_complete,517);
    s->post_flags=(uint64_t)s->native_after.frame.greg[REG_EFL];
    if(!s->endpoint_int3)s->post_flags&=~LI2_STEP_RF;
    need(!(s->initial_flags&(LI2_STEP_RF|LI2_STEP_TF))&&!(s->post_flags&(LI2_STEP_RF|LI2_STEP_TF)),103);
    need(!li2_lifecycle_fetch_release(&s->ref),104);s->native_fetch=*li2_lifecycle_fetch_progress();
    xgetbv_inputs(s);borrow(s);
    struct li2_step_request request={.decoded=s->decoded,.page_count=s->count,.original_flags=s->initial_flags};
    for(size_t i=0;i<s->count;i++)request.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
    struct li2_tf_hooks hooks={{s,authenticate,failure},continue_closed};
    int error=li2_tf_arm(&s->owner,&session,&hooks,&request);
    if(error)li2_tf_abort(&s->owner,(unsigned)error,0);
    lane=1;fixture_enter();need(!(s==&negative_sample),105);
    s->live[2]=fixture_live_before;s->live[3]=fixture_live_after;
    memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[3],fixture_fp_after,xsave_bytes);
    compare(s);xgetbv_effects(s);
    need(!li2_lifecycle_fetch_release(&s->ref),106);s->step_fetch=*li2_lifecycle_fetch_progress();
    ++result.completed;
}
static void xgetbv_failure(void *context,const struct li2_step_owner *o) {
    struct sample *s=context;
    result.owner_failure=o->first_error;result.owner_detail_abs=(uint64_t)o->first_detail;
    result.owner_detail_negative=o->first_detail<0;
    need(s==&negative_sample&&xgetbv_control>=4&&xgetbv_control<=6&&
         o->first_error==LI2_TF_XCR_INDEX&&o->first_detail==(long)(uint32_t)xgetbv_index&&
         o->phase==LI2_STEP_FAILED&&!o->trace_seen&&!o->after.initialized&&
         !s->owner.continuation_started&&!s->owner.continuation_complete&&
         !s->owner.unexpected_frame_observed&&!s->step_endpoint_seen&&
         !s->native_complete&&!s->native_fault,520);
    need(o->signal_number==SIGSEGV&&o->signal_code==SEGV_ACCERR&&!o->signal_errno&&
         o->signal_address==s->pc&&(uintptr_t)o->before.greg[REG_RIP]==s->pc&&
         o->before.greg[REG_TRAPNO]==14&&o->before.greg[REG_ERR]==21&&
         (uint64_t)o->before.greg[REG_RCX]==xgetbv_index&&
         (uint64_t)o->before.greg[REG_EFL]==(fixture_flags|LI2_STEP_RF)&&
         o->before.initialized==o->before.fp_bytes&&o->before.mask==mask,521);
    need(!memcmp(o->before.greg,s->step_before.frame.greg,sizeof(o->before.greg))&&
         o->before.fp_bytes==s->step_before.frame.fp_bytes&&
         !memcmp(o->before.fp,s->step_before.frame.fp,o->before.fp_bytes),522);
    for(unsigned i=0;i<16;i++)need((uint64_t)o->before.greg[regs[i]]==fixture_seed[i],523);
    for(size_t i=0;i<2;i++)need(!o->open_started[i]&&!o->opened[i]&&!o->open_result[i]&&
         !o->revoke_started[i]&&!o->revoked[i]&&!o->revoke_result[i],524);
    need(!o->open_sync&&o->revoke_sync_started&&!o->revoke_sync,525);
    for(size_t i=0;i<s->count;i++)need(!authenticate(s,&o->request.pages[i],PROT_READ)&&
         actual_protection(s->pages[i].address,0)==PROT_READ,526);
    need(!memcmp((void *)s->mapping,s->source,sizeof(s->source))&&
         !memcmp((void *)subject,s->step_before.stack,SUBJECT_BYTES)&&
         !memcmp((void *)data_page,s->step_before.data,DATA_BYTES)&&
         li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,527);
    s->live[2]=fixture_live_before;memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);
    need(s->live[2].started==1&&s->live[2].complete==1&&!s->live[2].reserved&&
         s->live[2].rflags==fixture_flags,528);
    for(unsigned i=0;i<16;i++)need(s->live[2].gpr[i]==fixture_seed[i],529);
    s->step_fetch=*li2_lifecycle_fetch_progress();s->negative_verified=1;result.expected_failure_verified=1;
    need(dump(),530);output("LI2_XGETBV_EXPECTED_REFUSAL index=");number((uint32_t)xgetbv_index);
    /* The unchanged owner then exits 125. This is not instruction completion. */
}
static void xgetbv_handler(int sig,siginfo_t *si,void *frame_) {
    if(xgetbv_control==7&&!lane&&native_phase==1) {
        need(current==&negative_sample&&si&&frame_&&!handling,531);handling=1;
        struct sample *s=current;ucontext_t *uc=frame_;greg_t *g=uc->uc_mcontext.gregs;
        need(sig==SIGSEGV&&si->si_code==SI_KERNEL&&!si->si_errno&&!si->si_addr&&
             g[REG_TRAPNO]==13&&!g[REG_ERR]&&(uintptr_t)g[REG_RIP]==s->pc&&
             (uint64_t)g[REG_RCX]==2,532);
        capture(&s->native_after,uc);s->native_fault=1;permissions(s,PROT_READ);native_phase=2;
        g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
        fixture_vector_clobber();handling=0;return;
    }
    handler(sig,si,frame_);
}
static _Noreturn void xgetbv_negative(void) {
    struct sample *s=&negative_sample;xgetbv_prepare(s,300+xgetbv_control,1);
    current=s;fixture_target=s->pc;xgetbv_inputs(s);borrow(s);
    if(xgetbv_control==7) {
        /* The CPU really executes ECX=2 and faults at the original instruction.
           Diagnostic escape retains the fault frame; it is never a completion. */
        lane=0;native_phase=0;fixture_enter();s->initial_flags=fixture_flags;
        s->live[0]=fixture_live_before;s->live[1]=fixture_live_after;
        memcpy(s->actual_fp[0],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[1],fixture_fp_after,xsave_bytes);
        need(s->native_fault&&!s->native_complete&&!s->step_endpoint_seen&&
             s->native_before.frame.greg[REG_EFL]==s->native_after.frame.greg[REG_EFL],533);
        for(unsigned i=0;i<16;i++)need(s->native_before.frame.greg[regs[i]]==
             s->native_after.frame.greg[regs[i]]&&s->live[0].gpr[i]==s->live[1].gpr[i],534);
        need(s->native_before.frame.fp_bytes==s->native_after.frame.fp_bytes&&
             !memcmp(s->native_before.frame.fp,s->native_after.frame.fp,s->native_before.frame.fp_bytes)&&
             !memcmp(s->actual_fp[0],s->actual_fp[1],xsave_bytes),535);
        compare_memory(&s->native_before,&s->native_after,536);
        need(s->native_before.fs==s->native_after.fs&&s->native_before.gs==s->native_after.gs&&
             s->live[0].started==1&&s->live[0].complete==1&&s->live[1].started==1&&s->live[1].complete==1&&
             s->live[0].rflags==s->live[1].rflags&&
             !memcmp(s->live[0].selectors,s->live[1].selectors,sizeof(s->live[0].selectors)),537);
        need(!li2_lifecycle_fetch_release(&s->ref),538);s->native_fetch=*li2_lifecycle_fetch_progress();
        s->negative_verified=1;result.expected_failure_verified=1;need(dump(),539);
        output("LI2_XGETBV_NATIVE_FAULT trap=13 index=2\n");
        (void)RAW(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
    s->initial_flags=samples[0].initial_flags;
    struct li2_step_request request={.decoded=s->decoded,.page_count=s->count,.original_flags=s->initial_flags};
    for(size_t i=0;i<s->count;i++)request.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
    struct li2_tf_hooks hooks={{s,authenticate,xgetbv_failure},continue_closed};
    int error=li2_tf_arm(&s->owner,&session,&hooks,&request);
    if(error)li2_tf_abort(&s->owner,(unsigned)error,0);
    lane=1;fixture_enter();die(540);
}
static void xgetbv_refusal_controls(void) {
    static const unsigned char bytes[][5]={
        {0x66,0x0f,0x01,0xd0},{0x48,0x0f,0x01,0xd0},{0x67,0x0f,0x01,0xd0},
        {0xf3,0x0f,0x01,0xd0},{0xf2,0x0f,0x01,0xd0},{0xf0,0x0f,0x01,0xd0},
        {0x2e,0x0f,0x01,0xd0},{0x40,0x0f,0x01,0xd0},{0x0f,0x01}};
    for(size_t i=0;i<sizeof(bytes)/sizeof(bytes[0]);i++) {
        result.failed_refusal=47+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,bytes[i],i==8?2:4,&refused_last);
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,541+(unsigned)i);
        ++result.refusals;
    }
    result.failed_refusal=SIZE_MAX;
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)<16*1024*1024,
                   "unchanged complete private record bound");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=XGETBV_PAIRS;
    need(stack[0]==1,550);setup(stack);
    const char *const *env=(const void *)(stack+3);
    const char prefix[]="LI2_XGETBV_CONTROL=";
    for(size_t i=0;env[i];i++)if(length(env[i])>=sizeof(prefix)-1&&!memcmp(env[i],prefix,sizeof(prefix)-1)) {
        need(!xgetbv_control,551);const char *v=env[i]+sizeof(prefix)-1;
        if(same(v,"index1")){xgetbv_control=4;xgetbv_index=1;}
        else if(same(v,"index1-high")){xgetbv_control=5;xgetbv_index=UINT64_C(0xdeadbeef00000001);}
        else if(same(v,"index2")){xgetbv_control=6;xgetbv_index=2;}
        else if(same(v,"native-index2")){xgetbv_control=7;xgetbv_index=2;}
        else die(552);
    }
    result.control=xgetbv_control;
    size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc&&complete==li2_tf_refusal_count()&&complete==47,130);
    xgetbv_refusal_controls();need(result.refusals==56,553);
    prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    if(xgetbv_control) {
        struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} action;
        action.handler=xgetbv_handler;action.flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL;
        action.restorer=step_restorer;action.mask=mask;
        need(!RAW(SYS_rt_sigaction,SIGSEGV,&action,0,8,0,0),554);xgetbv_negative();
    }
    for(unsigned i=0;i<6;i++) {
        xgetbv_index=i<3?0:UINT64_C(0xdeadbeef00000000);
        xgetbv_prepare(&samples[i+1],300+i,3-i%3);xgetbv_pair(&samples[i+1]);
    }
    need(result.completed==XGETBV_PAIRS&&dump(),555);
    output("LI2_XGETBV_TF_PASS pairs=7 xcr0=6 selftest=1 old_refusal_bytes=47 encoding_refusal_bytes=9 full_state=7 full_memory=7 live_endpoints=7\n");
    return 0;
}
