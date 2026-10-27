/* Original-PC F2 FF25 disp32 indirect JMP; old generic helpers stay exact. */
#define fixture_main li2_unchanged_generic_fixture_main
#include "tests/generic/fixture.c"
#undef fixture_main

#define BND_PAIRS 15
_Static_assert(PAIRS==21 && BND_PAIRS<PAIRS,"unchanged bounded record slots");
static unsigned bnd_control;
struct bnd_query { uint64_t attempted,complete,value; };
struct bnd_trailer {
    uint64_t magic,version,bytes,native_queries,injected_control,injected_calls;
    struct bnd_query native[22];
};
static struct bnd_trailer bnd_evidence;
_Static_assert(sizeof(bnd_evidence)==576,"bounded actual-observation trailer");
uint64_t li2_tf_actual_observe_xcr0(void);
/* Definition-only link adapter. Production has no supplied value path. */
uint64_t li2_tf_observe_xcr0(void) {
    if(bnd_control>=2) {
        need(bnd_control<=4&&current==&negative_sample&&lane==1&&handling&&
             current->owner.step.phase==LI2_STEP_ARMED,1500);
        ++bnd_evidence.injected_calls;
        return bnd_control==2?8:bnd_control==3?16:24;
    }
    return li2_tf_actual_observe_xcr0();
}
static int bnd_dump(void) {
    bnd_evidence.magic=UINT64_C(0x31444e424a324c);bnd_evidence.version=1;
    bnd_evidence.bytes=sizeof(bnd_evidence);bnd_evidence.injected_control=bnd_control>=2?bnd_control:0;
    return write_all(3,&bnd_evidence,sizeof(bnd_evidence));
}
static uintptr_t bnd_operand(const struct sample *s) {
    int32_t relative=0;memcpy(&relative,s->decoded.bytes+3,4);
    int64_t address=(int64_t)(s->pc+7)+(int64_t)relative;
    need(address>0&&(uint64_t)address<UINT64_C(1)<<47,1501);return (uintptr_t)address;
}
static void bnd_inputs(struct sample *s) {
    inputs(s);memcpy((void *)(data_page+64),&s->target,8);
}
static void bnd_prepare(struct sample *s,unsigned index) {
    need(index<14,1502);unsigned tail=7-index%7,negative=index>=7;
    s->id=2000+index;s->length=7;s->count=tail<7?2:1;
    /* One reservation proves signed32 reach; no ASLR adjacency assumption.
       guard/data/guard/source0/source1/target/guard/data/fault/guard. */
    long reserved=dispatch(SYS_mmap,0,10*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reserved>0,1503);s->mapping=(uintptr_t)reserved+3*PAGE;
    data_page=negative?s->mapping-2*PAGE:s->mapping+4*PAGE;data_fault=s->mapping+5*PAGE;
    need(!dispatch(SYS_mprotect,data_page,DATA_BYTES,PROT_READ|PROT_WRITE,0,0,0)&&
         !dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),1504);
    memset(s->source,0xcc,sizeof(s->source));s->pc=s->mapping+PAGE-tail;
    s->target=s->mapping+2*PAGE+32;s->expected_post=s->target;s->endpoint_int3=0;
    size_t offset=PAGE-tail;unsigned char *bytes=s->source+offset;
    bytes[0]=0xf2;bytes[1]=0xff;bytes[2]=0x25;
    uintptr_t operand=s==&negative_sample&&bnd_control==1?data_fault:data_page+64;
    int64_t displacement=(int64_t)operand-(int64_t)(s->pc+7);
    need(displacement>=INT32_MIN&&displacement<=INT32_MAX&&
         (s==&negative_sample&&bnd_control==1?displacement>0:
          negative?displacement<0:displacement>0),1505);
    emit_i32(bytes+3,displacement);memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),1506);
    need(!li2_decoder_decode(s->pc,(const void *)s->pc,7,&s->decoded)&&
         s->decoded.decode_status==LI2_VALID&&s->decoded.kind==LI2_NONE&&
         s->decoded.code==765&&s->decoded.length==7&&s->decoded.next_pc==s->pc+7&&
         !memcmp(s->decoded.bytes,bytes,7)&&bnd_operand(s)==operand&&
         actual_protection(s->target,0)==PROT_READ,1507);
}
static void bnd_effects(struct sample *s) {
    const struct li2_step_owner *o=&s->owner.step;
    unsigned index=s->id-2000,tail=7-index%7;
    need(index<14&&s->pc==s->mapping+PAGE-tail&&s->length==7&&s->count==(tail<7?2U:1U)&&
         s->owner.classification.code==765&&s->owner.classification.policy==1&&
         s->owner.classification.flow==LI2_TF_NEAR_FLOW&&s->owner.classification.family==LI2_TF_BRANCH&&
         s->decoded.bytes[0]==0xf2&&s->decoded.bytes[1]==0xff&&s->decoded.bytes[2]==0x25,1508);
    need(bnd_operand(s)==data_page+64&&s->target==s->mapping+2*PAGE+32&&
         s->owner.actual_post_pc==s->target&&(uintptr_t)o->after.greg[REG_RIP]==s->target&&
         s->owner.bnd_xcr0_attempted==1&&s->owner.bnd_xcr0_complete==1&&
         s->owner.bnd_xcr0==fixture_xcr0&&!(s->owner.bnd_xcr0&24),1509);
    const struct bnd_query *q=&bnd_evidence.native[s-samples];
    need(q->attempted==1&&q->complete==1&&q->value==fixture_xcr0&&!(q->value&24),1510);
    for(unsigned lane_=0;lane_<2;lane_++) {
        const struct state *before=lane_?&s->step_before:&s->native_before;
        const struct state *after=lane_?&s->step_endpoint:&s->native_after;
        need((uintptr_t)before->frame.greg[REG_RIP]==s->pc&&
             (uintptr_t)after->frame.greg[REG_RIP]==s->target&&word(before->data+64)==s->target,1511);
        for(unsigned r=0;r<16;r++)need((uint64_t)before->frame.greg[regs[r]]==fixture_seed[r]&&
             (uint64_t)after->frame.greg[regs[r]]==fixture_seed[r]&&
             s->live[2*lane_+1].gpr[r]==fixture_seed[r],1512);
        compare_memory(before,after,1513);
        need(before->frame.fp_bytes==after->frame.fp_bytes&&
             !memcmp(before->frame.fp,after->frame.fp,before->frame.fp_bytes)&&
             !memcmp(s->actual_fp[2*lane_],s->actual_fp[2*lane_+1],xsave_bytes),1514);
    }
    need(s->post_flags==s->initial_flags&&s->live[0].rflags==s->live[1].rflags&&
         s->live[2].rflags==s->live[3].rflags&&o->before.fp_bytes==o->after.fp_bytes&&
         !memcmp(o->before.fp,o->after.fp,o->before.fp_bytes),1515);
    for(size_t i=0;i<s->count;i++)need(s->pages[i].address==(s->pc&~(PAGE-1))+i*PAGE&&
         s->pages[i].address!=(s->target&~(PAGE-1))&&actual_protection(s->pages[i].address,0)==PROT_READ,1516);
    need(s->continuation.complete&&s->continuation.pc==s->target&&
         s->continuation.page.address==(s->target&~(PAGE-1))&&
         actual_protection(s->target,0)==PROT_READ,1517);
}
static void bnd_failure(void *context,const struct li2_step_owner *o) {
    struct sample *s=context;
    if(bnd_control==1) {
        need(s==&negative_sample&&o->before.greg[REG_RIP]==(greg_t)s->pc&&
             s->owner.bnd_xcr0_attempted==1&&s->owner.bnd_xcr0_complete==1&&
             s->owner.bnd_xcr0==fixture_xcr0&&!(fixture_xcr0&24)&&bnd_operand(s)==data_fault,1518);
        const struct bnd_query *q=&bnd_evidence.native[21];
        need(q->attempted==1&&q->complete==1&&q->value==fixture_xcr0&&
             bnd_evidence.native_queries==1&&!bnd_evidence.injected_calls,1546);
        for(unsigned r=0;r<16;r++)need(s->native_before.frame.greg[regs[r]]==
             s->native_after.frame.greg[regs[r]],1547);
        compare_memory(&s->native_before,&s->native_after,1548);
        need(s->native_before.frame.fp_bytes==s->native_after.frame.fp_bytes&&
             !memcmp(s->native_before.frame.fp,s->native_after.frame.fp,s->native_before.frame.fp_bytes)&&
             s->native_before.frame.greg[REG_EFL]==s->native_after.frame.greg[REG_EFL],1549);
        /* Every original real-read-fault frame/FP/memory/revocation predicate. */
        failure(context,o);need(bnd_dump(),1519);return;
    }
    need(bnd_control>=2&&bnd_control<=4&&s==&negative_sample,1520);
    uint64_t supplied=bnd_control==2?8:bnd_control==3?16:24;
    result.owner_failure=o->first_error;result.owner_detail_abs=(uint64_t)o->first_detail;
    result.owner_detail_negative=o->first_detail<0;
    need(o->phase==LI2_STEP_FAILED&&o->first_error==LI2_TF_MPX_ENABLED&&o->first_detail==(long)supplied&&
         s->owner.bnd_xcr0_attempted==1&&s->owner.bnd_xcr0_complete==1&&s->owner.bnd_xcr0==supplied&&
         bnd_evidence.injected_calls==1&&!bnd_evidence.native_queries&&
         !o->trace_seen&&!o->after.initialized&&!s->owner.continuation_started&&
         !s->owner.continuation_complete&&!s->owner.unexpected_frame_observed&&
         !s->native_complete&&!s->native_fault&&!s->step_endpoint_seen,1521);
    need(o->signal_number==SIGSEGV&&o->signal_code==SEGV_ACCERR&&!o->signal_errno&&
         o->signal_address==s->pc&&(uintptr_t)o->before.greg[REG_RIP]==s->pc&&
         o->before.greg[REG_TRAPNO]==14&&o->before.greg[REG_ERR]==21&&
         (uint64_t)o->before.greg[REG_EFL]==(fixture_flags|LI2_STEP_RF)&&
         o->before.initialized==o->before.fp_bytes&&o->before.mask==mask,1522);
    need(!memcmp(o->before.greg,s->step_before.frame.greg,sizeof(o->before.greg))&&
         o->before.fp_bytes==s->step_before.frame.fp_bytes&&
         !memcmp(o->before.fp,s->step_before.frame.fp,o->before.fp_bytes),1523);
    for(unsigned i=0;i<16;i++)need((uint64_t)o->before.greg[regs[i]]==fixture_seed[i],1524);
    for(size_t i=0;i<2;i++)need(!o->open_started[i]&&!o->opened[i]&&!o->open_result[i]&&
         !o->revoke_started[i]&&!o->revoked[i]&&!o->revoke_result[i],1525);
    need(!o->open_sync&&o->revoke_sync_started&&!o->revoke_sync,1526);
    for(size_t i=0;i<s->count;i++)need(!authenticate(s,&o->request.pages[i],PROT_READ)&&
         actual_protection(s->pages[i].address,0)==PROT_READ,1527);
    need(!memcmp((void *)s->mapping,s->source,sizeof(s->source))&&
         !memcmp((void *)subject,s->step_before.stack,SUBJECT_BYTES)&&
         !memcmp((void *)data_page,s->step_before.data,DATA_BYTES)&&
         li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,1528);
    s->live[2]=fixture_live_before;memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);
    need(s->live[2].started==1&&s->live[2].complete==1&&!s->live[2].reserved&&
         s->live[2].rflags==fixture_flags,1529);
    for(unsigned i=0;i<16;i++)need(s->live[2].gpr[i]==fixture_seed[i],1530);
    s->step_fetch=*li2_lifecycle_fetch_progress();s->negative_verified=1;result.expected_failure_verified=1;
    need(dump()&&bnd_dump(),1531);output("LI2_BND_JMP_SUPPLIED_MPX_REFUSAL ");number(supplied);
}
static void bnd_handler(int sig,siginfo_t *si,void *frame_) {
    if(current&&!current->selftest&&!lane&&!native_phase) {
        need(si&&frame_&&!handling,1532);handling=1;struct sample *s=current;ucontext_t *uc=frame_;
        need(nx(sig,si,uc->uc_mcontext.gregs,s->pc)&&
             (uint64_t)uc->uc_mcontext.gregs[REG_EFL]==(fixture_flags|LI2_STEP_RF)&&
             !memcmp((void *)s->mapping,s->source,sizeof(s->source)),1533);
        for(size_t i=0;i<s->count;i++)need(!authenticate(s,&(struct li2_step_page){
            s->pages[i].address,s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,
            PROT_READ,PROT_READ|PROT_EXEC},PROT_READ),1534);
        struct bnd_query *q=&bnd_evidence.native[s==&negative_sample?21:(size_t)(s-samples)];
        need(!q->attempted&&!q->complete&&!q->value,1535);
        handling=1;q->attempted=1;__asm__ volatile("":::"memory");
        q->value=li2_tf_actual_observe_xcr0();q->complete=1;
        need(q->value==fixture_xcr0&&!(q->value&24),1536);
        ++bnd_evidence.native_queries;handling=0;
    }
    handler(sig,si,frame_);
}
/* Old pair protocol: only inputs/hooks and the additive literal effect check. */
static void bnd_pair(struct sample *s) {
    current=s;fixture_target=s->pc;bnd_inputs(s);borrow(s);lane=0;native_phase=0;fixture_enter();
    s->initial_flags=fixture_flags;s->live[0]=fixture_live_before;s->live[1]=fixture_live_after;
    memcpy(s->actual_fp[0],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[1],fixture_fp_after,xsave_bytes);
    need(s->native_complete||(s==&negative_sample&&control==1&&s->native_fault),102);
    s->post_flags=(uint64_t)s->native_after.frame.greg[REG_EFL];
    if(!s->endpoint_int3)s->post_flags&=~LI2_STEP_RF;
    need(!(s->initial_flags&(LI2_STEP_RF|LI2_STEP_TF))&&!(s->post_flags&(LI2_STEP_RF|LI2_STEP_TF)),103);
    need(!li2_lifecycle_fetch_release(&s->ref),104);s->native_fetch=*li2_lifecycle_fetch_progress();
    bnd_inputs(s);borrow(s);
    struct li2_step_request request={.decoded=s->decoded,.page_count=s->count,.original_flags=s->initial_flags};
    for(size_t i=0;i<s->count;i++)request.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
    struct li2_tf_hooks hooks={{s,authenticate,bnd_failure},continue_closed};
    int error=s->selftest?li2_step_arm(&s->owner.step,&session,&hooks.step,&request,1):
                         li2_tf_arm(&s->owner,&session,&hooks,&request);
    if(error)li2_tf_abort(&s->owner,(unsigned)error,0);
    lane=1;fixture_enter();
    need(!(s==&negative_sample),105);
    s->live[2]=fixture_live_before;s->live[3]=fixture_live_after;
    memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[3],fixture_fp_after,xsave_bytes);
    compare(s);bnd_effects(s);need(!li2_lifecycle_fetch_release(&s->ref),106);s->step_fetch=*li2_lifecycle_fetch_progress();
    ++result.completed;
}
static _Noreturn void bnd_preopen(void) {
    struct sample *s=&negative_sample;bnd_prepare(s,6);current=s;fixture_target=s->pc;
    bnd_inputs(s);borrow(s);s->initial_flags=fixture_input_flags;
    struct li2_step_request request={.decoded=s->decoded,.page_count=s->count,.original_flags=s->initial_flags};
    for(size_t i=0;i<s->count;i++)request.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
    struct li2_tf_hooks hooks={{s,authenticate,bnd_failure},continue_closed};
    int error=li2_tf_arm(&s->owner,&session,&hooks,&request);
    if(error)li2_tf_abort(&s->owner,(unsigned)error,0);
    lane=1;fixture_enter();die(1537);
}
struct bnd_refusal {unsigned length;unsigned char bytes[9];};
static const struct bnd_refusal bnd_refusals[]={
    {7,{0xf2,0xff,0x15,0,0,0,0}}, /* CALL is not this JMP leaf */
    {3,{0xf2,0xff,0xe0}}, /* register */
    {3,{0xf2,0xff,0x20}}, /* base register memory */
    {7,{0xf2,0xff,0x2d,0,0,0,0}}, /* far */
    {8,{0x66,0xf2,0xff,0x25,0,0,0,0}},
    {8,{0x67,0xf2,0xff,0x25,0,0,0,0}},
    {8,{0x48,0xf2,0xff,0x25,0,0,0,0}},
    {8,{0xf2,0x48,0xff,0x25,0,0,0,0}},
    {8,{0xf2,0xf2,0xff,0x25,0,0,0,0}},
    {8,{0xf0,0xf2,0xff,0x25,0,0,0,0}},
    {8,{0xf3,0xf2,0xff,0x25,0,0,0,0}},
    {8,{0x3e,0xf2,0xff,0x25,0,0,0,0}},
    {8,{0x64,0xf2,0xff,0x25,0,0,0,0}},
    {8,{0x65,0xf2,0xff,0x25,0,0,0,0}},
    {8,{0xf2,0xff,0x24,0x25,0,0,0,0}}, /* absolute SIB */
    {6,{0xf2,0xff,0x25,0,0,0}}, /* truncated */
};
static void bnd_refusal_controls(void) {
    _Static_assert(sizeof(bnd_refusals)/sizeof(bnd_refusals[0])==16,"closed neighbor set");
    for(size_t i=0;i<16;i++) {
        const struct bnd_refusal *v=&bnd_refusals[i];result.failed_refusal=47+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,v->bytes,v->length,&refused_last);
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,1538);
        ++result.refusals;
    }
    result.failed_refusal=SIZE_MAX;
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)+
                   sizeof(bnd_evidence)<16*1024*1024,"unchanged bounded complete private record");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=BND_PAIRS;
    need(stack[0]==1,1539);setup(stack);
    const char *const *env=(const void *)(stack+3);const char prefix[]="LI2_BND_JMP_CONTROL=";
    for(size_t i=0;env[i];i++)if(length(env[i])>=sizeof(prefix)-1&&!memcmp(env[i],prefix,sizeof(prefix)-1)) {
        need(!bnd_control,1540);const char *v=env[i]+sizeof(prefix)-1;
        if(same(v,"load-fault"))bnd_control=1;
        else if(same(v,"supplied-bndregs"))bnd_control=2;
        else if(same(v,"supplied-bndcsr"))bnd_control=3;
        else if(same(v,"supplied-both"))bnd_control=4;
        else die(1541);
    }
    control=bnd_control==1?1:0;result.control=bnd_control;
    size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc&&complete==li2_tf_refusal_count()&&complete==47,130);
    bnd_refusal_controls();need(result.refusals==63,1542);
    prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} action;
    action.handler=bnd_handler;action.flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL;
    action.restorer=step_restorer;action.mask=mask;
    need(!RAW(SYS_rt_sigaction,SIGSEGV,&action,0,8,0,0)&&
         !RAW(SYS_rt_sigaction,SIGTRAP,&action,0,8,0,0)&&
         !RAW(SYS_rt_sigaction,SIGSYS,&action,0,8,0,0),1543);
    if(bnd_control==1){bnd_prepare(&negative_sample,6);bnd_pair(&negative_sample);die(1544);}
    if(bnd_control>=2)bnd_preopen();
    for(unsigned i=0;i<14;i++){bnd_prepare(&samples[i+1],i);bnd_pair(&samples[i+1]);}
    need(result.completed==BND_PAIRS&&bnd_evidence.native_queries==14&&
         !bnd_evidence.injected_calls&&dump()&&bnd_dump(),1545);
    output("LI2_BND_JMP_TF_PASS pairs=15 bnd_jmp=14 selftest=1 old_refusal_bytes=47 new_refusal_bytes=16 full_state=15 full_memory=15 live_endpoints=15\n");
    return 0;
}
