/* Canonical RDSSPQ with positively observed disabled user shadow stacks.
   Old generic source/assembly/comparators remain mandatory and unchanged. */
#define fixture_main li2_unchanged_generic_fixture_main
#define raw rdssp_actual_raw
#include "tests/generic/fixture.c"
#undef raw
#undef fixture_main
#ifndef RDSSP_GROUP
#error RDSSP_GROUP must select a bounded r64 destination group
#endif
_Static_assert(RDSSP_GROUP==0||RDSSP_GROUP==1,"closed RDSSPQ cohort");
_Static_assert(PAIRS==21,"unchanged original record slots");
#define RDSSP_PAIRS 17U
struct rdssp_query {uint64_t attempted,complete;int64_t result;uint64_t features;};
static struct {
    uint64_t magic,version,bytes,actual_native_queries,injected_calls,injected_control;
    struct rdssp_query native[PAIRS];
} rdssp_evidence;
static unsigned rdssp_control;
static int rdssp_dump(void) {
    rdssp_evidence.magic=UINT64_C(0x315053534452324c);rdssp_evidence.version=1;
    rdssp_evidence.bytes=sizeof(rdssp_evidence);
    return dump()&&write_all(3,&rdssp_evidence,sizeof(rdssp_evidence));
}
/* Never used to manufacture a successful target operation. Only the four
   named negative commands intercept this exact product-owned query pointer. */
long raw(long n,long a,long b,long c,long d,long e,long f) {
    if(rdssp_control&&n==SYS_arch_prctl&&a==0x5005&&
       b==(long)&negative_sample.owner.rdssp_features) {
        need(rdssp_control<=4&&lane==1&&current==&negative_sample&&
             negative_sample.owner.step.phase==LI2_STEP_ARMED&&
             negative_sample.owner.rdssp_query_attempted&&
             !negative_sample.owner.rdssp_query_complete&&!rdssp_evidence.injected_calls,1100);
        ++rdssp_evidence.injected_calls;rdssp_evidence.injected_control=rdssp_control;
        if(rdssp_control==1)return -22;
        if(rdssp_control==2)return -38;
        *(uint64_t *)b=rdssp_control==3?1:2;return 0;
    }
    return rdssp_actual_raw(n,a,b,c,d,e,f);
}
static void rdssp_prepare(struct sample *s,unsigned reg,unsigned tail) {
    need(reg<16&&tail>=1&&tail<=5,1101);s->id=1800+reg;s->length=5;
    unsigned char bytes[]={0xf3,reg<8?0x48:0x49,0x0f,0x1e,0xc8+(reg&7)};
    long area=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(area>0,1102);s->mapping=(uintptr_t)area+PAGE;
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),1103);
    memset(s->source,0xcc,sizeof(s->source));size_t offset=PAGE-tail;
    s->pc=s->mapping+offset;s->expected_post=s->pc+5;s->endpoint_int3=tail<5;s->count=tail<5?2:1;
    memcpy(s->source+offset,bytes,5);memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),1104);
    need(!li2_decoder_decode(s->pc,(const void *)s->pc,5,&s->decoded)&&
         s->decoded.decode_status==LI2_VALID&&s->decoded.kind==LI2_NONE&&s->decoded.code==1053&&
         s->decoded.length==5&&!memcmp(s->decoded.bytes,bytes,5),1105);
}
static void rdssp_native_query(unsigned index) {
    need(index>0&&index<RDSSP_PAIRS&&!rdssp_evidence.native[index].attempted,1106);
    struct rdssp_query *q=&rdssp_evidence.native[index];q->features=UINT64_MAX;q->attempted=1;
    q->result=rdssp_actual_raw(SYS_arch_prctl,0x5005,(long)&q->features,0,0,0,0);q->complete=1;
    ++rdssp_evidence.actual_native_queries;
    if(q->result||q->features) {
        result.fixture_failure=1107;(void)rdssp_dump();output("LI2_RDSSP_NATIVE_CUSTODY_FAILURE\n");
        (void)rdssp_actual_raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
}
static void rdssp_effects(struct sample *s,unsigned index) {
    const struct li2_step_owner *o=&s->owner.step;
    need(s->owner.classification.policy==1&&s->owner.classification.code==1053&&
         s->owner.classification.flow==LI2_TF_FALLTHROUGH&&s->owner.classification.family==LI2_TF_INTEGER&&
         s->length==5&&s->expected_post==s->pc+5,1108);
    need(rdssp_evidence.native[index].attempted==1&&rdssp_evidence.native[index].complete==1&&
         !rdssp_evidence.native[index].result&&!rdssp_evidence.native[index].features&&
         s->owner.rdssp_query_attempted==1&&s->owner.rdssp_query_complete==1&&
         !s->owner.rdssp_query_result&&!s->owner.rdssp_features&&!rdssp_evidence.injected_calls,1109);
    for(unsigned l=0;l<2;l++) {
        const struct state *before=l?&s->step_before:&s->native_before;
        const struct state *after=l?&s->step_endpoint:&s->native_after;
        for(unsigned i=0;i<16;i++)need((uint64_t)before->frame.greg[regs[i]]==fixture_seed[i]&&
             (uint64_t)after->frame.greg[regs[i]]==fixture_seed[i]&&
             s->live[2*l].gpr[i]==fixture_seed[i]&&s->live[2*l+1].gpr[i]==fixture_seed[i],1110);
        compare_memory(before,after,1111);
        need(before->frame.fp_bytes==after->frame.fp_bytes&&
             !memcmp(before->frame.fp,after->frame.fp,before->frame.fp_bytes)&&
             !memcmp(s->actual_fp[2*l],s->actual_fp[2*l+1],xsave_bytes)&&
             before->fs==after->fs&&before->gs==after->gs,1112);
        need(s->live[2*l].rflags==s->live[2*l+1].rflags&&
             !memcmp(s->live[2*l].selectors,s->live[2*l+1].selectors,sizeof(s->live[0].selectors)),1113);
    }
    need(s->initial_flags==s->post_flags&&o->before.fp_bytes==o->after.fp_bytes&&
         !memcmp(o->before.fp,o->after.fp,o->before.fp_bytes),1114);
    for(size_t i=0;i<s->count;i++)need(actual_protection(s->pages[i].address,0)==PROT_READ,1115);
    need(s->continuation.complete&&actual_protection(s->expected_post,0)==PROT_READ,1116);
}
static void rdssp_pair(struct sample *s,unsigned index) {
    current=s;fixture_target=s->pc;inputs(s);borrow(s);rdssp_native_query(index);
    lane=0;native_phase=0;fixture_enter();
    s->initial_flags=fixture_flags;s->live[0]=fixture_live_before;s->live[1]=fixture_live_after;
    memcpy(s->actual_fp[0],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[1],fixture_fp_after,xsave_bytes);
    need(s->native_complete,1117);s->post_flags=(uint64_t)s->native_after.frame.greg[REG_EFL];
    if(!s->endpoint_int3)s->post_flags&=~LI2_STEP_RF;
    need(!(s->initial_flags&(LI2_STEP_RF|LI2_STEP_TF))&&!(s->post_flags&(LI2_STEP_RF|LI2_STEP_TF)),103);
    need(!li2_lifecycle_fetch_release(&s->ref),104);s->native_fetch=*li2_lifecycle_fetch_progress();
    inputs(s);borrow(s);
    struct li2_step_request request={.decoded=s->decoded,.page_count=s->count,.original_flags=s->initial_flags};
    for(size_t i=0;i<s->count;i++)request.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
    struct li2_tf_hooks hooks={{s,authenticate,failure},continue_closed};
    int error=li2_tf_arm(&s->owner,&session,&hooks,&request);
    if(error)li2_tf_abort(&s->owner,(unsigned)error,0);
    lane=1;fixture_enter();need(!(s==&negative_sample),105);
    s->live[2]=fixture_live_before;s->live[3]=fixture_live_after;
    memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[3],fixture_fp_after,xsave_bytes);
    compare(s);rdssp_effects(s,index);
    need(!li2_lifecycle_fetch_release(&s->ref),106);s->step_fetch=*li2_lifecycle_fetch_progress();++result.completed;
}
static void rdssp_failure(void *context,const struct li2_step_owner *o) {
    struct sample *s=context;const struct li2_tf_owner *tf=&s->owner;
    long query=rdssp_control==1?-22:rdssp_control==2?-38:0;
    uint64_t features=rdssp_control<=2?UINT64_MAX:rdssp_control==3?1:2;
    unsigned error=rdssp_control<=2?LI2_TF_SHSTK_QUERY:LI2_TF_SHSTK_ENABLED;
    long detail=rdssp_control<=2?query:(long)features;
    result.owner_failure=o->first_error;result.owner_detail_abs=o->first_detail<0?0ULL-(uint64_t)o->first_detail:(uint64_t)o->first_detail;
    result.owner_detail_negative=o->first_detail<0;
    need(s==&negative_sample&&rdssp_control>=1&&rdssp_control<=4&&
         o->first_error==error&&o->first_detail==detail&&o->phase==LI2_STEP_FAILED&&
         !o->trace_seen&&!o->after.initialized&&!tf->continuation_started&&!tf->continuation_complete&&
         !tf->unexpected_frame_observed&&!s->step_endpoint_seen&&!s->native_complete&&!s->native_fault,1120);
    need(tf->rdssp_query_attempted==1&&tf->rdssp_query_complete==1&&
         tf->rdssp_query_result==query&&tf->rdssp_features==features&&
         rdssp_evidence.injected_calls==1&&rdssp_evidence.injected_control==rdssp_control&&
         !rdssp_evidence.actual_native_queries,1121);
    need(o->signal_number==SIGSEGV&&o->signal_code==SEGV_ACCERR&&!o->signal_errno&&
         o->signal_address==s->pc&&(uintptr_t)o->before.greg[REG_RIP]==s->pc&&
         o->before.greg[REG_TRAPNO]==14&&o->before.greg[REG_ERR]==21&&
         (uint64_t)o->before.greg[REG_EFL]==(fixture_flags|LI2_STEP_RF)&&
         o->before.initialized==o->before.fp_bytes&&o->before.mask==mask,1122);
    need(!memcmp(o->before.greg,s->step_before.frame.greg,sizeof(o->before.greg))&&
         o->before.fp_bytes==s->step_before.frame.fp_bytes&&
         !memcmp(o->before.fp,s->step_before.frame.fp,o->before.fp_bytes),1123);
    for(unsigned i=0;i<16;i++)need((uint64_t)o->before.greg[regs[i]]==fixture_seed[i],1124);
    for(size_t i=0;i<2;i++)need(!o->open_started[i]&&!o->opened[i]&&!o->open_result[i]&&
         !o->revoke_started[i]&&!o->revoked[i]&&!o->revoke_result[i],1125);
    need(!o->open_sync&&o->revoke_sync_started&&!o->revoke_sync,1126);
    for(size_t i=0;i<s->count;i++)need(!authenticate(s,&o->request.pages[i],PROT_READ)&&
         actual_protection(s->pages[i].address,0)==PROT_READ,1127);
    need(!memcmp((void *)s->mapping,s->source,sizeof(s->source))&&
         !memcmp((void *)subject,s->step_before.stack,SUBJECT_BYTES)&&
         !memcmp((void *)data_page,s->step_before.data,DATA_BYTES)&&
         li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,1128);
    s->live[2]=fixture_live_before;memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);
    need(s->live[2].started==1&&s->live[2].complete==1&&!s->live[2].reserved&&s->live[2].rflags==fixture_flags,1129);
    for(unsigned i=0;i<16;i++)need(s->live[2].gpr[i]==fixture_seed[i],1130);
    s->step_fetch=*li2_lifecycle_fetch_progress();s->negative_verified=1;result.expected_failure_verified=1;
    need(rdssp_dump(),1131);output("LI2_RDSSP_INJECTED_QUERY_REFUSAL control=");number(rdssp_control);
    /* Owner terminates125. No syscall was issued by the injected query, and
       no target RDSSPQ executed; neither is credited as native failure. */
}
static _Noreturn void rdssp_negative(void) {
    struct sample *s=&negative_sample;rdssp_prepare(s,0,4);
    current=s;fixture_target=s->pc;inputs(s);borrow(s);s->initial_flags=samples[0].initial_flags;
    struct li2_step_request request={.decoded=s->decoded,.page_count=s->count,.original_flags=s->initial_flags};
    for(size_t i=0;i<s->count;i++)request.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
    struct li2_tf_hooks hooks={{s,authenticate,rdssp_failure},continue_closed};
    int error=li2_tf_arm(&s->owner,&session,&hooks,&request);
    if(error)li2_tf_abort(&s->owner,(unsigned)error,0);
    lane=1;fixture_enter();die(1132);
}
static void rdssp_refusals(void) {
    static const struct {unsigned n;unsigned char b[7];} cases[]={
        {4,{0xf3,0x0f,0x1e,0xc8}},{5,{0xf3,0x41,0x0f,0x1e,0xc8}},
        {5,{0xf3,0x48,0x0f,0x1e,0x08}},{5,{0xf3,0x48,0x0f,0x1e,0xc0}},
        {5,{0xf3,0x4a,0x0f,0x1e,0xc8}},{5,{0xf3,0x4c,0x0f,0x1e,0xc8}},
        {5,{0xf3,0x4d,0x0f,0x1e,0xc8}},{5,{0xf3,0x4b,0x0f,0x1e,0xc8}},
        {6,{0x66,0xf3,0x48,0x0f,0x1e,0xc8}},{6,{0x67,0xf3,0x48,0x0f,0x1e,0xc8}},
        {6,{0xf2,0xf3,0x48,0x0f,0x1e,0xc8}},{6,{0xf0,0xf3,0x48,0x0f,0x1e,0xc8}},
        {6,{0xf3,0xf3,0x48,0x0f,0x1e,0xc8}},{6,{0xf3,0x48,0x48,0x0f,0x1e,0xc8}},
        {5,{0x48,0xf3,0x0f,0x1e,0xc8}},{4,{0xf3,0x48,0x0f,0x1e}}
    };
    _Static_assert(sizeof(cases)/sizeof(cases[0])==16,"exact new refusal palette");
    for(size_t i=0;i<16;i++) {
        result.failed_refusal=47+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,cases[i].b,cases[i].n,&refused_last);
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,1140+(unsigned)i);++result.refusals;
    }
    result.failed_refusal=SIZE_MAX;
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)+sizeof(rdssp_evidence)<16*1024*1024,
                   "bounded complete record including actual query evidence");
    _Static_assert(sizeof(rdssp_evidence)==720,"six header words plus21 four-word native queries");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=RDSSP_PAIRS;
    need(stack[0]==1,1160);setup(stack);
    const char *const *env=(const void *)(stack+3);const char key[]="LI2_RDSSP_CONTROL=";
    const char *names[]={"query-einval","query-enosys","status-shstk","status-wrss"};
    for(size_t i=0;env[i];i++)if(length(env[i])>=sizeof(key)-1&&!memcmp(env[i],key,sizeof(key)-1)) {
        need(!rdssp_control&&RDSSP_GROUP==0,1161);
        for(unsigned j=0;j<4;j++)if(same(env[i]+sizeof(key)-1,names[j]))rdssp_control=j+1;
        need(rdssp_control,1162);
    }
    result.control=rdssp_control;
    size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc&&complete==li2_tf_refusal_count()&&complete==47,130);rdssp_refusals();need(result.refusals==63,1163);
    prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    if(rdssp_control)rdssp_negative();
    for(unsigned i=0;i<16;i++){rdssp_prepare(&samples[i+1],8*RDSSP_GROUP+i/2,i%2?4:5);rdssp_pair(&samples[i+1],i+1);}
    need(result.completed==RDSSP_PAIRS&&rdssp_evidence.actual_native_queries==16&&!rdssp_evidence.injected_calls&&rdssp_dump(),1164);
#if RDSSP_GROUP==0
    output("LI2_RDSSP_TF_PASS group=0 pairs=17 rdsspq=16 selftest=1 actual_native_query_zero=16 actual_owner_query_zero=16 old_refusal_bytes=47 new_refusal_bytes=16 full_state=17 full_memory=17 live_endpoints=17\n");
#else
    output("LI2_RDSSP_TF_PASS group=1 pairs=17 rdsspq=16 selftest=1 actual_native_query_zero=16 actual_owner_query_zero=16 old_refusal_bytes=47 new_refusal_bytes=16 full_state=17 full_memory=17 live_endpoints=17\n");
#endif
    return 0;
}
