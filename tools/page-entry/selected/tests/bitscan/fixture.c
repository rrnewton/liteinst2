/* Additive BSF/BSR oracle. Every original comparator, capture instruction,
   refusal control and cohort remains separately required and unchanged. */
#define fixture_main li2_unchanged_generic_fixture_main
#include "tests/generic/fixture.c"
#undef fixture_main
#include "cases.inc"
#ifndef BITSCAN_GROUP
#error BITSCAN_GROUP must select one of the three bounded width cohorts
#endif
_Static_assert(BITSCAN_GROUP>=0 && BITSCAN_GROUP<3,"closed bitscan cohort");
_Static_assert(PAIRS==21,"unchanged bounded record layout");
#define BITSCAN_PAIRS 17
static unsigned bitscan_fault_reverse;

static const struct bitscan_case *bitscan_case(const struct sample *s) {
    need(s->id>=600+16*BITSCAN_GROUP && s->id<616+16*BITSCAN_GROUP,700);
    return &bitscan_cases[BITSCAN_GROUP][s->id-600-16*BITSCAN_GROUP];
}
static uint64_t bitscan_mask(unsigned width) {
    return width==64?UINT64_MAX:(UINT64_C(1)<<width)-1;
}
static void bitscan_inputs(struct sample *s) {
    inputs(s);const struct bitscan_case *v=bitscan_case(s);
    if(v->memory)memcpy((void *)data_page,&v->input,v->width/8);
    else fixture_seed[v->source]=v->input|(UINT64_C(0x8edcba9876543210)&~bitscan_mask(v->width));
    /* The original inputs() selects the real PROT_NONE data_fault for control1. */
}
static void bitscan_prepare(struct sample *s,unsigned index) {
    need(index<16,701);const struct bitscan_case *v=&bitscan_cases[BITSCAN_GROUP][index];
    s->id=600+16*BITSCAN_GROUP+index;s->length=v->length;
    long reserved=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reserved>0,702);s->mapping=(uintptr_t)reserved+PAGE;
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),703);
    need(v->tail>=1&&v->tail<=v->length,704);
    memset(s->source,0xcc,sizeof(s->source));size_t offset=PAGE-v->tail;
    s->pc=s->mapping+offset;s->expected_post=s->pc+s->length;
    s->endpoint_int3=v->tail<v->length;s->count=s->endpoint_int3?2:1;
    memcpy(s->source+offset,v->bytes,v->length);memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),705);
    need(!li2_decoder_decode(s->pc,(const void *)s->pc,s->length,&s->decoded)&&
         s->decoded.decode_status==LI2_VALID&&s->decoded.kind==LI2_NONE&&
         s->decoded.code==v->code&&s->decoded.length==v->length&&
         !memcmp(s->decoded.bytes,v->bytes,v->length),706);
}
static void bitscan_effects(struct sample *s) {
    const struct bitscan_case *v=bitscan_case(s);const struct li2_step_owner *o=&s->owner.step;
    need(s->owner.classification.policy==1&&s->owner.classification.code==v->code&&
         s->owner.classification.flow==LI2_TF_FALLTHROUGH&&s->owner.classification.family==LI2_TF_INTEGER&&
         s->expected_post==s->pc+s->length&&!memcmp(s->decoded.bytes,v->bytes,v->length),707);
    for(unsigned l=0;l<2;l++) {
        const struct state *before=l?&s->step_before:&s->native_before;
        const struct state *after=l?&s->step_endpoint:&s->native_after;
        for(unsigned r=0;r<16;r++)need((uint64_t)before->frame.greg[regs[r]]==fixture_seed[r],708);
        if(v->memory)need((uintptr_t)before->frame.greg[REG_RSI]==data_page&&
             !memcmp(before->data,&v->input,v->width/8),709);
        else need(((uint64_t)before->frame.greg[regs[v->source]]&bitscan_mask(v->width))==v->input,710);
        compare_memory(before,after,711);
        need(before->frame.fp_bytes==after->frame.fp_bytes&&
             !memcmp(before->frame.fp,after->frame.fp,before->frame.fp_bytes)&&
             !memcmp(s->actual_fp[2*l],s->actual_fp[2*l+1],xsave_bytes),712);
        for(unsigned r=0;r<16;r++) {
            uint64_t expected=(uint64_t)before->frame.greg[regs[r]];
            if(r==v->destination) {
                /* Portable literal contract: no assumed destination result
                   for a zero operand. compare(s) still requires its complete
                   actual native, TRACE and post-sigreturn values to agree. */
                if(!v->input)continue;
                expected=v->width==16?(expected&~UINT64_C(0xffff))|v->expected:v->expected;
            }
            need((uint64_t)after->frame.greg[regs[r]]==expected&&
                 s->live[2*l+1].gpr[r]==expected,713);
        }
    }
    need(o->before.fp_bytes==o->after.fp_bytes&&
         !memcmp(o->before.fp,o->after.fp,o->before.fp_bytes),714);
    /* ZF is the sole cross-processor literal flag claim. No undefined or
       model-dependent flag is masked out of the exact native/TF comparator. */
    uint64_t zf=v->input?0:UINT64_C(0x40);
    need((s->post_flags&UINT64_C(0x40))==zf&&
         ((uint64_t)o->after.greg[REG_EFL]&UINT64_C(0x40))==zf&&
         (s->live[1].rflags&UINT64_C(0x40))==zf&&
         (s->live[3].rflags&UINT64_C(0x40))==zf,715);
    if(v->input&&v->width==32)need(((uint64_t)s->native_before.frame.greg[regs[v->destination]]>>32)!=0&&
         !((uint64_t)s->native_after.frame.greg[regs[v->destination]]>>32),716);
    if(v->input&&v->width==16)need(((uint64_t)s->native_before.frame.greg[regs[v->destination]]>>16)!=0&&
         ((uint64_t)s->native_before.frame.greg[regs[v->destination]]>>16)==
         ((uint64_t)s->native_after.frame.greg[regs[v->destination]]>>16),717);
    for(size_t i=0;i<s->count;i++)need(actual_protection(s->pages[i].address,0)==PROT_READ,718);
    need(s->continuation.complete&&actual_protection(s->expected_post,0)==PROT_READ,719);
}
static void bitscan_failure(void *context,const struct li2_step_owner *o) {
    struct sample *s=context;
    if(control==1&&s==&negative_sample) {
        const struct bitscan_case *v=bitscan_case(s);
        need(v->memory&&v->width==64&&v->reverse==bitscan_fault_reverse&&
             v->code==(bitscan_fault_reverse?2126U:2120U)&&
             s->native_fault&&!s->native_complete&&!s->step_endpoint_seen,720);
        need((uintptr_t)s->native_after.frame.greg[REG_RIP]==s->pc&&
             s->native_after.frame.greg[REG_TRAPNO]==14&&s->native_after.frame.greg[REG_ERR]==4&&
             (uintptr_t)s->native_after.frame.greg[REG_RSI]==data_fault,721);
        for(unsigned i=0;i<16;i++)need(s->native_before.frame.greg[regs[i]]==
             s->native_after.frame.greg[regs[i]],722);
        need(s->native_before.frame.greg[REG_EFL]==s->native_after.frame.greg[REG_EFL]&&
             s->native_before.frame.fp_bytes==s->native_after.frame.fp_bytes&&
             !memcmp(s->native_before.frame.fp,s->native_after.frame.fp,s->native_before.frame.fp_bytes)&&
             !memcmp(s->actual_fp[0],s->actual_fp[1],xsave_bytes),723);
        compare_memory(&s->native_before,&s->native_after,724);
        need(s->native_before.fs==s->native_after.fs&&s->native_before.gs==s->native_after.gs&&
             s->native_before.frame.mask==mask&&s->native_after.frame.mask==mask&&
             s->native_before.frame.greg[REG_CSGSFS]==s->native_after.frame.greg[REG_CSGSFS]&&
             o->after.greg[REG_CSGSFS]==s->native_after.frame.greg[REG_CSGSFS],725);
        need(s->live[0].started==1&&s->live[0].complete==1&&!s->live[0].reserved&&
             s->live[1].started==1&&s->live[1].complete==1&&!s->live[1].reserved&&
             s->live[0].rflags==s->live[1].rflags&&
             !memcmp(s->live[0].gpr,s->live[1].gpr,sizeof(s->live[0].gpr))&&
             !memcmp(s->live[0].selectors,s->live[1].selectors,sizeof(s->live[0].selectors)),726);
    }
    /* Preserve every old failed-instruction/frame/revoke/sync/held-borrow
       predicate and the exact failed-operation exit, never mark it complete. */
    failure(context,o);
}
static void bitscan_pair(struct sample *s) {
    current=s;fixture_target=s->pc;bitscan_inputs(s);borrow(s);lane=0;native_phase=0;fixture_enter();
    s->initial_flags=fixture_flags;s->live[0]=fixture_live_before;s->live[1]=fixture_live_after;
    memcpy(s->actual_fp[0],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[1],fixture_fp_after,xsave_bytes);
    need(s->native_complete||(s==&negative_sample&&control==1&&s->native_fault),102);
    s->post_flags=(uint64_t)s->native_after.frame.greg[REG_EFL];
    if(!s->endpoint_int3)s->post_flags&=~LI2_STEP_RF;
    /* A failed memory load retains actual RF even in a crossing layout.
       The raw native frame remains intact; only this logical seed omits RF. */
    if(s==&negative_sample&&control==1)s->post_flags&=~LI2_STEP_RF;
    need(!(s->initial_flags&(LI2_STEP_RF|LI2_STEP_TF))&&!(s->post_flags&(LI2_STEP_RF|LI2_STEP_TF)),103);
    need(!li2_lifecycle_fetch_release(&s->ref),104);s->native_fetch=*li2_lifecycle_fetch_progress();
    bitscan_inputs(s);borrow(s);
    struct li2_step_request request={.decoded=s->decoded,.page_count=s->count,.original_flags=s->initial_flags};
    for(size_t i=0;i<s->count;i++)request.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
    struct li2_tf_hooks hooks={{s,authenticate,bitscan_failure},continue_closed};
    int error=li2_tf_arm(&s->owner,&session,&hooks,&request);
    if(error)li2_tf_abort(&s->owner,(unsigned)error,0);
    lane=1;fixture_enter();need(!(s==&negative_sample),105);
    s->live[2]=fixture_live_before;s->live[3]=fixture_live_after;
    memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[3],fixture_fp_after,xsave_bytes);
    compare(s);bitscan_effects(s);
    need(!li2_lifecycle_fetch_release(&s->ref),106);s->step_fetch=*li2_lifecycle_fetch_progress();
    ++result.completed;
}
static void bitscan_refusals(void) {
    static const struct {unsigned n;unsigned char b[5];} cases[]={
        {4,{0xf3,0x0f,0xbc,0xc2}},{5,{0xf3,0x66,0x0f,0xbc,0xc2}},
        {5,{0xf3,0x48,0x0f,0xbc,0xc2}},{4,{0xf2,0x0f,0xbc,0xc2}},
        {4,{0xf0,0x0f,0xbc,0xc2}},{5,{0x66,0x48,0x0f,0xbc,0xc2}},
        {5,{0x66,0x66,0x0f,0xbc,0xc2}},{5,{0x48,0x41,0x0f,0xbc,0xc2}},
        {4,{0x2e,0x0f,0xbc,0xc2}},{4,{0x64,0x0f,0xbc,0xc2}},
        {4,{0x67,0x0f,0xbc,0xc2}},{2,{0x0f,0xbc}},
        {4,{0xf3,0x0f,0xbd,0xc2}},{5,{0xf3,0x66,0x0f,0xbd,0xc2}},
        {5,{0xf3,0x48,0x0f,0xbd,0xc2}},{4,{0xf2,0x0f,0xbd,0xc2}},
        {4,{0xf0,0x0f,0xbd,0xc2}},{5,{0x66,0x48,0x0f,0xbd,0xc2}},
        {5,{0x66,0x66,0x0f,0xbd,0xc2}},{5,{0x48,0x41,0x0f,0xbd,0xc2}},
        {4,{0x2e,0x0f,0xbd,0xc2}},{4,{0x64,0x0f,0xbd,0xc2}},
        {4,{0x67,0x0f,0xbd,0xc2}},{2,{0x0f,0xbd}}
    };
    _Static_assert(sizeof(cases)/sizeof(cases[0])==24,"closed supplied-prefix cohort");
    for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
        result.failed_refusal=47+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,cases[i].b,cases[i].n,&refused_last);
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,730+(unsigned)i);
        ++result.refusals;
    }
    result.failed_refusal=SIZE_MAX;
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)<16*1024*1024,
                   "unchanged complete private record bound");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=BITSCAN_PAIRS;
    need(stack[0]==1,760);setup(stack);
    const char *const *env=(const void *)(stack+3);const char key[]="LI2_BITSCAN_CONTROL=";
    for(size_t i=0;env[i];i++)if(length(env[i])>=sizeof(key)-1&&!memcmp(env[i],key,sizeof(key)-1)) {
        need(!control&&BITSCAN_GROUP==2,761);
        const char *value=env[i]+sizeof(key)-1;
        need(same(value,"bsf-load-fault")||same(value,"bsr-load-fault"),762);
        bitscan_fault_reverse=same(value,"bsr-load-fault");control=1;
    }
    result.control=control;
    size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc&&complete==li2_tf_refusal_count()&&complete==47,130);
    bitscan_refusals();need(result.refusals==71,763);
    prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    if(control){bitscan_prepare(&negative_sample,bitscan_fault_reverse?13:5);bitscan_pair(&negative_sample);die(764);}
    for(unsigned i=0;i<16;i++){bitscan_prepare(&samples[i+1],i);bitscan_pair(&samples[i+1]);}
    need(result.completed==BITSCAN_PAIRS&&dump(),765);
#if BITSCAN_GROUP==0
    output("LI2_BITSCAN_TF_PASS group=0 width=16 pairs=17 bitscan=16 selftest=1 old_refusal_bytes=47 new_refusal_bytes=24 full_state=17 full_memory=17 live_endpoints=17\n");
#elif BITSCAN_GROUP==1
    output("LI2_BITSCAN_TF_PASS group=1 width=32 pairs=17 bitscan=16 selftest=1 old_refusal_bytes=47 new_refusal_bytes=24 full_state=17 full_memory=17 live_endpoints=17\n");
#else
    output("LI2_BITSCAN_TF_PASS group=2 width=64 pairs=17 bitscan=16 selftest=1 old_refusal_bytes=47 new_refusal_bytes=24 full_state=17 full_memory=17 live_endpoints=17\n");
#endif
    return 0;
}
