/* Additive legacy SSE2 oracle. The old fixture, assembly capture semantics,
   owners, refusal controls and every old cohort remain separately required. */
#define fixture_main li2_unchanged_generic_fixture_main
#include "tests/generic/fixture.c"
#undef fixture_main
#ifdef LI2_PMAXUD_FIXTURE
#include "../pmaxud/cases.inc"
#else
#include "cases.inc"
#endif
#ifndef SSE2_GROUP
#error SSE2_GROUP must select one of the two bounded cohorts
#endif
_Static_assert(SSE2_GROUP==0 || SSE2_GROUP==1,"closed SSE2 cohort");
_Static_assert(PAIRS==21,"unchanged bounded record layout");
#define SSE2_PAIRS 19
unsigned char sse2_vectors[16][32] __attribute__((aligned(32)));

static const struct sse2_case *sse2_case(const struct sample *s) {
    need(s->id>=400+18*SSE2_GROUP && s->id<418+18*SSE2_GROUP,600);
    return &sse2_cases[SSE2_GROUP][s->id-400-18*SSE2_GROUP];
}
static void sse2_seed_defaults(void) {
    for(unsigned r=0;r<16;r++)for(unsigned j=0;j<32;j++)
        sse2_vectors[r][j]=(unsigned char)(1+13*r+7*j);
}
static void sse2_inputs(struct sample *s) {
    inputs(s);sse2_seed_defaults();
    const struct sse2_case *v=sse2_case(s);
    if(v->movemask)memcpy(sse2_vectors[v->source],v->a,16);
    else {
        memcpy(sse2_vectors[v->destination],v->a,16);
        if(v->memory)memcpy((void *)data_page,v->b,16);
        else memcpy(sse2_vectors[v->source],v->b,16);
    }
#ifdef LI2_PMAXUD_FIXTURE
    pmaxud_inputs(s);
#endif
    /* inputs() retains the genuine PROT_NONE data_fault RSI for control 1. */
}
static void sse2_prepare(struct sample *s,unsigned index) {
    need(index<18,601);const struct sse2_case *v=&sse2_cases[SSE2_GROUP][index];
    s->id=400+18*SSE2_GROUP+index;s->length=v->length;
    long reserved=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reserved>0,602);s->mapping=(uintptr_t)reserved+PAGE;
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),603);
    need(v->tail>=1&&v->tail<=v->length,604);
    memset(s->source,0xcc,sizeof(s->source));size_t offset=PAGE-v->tail;
    s->pc=s->mapping+offset;s->expected_post=s->pc+s->length;
    s->endpoint_int3=v->tail<v->length;s->count=s->endpoint_int3?2:1;
    memcpy(s->source+offset,v->bytes,v->length);memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),605);
    need(!li2_decoder_decode(s->pc,(const void *)s->pc,s->length,&s->decoded)&&
         s->decoded.decode_status==LI2_VALID&&s->decoded.kind==LI2_NONE&&
         s->decoded.code==v->code&&s->decoded.length==v->length&&
         !memcmp(s->decoded.bytes,v->bytes,v->length),606);
}
/* Full initialized FP byte comparison with the single literal XMM write set.
   The standard legacy area starts XMM0 at 160 in both actual saved formats.
   No XSTATE_BV, upper-YMM, reserved, x87 or MXCSR bytes are normalized. */
static void sse2_fp_effect(const struct sse2_case *v,const unsigned char *before,
                           const unsigned char *after,size_t n,unsigned error) {
    need(n>=512,607);
    size_t at=160+16*v->destination;
    for(size_t i=0;i<n;i++) {
        unsigned char expected=before[i];
        if(!v->movemask&&i>=at&&i<at+16)expected=v->expected[i-at];
        need(after[i]==expected,error);
    }
}
static void sse2_effects(struct sample *s) {
    const struct sse2_case *v=sse2_case(s);const struct li2_step_owner *o=&s->owner.step;
    need(s->owner.classification.policy==1&&s->owner.classification.code==v->code&&
         s->owner.classification.flow==LI2_TF_FALLTHROUGH&&s->owner.classification.family==LI2_TF_SIMD&&
         s->expected_post==s->pc+s->length&&!memcmp(s->decoded.bytes,v->bytes,v->length),608);
    for(unsigned lane_=0;lane_<2;lane_++) {
        const struct state *before=lane_?&s->step_before:&s->native_before;
        const struct state *after=lane_?&s->step_endpoint:&s->native_after;
        /* Actual input registers must equal the independent literal seeds. */
        for(unsigned r=0;r<16;r++)need((uint64_t)before->frame.greg[regs[r]]==fixture_seed[r],608);
        for(unsigned r=0;r<16;r++)need(!memcmp(before->frame.fp+160+16*r,sse2_vectors[r],16)&&
             !memcmp(s->actual_fp[2*lane_]+160+16*r,sse2_vectors[r],16),609);
        if(v->memory)need((uintptr_t)before->frame.greg[REG_RSI]==data_page&&!(data_page&15)&&
             !memcmp(before->data,v->b,16),610);
        compare_memory(before,after,611);
        sse2_fp_effect(v,before->frame.fp,after->frame.fp,before->frame.fp_bytes,612);
        sse2_fp_effect(v,s->actual_fp[2*lane_],s->actual_fp[2*lane_+1],xsave_bytes,613);
    }
    sse2_fp_effect(v,o->before.fp,o->after.fp,o->before.fp_bytes,614);
    for(unsigned i=0;i<16;i++) {
        uint64_t expected=(uint64_t)s->native_before.frame.greg[regs[i]];
        if(v->movemask&&i==v->destination)expected=v->mask;
        need((uint64_t)s->native_after.frame.greg[regs[i]]==expected&&
             (uint64_t)o->after.greg[regs[i]]==expected&&
             (uint64_t)s->step_endpoint.frame.greg[regs[i]]==expected,615);
        for(unsigned l=0;l<2;l++)need(s->live[2*l+1].gpr[i]==
             ((v->movemask&&i==v->destination)?v->mask:s->live[2*l].gpr[i]),616);
    }
    if(v->movemask)need(((uint64_t)s->native_before.frame.greg[regs[v->destination]]>>32)!=0,617);
    need(s->initial_flags==s->post_flags&&s->live[0].rflags==s->live[1].rflags&&
         s->live[2].rflags==s->live[3].rflags,618);
    for(size_t i=0;i<s->count;i++)need(actual_protection(s->pages[i].address,0)==PROT_READ,619);
    need(s->continuation.complete&&actual_protection(s->expected_post,0)==PROT_READ,620);
}
#ifndef LI2_PMAXUD_FIXTURE
static void sse2_failure(void *context,const struct li2_step_owner *o) {
    struct sample *s=context;
    if(control==1&&s==&negative_sample) {
        const struct sse2_case *v=sse2_case(s);
        need(v->memory&&!v->movemask&&v->code==1715&&
             s->native_fault&&!s->native_complete&&!s->step_endpoint_seen,621);
        need((uintptr_t)s->native_after.frame.greg[REG_RIP]==s->pc&&
             s->native_after.frame.greg[REG_TRAPNO]==14&&s->native_after.frame.greg[REG_ERR]==4&&
             (uintptr_t)s->native_after.frame.greg[REG_RSI]==data_fault,622);
        for(unsigned i=0;i<16;i++)need(s->native_before.frame.greg[regs[i]]==
             s->native_after.frame.greg[regs[i]],623);
        need(s->native_before.frame.greg[REG_EFL]==s->native_after.frame.greg[REG_EFL]&&
             s->native_before.frame.fp_bytes==s->native_after.frame.fp_bytes&&
             !memcmp(s->native_before.frame.fp,s->native_after.frame.fp,s->native_before.frame.fp_bytes)&&
             !memcmp(s->actual_fp[0],s->actual_fp[1],xsave_bytes),624);
        compare_memory(&s->native_before,&s->native_after,625);
        for(unsigned r=0;r<16;r++)need(!memcmp(s->native_before.frame.fp+160+16*r,
             sse2_vectors[r],16),626);
        need(s->native_before.fs==s->native_after.fs&&s->native_before.gs==s->native_after.gs&&
             s->native_before.frame.mask==mask&&s->native_after.frame.mask==mask&&
             s->native_before.frame.greg[REG_CSGSFS]==s->native_after.frame.greg[REG_CSGSFS]&&
             o->after.greg[REG_CSGSFS]==s->native_after.frame.greg[REG_CSGSFS],627);
        need(s->live[0].started==1&&s->live[0].complete==1&&!s->live[0].reserved&&
             s->live[1].started==1&&s->live[1].complete==1&&!s->live[1].reserved&&
             s->live[0].rflags==s->live[1].rflags&&
             !memcmp(s->live[0].gpr,s->live[1].gpr,sizeof(s->live[0].gpr))&&
             !memcmp(s->live[0].selectors,s->live[1].selectors,sizeof(s->live[0].selectors)),628);
    }
    /* Exact old failed-operation checks retain actual signal/owner/frame,
       revoke+sync, memory and held-fetch prefix, then the owner exits 125. */
    failure(context,o);
}
#endif
static void sse2_pair(struct sample *s) {
    current=s;fixture_target=s->pc;sse2_inputs(s);borrow(s);lane=0;native_phase=0;fixture_enter();
    s->initial_flags=fixture_flags;s->live[0]=fixture_live_before;s->live[1]=fixture_live_after;
    memcpy(s->actual_fp[0],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[1],fixture_fp_after,xsave_bytes);
    need(s->native_complete||(s==&negative_sample&&control==1&&s->native_fault),102);
    s->post_flags=(uint64_t)s->native_after.frame.greg[REG_EFL];
    if(!s->endpoint_int3)s->post_flags&=~LI2_STEP_RF;
    /* A faulting native memory case retains RF even for a crossing layout. */
    if(s==&negative_sample&&control==1)s->post_flags&=~LI2_STEP_RF;
    need(!(s->initial_flags&(LI2_STEP_RF|LI2_STEP_TF))&&!(s->post_flags&(LI2_STEP_RF|LI2_STEP_TF)),103);
    need(!li2_lifecycle_fetch_release(&s->ref),104);s->native_fetch=*li2_lifecycle_fetch_progress();
    sse2_inputs(s);borrow(s);
    struct li2_step_request request={.decoded=s->decoded,.page_count=s->count,.original_flags=s->initial_flags};
    for(size_t i=0;i<s->count;i++)request.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
#ifdef LI2_PMAXUD_FIXTURE
    struct li2_tf_hooks hooks={{s,authenticate,pmaxud_failure},continue_closed};
#else
    struct li2_tf_hooks hooks={{s,authenticate,sse2_failure},continue_closed};
#endif
    int error=li2_tf_arm(&s->owner,&session,&hooks,&request);
    if(error)li2_tf_abort(&s->owner,(unsigned)error,0);
    lane=1;fixture_enter();need(!(s==&negative_sample),105);
    s->live[2]=fixture_live_before;s->live[3]=fixture_live_after;
    memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[3],fixture_fp_after,xsave_bytes);
    compare(s);sse2_effects(s);
    need(!li2_lifecycle_fetch_release(&s->ref),106);s->step_fetch=*li2_lifecycle_fetch_progress();
    ++result.completed;
}
static void sse2_refusals(void) {
    /* Nonlegacy/neighbor forms are supplied bytes only, never target code. */
    static const struct {unsigned n;unsigned char b[7];} cases[]={
        {3,{0x0f,0x74,0xe0}},{3,{0x0f,0x75,0xe0}},{3,{0x0f,0x76,0xe0}},
        {3,{0x0f,0x64,0xe0}},{3,{0x0f,0x65,0xe0}},{3,{0x0f,0x66,0xe0}},
        {3,{0x0f,0xda,0xe0}},{3,{0x0f,0xde,0xe0}},{3,{0x0f,0xd7,0xc4}},
        {5,{0x66,0x48,0x0f,0xd7,0xc4}},{4,{0x66,0x0f,0xd7,0x00}},
        {4,{0xc5,0xf9,0x74,0xe0}},{4,{0xc5,0xf9,0x64,0xe0}},
        {4,{0xc5,0xf9,0xda,0xe0}},{4,{0xc5,0xf9,0xde,0xe0}},
        {4,{0xc5,0xf9,0xd7,0xc4}},{6,{0x62,0xf1,0x7d,0x08,0x74,0xe0}},
        {5,{0xf3,0x66,0x0f,0x74,0xe0}},{5,{0xf2,0x66,0x0f,0x74,0xe0}},
        {5,{0xf0,0x66,0x0f,0x74,0xe0}},{5,{0x66,0x66,0x0f,0x74,0xe0}},
        {5,{0x48,0x66,0x0f,0x74,0xe0}},{6,{0x66,0x41,0x40,0x0f,0x74,0xe0}},
        {5,{0x2e,0x66,0x0f,0x74,0xe0}},{5,{0x64,0x66,0x0f,0x74,0xe0}},
        {5,{0x67,0x66,0x0f,0x74,0xe0}},{3,{0x66,0x0f,0x74}}
    };
    _Static_assert(sizeof(cases)/sizeof(cases[0])==27,"closed supplied-neighbor cohort");
    for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
        result.failed_refusal=47+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,cases[i].b,cases[i].n,&refused_last);
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,630+(unsigned)i);
        ++result.refusals;
    }
    result.failed_refusal=SIZE_MAX;
}
#ifndef LI2_PMAXUD_FIXTURE
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)<16*1024*1024,
                   "unchanged complete private record bound");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=SSE2_PAIRS;
    need(stack[0]==1,660);setup(stack);
    unsigned a=1,b,c,d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"=c"(c),"=d"(d));
    need(d&(1U<<26),661); /* Actual SSE2 prerequisite; no masked guest answer. */
    const char *const *env=(const void *)(stack+3);const char key[]="LI2_SSE2_CONTROL=";
    for(size_t i=0;env[i];i++)if(length(env[i])>=sizeof(key)-1&&!memcmp(env[i],key,sizeof(key)-1)) {
        need(!control&&SSE2_GROUP==0&&same(env[i]+sizeof(key)-1,"load-fault"),662);control=1;
    }
    result.control=control;
    size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc&&complete==li2_tf_refusal_count()&&complete==47,130);
    sse2_refusals();need(result.refusals==74,663);
    sse2_seed_defaults();prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    if(control){sse2_prepare(&negative_sample,1);sse2_pair(&negative_sample);die(664);}
    for(unsigned i=0;i<18;i++){sse2_prepare(&samples[i+1],i);sse2_pair(&samples[i+1]);}
    need(result.completed==SSE2_PAIRS&&dump(),665);
#if SSE2_GROUP==0
    output("LI2_SSE2_TF_PASS group=0 pairs=19 sse2=18 selftest=1 old_refusal_bytes=47 new_refusal_bytes=27 full_state=19 full_memory=19 live_endpoints=19\n");
#else
    output("LI2_SSE2_TF_PASS group=1 pairs=19 sse2=18 selftest=1 old_refusal_bytes=47 new_refusal_bytes=27 full_state=19 full_memory=19 live_endpoints=19\n");
#endif
    return 0;
}
#endif
