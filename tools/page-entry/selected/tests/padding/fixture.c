/* Additive padding-NOP oracle. Every original helper, endpoint comparison and
   old control is included unchanged; old cohorts remain separately required. */
#define fixture_main li2_unchanged_generic_fixture_main
#include "tests/generic/fixture.c"
#undef fixture_main

#ifndef PADDING_GROUP
#define PADDING_GROUP 0
#endif
#if PADDING_GROUP == 0
#define PADDING_COUNT 20
#define PADDING_FIRST 200
#elif PADDING_GROUP == 1
#define PADDING_COUNT 11
#define PADDING_FIRST 220
#else
#error unsupported padding group
#endif
struct padding_case { unsigned length,tail,code; unsigned char bytes[11]; };
static const struct padding_case padding_cases[]={
#if PADDING_GROUP == 0
    {1,1,300,{0x90}},
    {2,2,299,{0x66,0x90}},
    {3,3,1057,{0x0f,0x1f,0x00}},
    {4,4,1057,{0x0f,0x1f,0x40,0x00}},
    {5,5,1057,{0x0f,0x1f,0x44,0x00,0x00}},
    {6,6,1056,{0x66,0x0f,0x1f,0x44,0x00,0x00}},
    {7,7,1057,{0x0f,0x1f,0x80,0x00,0x00,0x00,0x00}},
    {8,8,1057,{0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {9,9,1056,{0x66,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {10,10,1056,{0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {10,1,1056,{0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {10,2,1056,{0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {10,3,1056,{0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {10,4,1056,{0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {10,5,1056,{0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {10,6,1056,{0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {10,7,1056,{0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {10,8,1056,{0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {10,9,1056,{0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {9,4,1056,{0x66,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
#else
    {11,11,1056,{0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {11,1,1056,{0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {11,2,1056,{0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {11,3,1056,{0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {11,4,1056,{0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {11,5,1056,{0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {11,6,1056,{0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {11,7,1056,{0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {11,8,1056,{0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {11,9,1056,{0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
    {11,10,1056,{0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00}},
#endif
};
_Static_assert(PAIRS==21 && PADDING_COUNT+1<=PAIRS &&
               sizeof(padding_cases)/sizeof(padding_cases[0])==PADDING_COUNT,
               "unchanged bounded capture layout and exact finite group");
static const struct padding_case *padding_case(const struct sample *s) {
    need(s->id>=PADDING_FIRST && s->id<PADDING_FIRST+PADDING_COUNT,400);return &padding_cases[s->id-PADDING_FIRST];
}
static void padding_prepare(struct sample *s,unsigned index) {
    need(index<PADDING_COUNT,401);const struct padding_case *v=&padding_cases[index];
    s->id=PADDING_FIRST+index;s->selftest=0;s->length=v->length;
    need(v->tail && v->tail<=v->length && v->length<=11,402);
    long reserved=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reserved>0,403);s->mapping=(uintptr_t)reserved+PAGE;
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),404);
    memset(s->source,0xcc,sizeof(s->source));size_t offset=PAGE-v->tail;
    s->pc=s->mapping+offset;s->expected_post=s->pc+s->length;
    s->endpoint_int3=v->tail<v->length;s->count=s->endpoint_int3?2:1;
    memcpy(s->source+offset,v->bytes,s->length);memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),405);
    need(!li2_decoder_decode(s->pc,(const void *)s->pc,s->length,&s->decoded) &&
         s->decoded.decode_status==LI2_VALID && s->decoded.kind==LI2_NONE &&
         s->decoded.code==v->code && s->decoded.length==s->length &&
         !memcmp(s->decoded.bytes,v->bytes,s->length),406);
}
static void padding_effects(struct sample *s) {
    const struct padding_case *v=padding_case(s);const struct li2_step_owner *o=&s->owner.step;
    need(s->owner.classification.policy==1 && s->owner.classification.code==v->code &&
         s->owner.classification.flow==LI2_TF_FALLTHROUGH &&
         s->owner.classification.family==LI2_TF_INTEGER && s->length==v->length &&
         s->expected_post==s->pc+v->length && !memcmp(s->decoded.bytes,v->bytes,v->length),407);
    /* Literal no-op effect in each independent lane, in addition to every
       unchanged cross-lane full-state assertion in compare(). */
    for(unsigned i=0;i<16;i++)need(
        s->native_before.frame.greg[regs[i]]==s->native_after.frame.greg[regs[i]] &&
        s->step_before.frame.greg[regs[i]]==o->after.greg[regs[i]] &&
        s->step_before.frame.greg[regs[i]]==s->step_endpoint.frame.greg[regs[i]],408);
    need(s->initial_flags==s->post_flags,409);
    compare_memory(&s->native_before,&s->native_after,410);
    compare_memory(&s->step_before,&s->step_endpoint,411);
    need(!memcmp(s->native_before.frame.fp,s->native_after.frame.fp,s->native_before.frame.fp_bytes) &&
         !memcmp(s->step_before.frame.fp,s->step_endpoint.frame.fp,s->step_before.frame.fp_bytes) &&
         !memcmp(o->before.fp,o->after.fp,o->before.fp_bytes),412);
    need(!memcmp(s->actual_fp[0],s->actual_fp[1],xsave_bytes) &&
         !memcmp(s->actual_fp[2],s->actual_fp[3],xsave_bytes),413);
    need(!memcmp(s->live[0].gpr,s->live[1].gpr,sizeof(s->live[0].gpr)) &&
         !memcmp(s->live[2].gpr,s->live[3].gpr,sizeof(s->live[2].gpr)) &&
         s->live[0].rflags==s->live[1].rflags && s->live[2].rflags==s->live[3].rflags,414);
    need(s->pc==s->mapping+PAGE-v->tail &&
         s->count==(v->tail<v->length?2:1) && s->endpoint_int3==(v->tail<v->length),415);
    for(size_t i=0;i<s->count;i++)need(actual_protection(s->pages[i].address,0)==PROT_READ,416);
    need(actual_protection(s->expected_post,0)==PROT_READ &&
         s->continuation.pc==s->expected_post && s->continuation.complete,417);
}

/* All twelve historical supplied byte strings stay installed. Entry two is
   intentionally promoted from refusal to exact accepted classification and
   additionally receives eleven actual native/TF pairs in group one. The other
   eleven remain refusals; all forty-seven generic controls run unchanged. */
struct padding_refusal { unsigned length; unsigned char bytes[12]; };
static const struct padding_refusal padding_refusals[]={
    {9,{0x2e,0x0f,0x1f,0x84,0,0,0,0,0}},
    {10,{0x2e,0x66,0x0f,0x1f,0x84,0,0,0,0,0}},
    {11,{0x66,0x66,0x2e,0x0f,0x1f,0x84,0,0,0,0,0}},
    {11,{0x66,0x2e,0x2e,0x0f,0x1f,0x84,0,0,0,0,0}},
    {10,{0x66,0x3e,0x0f,0x1f,0x84,0,0,0,0,0}},
    {11,{0x66,0x2e,0x48,0x0f,0x1f,0x84,0,0,0,0,0}},
    {11,{0xf3,0x66,0x2e,0x0f,0x1f,0x84,0,0,0,0,0}},
    {11,{0xf0,0x66,0x2e,0x0f,0x1f,0x84,0,0,0,0,0}},
    {10,{0x66,0x2e,0x0f,0x1f,0x84,0,1,0,0,0}},
    {7,{0x66,0x2e,0x0f,0x1f,0x44,0,0}},
    {5,{0x66,0x2e,0x0f,0x1f,0xc0}},
    {9,{0x66,0x2e,0x0f,0x1f,0x84,0,0,0,0}},
};
_Static_assert(sizeof(padding_refusals)/sizeof(padding_refusals[0])==12,"closed extra refusal set");
static size_t padding_promoted_acceptances;
static void padding_refusal_controls(void) {
    for(size_t i=0;i<12;i++) {
        const struct padding_refusal *v=&padding_refusals[i];result.failed_refusal=47+i;
        result.decoder_result=li2_decoder_tf_classify(UINT64_C(0x1000),v->bytes,v->length,&refused_last);
        if(i==2) {
            need(!result.decoder_result && refused_last.abi_version==1 &&
                 refused_last.pc==UINT64_C(0x1000) && refused_last.next_pc==UINT64_C(0x100b) &&
                 refused_last.length==11 && refused_last.code==1056 && refused_last.policy==1 &&
                 refused_last.flow==LI2_TF_FALLTHROUGH && refused_last.family==LI2_TF_INTEGER,418);
            ++padding_promoted_acceptances;
            continue;
        }
        need(!result.decoder_result && refused_last.abi_version==1 &&
             refused_last.pc==UINT64_C(0x1000) && !refused_last.policy &&
             !refused_last.flow && !refused_last.family,420+(unsigned)i);
        ++result.refusals;
    }
    result.failed_refusal=SIZE_MAX;
}
static void padding_long_refusal_controls(void) {
    static const struct padding_refusal v[]={
        {12,{0x66,0x66,0x66,0x2e,0x0f,0x1f,0x84,0,0,0,0,0}},
        {11,{0x66,0x66,0x2e,0x0f,0x1f,0x84,0,1,0,0,0}},
    };
    for(size_t i=0;i<2;i++) {
        result.failed_refusal=59+i;
        result.decoder_result=li2_decoder_tf_classify(UINT64_C(0x1000),v[i].bytes,v[i].length,&refused_last);
        need(!result.decoder_result && refused_last.abi_version==1 &&
             refused_last.pc==UINT64_C(0x1000) && !refused_last.policy &&
             !refused_last.flow && !refused_last.family,434+(unsigned)i);
        ++result.refusals;
    }
    result.failed_refusal=SIZE_MAX;
}
static void padding_no_memory_access(const struct sample *s) {
    if(PADDING_GROUP!=1)return;
    uint64_t native=(uint64_t)s->native_before.frame.greg[REG_RAX]*2;
    uint64_t stepped=(uint64_t)s->step_before.frame.greg[REG_RAX]*2;
    /* The exact SIB is [RAX+RAX], with zero displacement. These retained
       inputs are noncanonical for both 48- and 57-bit virtual addresses.
       A successful NOP therefore cannot be a hidden read from that operand. */
    need(native==stepped && (native>>48)!=((native&(UINT64_C(1)<<47))?UINT64_C(0xffff):0) &&
         (native>>57)!=((native&(UINT64_C(1)<<56))?UINT64_C(0x7f):0),436);
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)<16*1024*1024,
                   "unchanged complete private record bound");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=PADDING_COUNT+1;
    need(stack[0]==1,432);setup(stack);
    size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc && complete==li2_tf_refusal_count() && complete==47,130);
    padding_refusal_controls();need(result.refusals==58 && padding_promoted_acceptances==1,433);
    padding_long_refusal_controls();need(result.refusals==60,437);
    prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    for(unsigned i=0;i<PADDING_COUNT;i++){padding_prepare(&samples[i+1],i);run_pair(&samples[i+1]);padding_effects(&samples[i+1]);padding_no_memory_access(&samples[i+1]);}
    #if PADDING_GROUP == 1
    const unsigned char *unused=(const void *)&samples[PADDING_COUNT+1];
    for(size_t i=0;i<(PAIRS-PADDING_COUNT-1)*sizeof(samples[0]);i++)need(!unused[i],438);
#endif
    need(result.completed==PADDING_COUNT+1 && dump(),133);
#if PADDING_GROUP == 0
    output("LI2_PADDING_TF_PASS group=0 pairs=21 generic=20 selftest=1 old_refusal_bytes=47 retained_padding_refusal_bytes=11 new_padding_refusal_bytes=2 promoted_padding_encodings=1 full_state=21 full_memory=21 live_endpoints=21\n");
#else
    output("LI2_PADDING_TF_PASS group=1 pairs=12 generic=11 selftest=1 old_refusal_bytes=47 retained_padding_refusal_bytes=11 new_padding_refusal_bytes=2 promoted_padding_encodings=1 full_state=12 full_memory=12 live_endpoints=12\n");
#endif
    return 0;
}
