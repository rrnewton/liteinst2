/* Two legacy byte shifts. Reuse the unchanged native/TF full-state oracle
   and actual live GPR/selector/XSAVE capture; add literal per-lane effects. */
#define fixture_main li2_unchanged_generic_fixture_main
#include "tests/generic/fixture.c"
#undef fixture_main
#include "cases.inc"
#ifndef BYTE_SHIFT_GROUP
#error BYTE_SHIFT_GROUP must select one of the two bounded cohorts
#endif
_Static_assert(BYTE_SHIFT_GROUP==0 || BYTE_SHIFT_GROUP==1,"closed byte-shift cohort");
_Static_assert(PAIRS==21,"unchanged complete record layout");
#define BYTE_SHIFT_COUNT 20U
#define BYTE_SHIFT_PAIRS (BYTE_SHIFT_COUNT+1)
/* The existing SSE2 assembly initializes all sixteen XMM/YMM registers. */
unsigned char sse2_vectors[16][32] __attribute__((aligned(32)));

static const struct byte_shift_case *byte_shift_case(const struct sample *s) {
    need(s->id>=1200+20*BYTE_SHIFT_GROUP&&s->id<1220+20*BYTE_SHIFT_GROUP,900);
    return &byte_shift_cases[BYTE_SHIFT_GROUP][s->id-1200-20*BYTE_SHIFT_GROUP];
}
static void byte_shift_seed_defaults(void) {
    for(unsigned r=0;r<16;r++)for(unsigned j=0;j<32;j++)
        sse2_vectors[r][j]=(unsigned char)(1+13*r+7*j);
}
static void byte_shift_inputs(struct sample *s) {
    inputs(s);byte_shift_seed_defaults();
    const struct byte_shift_case *v=byte_shift_case(s);
    memcpy(sse2_vectors[v->xmm],v->input,16);
}
static void byte_shift_prepare(struct sample *s,unsigned index) {
    need(index<BYTE_SHIFT_COUNT,901);const struct byte_shift_case *v=&byte_shift_cases[BYTE_SHIFT_GROUP][index];
    s->id=1200+20*BYTE_SHIFT_GROUP+index;s->length=v->length;
    long reserved=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reserved>0,902);s->mapping=(uintptr_t)reserved+PAGE;
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),903);
    need(v->tail>=1&&v->tail<=v->length,904);
    memset(s->source,0xcc,sizeof(s->source));size_t offset=PAGE-v->tail;
    s->pc=s->mapping+offset;s->expected_post=s->pc+s->length;
    s->endpoint_int3=v->tail<v->length;s->count=s->endpoint_int3?2:1;
    memcpy(s->source+offset,v->bytes,v->length);memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),905);
    need(!li2_decoder_decode(s->pc,(const void *)s->pc,s->length,&s->decoded)&&
         s->decoded.decode_status==LI2_VALID&&s->decoded.kind==LI2_NONE&&s->decoded.code==v->code&&
         s->decoded.length==v->length&&!memcmp(s->decoded.bytes,v->bytes,v->length),906);
}
/* Only the selected low 128 bits may change. Every other initialized kernel
   FP/live XSAVE byte remains exact, including upper vectors and state headers. */
static void byte_shift_fp_effect(const struct byte_shift_case *v,const unsigned char *before,
                                 const unsigned char *after,size_t n,unsigned error) {
    need(n>=512,907);size_t at=160+16*v->xmm;
    for(size_t i=0;i<n;i++) {
        unsigned char expected=before[i];
        if(i>=at&&i<at+16)expected=v->expected[i-at];
        need(after[i]==expected,error);
    }
}
static void byte_shift_effects(struct sample *s) {
    const struct byte_shift_case *v=byte_shift_case(s);const struct li2_step_owner *o=&s->owner.step;
    need(v->left<=1&&(v->count==0||v->count==1||v->count==15||v->count==16||v->count==255)&&
         v->code==(v->left?1708U:1695U)&&v->xmm==(BYTE_SHIFT_GROUP?9U:1U),908);
    need(s->owner.classification.policy==1&&s->owner.classification.code==v->code&&
         s->owner.classification.flow==LI2_TF_FALLTHROUGH&&s->owner.classification.family==LI2_TF_SIMD&&
         s->expected_post==s->pc+s->length&&!memcmp(s->decoded.bytes,v->bytes,v->length),909);
    /* Independently check every literal expected byte; no native result is
       used to manufacture the expected value. Counts >=16 zero all 16 bytes. */
    for(unsigned i=0;i<16;i++) {
        unsigned char expected=0;
        if(v->count<16) {
            if(v->left&&i>=v->count)expected=v->input[i-v->count];
            if(!v->left&&i+v->count<16)expected=v->input[i+v->count];
        }
        need(v->expected[i]==expected,910);
    }
    for(unsigned l=0;l<2;l++) {
        const struct state *before=l?&s->step_before:&s->native_before;
        const struct state *after=l?&s->step_endpoint:&s->native_after;
        for(unsigned r=0;r<16;r++) {
            need((uint64_t)before->frame.greg[regs[r]]==fixture_seed[r]&&
                 before->frame.greg[regs[r]]==after->frame.greg[regs[r]],911);
            need(!memcmp(before->frame.fp+160+16*r,sse2_vectors[r],16)&&
                 !memcmp(s->actual_fp[2*l]+160+16*r,sse2_vectors[r],16),912);
            need(s->live[2*l].gpr[r]==s->live[2*l+1].gpr[r],913);
        }
        compare_memory(before,after,914);
        need(!memcmp(after->frame.fp+160+16*v->xmm,v->expected,16),915);
        byte_shift_fp_effect(v,before->frame.fp,after->frame.fp,before->frame.fp_bytes,916);
        byte_shift_fp_effect(v,s->actual_fp[2*l],s->actual_fp[2*l+1],xsave_bytes,917);
    }
    byte_shift_fp_effect(v,o->before.fp,o->after.fp,o->before.fp_bytes,918);
    need(s->initial_flags==s->post_flags&&s->live[0].rflags==s->live[1].rflags&&
         s->live[2].rflags==s->live[3].rflags,919);
    for(size_t i=0;i<s->count;i++)need(actual_protection(s->pages[i].address,0)==PROT_READ,920);
    need(s->continuation.complete&&actual_protection(s->expected_post,0)==PROT_READ,921);
}
static void byte_shift_pair(struct sample *s) {
    current=s;fixture_target=s->pc;byte_shift_inputs(s);borrow(s);lane=0;native_phase=0;fixture_enter();
    s->initial_flags=fixture_flags;s->live[0]=fixture_live_before;s->live[1]=fixture_live_after;
    memcpy(s->actual_fp[0],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[1],fixture_fp_after,xsave_bytes);
    need(s->native_complete||(s==&negative_sample&&control==1&&s->native_fault),102);
    s->post_flags=(uint64_t)s->native_after.frame.greg[REG_EFL];
    if(!s->endpoint_int3)s->post_flags&=~LI2_STEP_RF;
    need(!(s->initial_flags&(LI2_STEP_RF|LI2_STEP_TF))&&!(s->post_flags&(LI2_STEP_RF|LI2_STEP_TF)),103);
    need(!li2_lifecycle_fetch_release(&s->ref),104);s->native_fetch=*li2_lifecycle_fetch_progress();
    byte_shift_inputs(s);borrow(s);
    struct li2_step_request request={.decoded=s->decoded,.page_count=s->count,.original_flags=s->initial_flags};
    for(size_t i=0;i<s->count;i++)request.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
    struct li2_tf_hooks hooks={{s,authenticate,failure},continue_closed};
    int error=s->selftest?li2_step_arm(&s->owner.step,&session,&hooks.step,&request,1):
                         li2_tf_arm(&s->owner,&session,&hooks,&request);
    if(error)li2_tf_abort(&s->owner,(unsigned)error,0);
    lane=1;fixture_enter();
    need(!(s==&negative_sample),105);
    s->live[2]=fixture_live_before;s->live[3]=fixture_live_after;
    memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[3],fixture_fp_after,xsave_bytes);
    compare(s);byte_shift_effects(s);
    need(!li2_lifecycle_fetch_release(&s->ref),106);s->step_fetch=*li2_lifecycle_fetch_progress();
    ++result.completed;
}
/* Supplied malformed/nonlegacy neighbors only, never executed as target code. */
static void byte_shift_refusals(void) {
    for(size_t i=0;i<sizeof(byte_shift_refused)/sizeof(byte_shift_refused[0]);i++) {
        const struct byte_shift_refusal *v=&byte_shift_refused[i];
        result.failed_refusal=47+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,v->b,v->n,&refused_last);
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,930+(unsigned)i);
        ++result.refusals;
    }
    result.failed_refusal=SIZE_MAX;
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)<16*1024*1024,
                   "unchanged complete private record bound");
    _Static_assert(sizeof(byte_shift_refused)/sizeof(byte_shift_refused[0])==30,"closed supplied refusal cohort");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=BYTE_SHIFT_PAIRS;
    need(stack[0]==1,970);setup(stack);
    unsigned a=1,b,c,d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"=c"(c),"=d"(d));
    need(d&(1U<<26),971);
    /* No operation-fault command is claimed for these register-only forms. */
    need(!control,972);
    size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc&&complete==li2_tf_refusal_count()&&complete==47,130);
    byte_shift_refusals();need(result.refusals==77,973);
    byte_shift_seed_defaults();prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    for(unsigned i=0;i<BYTE_SHIFT_COUNT;i++){byte_shift_prepare(&samples[i+1],i);byte_shift_pair(&samples[i+1]);}
    need(result.completed==BYTE_SHIFT_PAIRS&&dump(),974);
#if BYTE_SHIFT_GROUP==0
    output("LI2_BYTE_SHIFT_TF_PASS group=0 pairs=21 shifts=20 selftest=1 old_refusal_bytes=47 new_refusal_bytes=30 full_state=21 full_memory=21 live_endpoints=21\n");
#else
    output("LI2_BYTE_SHIFT_TF_PASS group=1 pairs=21 shifts=20 selftest=1 old_refusal_bytes=47 new_refusal_bytes=30 full_state=21 full_memory=21 live_endpoints=21\n");
#endif
    return 0;
}
