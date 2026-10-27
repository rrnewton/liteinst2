/* Three legacy SSE2 low-lane unpack/shuffle Codes. Old suites and the
   complete original generic state comparator remain separately required. */
#define fixture_main li2_unchanged_generic_fixture_main
#include "tests/generic/fixture.c"
#undef fixture_main
#include "cases.inc"
#ifndef STRING_SETUP_GROUP
#error STRING_SETUP_GROUP must select one of the two bounded cohorts
#endif
_Static_assert(STRING_SETUP_GROUP==0 || STRING_SETUP_GROUP==1,"closed string setup cohort");
_Static_assert(PAIRS==21,"unchanged complete record layout");
#define STRING_SETUP_COUNT 18U
#define STRING_SETUP_PAIRS 19U
unsigned char sse2_vectors[16][32] __attribute__((aligned(32)));
static unsigned string_setup_fault_op;
static const struct string_setup_case *string_setup_case(const struct sample *s) {
    need(s->id>=1600+18*STRING_SETUP_GROUP&&s->id<1618+18*STRING_SETUP_GROUP,900);
    return &string_setup_cases[STRING_SETUP_GROUP][s->id-1600-18*STRING_SETUP_GROUP];
}
static void string_setup_seed_defaults(void) {
    for(unsigned r=0;r<16;r++)for(unsigned j=0;j<32;j++)
        sse2_vectors[r][j]=(unsigned char)(1+13*r+7*j);
}
static void string_setup_inputs(struct sample *s) {
    inputs(s);string_setup_seed_defaults();const struct string_setup_case *v=string_setup_case(s);
    memcpy(sse2_vectors[v->destination],v->a,16);
    if(!v->memory)memcpy(sse2_vectors[v->source],v->b,16);
    memcpy((void *)(data_page+v->offset),v->b,16);
    if(v->memory)fixture_seed[v->base]=(s==&negative_sample&&control==1)?data_fault:data_page+v->offset;
}
static void string_setup_prepare(struct sample *s,unsigned index) {
    need(index<STRING_SETUP_COUNT,901);const struct string_setup_case *v=&string_setup_cases[STRING_SETUP_GROUP][index];
    s->id=1600+18*STRING_SETUP_GROUP+index;s->length=v->length;
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
/* No XSTATE_BV, reserved, x87/MXCSR, upper-vector, or other register bytes are
   normalized: exactly the destination's low128 bits take the literal result. */
static void string_setup_fp_effect(const struct string_setup_case *v,const unsigned char *before,
                                   const unsigned char *after,size_t n,unsigned error) {
    need(n>=512,907);size_t at=160+16*v->destination;
    for(size_t i=0;i<n;i++) {
        unsigned char expected=before[i];
        if(i>=at&&i<at+16)expected=v->expected[i-at];
        need(after[i]==expected,error);
    }
}
static void string_setup_effects(struct sample *s) {
    const struct string_setup_case *v=string_setup_case(s);const struct li2_step_owner *o=&s->owner.step;
    need(s->owner.classification.policy==1&&s->owner.classification.code==v->code&&
         s->owner.classification.flow==LI2_TF_FALLTHROUGH&&s->owner.classification.family==LI2_TF_SIMD&&
         s->expected_post==s->pc+s->length&&!memcmp(s->decoded.bytes,v->bytes,v->length),908);
    need(v->op<3&&v->memory<=1&&v->offset+16<=DATA_BYTES&&!(v->offset&15),909);
    if(!v->memory&&v->source==v->destination)need(!memcmp(v->a,v->b,16),910);
    for(unsigned l=0;l<2;l++) {
        const struct state *before=l?&s->step_before:&s->native_before;
        const struct state *after=l?&s->step_endpoint:&s->native_after;
        for(unsigned r=0;r<16;r++) {
            need((uint64_t)before->frame.greg[regs[r]]==fixture_seed[r]&&
                 (uint64_t)after->frame.greg[regs[r]]==fixture_seed[r],911);
            need(!memcmp(before->frame.fp+160+16*r,sse2_vectors[r],16)&&
                 !memcmp(s->actual_fp[2*l]+160+16*r,sse2_vectors[r],16),912);
            need(s->live[2*l].gpr[r]==fixture_seed[r]&&s->live[2*l+1].gpr[r]==fixture_seed[r],913);
        }
        if(v->memory)need((uintptr_t)before->frame.greg[regs[v->base]]==data_page+v->offset&&
                          !((data_page+v->offset)&15),914);
        need(!memcmp(before->data+v->offset,v->b,16),915);
        compare_memory(before,after,916);
        need(!memcmp(after->frame.fp+160+16*v->destination,v->expected,16),917);
        string_setup_fp_effect(v,before->frame.fp,after->frame.fp,before->frame.fp_bytes,918);
        string_setup_fp_effect(v,s->actual_fp[2*l],s->actual_fp[2*l+1],xsave_bytes,919);
        /* Independent byte-index oracle supplements the literal table. */
        for(unsigned i=0;i<16;i++) {
            unsigned char expected;
            if(v->op==0)expected=(i&1)?v->b[i/2]:v->a[i/2];
            else if(v->op==1)expected=(i&2)?v->b[2*(i/4)+(i&1)]:v->a[2*(i/4)+(i&1)];
            else expected=v->b[4*((v->imm>>(2*(i/4)))&3)+(i&3)];
            need(v->expected[i]==expected&&after->frame.fp[160+16*v->destination+i]==expected,920);
        }
    }
    string_setup_fp_effect(v,o->before.fp,o->after.fp,o->before.fp_bytes,921);
    need(s->initial_flags==s->post_flags&&s->live[0].rflags==s->live[1].rflags&&
         s->live[2].rflags==s->live[3].rflags,922);
    for(size_t i=0;i<s->count;i++)need(actual_protection(s->pages[i].address,0)==PROT_READ,923);
    need(s->continuation.complete&&actual_protection(s->expected_post,0)==PROT_READ,924);
}
static void string_setup_failure(void *context,const struct li2_step_owner *o) {
    struct sample *s=context;
    if(control==1&&s==&negative_sample) {
        const struct string_setup_case *v=string_setup_case(s);
        need(v->memory&&v->op==string_setup_fault_op&&
             s->native_fault&&!s->native_complete&&!s->step_endpoint_seen,925);
        need((uintptr_t)s->native_after.frame.greg[REG_RIP]==s->pc&&
             s->native_after.frame.greg[REG_TRAPNO]==14&&s->native_after.frame.greg[REG_ERR]==4&&
             (uintptr_t)s->native_after.frame.greg[regs[v->base]]==data_fault&&
             (uintptr_t)s->native_after.frame.greg[REG_CR2]==data_fault,926);
        for(unsigned i=0;i<16;i++)need(s->native_before.frame.greg[regs[i]]==
             s->native_after.frame.greg[regs[i]],927);
        need(s->native_before.frame.greg[REG_EFL]==s->native_after.frame.greg[REG_EFL]&&
             s->native_before.frame.fp_bytes==s->native_after.frame.fp_bytes&&
             !memcmp(s->native_before.frame.fp,s->native_after.frame.fp,s->native_before.frame.fp_bytes)&&
             !memcmp(s->actual_fp[0],s->actual_fp[1],xsave_bytes),928);
        compare_memory(&s->native_before,&s->native_after,929);
        for(unsigned r=0;r<16;r++)need(!memcmp(s->native_before.frame.fp+160+16*r,sse2_vectors[r],16),930);
        need(s->native_before.fs==s->native_after.fs&&s->native_before.gs==s->native_after.gs&&
             s->native_before.frame.mask==mask&&s->native_after.frame.mask==mask&&
             s->native_before.frame.greg[REG_CSGSFS]==s->native_after.frame.greg[REG_CSGSFS]&&
             o->after.greg[REG_CSGSFS]==s->native_after.frame.greg[REG_CSGSFS],931);
        need(s->live[0].started==1&&s->live[0].complete==1&&!s->live[0].reserved&&
             s->live[1].started==1&&s->live[1].complete==1&&!s->live[1].reserved&&
             s->live[0].rflags==s->live[1].rflags&&
             !memcmp(s->live[0].gpr,s->live[1].gpr,sizeof(s->live[0].gpr))&&
             !memcmp(s->live[0].selectors,s->live[1].selectors,sizeof(s->live[0].selectors)),932);
    }
    /* Every old failed-frame/revoke/sync/held-borrow check still executes. */
    failure(context,o);
}
static void string_setup_pair(struct sample *s) {
    current=s;fixture_target=s->pc;string_setup_inputs(s);borrow(s);lane=0;native_phase=0;fixture_enter();
    s->initial_flags=fixture_flags;s->live[0]=fixture_live_before;s->live[1]=fixture_live_after;
    memcpy(s->actual_fp[0],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[1],fixture_fp_after,xsave_bytes);
    need(s->native_complete||(s==&negative_sample&&control==1&&s->native_fault),102);
    s->post_flags=(uint64_t)s->native_after.frame.greg[REG_EFL];
    if(!s->endpoint_int3)s->post_flags&=~LI2_STEP_RF;
    /* A faulting native memory case retains RF even for a crossing layout. */
    if(s==&negative_sample&&control==1)s->post_flags&=~LI2_STEP_RF;
    need(!(s->initial_flags&(LI2_STEP_RF|LI2_STEP_TF))&&!(s->post_flags&(LI2_STEP_RF|LI2_STEP_TF)),103);
    need(!li2_lifecycle_fetch_release(&s->ref),104);s->native_fetch=*li2_lifecycle_fetch_progress();
    string_setup_inputs(s);borrow(s);
    struct li2_step_request request={.decoded=s->decoded,.page_count=s->count,.original_flags=s->initial_flags};
    for(size_t i=0;i<s->count;i++)request.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
    struct li2_tf_hooks hooks={{s,authenticate,string_setup_failure},continue_closed};
    int error=li2_tf_arm(&s->owner,&session,&hooks,&request);
    if(error)li2_tf_abort(&s->owner,(unsigned)error,0);
    lane=1;fixture_enter();need(!(s==&negative_sample),105);
    s->live[2]=fixture_live_before;s->live[3]=fixture_live_after;
    memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[3],fixture_fp_after,xsave_bytes);
    compare(s);string_setup_effects(s);
    need(!li2_lifecycle_fetch_release(&s->ref),106);s->step_fetch=*li2_lifecycle_fetch_progress();
    ++result.completed;
}
static void string_setup_refusals(void) {
    static const struct {unsigned n;unsigned char b[7];} cases[]={
        {3,{0x0f,0x60,0xc9}},
        {4,{0xc5,0xf9,0x60,0xc9}},
        {6,{0x62,0xf1,0x7d,0x08,0x60,0xc9}},
        {5,{0xf0,0x66,0x0f,0x60,0xc9}},
        {5,{0xf2,0x66,0x0f,0x60,0xc9}},
        {5,{0xf3,0x66,0x0f,0x60,0xc9}},
        {5,{0x66,0x66,0x0f,0x60,0xc9}},
        {5,{0x66,0x48,0x0f,0x60,0xc9}},
        {6,{0x66,0x45,0x40,0x0f,0x60,0xc9}},
        {5,{0x2e,0x66,0x0f,0x60,0xc9}},
        {5,{0x67,0x66,0x0f,0x60,0xc9}},
        {3,{0x66,0x0f,0x60}},
        {3,{0x0f,0x61,0xc9}},
        {4,{0xc5,0xf9,0x61,0xc9}},
        {6,{0x62,0xf1,0x7d,0x08,0x61,0xc9}},
        {5,{0xf0,0x66,0x0f,0x61,0xc9}},
        {5,{0xf2,0x66,0x0f,0x61,0xc9}},
        {5,{0xf3,0x66,0x0f,0x61,0xc9}},
        {5,{0x66,0x66,0x0f,0x61,0xc9}},
        {5,{0x66,0x48,0x0f,0x61,0xc9}},
        {6,{0x66,0x45,0x40,0x0f,0x61,0xc9}},
        {5,{0x2e,0x66,0x0f,0x61,0xc9}},
        {5,{0x67,0x66,0x0f,0x61,0xc9}},
        {3,{0x66,0x0f,0x61}},
        {4,{0x0f,0x70,0xc9,0x00}},
        {5,{0xc5,0xf9,0x70,0xc9,0x00}},
        {7,{0x62,0xf1,0x7d,0x08,0x70,0xc9,0x00}},
        {6,{0xf0,0x66,0x0f,0x70,0xc9,0x00}},
        {6,{0xf2,0x66,0x0f,0x70,0xc9,0x00}},
        {6,{0xf3,0x66,0x0f,0x70,0xc9,0x00}},
        {6,{0x66,0x66,0x0f,0x70,0xc9,0x00}},
        {6,{0x66,0x48,0x0f,0x70,0xc9,0x00}},
        {7,{0x66,0x45,0x40,0x0f,0x70,0xc9,0x00}},
        {6,{0x2e,0x66,0x0f,0x70,0xc9,0x00}},
        {6,{0x67,0x66,0x0f,0x70,0xc9,0x00}},
        {4,{0x66,0x0f,0x70,0xc9}},
    };
    _Static_assert(sizeof(cases)/sizeof(cases[0])==36,"closed supplied-neighbor cohort");
    for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
        result.failed_refusal=47+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,cases[i].b,cases[i].n,&refused_last);
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,940+(unsigned)i);
        ++result.refusals;
    }
    result.failed_refusal=SIZE_MAX;
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)<16*1024*1024,
                   "unchanged complete private record bound");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=STRING_SETUP_PAIRS;
    need(stack[0]==1,990);setup(stack);
    long data_guard=RAW(SYS_mmap,0,3*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(data_guard>0,933);data_page=(uintptr_t)data_guard+PAGE;
    need(!RAW(SYS_mprotect,data_page,PAGE,PROT_READ|PROT_WRITE,0,0,0)&&
         actual_protection(data_page-PAGE,0)==PROT_NONE&&
         actual_protection(data_page+PAGE,0)==PROT_NONE,934);
    unsigned a=1,b,c,d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"=c"(c),"=d"(d));
    need(d&(1U<<26),991);
    const char *const *env=(const void *)(stack+3);const char key[]="LI2_STRING_SETUP_CONTROL=";
    const char *names[]={"punpcklbw-load-fault","punpcklwd-load-fault","pshufd-load-fault"};
    for(size_t i=0;env[i];i++)if(length(env[i])>=sizeof(key)-1&&!memcmp(env[i],key,sizeof(key)-1)) {
        need(!control&&STRING_SETUP_GROUP==0,992);unsigned found=0;
        for(unsigned j=0;j<3;j++)if(same(env[i]+sizeof(key)-1,names[j])){string_setup_fault_op=j;found++;}
        need(found==1,993);control=1;
    }
    result.control=control;
    size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc&&complete==li2_tf_refusal_count()&&complete==47,130);
    string_setup_refusals();need(result.refusals==83,994);
    string_setup_seed_defaults();prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    if(control){string_setup_prepare(&negative_sample,5+6*string_setup_fault_op);string_setup_pair(&negative_sample);die(995);}
    for(unsigned i=0;i<STRING_SETUP_COUNT;i++){string_setup_prepare(&samples[i+1],i);string_setup_pair(&samples[i+1]);}
    need(result.completed==STRING_SETUP_PAIRS&&dump(),996);
#if STRING_SETUP_GROUP==0
    output("LI2_STRING_SETUP_TF_PASS group=0 pairs=19 string_setup=18 selftest=1 old_refusal_bytes=47 new_refusal_bytes=36 full_state=19 full_memory=19 live_endpoints=19\n");
#else
    output("LI2_STRING_SETUP_TF_PASS group=1 pairs=19 string_setup=18 selftest=1 old_refusal_bytes=47 new_refusal_bytes=36 full_state=19 full_memory=19 live_endpoints=19\n");
#endif
    return 0;
}
