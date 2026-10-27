/* Additional ordinary-integer corpus. The original fixture and every old
   pair/control remain unchanged and are run separately at the same revision. */
#define fixture_main li2_unchanged_generic_fixture_main
#include "../generic/fixture.c"
#undef fixture_main
#include "cases.inc"
#ifndef INTEGER_GROUP
#error INTEGER_GROUP must select an exact compiled cohort
#endif
_Static_assert(INTEGER_GROUP==0 || INTEGER_GROUP==1,"closed integer cohort");
_Static_assert(PAIRS==21,"unchanged bounded shared capture layout");

static const struct integer_case *integer_case(const struct sample *s) {
    need(s->id>=100+20*INTEGER_GROUP && s->id<120+20*INTEGER_GROUP,300);
    return &integer_cases[INTEGER_GROUP][s->id-100-20*INTEGER_GROUP];
}
static void integer_inputs(struct sample *s) {
    inputs(s);
    const struct integer_case *v=integer_case(s);
    fixture_seed[0]=v->a;fixture_seed[1]=v->c;fixture_seed[2]=v->d;fixture_seed[3]=v->b;
    memcpy((void *)(data_page+8),&v->m,8);
}
static void integer_prepare(struct sample *s,unsigned index) {
    need(index<20,301);const struct integer_case *v=&integer_cases[INTEGER_GROUP][index];
    s->id=100+20*INTEGER_GROUP+index;s->selftest=0;s->length=v->length;
    long reserved=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reserved>0,302);s->mapping=(uintptr_t)reserved+PAGE;
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),303);
    memset(s->source,0xcc,sizeof(s->source));size_t offset=PAGE-s->length;
    s->pc=s->mapping+offset;s->expected_post=s->pc+s->length;
    memcpy(s->source+offset,v->bytes,s->length);memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),304);
    need(!li2_decoder_decode(s->pc,(const void *)s->pc,s->length,&s->decoded)&&
         s->decoded.decode_status==LI2_VALID&&s->decoded.kind==LI2_NONE&&s->decoded.length==s->length,305);
    s->count=1;
}
static void integer_effects(struct sample *s) {
    const struct integer_case *v=integer_case(s);
    const struct li2_step_owner *o=&s->owner.step;
    need(s->owner.classification.policy==1 && s->owner.classification.flow==LI2_TF_FALLTHROUGH &&
         s->owner.classification.family==LI2_TF_INTEGER && s->expected_post==s->pc+s->length &&
         !memcmp(s->decoded.bytes,v->bytes,v->length),306);
    for(unsigned i=0;i<16;i++) {
        uint64_t expected=(uint64_t)s->native_before.frame.greg[regs[i]];
        if(i==0)expected=v->ao;else if(i==2)expected=v->do_;else if(i==3)expected=v->bo;
        need((uint64_t)s->native_after.frame.greg[regs[i]]==expected &&
             (uint64_t)o->after.greg[regs[i]]==expected &&
             (uint64_t)s->step_endpoint.frame.greg[regs[i]]==expected,307);
    }
    need((s->post_flags&v->flag_mask)==v->flag_value,308);
    need(!memcmp(s->native_before.stack,s->native_after.stack,SUBJECT_BYTES)&&
         !memcmp(s->step_before.stack,s->step_endpoint.stack,SUBJECT_BYTES),309);
    for(size_t i=0;i<DATA_BYTES;i++) {
        unsigned char expected=s->native_before.data[i];
        if(i>=8&&i<16)expected=(unsigned char)(v->mo>>(8*(i-8)));
        need(s->native_after.data[i]==expected&&s->step_endpoint.data[i]==expected,310);
    }
    need(!memcmp(s->native_before.frame.fp,s->native_after.frame.fp,s->native_before.frame.fp_bytes)&&
         !memcmp(s->step_before.frame.fp,s->step_endpoint.frame.fp,s->step_before.frame.fp_bytes)&&
         !memcmp(o->before.fp,o->after.fp,o->before.fp_bytes),311);
    need(!memcmp(s->actual_fp[0],s->actual_fp[1],xsave_bytes)&&
         !memcmp(s->actual_fp[2],s->actual_fp[3],xsave_bytes),312);
}
/* Same protocol as run_pair, with independent per-case input seeds and
   additional literal effect checks. No original assertion is replaced. */
static void integer_pair(struct sample *s) {
    current=s;fixture_target=s->pc;integer_inputs(s);borrow(s);lane=0;native_phase=0;fixture_enter();
    s->initial_flags=fixture_flags;s->live[0]=fixture_live_before;s->live[1]=fixture_live_after;
    memcpy(s->actual_fp[0],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[1],fixture_fp_after,xsave_bytes);
    need(s->native_complete,313);
    s->post_flags=(uint64_t)s->native_after.frame.greg[REG_EFL]&~LI2_STEP_RF;
    need(!(s->initial_flags&(LI2_STEP_RF|LI2_STEP_TF))&&!(s->post_flags&(LI2_STEP_RF|LI2_STEP_TF)),103);
    need(!li2_lifecycle_fetch_release(&s->ref),104);s->native_fetch=*li2_lifecycle_fetch_progress();
    integer_inputs(s);borrow(s);
    struct li2_step_request request={.decoded=s->decoded,.page_count=s->count,.original_flags=s->initial_flags};
    for(size_t i=0;i<s->count;i++)request.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
    struct li2_tf_hooks hooks={{s,authenticate,failure},continue_closed};
    int error=li2_tf_arm(&s->owner,&session,&hooks,&request);
    if(error)li2_tf_abort(&s->owner,(unsigned)error,0);
    lane=1;fixture_enter();
    need(!(s==&negative_sample),105);
    s->live[2]=fixture_live_before;s->live[3]=fixture_live_after;
    memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[3],fixture_fp_after,xsave_bytes);
    compare(s);integer_effects(s);
    need(!li2_lifecycle_fetch_release(&s->ref),106);s->step_fetch=*li2_lifecycle_fetch_progress();
    ++result.completed;
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)<16*1024*1024,"bounded complete private record");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=PAIRS;
    need(stack[0]==1,314);setup(stack);
    size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc&&complete==li2_tf_refusal_count()&&complete==47,130);
    prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    for(unsigned i=0;i<20;i++){integer_prepare(&samples[i+1],i);integer_pair(&samples[i+1]);}
    need(result.completed==PAIRS&&dump(),133);
#if INTEGER_GROUP==0
    output("LI2_INTEGER_TF_PASS group=0 pairs=21 generic=20 selftest=1 refusal_bytes=47 full_state=21 full_memory=21 live_endpoints=21\n");
#else
    output("LI2_INTEGER_TF_PASS group=1 pairs=21 generic=20 selftest=1 refusal_bytes=47 full_state=21 full_memory=21 live_endpoints=21\n");
#endif
    return 0;
}
