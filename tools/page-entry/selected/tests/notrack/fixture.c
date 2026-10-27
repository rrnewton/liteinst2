/* Additive original-address near-register NOTRACK oracle. Every old capture,
   comparator, setup, refusal and cohort remains unchanged and separately run. */
#define fixture_main li2_unchanged_generic_fixture_main
#include "tests/generic/fixture.c"
#undef fixture_main
#include "cases.inc"
#ifndef NOTRACK_GROUP
#error NOTRACK_GROUP must select JMP or CALL
#endif
_Static_assert(NOTRACK_GROUP>=0&&NOTRACK_GROUP<2,"closed near-branch cohorts");
_Static_assert(PAIRS==21,"unchanged complete private record layout");

static const struct notrack_case *notrack_case(const struct sample *s) {
    need(s->id>=900+20*NOTRACK_GROUP&&s->id<920+20*NOTRACK_GROUP,950);
    return &notrack_cases[NOTRACK_GROUP][s->id-900-20*NOTRACK_GROUP];
}
static void notrack_inputs(struct sample *s) {
    inputs(s);const struct notrack_case *v=notrack_case(s);
    need(v->source<16&&v->source!=4,951);
    fixture_seed[v->source]=s->target;
}
static void notrack_prepare(struct sample *s,unsigned index) {
    need(index<20,952);const struct notrack_case *v=&notrack_cases[NOTRACK_GROUP][index];
    s->id=900+20*NOTRACK_GROUP+index;s->length=v->length;
    need(v->length==(v->source<8?3U:4U)&&v->tail>=1&&v->tail<=v->length&&
         v->call==NOTRACK_GROUP&&v->code==(v->call?759U:765U),953);
    long reserved=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reserved>0,954);s->mapping=(uintptr_t)reserved+PAGE;
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),955);
    memset(s->source,0xcc,sizeof(s->source));size_t offset=PAGE-v->tail;
    s->pc=s->mapping+offset;s->target=s->mapping+2*PAGE+32;s->expected_post=s->target;
    /* Both native and TF endpoints are real NX at the same separate target.
       Even a crossing source opens only pages0/1; target page2 stays closed. */
    s->endpoint_int3=0;s->count=v->tail<v->length?2:1;
    memcpy(s->source+offset,v->bytes,v->length);memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),956);
    need(!li2_decoder_decode(s->pc,(const void *)s->pc,s->length,&s->decoded)&&
         s->decoded.decode_status==LI2_VALID&&s->decoded.kind==LI2_NONE&&
         s->decoded.code==v->code&&s->decoded.length==v->length&&
         s->decoded.next_pc==s->pc+v->length&&!memcmp(s->decoded.bytes,v->bytes,v->length),957);
    need(actual_protection(s->target,0)==PROT_READ,958);
}
static void notrack_effects(struct sample *s) {
    const struct notrack_case *v=notrack_case(s);const struct li2_step_owner *o=&s->owner.step;
    need(s->owner.classification.policy==1&&s->owner.classification.code==v->code&&
         s->owner.classification.flow==LI2_TF_NEAR_FLOW&&
         s->owner.classification.family==(v->call?LI2_TF_CALL:LI2_TF_BRANCH)&&
         s->length==v->length&&s->pc==s->mapping+PAGE-v->tail&&
         s->count==(v->tail<v->length?2U:1U)&&!s->endpoint_int3&&
         !memcmp(s->decoded.bytes,v->bytes,v->length),959);
    need(s->expected_post==s->target&&s->target==s->mapping+2*PAGE+32&&
         s->owner.actual_post_pc==s->target&&(uintptr_t)o->after.greg[REG_RIP]==s->target,960);
    for(unsigned l=0;l<2;l++) {
        const struct state *before=l?&s->step_before:&s->native_before;
        const struct state *after=l?&s->step_endpoint:&s->native_after;
        need((uintptr_t)before->frame.greg[regs[v->source]]==s->target&&
             (uintptr_t)before->frame.greg[REG_RIP]==s->pc&&
             (uintptr_t)after->frame.greg[REG_RIP]==s->target,961);
        for(unsigned r=0;r<16;r++) {
            need((uint64_t)before->frame.greg[regs[r]]==fixture_seed[r],962);
            uint64_t expected=fixture_seed[r];if(r==4&&v->call)expected-=8;
            need((uint64_t)after->frame.greg[regs[r]]==expected&&
                 s->live[2*l+1].gpr[r]==expected,963);
        }
        need(!memcmp(before->data,after->data,DATA_BYTES),964);
        if(v->call) {
            size_t at=SUBJECT_BYTES/2-8;uint64_t original_return=s->pc+s->length;
            need((uintptr_t)before->frame.greg[REG_RSP]==subject+SUBJECT_BYTES/2&&
                 word(before->stack+at)!=original_return&&word(after->stack+at)==original_return&&
                 !memcmp(before->stack,after->stack,at)&&
                 !memcmp(before->stack+at+8,after->stack+at+8,SUBJECT_BYTES-at-8),965);
        } else compare_memory(before,after,966);
        need(before->frame.fp_bytes==after->frame.fp_bytes&&
             !memcmp(before->frame.fp,after->frame.fp,before->frame.fp_bytes)&&
             !memcmp(s->actual_fp[2*l],s->actual_fp[2*l+1],xsave_bytes),967);
    }
    need(s->post_flags==s->initial_flags&&s->live[0].rflags==s->live[1].rflags&&
         s->live[2].rflags==s->live[3].rflags&&o->before.fp_bytes==o->after.fp_bytes&&
         !memcmp(o->before.fp,o->after.fp,o->before.fp_bytes),968);
    for(size_t i=0;i<s->count;i++)need(s->pages[i].address==(s->pc&~(PAGE-1))+i*PAGE&&
         s->pages[i].address!=(s->target&~(PAGE-1))&&
         actual_protection(s->pages[i].address,0)==PROT_READ,969);
    need(s->continuation.complete&&s->continuation.pc==s->target&&
         s->continuation.page.address==(s->target&~(PAGE-1))&&
         actual_protection(s->target,0)==PROT_READ&&
         actual_protection(s->pc+s->length,0)==PROT_READ,970);
    /* For every page-ending CALL, the actual pushed return points to the next
       source page, which was never in the one-page opened fetch request. */
    if(v->call&&v->tail==v->length)need(s->count==1&&
         s->pc+s->length==s->mapping+PAGE&&
         s->pages[0].address==s->mapping,971);
}

/* The old run_pair body, changing only the two input calls and adding the
   literal effects check after its unchanged complete compare(s). */
static void notrack_pair(struct sample *s) {
    current=s;fixture_target=s->pc;notrack_inputs(s);borrow(s);lane=0;native_phase=0;fixture_enter();
    s->initial_flags=fixture_flags;s->live[0]=fixture_live_before;s->live[1]=fixture_live_after;
    memcpy(s->actual_fp[0],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[1],fixture_fp_after,xsave_bytes);
    need(s->native_complete||(s==&negative_sample&&control==1&&s->native_fault),102);
    s->post_flags=(uint64_t)s->native_after.frame.greg[REG_EFL];
    if(!s->endpoint_int3)s->post_flags&=~LI2_STEP_RF;
    need(!(s->initial_flags&(LI2_STEP_RF|LI2_STEP_TF))&&!(s->post_flags&(LI2_STEP_RF|LI2_STEP_TF)),103);
    need(!li2_lifecycle_fetch_release(&s->ref),104);s->native_fetch=*li2_lifecycle_fetch_progress();
    notrack_inputs(s);borrow(s);
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
    compare(s);notrack_effects(s);need(!li2_lifecycle_fetch_release(&s->ref),106);s->step_fetch=*li2_lifecycle_fetch_progress();
    ++result.completed;
}
static void notrack_refusals(void) {
    for(size_t i=0;i<NOTRACK_REFUSALS;i++) {
        const struct notrack_refusal *v=&notrack_refusal_cases[i];result.failed_refusal=47+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,v->bytes,v->length,&refused_last);
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,972);
        ++result.refusals;
    }
    result.failed_refusal=SIZE_MAX;
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)<16*1024*1024,
                   "unchanged complete private record bound");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=PAIRS;
    need(stack[0]==1,973);setup(stack);
    size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc&&complete==li2_tf_refusal_count()&&complete==47,130);
    notrack_refusals();need(result.refusals==47+NOTRACK_REFUSALS,974);
    prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    for(unsigned i=0;i<20;i++){notrack_prepare(&samples[i+1],i);notrack_pair(&samples[i+1]);}
    need(result.completed==PAIRS&&dump(),133);
#if NOTRACK_GROUP==0
    output("LI2_NOTRACK_TF_PASS group=0 branch=jmp pairs=21 notrack=20 selftest=1 old_refusal_bytes=47 new_refusal_bytes=44 full_state=21 full_memory=21 live_endpoints=21\n");
#else
    output("LI2_NOTRACK_TF_PASS group=1 branch=call pairs=21 notrack=20 selftest=1 old_refusal_bytes=47 new_refusal_bytes=44 full_state=21 full_memory=21 live_endpoints=21\n");
#endif
    return 0;
}
