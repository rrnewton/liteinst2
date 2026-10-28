/* The full SSE2 endpoint machinery is shared through one closed selector.
   No old comparator, owner, refusal or default fixture branch is replaced. */
struct sample;
struct li2_step_owner;
static void pmaxud_inputs(struct sample *);
static void pmaxud_failure(void *,const struct li2_step_owner *);
#define LI2_PMAXUD_FIXTURE 1
#define SSE2_GROUP 0
#include "../sse2_compare/fixture.c"
_Static_assert(SSE2_GROUP==0&&SSE2_PAIRS==19,"one bounded PMAXUD cohort");
static unsigned pmaxud_unaligned;

static void pmaxud_guard_check(void) {
    need(!RAW(SYS_mprotect,data_fault,PAGE,PROT_READ,0,0,0),700);
    for(size_t i=0;i<PAGE;i++)need(((const unsigned char *)data_fault)[i]==(unsigned char)(i*13+0x5b),701);
    need(!RAW(SYS_mprotect,data_fault,PAGE,PROT_NONE,0,0,0),702);
}
static void pmaxud_inputs(struct sample *s) {
    if(s!=&negative_sample)return;
    const struct sse2_case *v=sse2_case(s);need(control==1&&v->memory&&v->code==2993,703);
    if(pmaxud_unaligned) {
        fixture_seed[6]=data_page+1;memcpy((void *)(data_page+1),v->b,16);
        need(actual_protection(data_page,0)==(PROT_READ|PROT_WRITE),704);
    } else {
        need(fixture_seed[6]==data_fault&&!RAW(SYS_mprotect,data_fault,PAGE,PROT_READ|PROT_WRITE,0,0,0),705);
        for(size_t i=0;i<PAGE;i++)((unsigned char *)data_fault)[i]=(unsigned char)(i*13+0x5b);
        need(!RAW(SYS_mprotect,data_fault,PAGE,PROT_NONE,0,0,0),706);
    }
}
/* Only the explicit unaligned control has a new native endpoint. The native
   CPU raises #GP, not #PF. It is retained as a failed instruction before this
   diagnostic observer returns to its trusted capture path. */
static void pmaxud_handler(int sig,siginfo_t *si,void *frame_) {
    if(pmaxud_unaligned&&control==1&&current==&negative_sample&&!lane&&native_phase==1) {
        need(!handling&&si&&frame_,707);handling=1;
        struct sample *s=current;ucontext_t *uc=frame_;greg_t *g=uc->uc_mcontext.gregs;
        need(sig==SIGSEGV&&si->si_signo==SIGSEGV&&si->si_code==SI_KERNEL&&!si->si_errno&&!si->si_addr&&
             (uintptr_t)g[REG_RIP]==s->pc&&g[REG_TRAPNO]==13&&!g[REG_ERR]&&
             (uintptr_t)g[REG_RSI]==data_page+1,708);
        s->native_fault=1;capture(&s->native_after,uc);permissions(s,PROT_READ);native_phase=2;
        g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
        fixture_vector_clobber();handling=0;return;
    }
    handler(sig,si,frame_);
}
static void pmaxud_install_handler(void) {
    struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} action;
    action.handler=pmaxud_handler;action.flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL;
    action.restorer=step_restorer;action.mask=mask;
    need(!RAW(SYS_rt_sigaction,SIGSEGV,&action,0,8,0,0)&&!RAW(SYS_rt_sigaction,SIGTRAP,&action,0,8,0,0)&&
         !RAW(SYS_rt_sigaction,SIGSYS,&action,0,8,0,0),709);
}
static void pmaxud_failure(void *context,const struct li2_step_owner *o) {
    struct sample *s=context;
    if(!(control==1&&s==&negative_sample)){failure(context,o);return;}
    need(control==1&&s==&negative_sample&&sse2_case(s)->memory&&sse2_case(s)->code==2993&&
         s->native_fault&&!s->native_complete&&!s->step_endpoint_seen,710);
    const struct state *before=&s->native_before,*after=&s->native_after;
    need((uintptr_t)after->frame.greg[REG_RIP]==s->pc&&
         after->frame.greg[REG_TRAPNO]==(pmaxud_unaligned?13:14)&&
         after->frame.greg[REG_ERR]==(pmaxud_unaligned?0:4)&&
         (uintptr_t)after->frame.greg[REG_RSI]==(pmaxud_unaligned?data_page+1:data_fault),711);
    if(!pmaxud_unaligned)need((uintptr_t)after->frame.greg[REG_CR2]==data_fault,712);
    for(unsigned i=0;i<16;i++)need(before->frame.greg[regs[i]]==after->frame.greg[regs[i]]&&
         o->after.greg[regs[i]]==after->frame.greg[regs[i]],713);
    need(before->frame.greg[REG_EFL]==after->frame.greg[REG_EFL]&&
         (uint64_t)after->frame.greg[REG_EFL]==((uint64_t)o->after.greg[REG_EFL]&~LI2_STEP_TF)&&
         before->frame.fp_bytes==after->frame.fp_bytes&&o->after.fp_bytes==after->frame.fp_bytes&&
         !memcmp(before->frame.fp,after->frame.fp,before->frame.fp_bytes)&&
         !memcmp(o->after.fp,after->frame.fp,after->frame.fp_bytes)&&
         !memcmp(s->actual_fp[0],s->actual_fp[1],xsave_bytes),714);
    compare_memory(before,after,715);
    need(!memcmp((const void *)subject,after->stack,SUBJECT_BYTES)&&
         !memcmp((const void *)data_page,after->data,DATA_BYTES),716);
    for(unsigned r=0;r<16;r++)need(!memcmp(before->frame.fp+160+16*r,sse2_vectors[r],16),717);
    need(before->fs==after->fs&&before->gs==after->gs&&before->frame.mask==mask&&after->frame.mask==mask&&
         before->frame.greg[REG_CSGSFS]==after->frame.greg[REG_CSGSFS]&&
         o->after.greg[REG_CSGSFS]==after->frame.greg[REG_CSGSFS],718);
    need(s->live[0].started==1&&s->live[0].complete==1&&!s->live[0].reserved&&
         s->live[1].started==1&&s->live[1].complete==1&&!s->live[1].reserved&&
         s->live[0].rflags==s->live[1].rflags&&!memcmp(s->live[0].gpr,s->live[1].gpr,sizeof(s->live[0].gpr))&&
         !memcmp(s->live[0].selectors,s->live[1].selectors,sizeof(s->live[0].selectors)),719);
    need(o->signal_number==SIGSEGV&&!o->signal_errno&&o->signal_code==(pmaxud_unaligned?SI_KERNEL:SEGV_ACCERR)&&
         o->signal_address==(pmaxud_unaligned?0:data_fault),720);
    if(!pmaxud_unaligned) {pmaxud_guard_check();failure(context,o);return;}
    /* The old #PF callback stays exact. This distinct #GP endpoint retains
       its full actual frame, precise fault identity and the same cleanup. */
    result.owner_failure=o->first_error;result.owner_detail_abs=o->first_detail<0?0ULL-(uint64_t)o->first_detail:(uint64_t)o->first_detail;
    result.owner_detail_negative=o->first_detail<0;
    need(o->first_error==LI2_STEP_FOREIGN_EVENT&&o->phase==LI2_STEP_FAILED&&!o->trace_seen&&
         s->owner.unexpected_frame_observed&&!s->owner.continuation_started&&!s->owner.continuation_complete&&
         (uintptr_t)o->after.greg[REG_RIP]==s->pc&&o->after.greg[REG_TRAPNO]==13&&!o->after.greg[REG_ERR],721);
    for(size_t i=0;i<s->count;i++)need(o->opened[i]&&o->revoked[i]&&!o->revoke_result[i]&&
         actual_protection(s->pages[i].address,0)==PROT_READ,722);
    need(o->revoke_sync_started&&!o->revoke_sync,723);
    s->step_fetch=*li2_lifecycle_fetch_progress();need(s->step_fetch.held,724);
    s->negative_verified=1;result.expected_failure_verified=1;
    need(dump(),725);output("LI2_TF_EXPECTED_FAILURE ");number(LI2_STEP_FOREIGN_EVENT);
}
static void pmaxud_refusals(void) {
    static const struct {unsigned n;unsigned char b[8];} rows[]={
        {4,{0x0f,0x38,0x3f,0xc1}},
        {6,{0xf0,0x66,0x0f,0x38,0x3f,0xc1}},
        {6,{0xf2,0x66,0x0f,0x38,0x3f,0xc1}},
        {6,{0xf3,0x66,0x0f,0x38,0x3f,0xc1}},
        {6,{0x66,0x66,0x0f,0x38,0x3f,0xc1}},
        {6,{0x66,0x48,0x0f,0x38,0x3f,0xc1}},
        {6,{0x66,0x40,0x0f,0x38,0x3f,0xc1}},
        {6,{0x66,0x41,0x0f,0x38,0x3f,0xc1}},
        {6,{0x66,0x44,0x0f,0x38,0x3f,0xc1}},
        {6,{0x66,0x45,0x0f,0x38,0x3f,0xe2}},
        {6,{0x66,0x46,0x0f,0x38,0x3f,0xe1}},
        {7,{0x66,0x45,0x40,0x0f,0x38,0x3f,0xe1}},
        {6,{0x2e,0x66,0x0f,0x38,0x3f,0xc1}},
        {6,{0x64,0x66,0x0f,0x38,0x3f,0x06}},
        {6,{0x65,0x66,0x0f,0x38,0x3f,0x06}},
        {6,{0x67,0x66,0x0f,0x38,0x3f,0x06}},
        {5,{0x66,0x0f,0x38,0x3f,0x00}},
        {6,{0x66,0x0f,0x38,0x3f,0x04,0x24}},
        {6,{0x66,0x0f,0x38,0x3f,0x46,0x01}},
        {5,{0xc4,0xe2,0x71,0x3f,0xc1}},
        {6,{0x62,0xf2,0x75,0x08,0x3f,0xc1}},
        {4,{0x66,0x0f,0x38,0x3f}},
        {5,{0x66,0x0f,0x38,0x3d,0xc1}},
        {5,{0x66,0x0f,0x38,0x3b,0xc1}}
    };
    _Static_assert(sizeof(rows)/sizeof(rows[0])==24,"closed PMAXUD neighbors");
    for(size_t i=0;i<sizeof(rows)/sizeof(rows[0]);i++) {
        result.failed_refusal=74+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,rows[i].b,rows[i].n,&refused_last);
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,726);
        ++result.refusals;
    }
    result.failed_refusal=SIZE_MAX;
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)<16*1024*1024,
                   "unchanged complete private record bound");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=SSE2_PAIRS;
    need(stack[0]==1,727);setup(stack);
    unsigned a=1,b,c,d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"=c"(c),"=d"(d));
    need((d&(1U<<26))&&(c&(1U<<19)),728); /* Actual SSE2 and SSE4.1. */
    const char *const *env=(const void *)(stack+3);const char key[]="LI2_PMAXUD_CONTROL=";
    for(size_t i=0;env[i];i++)if(length(env[i])>=sizeof(key)-1&&!memcmp(env[i],key,sizeof(key)-1)) {
        need(!control,729);
        if(same(env[i]+sizeof(key)-1,"load-fault")){control=1;pmaxud_unaligned=0;}
        else {need(same(env[i]+sizeof(key)-1,"unaligned"),730);control=1;pmaxud_unaligned=1;}
    }
    result.control=control;pmaxud_install_handler();
    size_t done=0,failed=0;uint32_t decoder=0;
    need(!li2_tf_refusal_controls(&done,&failed,&decoder,&refused_last)&&done==47&&failed==SIZE_MAX&&!decoder,731);
    result.refusals=done;result.failed_refusal=failed;result.decoder_result=decoder;
    sse2_refusals();pmaxud_refusals();need(result.refusals==98,732);
    sse2_seed_defaults();prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,733);
    if(control){sse2_prepare(&negative_sample,13);sse2_pair(&negative_sample);die(734);}
    for(unsigned i=0;i<18;i++){sse2_prepare(&samples[i+1],i);sse2_pair(&samples[i+1]);}
    need(result.completed==SSE2_PAIRS&&dump(),735);
    output("LI2_PMAXUD_TF_PASS pairs=19 pmaxud=18 selftest=1 old_refusal_bytes=74 new_refusal_bytes=24 full_state=19 full_memory=19 live_endpoints=19\n");
    return 0;
}
