/* Four legacy SSE2 m64 half moves. Old fixture bodies remain included exact.
   This oracle adds literal per-lane effects and genuine load/store faults. */
#define fixture_main li2_unchanged_generic_fixture_main
#include "tests/generic/fixture.c"
#undef fixture_main
#include "cases.inc"
#ifndef HALVES_GROUP
#error HALVES_GROUP must select one of the two bounded cohorts
#endif
_Static_assert(HALVES_GROUP==0 || HALVES_GROUP==1,"closed halves cohort");
_Static_assert(PAIRS==21,"unchanged complete record layout");
#define HALVES_COUNT (HALVES_GROUP?20U:16U)
#define HALVES_PAIRS (HALVES_COUNT+1)
/* This is the existing SSE2 assembly seed symbol; that assembly is unchanged. */
unsigned char sse2_vectors[16][32] __attribute__((aligned(32)));
static unsigned halves_fault_op;
static const struct halves_case *halves_case(const struct sample *s) {
    need(s->id>=1000+20*HALVES_GROUP&&s->id<1000+20*HALVES_GROUP+HALVES_COUNT,800);
    return &halves_cases[HALVES_GROUP][s->id-1000-20*HALVES_GROUP];
}
static void halves_seed_defaults(void) {
    for(unsigned r=0;r<16;r++)for(unsigned j=0;j<32;j++)
        sse2_vectors[r][j]=(unsigned char)(1+13*r+7*j);
}
static void halves_fault_memory(void) {
    need(!RAW(SYS_mprotect,data_fault,PAGE,PROT_READ,0,0,0),797);
    for(size_t i=0;i<PAGE;i++)need(((const unsigned char *)data_fault)[i]==(unsigned char)(i*13+0x5b),798);
    need(!RAW(SYS_mprotect,data_fault,PAGE,PROT_NONE,0,0,0),799);
}
static void halves_inputs(struct sample *s) {
    inputs(s);halves_seed_defaults();const struct halves_case *v=halves_case(s);
    memcpy(sse2_vectors[v->xmm],v->input_xmm,16);
    memcpy((void *)(data_page+v->offset),v->input_memory,8);
    fixture_seed[7]=(s==&negative_sample&&control==1)?data_fault:data_page+v->offset;
    if(s==&negative_sample&&control==1) {
        need(!RAW(SYS_mprotect,data_fault,PAGE,PROT_READ|PROT_WRITE,0,0,0),795);
        for(size_t i=0;i<PAGE;i++)((unsigned char *)data_fault)[i]=(unsigned char)(i*13+0x5b);
        need(!RAW(SYS_mprotect,data_fault,PAGE,PROT_NONE,0,0,0),796);
    }
}
static void halves_prepare(struct sample *s,unsigned index) {
    need(index<HALVES_COUNT,801);const struct halves_case *v=&halves_cases[HALVES_GROUP][index];
    s->id=1000+20*HALVES_GROUP+index;s->length=v->length;
    long reserved=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reserved>0,802);s->mapping=(uintptr_t)reserved+PAGE;
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),803);
    need(v->tail>=1&&v->tail<=v->length,804);
    memset(s->source,0xcc,sizeof(s->source));size_t offset=PAGE-v->tail;
    s->pc=s->mapping+offset;s->expected_post=s->pc+s->length;
    s->endpoint_int3=v->tail<v->length;s->count=s->endpoint_int3?2:1;
    memcpy(s->source+offset,v->bytes,v->length);memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),805);
    need(!li2_decoder_decode(s->pc,(const void *)s->pc,s->length,&s->decoded)&&
         s->decoded.decode_status==LI2_VALID&&s->decoded.kind==LI2_NONE&&s->decoded.code==v->code&&
         s->decoded.length==v->length&&!memcmp(s->decoded.bytes,v->bytes,v->length),806);
}
/* Compare all initialized kernel/live FP bytes. Only a load's selected eight
   XMM bytes may change. No header, init-state, upper-vector or flags masking. */
static void halves_fp_effect(const struct halves_case *v,const unsigned char *before,
                             const unsigned char *after,size_t n,unsigned error) {
    need(n>=512,807);size_t at=160+16*v->xmm+8*v->high;
    for(size_t i=0;i<n;i++) {
        unsigned char expected=before[i];
        if(!v->store&&i>=at&&i<at+8)expected=v->input_memory[i-at];
        need(after[i]==expected,error);
    }
}
static void halves_effects(struct sample *s) {
    const struct halves_case *v=halves_case(s);const struct li2_step_owner *o=&s->owner.step;
    need(s->owner.classification.policy==1&&s->owner.classification.code==v->code&&
         s->owner.classification.flow==LI2_TF_FALLTHROUGH&&s->owner.classification.family==LI2_TF_SIMD&&
         s->expected_post==s->pc+s->length&&!memcmp(s->decoded.bytes,v->bytes,v->length),808);
    need(v->offset+8<=DATA_BYTES&&!(v->offset&7),809);
    for(unsigned l=0;l<2;l++) {
        const struct state *before=l?&s->step_before:&s->native_before;
        const struct state *after=l?&s->step_endpoint:&s->native_after;
        for(unsigned r=0;r<16;r++) {
            need((uint64_t)before->frame.greg[regs[r]]==fixture_seed[r]&&
                 before->frame.greg[regs[r]]==after->frame.greg[regs[r]],810);
            need(!memcmp(before->frame.fp+160+16*r,sse2_vectors[r],16)&&
                 !memcmp(s->actual_fp[2*l]+160+16*r,sse2_vectors[r],16),811);
            need(s->live[2*l].gpr[r]==s->live[2*l+1].gpr[r],812);
        }
        need((uintptr_t)before->frame.greg[REG_RDI]==data_page+v->offset&&
             !memcmp(before->data+v->offset,v->input_memory,8)&&
             !memcmp(after->data+v->offset,v->expected_memory,8),813);
        need(!memcmp(before->stack,after->stack,SUBJECT_BYTES),814);
        for(size_t i=0;i<DATA_BYTES;i++) {
            unsigned char expected=before->data[i];
            if(v->store&&i>=v->offset&&i<v->offset+8)expected=v->expected_memory[i-v->offset];
            need(after->data[i]==expected,815);
        }
        need(!memcmp(after->frame.fp+160+16*v->xmm,v->expected_xmm,16),816);
        halves_fp_effect(v,before->frame.fp,after->frame.fp,before->frame.fp_bytes,817);
        halves_fp_effect(v,s->actual_fp[2*l],s->actual_fp[2*l+1],xsave_bytes,818);
    }
    halves_fp_effect(v,o->before.fp,o->after.fp,o->before.fp_bytes,819);
    need(s->initial_flags==s->post_flags&&s->live[0].rflags==s->live[1].rflags&&
         s->live[2].rflags==s->live[3].rflags,820);
    for(size_t i=0;i<s->count;i++)need(actual_protection(s->pages[i].address,0)==PROT_READ,821);
    need(s->continuation.complete&&actual_protection(s->expected_post,0)==PROT_READ,822);
}
/* The old native handler's load-fault branch requires ERR=4. Add a separate
   exact store-only branch; every old handler body and load predicate remains.
   It observes the genuine first-store #PF (ERR=6), never a synthetic event. */
static void halves_handler(int sig,siginfo_t *si,void *frame_) {
    if(control==1&&current==&negative_sample&&!lane&&native_phase==1&&halves_case(current)->store) {
        need(!handling&&si&&frame_,823);handling=1;
        struct sample *s=current;ucontext_t *uc=frame_;greg_t *g=uc->uc_mcontext.gregs;
        need(sig==SIGSEGV&&si->si_signo==SIGSEGV&&si->si_code==SEGV_ACCERR&&!si->si_errno&&
             (uintptr_t)si->si_addr==data_fault&&(uintptr_t)g[REG_RIP]==s->pc&&
             g[REG_TRAPNO]==14&&g[REG_ERR]==6&&(uintptr_t)g[REG_CR2]==data_fault,824);
        s->native_fault=1;capture(&s->native_after,uc);permissions(s,PROT_READ);native_phase=2;
        g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
        fixture_vector_clobber();handling=0;return;
    }
    handler(sig,si,frame_);
}
static void halves_install_handler(void) {
    struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} action;
    action.handler=halves_handler;action.flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL;
    action.restorer=step_restorer;action.mask=mask;
    need(!RAW(SYS_rt_sigaction,SIGSEGV,&action,0,8,0,0)&&!RAW(SYS_rt_sigaction,SIGTRAP,&action,0,8,0,0)&&
         !RAW(SYS_rt_sigaction,SIGSYS,&action,0,8,0,0),825);
}
static void halves_failure(void *context,const struct li2_step_owner *o) {
    struct sample *s=context;
    if(control==1&&s==&negative_sample) {
        const struct halves_case *v=halves_case(s);
        need(v->store==(halves_fault_op&1)&&v->high==(halves_fault_op>>1)&&
             s->native_fault&&!s->native_complete&&!s->step_endpoint_seen,826);
        need((uintptr_t)s->native_after.frame.greg[REG_RIP]==s->pc&&
             s->native_after.frame.greg[REG_TRAPNO]==14&&s->native_after.frame.greg[REG_ERR]==(v->store?6:4)&&
             (uintptr_t)s->native_after.frame.greg[REG_RDI]==data_fault&&
             (uintptr_t)s->native_after.frame.greg[REG_CR2]==data_fault,827);
        for(unsigned i=0;i<16;i++)need(s->native_before.frame.greg[regs[i]]==
             s->native_after.frame.greg[regs[i]],828);
        need(s->native_before.frame.greg[REG_EFL]==s->native_after.frame.greg[REG_EFL]&&
             s->native_before.frame.fp_bytes==s->native_after.frame.fp_bytes&&
             !memcmp(s->native_before.frame.fp,s->native_after.frame.fp,s->native_before.frame.fp_bytes)&&
             !memcmp(s->actual_fp[0],s->actual_fp[1],xsave_bytes),829);
        compare_memory(&s->native_before,&s->native_after,830);halves_fault_memory();
        for(unsigned r=0;r<16;r++)need(!memcmp(s->native_before.frame.fp+160+16*r,sse2_vectors[r],16),831);
        need(s->native_before.fs==s->native_after.fs&&s->native_before.gs==s->native_after.gs&&
             s->native_before.frame.mask==mask&&s->native_after.frame.mask==mask&&
             s->native_before.frame.greg[REG_CSGSFS]==s->native_after.frame.greg[REG_CSGSFS]&&
             o->after.greg[REG_CSGSFS]==s->native_after.frame.greg[REG_CSGSFS],832);
        need(s->live[0].started==1&&s->live[0].complete==1&&!s->live[0].reserved&&
             s->live[1].started==1&&s->live[1].complete==1&&!s->live[1].reserved&&
             s->live[0].rflags==s->live[1].rflags&&
             !memcmp(s->live[0].gpr,s->live[1].gpr,sizeof(s->live[0].gpr))&&
             !memcmp(s->live[0].selectors,s->live[1].selectors,sizeof(s->live[0].selectors)),833);
    }
    /* Exact old frame/failed operation/revoke/sync/held-borrow predicates. */
    failure(context,o);
}
static void halves_pair(struct sample *s) {
    current=s;fixture_target=s->pc;halves_inputs(s);borrow(s);lane=0;native_phase=0;fixture_enter();
    s->initial_flags=fixture_flags;s->live[0]=fixture_live_before;s->live[1]=fixture_live_after;
    memcpy(s->actual_fp[0],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[1],fixture_fp_after,xsave_bytes);
    if(s==&negative_sample&&control==1)halves_fault_memory();
    need(s->native_complete||(s==&negative_sample&&control==1&&s->native_fault),102);
    s->post_flags=(uint64_t)s->native_after.frame.greg[REG_EFL];
    if(!s->endpoint_int3)s->post_flags&=~LI2_STEP_RF;
    /* A faulting native memory case retains RF even for a crossing layout. */
    if(s==&negative_sample&&control==1)s->post_flags&=~LI2_STEP_RF;
    need(!(s->initial_flags&(LI2_STEP_RF|LI2_STEP_TF))&&!(s->post_flags&(LI2_STEP_RF|LI2_STEP_TF)),103);
    need(!li2_lifecycle_fetch_release(&s->ref),104);s->native_fetch=*li2_lifecycle_fetch_progress();
    halves_inputs(s);borrow(s);
    struct li2_step_request request={.decoded=s->decoded,.page_count=s->count,.original_flags=s->initial_flags};
    for(size_t i=0;i<s->count;i++)request.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
    struct li2_tf_hooks hooks={{s,authenticate,halves_failure},continue_closed};
    int error=li2_tf_arm(&s->owner,&session,&hooks,&request);
    if(error)li2_tf_abort(&s->owner,(unsigned)error,0);
    lane=1;fixture_enter();need(!(s==&negative_sample),105);
    s->live[2]=fixture_live_before;s->live[3]=fixture_live_after;
    memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[3],fixture_fp_after,xsave_bytes);
    compare(s);halves_effects(s);
    need(!li2_lifecycle_fetch_release(&s->ref),106);s->step_fetch=*li2_lifecycle_fetch_progress();
    ++result.completed;
}
static void halves_refusals(void) {
    static const struct {unsigned n;unsigned char b[6];} cases[]={
        {3,{0x0f,0x12,0x0f}},
        {4,{0x66,0x0f,0x12,0xc9}},
        {4,{0xc5,0xf9,0x12,0x0f}},
        {6,{0x62,0xf1,0xfd,0x08,0x12,0x0f}},
        {5,{0xf0,0x66,0x0f,0x12,0x0f}},
        {5,{0xf3,0x66,0x0f,0x12,0x0f}},
        {5,{0xf2,0x66,0x0f,0x12,0x0f}},
        {5,{0x66,0x66,0x0f,0x12,0x0f}},
        {5,{0x66,0x48,0x0f,0x12,0x0f}},
        {6,{0x66,0x44,0x40,0x0f,0x12,0x0f}},
        {5,{0x2e,0x66,0x0f,0x12,0x0f}},
        {3,{0x66,0x0f,0x12}},
        {3,{0x0f,0x13,0x0f}},
        {4,{0x66,0x0f,0x13,0xc9}},
        {4,{0xc5,0xf9,0x13,0x0f}},
        {6,{0x62,0xf1,0xfd,0x08,0x13,0x0f}},
        {5,{0xf0,0x66,0x0f,0x13,0x0f}},
        {5,{0xf3,0x66,0x0f,0x13,0x0f}},
        {5,{0xf2,0x66,0x0f,0x13,0x0f}},
        {5,{0x66,0x66,0x0f,0x13,0x0f}},
        {5,{0x66,0x48,0x0f,0x13,0x0f}},
        {6,{0x66,0x44,0x40,0x0f,0x13,0x0f}},
        {5,{0x2e,0x66,0x0f,0x13,0x0f}},
        {3,{0x66,0x0f,0x13}},
        {3,{0x0f,0x16,0x0f}},
        {4,{0x66,0x0f,0x16,0xc9}},
        {4,{0xc5,0xf9,0x16,0x0f}},
        {6,{0x62,0xf1,0xfd,0x08,0x16,0x0f}},
        {5,{0xf0,0x66,0x0f,0x16,0x0f}},
        {5,{0xf3,0x66,0x0f,0x16,0x0f}},
        {5,{0xf2,0x66,0x0f,0x16,0x0f}},
        {5,{0x66,0x66,0x0f,0x16,0x0f}},
        {5,{0x66,0x48,0x0f,0x16,0x0f}},
        {6,{0x66,0x44,0x40,0x0f,0x16,0x0f}},
        {5,{0x2e,0x66,0x0f,0x16,0x0f}},
        {3,{0x66,0x0f,0x16}},
        {3,{0x0f,0x17,0x0f}},
        {4,{0x66,0x0f,0x17,0xc9}},
        {4,{0xc5,0xf9,0x17,0x0f}},
        {6,{0x62,0xf1,0xfd,0x08,0x17,0x0f}},
        {5,{0xf0,0x66,0x0f,0x17,0x0f}},
        {5,{0xf3,0x66,0x0f,0x17,0x0f}},
        {5,{0xf2,0x66,0x0f,0x17,0x0f}},
        {5,{0x66,0x66,0x0f,0x17,0x0f}},
        {5,{0x66,0x48,0x0f,0x17,0x0f}},
        {6,{0x66,0x44,0x40,0x0f,0x17,0x0f}},
        {5,{0x2e,0x66,0x0f,0x17,0x0f}},
        {3,{0x66,0x0f,0x17}},
    };
    _Static_assert(sizeof(cases)/sizeof(cases[0])==48,"closed supplied-neighbor cohort");
    for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
        result.failed_refusal=47+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,cases[i].b,cases[i].n,&refused_last);
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,840+(unsigned)i);
        ++result.refusals;
    }
    result.failed_refusal=SIZE_MAX;
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)<16*1024*1024,
                   "unchanged complete private record bound");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=HALVES_PAIRS;
    need(stack[0]==1,890);setup(stack);halves_install_handler();
    unsigned a=1,b,c,d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"=c"(c),"=d"(d));
    need(d&(1U<<26),891);
    const char *const *env=(const void *)(stack+3);const char key[]="LI2_HALVES_CONTROL=";
    const char *names[]={"movlpd-load-fault","movlpd-store-fault","movhpd-load-fault","movhpd-store-fault"};
    for(size_t i=0;env[i];i++)if(length(env[i])>=sizeof(key)-1&&!memcmp(env[i],key,sizeof(key)-1)) {
        need(!control&&HALVES_GROUP==0,892);unsigned found=0;
        for(unsigned j=0;j<4;j++)if(same(env[i]+sizeof(key)-1,names[j])){halves_fault_op=j;found++;}
        need(found==1,893);control=1;
    }
    result.control=control;
    size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc&&complete==li2_tf_refusal_count()&&complete==47,130);
    halves_refusals();need(result.refusals==95,894);
    halves_seed_defaults();prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    if(control){halves_prepare(&negative_sample,4*halves_fault_op+1);halves_pair(&negative_sample);die(895);}
    for(unsigned i=0;i<HALVES_COUNT;i++){halves_prepare(&samples[i+1],i);halves_pair(&samples[i+1]);}
    need(result.completed==HALVES_PAIRS&&dump(),896);
#if HALVES_GROUP==0
    output("LI2_HALVES_TF_PASS group=0 pairs=17 halves=16 selftest=1 old_refusal_bytes=47 new_refusal_bytes=48 full_state=17 full_memory=17 live_endpoints=17\n");
#else
    output("LI2_HALVES_TF_PASS group=1 pairs=21 halves=20 selftest=1 old_refusal_bytes=47 new_refusal_bytes=48 full_state=21 full_memory=21 live_endpoints=21\n");
#endif
    return 0;
}
