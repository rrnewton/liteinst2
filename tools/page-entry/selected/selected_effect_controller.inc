/* Included after selected_prepare/release, before the publication controller.
   New profile only. Old finite controller/provider paths remain unchanged. */
#if !defined(LI2_EFFECT_PROVIDER) || !defined(LI2_CPUID_NX_ONLY) || !defined(LI2_RSEQ_INACTIVE)
#error "effect controller requires its explicit CPUID-NX/rseq profile"
#endif
#include "selected_effect.h"
#include "selected_source_identity.h"
extern const struct li2_effect_binding li2_effect_runtime_binding;

static struct {
    struct li2_effect_owner owner;
    struct li2_effect_input input;
    struct li2_effect_state applied;
    ucontext_t before,work,after;
    ucontext_t *frame;
    uintptr_t fp_address;
    size_t fp_bytes,before_initialized,after_initialized;
    unsigned char before_fp[LI2_STEP_FP_BYTES] __attribute__((aligned(64)));
    unsigned char after_fp[LI2_STEP_FP_BYTES] __attribute__((aligned(64)));
    volatile sig_atomic_t busy,finished,stage,random_applied;
    volatile sig_atomic_t random_backend_returned;
    int random_backend_status;
    unsigned first_error;
    long first_detail;
    uint64_t sequence,attempts,commits,completed,native_completed,scripted_completed;
    uint64_t classes[7];
} selected_effect_runtime;
static const unsigned selected_effect_registers[16]={
    REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,
    REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};

static void selected_effect_need(int ok,unsigned code,long detail) {
    if(!ok && !selected_effect_runtime.first_error) {
        selected_effect_runtime.first_detail=detail;
        __asm__ volatile("":::"memory");selected_effect_runtime.first_error=code;
    }
    checked(ok,code,detail);
}
static void selected_effect_status(int status,unsigned code) {
    selected_effect_need(!status,code,status);
}
static void selected_effect_count(uint64_t *p) {
    selected_effect_need(*p!=UINT64_MAX,1740,0);++*p;
}
static uint32_t selected_effect_u32(const unsigned char *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static int selected_effect_frame_range(const void *p,size_t n) {
    uintptr_t a=(uintptr_t)p,first=(uintptr_t)fork_gate_stack.ss_sp;
    return !p || !n || first>UINTPTR_MAX-fork_gate_stack.ss_size ||
        a<first || a>first+fork_gate_stack.ss_size || n>first+fork_gate_stack.ss_size-a;
}
static size_t selected_effect_fp_size(const ucontext_t *uc) {
    selected_effect_need(!selected_effect_frame_range(uc,sizeof(*uc)),1741,1);
    uintptr_t address=(uintptr_t)uc->uc_mcontext.fpregs;
    selected_effect_need(!(address&15) && !selected_effect_frame_range((const void *)address,512),1741,2);
    const unsigned char *p=(const void *)address;size_t n=512;
    /* Existing Linux signal-FP ABI, exactly the step-owner size/magic checks.
       These actual bytes remain separate from the provider's XSTATE=NONE. */
    if(selected_effect_u32(p+464)==UINT32_C(0x46505853)) {
        n=selected_effect_u32(p+468);size_t x=selected_effect_u32(p+480);
        selected_effect_need(n>=580 && n<=LI2_STEP_FP_BYTES && x>=576 && x<=n-4 &&
            !selected_effect_frame_range(p,n),1741,3);
        selected_effect_need(selected_effect_u32(p+n-4)==UINT32_C(0x46505845),1741,4);
    }
    return n;
}
static void selected_effect_state(const ucontext_t *uc,uintptr_t pc,uint64_t flags,
                                   struct li2_effect_state *out) {
    *out=(struct li2_effect_state){.pc=pc,.logical_flags=flags};
    for(unsigned i=0;i<16;i++)out->gpr[i]=(uint64_t)uc->uc_mcontext.gregs[selected_effect_registers[i]];
    /* Linux supplies CS/GS/FS in this field. Do not invent DS/ES, SS or bases. */
    uint64_t packed=(uint64_t)uc->uc_mcontext.gregs[REG_CSGSFS];
    out->selectors_observed=(1U<<LI2_EFFECT_CS)|(1U<<LI2_EFFECT_FS)|(1U<<LI2_EFFECT_GS);
    out->selectors[LI2_EFFECT_CS]=(uint16_t)packed;
    out->selectors[LI2_EFFECT_GS]=(uint16_t)(packed>>16);
    out->selectors[LI2_EFFECT_FS]=(uint16_t)(packed>>32);
    /* No provider extended-state format is invented. Complete raw actual
       ucontext and initialized FP preservation is independently checked below. */
}
static void selected_effect_selected_guard(void) {
    if(selected_effect_runtime.input.decoded.kind!=LI2_SYSCALL) {
        int e=li2_rseq_check_selected(&selected_effect_runtime.input.decoded);
        selected_effect_need(!e,(unsigned)e,li2_rseq_snapshot()->first_detail);
    }
}
/* Independent expected full actual frame. Keep landing RIP/vector/error and
   every byte outside the literal allowed effect unchanged. This is not a
   synthesized ingress frame and is never passed to an execution backend. */
static void selected_effect_expected_frame(const struct li2_effect_result *result) {
    __typeof__(selected_effect_runtime) *p=&selected_effect_runtime;
    copy(&p->work,&p->before,sizeof(p->work));
    greg_t *g=p->work.uc_mcontext.gregs;
    const struct li2_decoded *d=&p->input.decoded;
    if(d->kind==LI2_SYSCALL) {
        g[REG_RIP]=(greg_t)d->next_pc;g[REG_RCX]=g[REG_RIP];
        g[REG_R11]=(greg_t)p->input.before.logical_flags;g[REG_EFL]=g[REG_R11];
    }
    if(!result)return;
    selected_effect_need(result->kind==d->kind,1742,1);
    uint64_t flags=p->input.before.logical_flags;
    switch(d->kind) {
    case LI2_CPUID:
        g[REG_RAX]=(greg_t)result->cpuid[0];g[REG_RBX]=(greg_t)result->cpuid[1];
        g[REG_RCX]=(greg_t)result->cpuid[2];g[REG_RDX]=(greg_t)result->cpuid[3];break;
    case LI2_RDTSC:case LI2_RDTSCP:
        g[REG_RAX]=(greg_t)(uint32_t)result->value;
        g[REG_RDX]=(greg_t)(uint32_t)(result->value>>32);
        if(d->kind==LI2_RDTSCP)g[REG_RCX]=(greg_t)result->aux;
        break;
    case LI2_SYSCALL:g[REG_RAX]=(greg_t)result->value;break;
    case LI2_RDRAND:case LI2_RDSEED:case LI2_RDPID: {
        selected_effect_need(d->destination<16 && d->destination!=4,1742,2);
        unsigned reg=selected_effect_registers[d->destination];
        uint64_t value=result->value;
        if(d->width_bits==16)value=((uint64_t)g[reg]&~UINT64_C(0xffff))|value;
        g[reg]=(greg_t)value;
        if(d->kind!=LI2_RDPID)flags=(flags&~UINT64_C(0x8d5))|result->carry;
        break;
    }
    default:selected_effect_need(0,1742,d->kind);
    }
    g[REG_RIP]=(greg_t)d->next_pc;g[REG_EFL]=(greg_t)flags;
}
static void selected_effect_frame_exact(const struct li2_effect_result *result) {
    __typeof__(selected_effect_runtime) *p=&selected_effect_runtime;
    selected_effect_need(!selected_effect_frame_range(p->frame,sizeof(*p->frame)) &&
        p->before_initialized==p->fp_bytes && p->fp_bytes,1743,1);
    selected_effect_expected_frame(result);
    selected_effect_need(equal(p->frame,&p->work,sizeof(p->work)) &&
        (uintptr_t)p->frame->uc_mcontext.fpregs==p->fp_address &&
        selected_effect_fp_size(p->frame)==p->fp_bytes &&
        equal(p->frame->uc_mcontext.fpregs,p->before_fp,p->fp_bytes),1743,2);
}
static void selected_effect_current_frame(void) {
    __typeof__(selected_effect_runtime) *p=&selected_effect_runtime;
    const struct li2_effect_result *result=0;
    if(p->random_applied)result=p->owner.decision.action==LI2_EFFECT_NATIVE?
        &p->owner.native_result:&p->owner.result;
    selected_effect_frame_exact(result);
}
static void selected_effect_begin(ucontext_t *uc,uintptr_t logical_pc,uint64_t flags) {
    __typeof__(selected_effect_runtime) *p=&selected_effect_runtime;
    /* Qualify the complete actual frame before any member access. fp_size
       separately qualifies its fixed header and complete variable extent
       before the corresponding reads, including the trailing magic. */
    size_t fp_bytes=selected_effect_fp_size(uc);
    selected_effect_need(!p->busy && !p->first_error && !selected_step_pending &&
        (!p->attempts || (p->finished && p->owner.phase==LI2_EFFECT_COMMITTED &&
                         p->commits==p->completed)) &&
        li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY && selected_flags_known &&
        !selected_selftesting && selected_decoded.pc==logical_pc && selected_view.pc==logical_pc &&
        selected_view.length==selected_decoded.available && selected_view.length<=15 &&
        equal(selected_view.bytes,selected_decoded.bytes,selected_view.length) &&
        (uint64_t)uc->uc_mcontext.gregs[REG_EFL]==(flags|SELECTED_RF),1744,1);
    /* Prior publication retirement is checked by root's attempt owner before
       preparing another attempt. Current restored publication may still exist. */
    selected_effect_count(&p->sequence);selected_effect_count(&p->attempts);
    p->busy=1;p->finished=0;p->stage=1;p->random_applied=0;p->frame=uc;
    p->random_backend_returned=0;p->random_backend_status=0;
    p->before_initialized=p->after_initialized=0;
    selected_effect_raw=(struct selected_effect_raw_prefix){0};
    copy(&p->before,uc,sizeof(p->before));
    p->fp_address=(uintptr_t)uc->uc_mcontext.fpregs;p->fp_bytes=fp_bytes;
    for(size_t i=0;i<p->fp_bytes;i++) {
        p->before_fp[i]=((const unsigned char *)p->fp_address)[i];p->before_initialized=i+1;
    }
    p->input=(struct li2_effect_input){.abi_version=LI2_EFFECT_ABI,.sequence=p->sequence,
        .decoded=selected_decoded};
    selected_effect_state(uc,logical_pc,flags,&p->input.before);
    size_t count=0;
    selected_effect_status(li2_lifecycle_effect_sources(&selected_borrow,p->input.source,&count),1744);
    selected_effect_need(count==selected_view.page_count && count>=1 && count<=2,1744,2);
    p->input.source_count=(uint32_t)count;
    selected_effect_selected_guard();
    selected_effect_need(equal(uc,&p->before,sizeof(p->before)) &&
        equal(uc->uc_mcontext.fpregs,p->before_fp,p->fp_bytes),1744,3);
    selected_effect_status(li2_effect_begin(&p->owner,&li2_effect_runtime_binding,&p->input),1745);
    /* Ingress remains raw NX/UD2 until the real effect writes; SYSCALL has not
       yet received root's explicit dispatch-header writes at this boundary. */
    selected_effect_need(equal(uc,&p->before,sizeof(p->before)) &&
        equal(uc->uc_mcontext.fpregs,p->before_fp,p->fp_bytes),1745,1);
    p->stage=2;
}
static void selected_effect_guarded(void) {
    selected_effect_need(selected_effect_runtime.busy && !selected_step_pending,1746,1);
    selected_effect_current_frame();selected_effect_selected_guard();
    selected_effect_status(li2_effect_guarded(&selected_effect_runtime.owner),1746);
    selected_effect_runtime.stage=3;
}
static int selected_effect_is_native(void) {
    const struct li2_effect_owner *o=&selected_effect_runtime.owner;
    selected_effect_need(selected_effect_runtime.busy && !o->first_error &&
        (o->decision.action==LI2_EFFECT_NATIVE || o->decision.action==LI2_EFFECT_SCRIPTED),1746,2);
    return o->decision.action==LI2_EFFECT_NATIVE;
}
static void selected_effect_native_enter(void) {
    selected_effect_current_frame();
    selected_effect_status(li2_effect_native_enter(&selected_effect_runtime.owner),1747);
    selected_effect_runtime.stage=4;
}
static void selected_effect_native_return(const struct li2_effect_result *result) {
    /* Record genuine backend return before any postguard/frame comparison. */
    selected_effect_status(li2_effect_native_return(&selected_effect_runtime.owner,result),1748);
    selected_effect_runtime.stage=5;
}
static void selected_effect_native_outcome(void) {
    selected_effect_current_frame();selected_effect_selected_guard();
    selected_effect_status(li2_effect_native_outcome(&selected_effect_runtime.owner),1749);
    selected_effect_current_frame();selected_effect_runtime.stage=6;
}
static void selected_effect_scripted_outcome(void) {
    selected_effect_current_frame();
    selected_effect_status(li2_effect_scripted_outcome(&selected_effect_runtime.owner),1750);
    selected_effect_runtime.stage=6;
}
static void selected_effect_apply_and_commit(ucontext_t *uc) {
    __typeof__(selected_effect_runtime) *p=&selected_effect_runtime;
    selected_effect_need(uc==p->frame && p->busy,1751,1);
    selected_effect_current_frame();selected_effect_selected_guard();
    struct li2_effect_state expected;
    selected_effect_status(li2_effect_expected(&p->owner,&expected),1751);
    /* Independent literal class model must agree before any actual write. */
    selected_effect_expected_frame(&p->owner.result);
    for(unsigned i=0;i<16;i++)selected_effect_need(
        (uint64_t)p->work.uc_mcontext.gregs[selected_effect_registers[i]]==expected.gpr[i],1751,i+2);
    selected_effect_need((uint64_t)p->work.uc_mcontext.gregs[REG_RIP]==expected.pc &&
        (uint64_t)p->work.uc_mcontext.gregs[REG_EFL]==expected.logical_flags,1751,18);
    unsigned kind=p->input.decoded.kind,mask;
    if(kind==LI2_CPUID)mask=0xf;
    else if(kind==LI2_RDTSC)mask=5;
    else if(kind==LI2_RDTSCP)mask=7;
    else if(kind==LI2_SYSCALL)mask=(1U<<0)|(1U<<1)|(1U<<11);
    else {selected_effect_need(kind>=LI2_RDRAND && kind<=LI2_RDPID &&
        p->input.decoded.destination<16 && p->input.decoded.destination!=4,1751,19);
        mask=1U<<p->input.decoded.destination;}
    for(unsigned i=0;i<16;i++)if(mask&(1U<<i))
        uc->uc_mcontext.gregs[selected_effect_registers[i]]=(greg_t)expected.gpr[i];
    uc->uc_mcontext.gregs[REG_RIP]=(greg_t)expected.pc;
    uc->uc_mcontext.gregs[REG_EFL]=(greg_t)expected.logical_flags;
    selected_effect_frame_exact(&p->owner.result);
    copy(&p->after,uc,sizeof(p->after));
    for(size_t i=0;i<p->fp_bytes;i++) {
        p->after_fp[i]=((const unsigned char *)p->fp_address)[i];p->after_initialized=i+1;
    }
    selected_effect_need(equal(p->after_fp,p->before_fp,p->fp_bytes),1751,20);
    selected_effect_state(uc,(uintptr_t)uc->uc_mcontext.gregs[REG_RIP],
        (uint64_t)uc->uc_mcontext.gregs[REG_EFL],&p->applied);
    selected_effect_status(li2_effect_commit(&p->owner,&p->applied),1752);
    selected_effect_count(&p->commits);p->stage=7;
    selected_logical_flags=p->applied.logical_flags;selected_flags_known=1;
}
static void selected_effect_finish(void) {
    __typeof__(selected_effect_runtime) *p=&selected_effect_runtime;
    selected_effect_need(!selected_effect_frame_range(p->frame,sizeof(*p->frame)) &&
        selected_effect_fp_size(p->frame)==p->fp_bytes,1753,1);
    selected_effect_need(p->busy && !p->finished && p->stage==7 && !p->first_error &&
        p->owner.phase==LI2_EFFECT_COMMITTED && p->owner.committed && !p->owner.first_error &&
        !li2_lifecycle_fetch_interlock() && !selected_step_pending &&
        p->after_initialized==p->fp_bytes && equal(p->frame,&p->after,sizeof(p->after)) &&
        equal(p->frame->uc_mcontext.fpregs,p->after_fp,p->fp_bytes),1753,0);
    selected_effect_count(&p->completed);
    selected_effect_count(p->owner.decision.action==LI2_EFFECT_NATIVE?&p->native_completed:&p->scripted_completed);
    selected_effect_count(&p->classes[p->input.decoded.kind-1]);
    p->stage=8;__asm__ volatile("":::"memory");p->finished=1;p->busy=0;
    /* Keep full last owner/result/frame prefix. Root may now complete and retire
       the restored publication; no subsequent begin may precede that retirement. */
}
static int selected_effect_complete(siginfo_t *si,ucontext_t *uc,uint64_t flags) {
    unsigned kind=selected_decoded.kind;
    if(kind<LI2_CPUID || kind>LI2_RDTSCP)return 0;
    (void)selected_effect_fp_size(uc);
    int random=kind>=LI2_RDRAND && kind<=LI2_RDPID;
    if(random)selected_effect_need(!selected_effect_frame_range(si,sizeof(*si)),1754,1);
    if(random)selected_effect_need(si->si_signo==SIGSEGV && si->si_code==SEGV_ACCERR &&
        !si->si_errno && (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==selected_decoded.pc &&
        uc->uc_mcontext.gregs[REG_TRAPNO]==14 && uc->uc_mcontext.gregs[REG_ERR]==21 &&
        (uintptr_t)si->si_addr>=selected_decoded.pc && (uintptr_t)si->si_addr<selected_decoded.next_pc,1754,2);
    selected_effect_begin(uc,selected_decoded.pc,flags);selected_effect_guarded();
    struct li2_effect_owner *o=&selected_effect_runtime.owner;
    struct li2_selected_request request={&selected_decoded,selected_view.bytes,selected_view.length,
        flags,LI2_SELECTED_NX_KNOWN_INPUT,si};
    struct selected_builtin_prefix *p=&selected_builtin_prefix;
    if(!random)*p=(struct selected_builtin_prefix){.kind=kind};
    if(selected_effect_is_native()) {
        if(random) {
            selected_effect_native_enter();
            int status=li2_selected_complete_native(uc,&request,&selected_hardware,&selected_completion);
            selected_effect_runtime.random_backend_status=status;
            __asm__ volatile("":::"memory");selected_effect_runtime.random_backend_returned=1;
            /* provider.c retains the genuine random attempt/exception prefix
               and writes only its actual completed scalar frame fields. */
            selected_effect_need(!status,1754,status);
            const struct li2_effect_result result={.kind=kind,.carry=selected_completion.carry,
                .value=selected_completion.value};
            selected_effect_native_return(&result);selected_effect_runtime.random_applied=1;
        } else {
            uint32_t a=0,b=0,c=0,d=0;
            if(kind==LI2_CPUID) {
                selected_effect_native_enter();
                selected_cpuid_nx_sample(uc->uc_mcontext.gregs,&a,&b,&c,&d);
                const struct li2_effect_result result={.kind=kind,.cpuid={a,b,c,d}};
                selected_effect_native_return(&result);p->a=a;p->b=b;p->c=c;p->d=d;
                /* No fake CPUID enable/rearm: the existing separate prefix
                   retains real hardware sample and final masked commit. */
            } else {
                p->phase=1;p->enable_result=raw(SYS_prctl,PR_SET_TSC,PR_TSC_ENABLE,0,0,0,0);
                p->phase=2;selected_effect_need(!p->enable_result,647,p->enable_result);
                selected_effect_native_enter();p->phase=3;
                if(kind==LI2_RDTSCP)__asm__ volatile("rdtscp":"=a"(a),"=d"(d),"=c"(c)::"memory");
                else __asm__ volatile("rdtsc":"=a"(a),"=d"(d)::"memory");
                const struct li2_effect_result result={.kind=kind,.aux=kind==LI2_RDTSCP?c:0,
                    .value=(uint64_t)d<<32|a};
                selected_effect_native_return(&result);
                p->a=a;p->b=b;p->c=c;p->d=d;p->phase=4;
                p->phase=5;p->restore_result=raw(SYS_prctl,PR_SET_TSC,PR_TSC_SIGSEGV,0,0,0,0);
                p->phase=6;selected_effect_need(!p->restore_result,648,p->restore_result);
            }
        }
        selected_effect_native_outcome();
    } else {
        selected_effect_scripted_outcome();
        if(random) {
            const struct li2_selected_script script={kind,selected_decoded.width_bits,
                o->result.carry,0,o->result.value};
            int status=li2_selected_complete_scripted(uc,&request,&script,&selected_completion);
            selected_effect_need(!status,1754,status);selected_effect_runtime.random_applied=1;
        }
    }
    selected_effect_apply_and_commit(uc);
    if(random)selected_effect_count(&selected_provider_calls[kind-LI2_RDRAND]);
    else if(kind==LI2_CPUID) {
        if(selected_effect_is_native())selected_cpuid_nx_committed(uc->uc_mcontext.gregs);
        selected_effect_count(&cpuid_count);
    } else {
        if(selected_effect_is_native())p->phase=7;
        selected_effect_count(kind==LI2_RDTSCP?&tscp_count:&tsc_count);
    }
    return 1; /* Caller releases actual source, then finish, then publication retirement. */
}
static void selected_effect_report(unsigned status,unsigned code,long detail) {
    const __typeof__(selected_effect_runtime) *p=&selected_effect_runtime;
    const struct li2_effect_owner *o=&p->owner;
    struct writer w={.used=0};
    text(&w,"LI2_SELECTED_EFFECT {\"version\":1,\"scope\":\"linked_full_input_effect\"");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",detail<0?0ULL-(uint64_t)detail:(uint64_t)detail);
    field(&w,",\"first_error\":",p->first_error);field(&w,",\"stage\":",p->stage);
    field(&w,",\"busy\":",p->busy);field(&w,",\"finished\":",p->finished);
    field(&w,",\"sequence\":",p->sequence);field(&w,",\"attempts\":",p->attempts);
    field(&w,",\"commits\":",p->commits);field(&w,",\"completed\":",p->completed);
    field(&w,",\"native_completed\":",p->native_completed);
    field(&w,",\"scripted_completed\":",p->scripted_completed);
    field(&w,",\"kind\":",o->input.decoded.kind);field(&w,",\"action\":",o->decision.action);
    field(&w,",\"phase\":",o->phase);field(&w,",\"error\":",o->first_error);
    field(&w,",\"pc\":",o->input.decoded.pc);field(&w,",\"next_pc\":",o->input.decoded.next_pc);
    field(&w,",\"callback_entered\":",o->callback_entered);field(&w,",\"callback_returned\":",o->callback_returned);
    field(&w,",\"native_entered\":",o->native_entered);field(&w,",\"native_returned\":",o->native_returned);
    field(&w,",\"random_backend_returned\":",p->random_backend_returned);
    field(&w,",\"random_backend_status\":",(unsigned)p->random_backend_status);
    field(&w,",\"exit_entered\":",o->exit_entered);field(&w,",\"post_guards_complete\":",o->post_guards_complete);
    field(&w,",\"post_callback_entered\":",o->post_callback_entered);
    field(&w,",\"post_callback_returned\":",o->post_callback_returned);field(&w,",\"committed\":",o->committed);
    field(&w,",\"fp_bytes\":",p->fp_bytes);field(&w,",\"fp_before_initialized\":",p->before_initialized);
    field(&w,",\"fp_after_initialized\":",p->after_initialized);
    field(&w,",\"raw_entered\":",o->input.decoded.kind==LI2_SYSCALL?selected_effect_raw.entered:0);
    field(&w,",\"raw_returned\":",o->input.decoded.kind==LI2_SYSCALL?selected_effect_raw.returned:0);
    text(&w,",\"classes\":[");for(unsigned i=0;i<7;i++){if(i)text(&w,",");number(&w,p->classes[i]);}
    text(&w,"]}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
