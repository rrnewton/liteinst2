/* Every target instruction stays NX until exact selected completion or one
   of three distinct original-address step owners. No fast page is admitted. */
static void selected_report(struct writer *w) {
    field(w,",\"selected_profile\":",1);
    field(w,",\"selected_steps\":",selected_steps);
    field(w,",\"selected_selftests\":",selected_selftests);
    field(w,",\"rdrand\":",selected_provider_calls[0]);
    field(w,",\"rdseed\":",selected_provider_calls[1]);
    field(w,",\"rdpid\":",selected_provider_calls[2]);
    field(w,",\"source_syscalls\":",selected_source_syscalls);
    field(w,",\"vdso_close_attempted\":",selected_vdso_close_attempted);
    field(w,",\"vdso_close_observed\":",selected_vdso_close_observed);
    field(w,",\"vdso_close_result_abs\":",selected_vdso_close_result<0?0ULL-(uint64_t)selected_vdso_close_result:(uint64_t)selected_vdso_close_result);
    field(w,",\"vdso_close_result_negative\":",selected_vdso_close_result<0);
    field(w,",\"vdso_closed\":",selected_vdso_closed);
    field(w,",\"selected_last_kind\":",selected_completion.kind);
    field(w,",\"selected_last_width\":",selected_completion.width_bits);
    field(w,",\"selected_last_destination\":",selected_completion.destination);
    field(w,",\"selected_last_value\":",selected_completion.value);
    field(w,",\"selected_last_carry\":",selected_completion.carry);
    field(w,",\"selected_last_input_destination\":",selected_completion.input_destination);
    field(w,",\"selected_last_output_destination\":",selected_completion.output_destination);
    field(w,",\"selected_last_status\":",selected_completion.status);
    field(w,",\"selected_last_phase\":",selected_completion.phase);
    field(w,",\"selected_last_native_attempts\":",selected_completion.native_attempts);
    field(w,",\"builtin_kind\":",selected_builtin_prefix.kind);
    field(w,",\"builtin_phase\":",selected_builtin_prefix.phase);
    field(w,",\"builtin_enable_result_abs\":",selected_builtin_prefix.enable_result<0?0ULL-(uint64_t)selected_builtin_prefix.enable_result:(uint64_t)selected_builtin_prefix.enable_result);
    field(w,",\"builtin_enable_result_negative\":",selected_builtin_prefix.enable_result<0);
    field(w,",\"builtin_restore_result_abs\":",selected_builtin_prefix.restore_result<0?0ULL-(uint64_t)selected_builtin_prefix.restore_result:(uint64_t)selected_builtin_prefix.restore_result);
    field(w,",\"builtin_restore_result_negative\":",selected_builtin_prefix.restore_result<0);
    field(w,",\"builtin_a\":",selected_builtin_prefix.a);
    field(w,",\"builtin_b\":",selected_builtin_prefix.b);
    field(w,",\"builtin_c\":",selected_builtin_prefix.c);
    field(w,",\"builtin_d\":",selected_builtin_prefix.d);
    field(w,",\"generic_tf_profile\":",1);
    field(w,",\"generic_tf_attempts\":",selected_tf_attempts);
    field(w,",\"generic_tf_steps\":",selected_tf_steps);
    field(w,",\"step_route\":",selected_pending_route);
    const struct li2_step_owner *p=&selected_tf.step;
    field(w,",\"tf_phase\":",p->phase);
    field(w,",\"tf_error\":",p->first_error);
    field(w,",\"tf_detail_abs\":",p->first_detail<0?0ULL-(uint64_t)p->first_detail:(uint64_t)p->first_detail);
    field(w,",\"tf_detail_negative\":",p->first_detail<0);
    field(w,",\"tf_pc\":",p->request.decoded.pc);
    field(w,",\"tf_length\":",p->request.decoded.length);
    uint64_t bytes_lo=0,bytes_hi=0;
    for(size_t i=0;i<p->request.decoded.length && i<15;i++) {
        if(i<8)bytes_lo|=(uint64_t)p->request.decoded.bytes[i]<<(8*i);
        else bytes_hi|=(uint64_t)p->request.decoded.bytes[i]<<(8*(i-8));
    }
    field(w,",\"tf_bytes_lo\":",bytes_lo);
    field(w,",\"tf_bytes_hi\":",bytes_hi);
    field(w,",\"tf_code\":",selected_tf.classification.code);
    field(w,",\"tf_flow\":",selected_tf.classification.flow);
    field(w,",\"tf_family\":",selected_tf.classification.family);
    field(w,",\"tf_trace\":",p->trace_seen);
    field(w,",\"tf_actual_flags\":",selected_tf.actual_post_flags);
    field(w,",\"tf_open_started\":",p->open_started[0]|(p->open_started[1]<<1));
    field(w,",\"tf_opened\":",p->opened[0]|(p->opened[1]<<1));
    field(w,",\"tf_revoke_started\":",p->revoke_started[0]|(p->revoke_started[1]<<1));
    field(w,",\"tf_revoked\":",p->revoked[0]|(p->revoked[1]<<1));
    field(w,",\"tf_sync_started\":",p->revoke_sync_started);
    field(w,",\"tf_sync_abs\":",p->revoke_sync<0?0ULL-(uint64_t)p->revoke_sync:(uint64_t)p->revoke_sync);
    field(w,",\"tf_sync_negative\":",p->revoke_sync<0);
    field(w,",\"tf_continuation_started\":",selected_tf.continuation_started);
    field(w,",\"tf_continuation_complete\":",selected_tf.continuation_complete);
    field(w,",\"tf_continuation_result_abs\":",selected_tf.continuation_result<0?0ULL-(uint64_t)selected_tf.continuation_result:(uint64_t)selected_tf.continuation_result);
    field(w,",\"tf_continuation_result_negative\":",selected_tf.continuation_result<0);
    field(w,",\"tf_query_attempted\":",selected_tf_continuation.attempted);
    field(w,",\"tf_query_complete\":",selected_tf_continuation.complete);
    field(w,",\"tf_release_started\":",selected_tf_release_started);
    field(w,",\"tf_release_complete\":",selected_tf_release_complete);
    field(w,",\"tf_release_result_abs\":",selected_tf_release_result<0?0ULL-(uint64_t)selected_tf_release_result:(uint64_t)selected_tf_release_result);
    field(w,",\"tf_release_result_negative\":",selected_tf_release_result<0);
    field(w,",\"tf_unexpected_frame\":",selected_tf.unexpected_frame_observed);
}
static int selected_authenticate(void *context,const struct li2_step_page *p,int prot) {
    (void)context;
    for(size_t i=0;i<selected_view.page_count;i++) {
        const struct li2_fetch_page *owned=&selected_view.pages[i];
        if(p->address==owned->address && p->object==owned->allocation &&
           p->generation==owned->generation && p->offset==owned->offset &&
           p->closed_prot==PROT_READ && p->open_prot==(PROT_READ|PROT_EXEC))
            return li2_lifecycle_fetch_validate(&selected_borrow,i,prot);
    }
    return LI2_FETCH_STALE;
}
static void selected_step_failure(void *context,const struct li2_step_owner *owner) {
    (void)context;report(125,owner->first_error,owner->first_detail);
}
_Noreturn void li2_decoder_abort(uint32_t code) { fail(606,code); }
static void selected_initialized(void) {
    struct li2_decoder_stats now;
    checked(!li2_decoder_stats(&now) && equal(&now,&selected_initial_stats,sizeof now),607,0);
}
static void selected_preflight(void) {
    unsigned char affinity[1024]={0};
    long bytes=raw(SYS_sched_getaffinity,0,sizeof affinity,(long)affinity,0,0,0);
    checked(bytes>0 && (size_t)bytes<=sizeof affinity,639,bytes);
    unsigned bits=0;
    for(long i=0;i<bytes;i++)for(unsigned j=0;j<8;j++)bits+=(affinity[i]>>j)&1;
    checked(bits==1,640,bits);
    char status[16384];size_t length=0;
    const char path[]="/proc/self/status";
    long fd=raw(SYS_openat,AT_FDCWD,(long)path,O_RDONLY|O_CLOEXEC,0,0,0);
    checked(fd>=0,641,fd);
    for(;;) {
        checked(length<sizeof status,642,0);
        long got=raw(SYS_read,fd,(long)(status+length),sizeof status-length,0,0,0);
        checked(got>=0 && (size_t)got<=sizeof status-length,643,got);
        if(!got)break;
        length+=(size_t)got;
    }
    checked(!raw(SYS_close,fd,0,0,0,0,0),644,0);
    const char *keys[]={"TracerPid:\t0\n","Threads:\t1\n"};
    for(size_t k=0;k<2;k++) {
        size_t n=0;while(keys[k][n])++n;
        unsigned found=0;
        for(size_t i=0;i+n<=length;i++)if((!i || status[i-1]=='\n') && equal(status+i,keys[k],n))++found;
        checked(found==1,645,k);
    }
}
static void selected_initialize(void) {
    selected_preflight();
    checked(!li2_decoder_initialize(selected_arena,sizeof selected_arena,&selected_initial_stats) &&
            selected_initial_stats.phase==2,608,0);
    checked(!li2_selected_observe_hardware(&selected_hardware),609,0);
    checked(!li2_step_session_init(&selected_session,SELECTED_MASK),610,0);
    checked(!(li2_saved[16]&(SELECTED_TF|SELECTED_RF)),611,0);
    selected_logical_flags=li2_saved[16];selected_flags_known=1;
}
static void selected_prepare(uintptr_t pc) {
    size_t bytes=PAGE-(pc&(PAGE-1));if(bytes>15)bytes=15;
    checked(!li2_lifecycle_fetch_prepare(pc,bytes,&selected_borrow),612,0);
    checked(!li2_lifecycle_fetch_view(&selected_borrow,&selected_view),613,0);
    checked(!li2_decoder_decode(pc,selected_view.bytes,selected_view.length,&selected_decoded),614,0);
    if(selected_decoded.decode_status==LI2_TRUNCATED && bytes<15) {
        checked(!li2_lifecycle_fetch_release(&selected_borrow),615,0);
        checked(!li2_lifecycle_fetch_prepare(pc,15,&selected_borrow),616,0);
        checked(!li2_lifecycle_fetch_view(&selected_borrow,&selected_view),617,0);
        checked(!li2_decoder_decode(pc,selected_view.bytes,selected_view.length,&selected_decoded),618,0);
    }
    checked(selected_decoded.decode_status==LI2_VALID && selected_decoded.length &&
            selected_decoded.length<=selected_view.length,619,selected_decoded.decode_status);
    selected_initialized();
}
static void selected_release(void) {
    checked(!li2_lifecycle_fetch_release(&selected_borrow),620,0);
}
static void selected_trace(int sig,siginfo_t *si,ucontext_t *context) {
    li2_step_trace(&selected_step,sig,si,context);
    checked(selected_step.phase==LI2_STEP_COMPLETE && !selected_step.first_error &&
            selected_step.trace_seen && selected_step.revoke_sync_started &&
            !selected_step.revoke_sync,621,0);
    for(size_t i=0;i<selected_step.request.page_count;i++)
        checked(selected_step.open_started[i] && selected_step.opened[i] &&
                selected_step.revoke_started[i] && selected_step.revoked[i],622,i);
    selected_release();
    selected_logical_flags=(uint64_t)context->uc_mcontext.gregs[REG_EFL];
    checked(!(selected_logical_flags&(SELECTED_TF|SELECTED_RF)),623,0);
    selected_flags_known=1;selected_step_pending=0;
    if(selected_selftesting) {
        ++selected_selftests;
        /* Runtime-only selftest continuation. No application instruction is
           redirected: the selftest CALL's own stack word is consumed by RET. */
        context->uc_mcontext.gregs[REG_RIP]=(greg_t)(uintptr_t)selected_selftest_return;
    } else ++selected_steps;
    /* The same fixed owner may be initialized after genuine TRACE, every
       revoke/sync, and release of the sole source borrow. No pending references
       survive. Counts retain completed operations, not an unbounded journal. */
    selected_step=(struct li2_step_owner){0};
}
/* Read-only callback. The sole source borrow remains occupied throughout
   TRACE, every source-page revoke/sync, and actual continuation validation. */
static int selected_continue_closed(void *context,uintptr_t pc) {
    (void)context;
    return li2_lifecycle_tf_continuation(&selected_borrow,pc,&selected_tf_continuation);
}
static void selected_generic_begin(int sig,siginfo_t *si,ucontext_t *context,uint64_t flags) {
    checked(!selected_selftesting && !selected_step_pending &&
            selected_pending_route==SELECTED_NO_STEP &&
            li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,649,0);
    /* Reuse only a never-used owner or the fully closed previous attempt.
       Failed owners terminate with their complete installed prefix intact. */
    checked((selected_tf.step.phase==LI2_STEP_EMPTY && !selected_tf.step.session) ||
            (selected_tf.step.phase==LI2_STEP_COMPLETE && !selected_tf.step.first_error &&
             selected_tf.continuation_complete && selected_tf_continuation.complete &&
             selected_tf_release_complete),650,0);
    checked(selected_tf_attempts!=UINT64_MAX,651,0);
    selected_tf=(struct li2_tf_owner){0};
    selected_tf_continuation=(struct li2_tf_continuation){0};
    selected_tf_release_started=0;selected_tf_release_complete=0;selected_tf_release_result=0;
    ++selected_tf_attempts;
    struct li2_step_request request={.decoded=selected_decoded,.original_flags=flags};
    uintptr_t first=selected_decoded.pc&~(PAGE-1),last=(selected_decoded.next_pc-1)&~(PAGE-1);
    request.page_count=first==last?1:2;
    checked(request.page_count<=selected_view.page_count,652,0);
    for(size_t i=0;i<request.page_count;i++) {
        const struct li2_fetch_page *p=&selected_view.pages[i];
        request.pages[i]=(struct li2_step_page){p->address,p->allocation,p->generation,p->offset,PROT_READ,PROT_READ|PROT_EXEC};
    }
    const struct li2_tf_hooks hooks={{0,selected_authenticate,selected_step_failure},selected_continue_closed};
    selected_pending_route=SELECTED_GENERIC_TF;selected_step_pending=1;
    int error=li2_tf_arm(&selected_tf,&selected_session,&hooks,&request);
    if(error)li2_tf_abort(&selected_tf,(unsigned)error,0);
    selected_initialized();
    li2_tf_begin(&selected_tf,sig,si,context);
}
static void selected_generic_trace(int sig,siginfo_t *si,ucontext_t *context) {
    li2_tf_trace(&selected_tf,sig,si,context);
    const struct li2_step_owner *p=&selected_tf.step;
    checked(p->phase==LI2_STEP_COMPLETE && !p->first_error && p->trace_seen &&
            p->revoke_sync_started && !p->revoke_sync &&
            selected_tf.continuation_started && selected_tf.continuation_complete &&
            !selected_tf.continuation_result && selected_tf_continuation.attempted &&
            selected_tf_continuation.page_observed && selected_tf_continuation.complete &&
            !selected_tf_continuation.result &&
            selected_tf_continuation.pc==selected_tf.actual_post_pc &&
            (uintptr_t)context->uc_mcontext.gregs[REG_RIP]==selected_tf.actual_post_pc,653,0);
    for(size_t i=0;i<p->request.page_count;i++)
        checked(p->open_started[i] && p->opened[i] && p->revoke_started[i] && p->revoked[i],654,i);
    selected_tf_release_started=1;
    selected_tf_release_result=li2_lifecycle_fetch_release(&selected_borrow);
    checked(!selected_tf_release_result,655,selected_tf_release_result);
    selected_tf_release_complete=1;
    selected_logical_flags=(uint64_t)context->uc_mcontext.gregs[REG_EFL];
    checked(!(selected_logical_flags&(SELECTED_TF|SELECTED_RF)) &&
            selected_logical_flags==(selected_tf.actual_post_flags&~SELECTED_TF),656,0);
    selected_flags_known=1;++selected_tf_steps;
    selected_step_pending=0;selected_pending_route=SELECTED_NO_STEP;
    /* Retain the actual last owner, frame, query and release prefix until the
       next generic attempt. Counters are not an unbounded execution journal. */
}
#include "selected_repeat.inc"

/* Internal-only controls while target is stopped and no step page is open.
   These controls cannot change source/lifecycle generations. Actual restoration
   must complete before any frame commit, fetch release or application return. */
static void selected_builtin(ucontext_t *context) {
    greg_t *g=context->uc_mcontext.gregs;
    checked(!selected_step_pending && li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,646,0);
    struct selected_builtin_prefix *p=&selected_builtin_prefix;
    *p=(struct selected_builtin_prefix){.kind=selected_decoded.kind};
    uint32_t a,d,c=0,b=0;
    p->phase=1; /* enable operation entered, no result claimed */
    if(p->kind==LI2_CPUID) p->enable_result=raw(SYS_arch_prctl,ARCH_SET_CPUID,1,0,0,0,0);
    else p->enable_result=raw(SYS_prctl,PR_SET_TSC,PR_TSC_ENABLE,0,0,0,0);
    p->phase=2;
    checked(!p->enable_result,647,p->enable_result);
    p->phase=3; /* exactly one sample attempted */
    if(p->kind==LI2_CPUID) {
        a=(uint32_t)g[REG_RAX];c=(uint32_t)g[REG_RCX];
        __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d)::"memory");
    } else if(p->kind==LI2_RDTSCP) __asm__ volatile("rdtscp":"=a"(a),"=d"(d),"=c"(c)::"memory");
    else __asm__ volatile("rdtsc":"=a"(a),"=d"(d)::"memory");
    p->a=a;p->b=b;p->c=c;p->d=d;p->phase=4; /* outcome retained */
    p->phase=5;
    if(p->kind==LI2_CPUID) p->restore_result=raw(SYS_arch_prctl,ARCH_SET_CPUID,0,0,0,0,0);
    else p->restore_result=raw(SYS_prctl,PR_SET_TSC,PR_TSC_SIGSEGV,0,0,0,0);
    p->phase=6;
    checked(!p->restore_result,648,p->restore_result);
    g[REG_RAX]=a;g[REG_RDX]=d;
    if(p->kind==LI2_CPUID) {g[REG_RBX]=b;g[REG_RCX]=c;++cpuid_count;}
    else if(p->kind==LI2_RDTSCP) {g[REG_RCX]=c;++tscp_count;}else ++tsc_count;
    g[REG_EFL]=(greg_t)selected_logical_flags;g[REG_RIP]=(greg_t)selected_decoded.next_pc;
    p->phase=7; /* selected context committed */
}

static void selected_fetch(int sig,siginfo_t *si,ucontext_t *context) {
    greg_t *g=context->uc_mcontext.gregs;uintptr_t pc=(uintptr_t)g[REG_RIP];
    checked(!selected_step_pending && !li2_lifecycle_fetch_interlock() && selected_flags_known &&
            sig==SIGSEGV && si->si_signo==SIGSEGV && si->si_code==SEGV_ACCERR && !si->si_errno &&
            g[REG_TRAPNO]==14 && g[REG_ERR]==21 &&
            ((uint64_t)g[REG_CSGSFS]&0xffff)==0x33,624,0);
    uint64_t flags=selected_selftesting?selected_selftest_flags:selected_logical_flags;
    checked((uint64_t)g[REG_EFL]==(flags|SELECTED_RF),625,g[REG_EFL]);
    uint64_t mask=0;copy(&mask,&context->uc_sigmask,8);checked(mask==SELECTED_MASK,626,0);
    selected_prepare(pc);
    checked((uintptr_t)si->si_addr>=pc && (uintptr_t)si->si_addr<selected_decoded.next_pc,627,0);
    if(!selected_selftesting) {
        if(!first_target_pc)first_target_pc=pc;
        ++faults;if(pc==original_interpreter.entry)++first_interpreter;
        if(image_code(&original_main,pc))++main_faults;
        else if(image_code(&original_interpreter,pc))++interpreter_faults;else ++dependency_faults;
    }
    if(selected_decoded.kind>=LI2_RDRAND && selected_decoded.kind<=LI2_RDPID) {
        checked(!selected_selftesting,628,0);
        struct li2_selected_request request={&selected_decoded,selected_view.bytes,selected_view.length,
            flags,LI2_SELECTED_NX_KNOWN_INPUT,si};
        int status=li2_selected_complete_native(context,&request,&selected_hardware,&selected_completion);
        checked(!status,629,status);
        ++selected_provider_calls[selected_decoded.kind-LI2_RDRAND];
        selected_logical_flags=(uint64_t)g[REG_EFL];selected_release();return;
    }
    if(selected_decoded.kind==LI2_CPUID || selected_decoded.kind==LI2_RDTSC || selected_decoded.kind==LI2_RDTSCP) {
        checked(!selected_selftesting,630,0);selected_builtin(context);selected_release();return;
    }
    if(selected_decoded.kind==LI2_SYSCALL) {
        checked(!selected_selftesting,631,0);
        long number=g[REG_RAX];
        g[REG_RIP]=(greg_t)selected_decoded.next_pc;g[REG_RCX]=g[REG_RIP];
        g[REG_EFL]=(greg_t)flags;g[REG_R11]=(greg_t)flags;
        selected_release();++selected_source_syscalls;dispatch_operation(number,context);return;
    }
    if(!selected_selftesting && li2_repeat_candidate(&selected_decoded)) {
        selected_repeat_begin(sig,si,context,flags);return;
    }
    if(!selected_selftesting && selected_decoded.kind==LI2_NONE &&
       selected_decoded.step_disposition!=LI2_STEP_CANDIDATE) {
        selected_generic_begin(sig,si,context,flags);return;
    }
    checked(selected_decoded.kind==LI2_NONE && selected_decoded.step_disposition==LI2_STEP_CANDIDATE,632,selected_decoded.code);
    struct li2_step_request request={.decoded=selected_decoded,.original_flags=flags};
    uintptr_t first=pc&~(PAGE-1),last=(selected_decoded.next_pc-1)&~(PAGE-1);
    request.page_count=first==last?1:2;
    checked(request.page_count<=selected_view.page_count,633,0);
    for(size_t i=0;i<request.page_count;i++) {
        const struct li2_fetch_page *p=&selected_view.pages[i];
        request.pages[i]=(struct li2_step_page){p->address,p->allocation,p->generation,p->offset,PROT_READ,PROT_READ|PROT_EXEC};
    }
    const struct li2_step_hooks hooks={0,selected_authenticate,selected_step_failure};
    selected_pending_route=SELECTED_OLD_STEP;
    selected_step_pending=1;
    int error=li2_step_arm(&selected_step,&selected_session,&hooks,&request,selected_selftesting);
    if(error)li2_step_abort(&selected_step,(unsigned)error,0);
    li2_step_begin(&selected_step,sig,si,context);
}
static void selected_selftest(void) {
    uint64_t mask=SELECTED_MASK;
    checked(!raw(SYS_rt_sigprocmask,SIG_SETMASK,(long)&mask,0,8,0,0),634,0);
    long args[6]={0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0},result;
    checked(li2_lifecycle_dispatch(SYS_mmap,args,&result) && result>0,635,0);
    uintptr_t page=(uintptr_t)result;*(unsigned char *)page=0x90;
    args[0]=(long)page;args[2]=PROT_READ|PROT_EXEC;
    checked(li2_lifecycle_dispatch(SYS_mprotect,args,&result) && !result,636,0);
    selected_selftesting=1;selected_selftest_enter(page);selected_selftesting=0;
    checked(selected_selftests==1 && selected_session.self_test_complete &&
            !selected_step_pending && !li2_lifecycle_fetch_interlock(),637,0);
    args[0]=(long)page;args[1]=PAGE;
    checked(li2_lifecycle_dispatch(SYS_munmap,args,&result) && !result,638,0);
    selected_logical_flags=li2_saved[16];selected_flags_known=1;
}
