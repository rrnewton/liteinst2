/* Additive original-address oracle for the opaque TRACE -> run APIs.
   Three independent native observations precede one restoration and genuine
   miss/hit executions. This does not replace the old run/chain populations. */
static int tr_dump(void);
#define fixture_main unchanged_generic_fixture_main
#include "trace_run_support.inc"
#undef fixture_main
#include "tf_chain.h"
#include "register_run_reset.h"

enum { TR_POSITIVE,TR_NULL,TR_FRAME,TR_REPLAY,TR_RELEASED,TR_NESTED,TR_FAULT,TR_MODES };
struct tr_snapshot {
    struct state state;
    uintptr_t uc_address,si_address;
    unsigned char uc[sizeof(ucontext_t)],si[sizeof(siginfo_t)];
    int signal,code,error;
    uintptr_t address;
};
struct tr_native {
    struct tr_snapshot before,after;
    struct live live[2];
    unsigned char fp[2][FP_CAPACITY] __attribute__((aligned(64)));
    unsigned started,complete,fault,events;
    uintptr_t start,stop;
    struct li2_fetch_progress released;
};
struct tr_lane {
    struct tr_snapshot before,trace,closed,input,redirected,after;
    struct live live[2];
    unsigned char fp[2][FP_CAPACITY] __attribute__((aligned(64)));
    struct li2_tf_chain closed_chain;
    struct li2_tf_run_origin offered,consumed;
    struct li2_run_plan plan;
    struct li2_run_owner complete_owner;
    struct li2_run_cache_diagnostic published,finished;
    struct li2_run_publication_progress publication;
    struct li2_fetch_progress fresh,final_fetch;
    unsigned started,complete,nx,trace_events,events,returns,reset;
    uint64_t history_before,history_after;
};
struct tr_record {
    uint64_t magic,version,bytes,mode,xcr0,xsave_bytes;
    uint64_t old_refusals,startup_pairs,native_completed,native_faults,completed_runs;
    uint64_t verified_failure,error,detail_abs,detail_negative;
    uint64_t supplied_mutations,consume_calls,real_signals,guard_executed;
    uint64_t fixture_failure,complete,pid,tid,uid;
    uintptr_t mapping,pc,run_pc,guard,subject_address,data_address,fault_address;
    unsigned char literal[CODE_BYTES],reference_source[3][CODE_BYTES];
    struct tr_native native[3];
    struct tr_lane lanes[2];
    struct tr_snapshot delivered;
    struct li2_tf_chain final_chain;
    struct li2_tf_run_origin final_origin;
    struct li2_run_owner final_owner;
    struct li2_run_completion_history history;
    struct li2_run_cache_diagnostic cache;
    struct li2_fetch_progress final_fetch;
    struct li2_decoder_stats initial_stats,final_stats;
};
static struct tr_record tr;
static struct li2_tf_chain tr_chain;
static struct li2_run_owner tr_owner;
static struct li2_run_cache *tr_cache;
static const struct li2_run_publication *tr_publication;
static const struct li2_tf_run_entry *tr_origin;
static struct sample tr_source;
static struct li2_fetch_ref tr_ref;
static struct li2_fetch_view tr_view;
static struct li2_decoded tr_decoded;
static unsigned tr_mode,tr_which,tr_native_mode,tr_phase;
static volatile sig_atomic_t tr_handling;

static int tr_dump(void) {
    tr.magic=UINT64_C(0x3152554e5446324c);tr.version=1;tr.bytes=sizeof(tr);tr.mode=tr_mode;
    tr.xcr0=fixture_xcr0;tr.xsave_bytes=xsave_bytes;tr.fixture_failure=result.fixture_failure;
    tr.final_chain=tr_chain;tr.final_owner=tr_owner;
    const struct li2_tf_run_origin *p=li2_tf_chain_run_snapshot(&tr_chain);
    if(p)tr.final_origin=*p;
    if(tr_cache)tr.cache=*li2_run_cache_diagnostic(tr_cache);
    tr.final_fetch=*li2_lifecycle_fetch_progress();
    return write_all(3,&tr,sizeof(tr))&&write_all(3,&samples[0],sizeof(samples[0]));
}
static void tr_snap(struct tr_snapshot *out,int sig,const siginfo_t *si,ucontext_t *uc) {
    need(si&&uc,400);capture(&out->state,uc);
    out->uc_address=(uintptr_t)uc;out->si_address=(uintptr_t)si;
    memcpy(out->uc,uc,sizeof(out->uc));memcpy(out->si,si,sizeof(out->si));
    out->signal=sig;out->code=si->si_code;out->error=si->si_errno;out->address=(uintptr_t)si->si_addr;
}
static void tr_source_closed(void) {
    need(!memcmp((const void *)tr.mapping,tr.literal,CODE_BYTES),401);
    for(unsigned i=0;i<3;i++)need(actual_protection(tr.mapping+i*PAGE,0)==PROT_READ,402);
}
static unsigned tr_expected_error(void) {
    return tr_mode==TR_RELEASED?LI2_CHAIN_PREPARE:
           tr_mode==TR_NESTED?LI2_RUN_EVENT:
           tr_mode==TR_FAULT?LI2_STEP_FOREIGN_EVENT:LI2_CHAIN_ORIGIN;
}
static _Noreturn void tr_failed(unsigned code,long detail) {
    tr.error=code;tr.detail_abs=detail<0?0ULL-(uint64_t)detail:(uint64_t)detail;tr.detail_negative=detail<0;
    if(tr_mode&&code==tr_expected_error()&&!result.fixture_failure&&!tr.completed_runs) {
        tr_source_closed();tr.verified_failure=1;
        need(tr_dump(),403);output("LI2_TRACE_RUN_EXPECTED_FAILURE\n");
    } else {(void)tr_dump();output("LI2_TRACE_RUN_UNEXPECTED_FAILURE\n");}
    (void)RAW(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static void tr_chain_failure(const struct li2_tf_chain *c) {tr_failed(c->first_error,c->first_detail);}
static void tr_run_failure(void *unused,const struct li2_run_owner *o) {(void)unused;tr_failed(o->first_error,o->first_detail);}
static int tr_contains(void *unused,uintptr_t first,size_t n) {
    (void)unused;if(!n||first>UINTPTR_MAX-n)return 0;
    for(size_t i=0;i<protected_count;i++)if(protected[i].first<=first&&first+n<=protected[i].end)return 1;
    return 0;
}
static int tr_protect(void *unused,uintptr_t first,size_t n) {
    if(tr_contains(unused,first,n))return 0;
    if(!n||first>UINTPTR_MAX-n||protected_count==128)return 1;
    protected[protected_count].first=first;protected[protected_count++].end=first+n;return 0;
}
static const struct li2_run_protection tr_protection={0,tr_protect,tr_contains};
static void tr_fetch(uintptr_t pc) {
    size_t n=PAGE-(pc&(PAGE-1));if(n>15)n=15;
    need(!li2_lifecycle_fetch_prepare(pc,n,&tr_ref)&&!li2_lifecycle_fetch_view(&tr_ref,&tr_view),404);
    need(!li2_decoder_decode(pc,tr_view.bytes,tr_view.length,&tr_decoded),405);
    if(tr_decoded.decode_status==LI2_TRUNCATED&&n<15) {
        need(!li2_lifecycle_fetch_release(&tr_ref)&&!li2_lifecycle_fetch_prepare(pc,15,&tr_ref)&&
            !li2_lifecycle_fetch_view(&tr_ref,&tr_view)&&
            !li2_decoder_decode(pc,tr_view.bytes,tr_view.length,&tr_decoded),406);
    }
    need(tr_decoded.decode_status==LI2_VALID&&tr_decoded.length&&tr_decoded.length<=tr_view.length,407);
}
static void tr_permissions(int prot) {
    need(!RAW(SYS_mprotect,tr.mapping,CODE_BYTES,prot,0,0,0)&&!RAW(SYS_membarrier,32,0,0,0,0,0),408);
}
static void tr_native_handler(int sig,siginfo_t *si,ucontext_t *uc) {
    struct tr_native *n=&tr.native[tr_which];greg_t *g=uc->uc_mcontext.gregs;++n->events;
    if(!tr_phase) {
        need(nx(sig,si,g,n->start)&&(uint64_t)g[REG_EFL]==(fixture_flags|LI2_STEP_RF),409);
        tr_snap(&n->before,sig,si,uc);tr_permissions(PROT_READ|PROT_EXEC);tr_phase=1;
    } else {
        need(tr_phase==1,410);
        if(tr_mode==TR_FAULT) {
            need(sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&!si->si_errno&&
                (uintptr_t)si->si_addr==data_fault&&(uintptr_t)g[REG_RIP]==tr.pc&&
                g[REG_TRAPNO]==14&&g[REG_ERR]==4,411);n->fault=1;
        } else {
            need(sig==SIGTRAP&&si->si_signo==SIGTRAP&&si->si_code==SI_KERNEL&&!si->si_errno&&
                g[REG_TRAPNO]==3&&!g[REG_ERR]&&(uintptr_t)g[REG_RIP]==n->stop+1,412);n->complete=1;
        }
        tr_snap(&n->after,sig,si,uc);tr_permissions(PROT_READ);tr_phase=2;
        g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
    }
}
static void tr_begin_run(int sig,siginfo_t *si,ucontext_t *uc) {
    struct tr_lane *l=&tr.lanes[tr_which];
    tr_origin=li2_tf_chain_run_entry(&tr_chain);need(tr_origin!=0,413);
    const struct li2_tf_run_origin *o=li2_tf_chain_run_snapshot(&tr_chain);need(o!=0,414);l->offered=*o;
    tr_snap(&l->closed,sig,si,uc);l->closed_chain=tr_chain;
    tr_fetch(tr.run_pc);l->fresh=*li2_lifecycle_fetch_progress();
    need(!li2_run_plan_bytes(tr.run_pc,tr_view.bytes,tr_view.length,&l->plan)&&
        l->plan.instruction_count==2&&l->plan.run_length==7&&l->plan.stop==tr.guard,415);
    l->history_before=tr.history.completed_runs;
    need(!li2_run_cache_publish(tr_cache,&tr_ref,&l->plan,&tr_publication)&&tr_publication,416);
    l->published=*li2_run_cache_diagnostic(tr_cache);
    const struct li2_run_publication_progress *pp=li2_run_publication_progress(tr_cache,tr_publication);
    need(pp!=0,417);l->publication=*pp;
    const struct li2_run_publisher publisher={tr_cache,li2_run_publication_observe,tr_run_failure};
    need(!li2_run_arm(&tr_owner,&session,&tr_ref,(uint64_t)uc->uc_mcontext.gregs[REG_EFL],&publisher,tr_publication),418);
    tr_snap(&l->input,sig,si,uc);
    if(tr_mode==TR_NULL){++tr.supplied_mutations;tr_origin=0;}
    if(tr_mode==TR_FRAME){++tr.supplied_mutations;uc->uc_mcontext.gregs[REG_RAX]^=1;}
    if(tr_mode==TR_REPLAY) {
        ++tr.consume_calls;
        need(!li2_tf_chain_run_consume(tr_origin,&session,&tr_ref,tr.run_pc,tr_owner.logical_flags,sig,si,uc),419);
    }
    if(tr_mode==TR_RELEASED)need(!li2_lifecycle_fetch_release(&tr_ref),420);
    if(tr_mode==TR_NESTED) {
        ++tr.real_signals;(void)RAW(SYS_tgkill,session.pid,session.tid,SIGTRAP,0,0,0);die(421);
    }
    ++tr.consume_calls;li2_run_begin_trace(&tr_owner,tr_origin,sig,si,uc);
    o=li2_tf_chain_run_snapshot(&tr_chain);need(o!=0,422);l->consumed=*o;
    tr_snap(&l->redirected,sig,si,uc);
}
static void tr_handler(int sig,siginfo_t *si,void *frame_) {
    ucontext_t *uc=frame_;
    li2_tf_chain_event_boundary(&tr_chain);
    if(tr_handling) {
        tr_snap(&tr.delivered,sig,si,uc);li2_run_unexpected(&tr_owner,sig,si,uc);
    }
    tr_handling=1;need(si&&uc,423);
    if(tr_native_mode)tr_native_handler(sig,si,uc);
    else {
        struct tr_lane *l=&tr.lanes[tr_which];greg_t *g=uc->uc_mcontext.gregs;
        ++l->events;if(sig==SIGSEGV)++l->nx;if(sig==SIGTRAP&&si->si_code==TRAP_TRACE)++l->trace_events;
        if(tr_owner.phase==LI2_RUN_RUNNING) {
            tr_snap(&l->after,sig,si,uc);li2_run_exit(&tr_owner,sig,si,uc);l->complete_owner=tr_owner;
            need(!li2_run_complete_reset(&tr_owner,&tr.history,&tr_protection,uc),424);
            l->reset=1;l->final_fetch=*li2_lifecycle_fetch_progress();l->finished=*li2_run_cache_diagnostic(tr_cache);
            l->history_after=tr.history.completed_runs;l->complete=1;++tr.completed_runs;
            tr_source_closed();g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
        } else if(tr_chain.pending) {
            tr_snap(&l->trace,sig,si,uc);
            if(sig!=SIGTRAP||si->si_code!=TRAP_TRACE)li2_tf_chain_unexpected(&tr_chain,sig,si,uc);
            need(li2_tf_chain_trace(&tr_chain,sig,si,uc)==LI2_CHAIN_NX_FALLBACK&&
                tr_chain.slots[tr_chain.active].fallback==LI2_CHAIN_OLD_STEP&&!tr_chain.pending,425);
            tr_begin_run(sig,si,uc);
        } else {
            need(!tr_phase&&nx(sig,si,g,tr.pc),426);tr_phase=1;tr_snap(&l->before,sig,si,uc);
            tr_fetch(tr.pc);li2_tf_chain_begin_nx(&tr_chain,&tr_ref,&tr_decoded,fixture_flags,sig,si,uc);
        }
        ++l->returns;
    }
    fixture_vector_clobber();li2_tf_chain_handler_end(&tr_chain);tr_handling=0;
}
static void tr_install(void) {
    struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} a;
    a.handler=tr_handler;a.flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL;a.restorer=step_restorer;a.mask=mask;
    need(!RAW(SYS_rt_sigaction,SIGSEGV,&a,0,8,0,0)&&!RAW(SYS_rt_sigaction,SIGTRAP,&a,0,8,0,0)&&
        !RAW(SYS_rt_sigaction,SIGSYS,&a,0,8,0,0),427);
}
static void tr_replace(const unsigned char *bytes) {
    need(!li2_lifecycle_fetch_interlock()&&!dispatch(SYS_mprotect,tr.mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),428);
    memcpy((void *)tr.mapping,bytes,CODE_BYTES);
    need(!dispatch(SYS_mprotect,tr.mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),429);
}
static void tr_inputs(unsigned block) {
    tr_source.id=100;inputs(&tr_source);fixture_seed[0]=UINT64_C(0x7fffffffffffffff);
    if(tr_mode==TR_FAULT)fixture_seed[6]=data_fault;
    if(block) {
        for(unsigned i=0;i<16;i++)fixture_seed[i]=(uint64_t)tr.native[0].after.state.frame.greg[regs[i]];
        fixture_input_flags=(uint64_t)tr.native[0].after.state.frame.greg[REG_EFL];
    }
}
static void tr_reference(unsigned i) {
    struct tr_native *n=&tr.native[i];n->started=1;n->start=i==1?tr.run_pc:tr.pc;n->stop=i==0?tr.run_pc:tr.guard;
    memcpy(tr.reference_source[i],tr.literal,CODE_BYTES);tr.reference_source[i][n->stop-tr.mapping]=0xcc;
    tr_replace(tr.reference_source[i]);tr_fetch(n->start);tr_inputs(i==1);fixture_target=n->start;
    tr_native_mode=1;tr_which=i;tr_phase=0;fixture_enter();
    need(tr_phase==2&&n->events==2&&(tr_mode==TR_FAULT?n->fault&&!n->complete:n->complete&&!n->fault),430);
    n->live[0]=fixture_live_before;n->live[1]=fixture_live_after;
    memcpy(n->fp[0],fixture_fp_before,xsave_bytes);memcpy(n->fp[1],fixture_fp_after,xsave_bytes);
    need(!memcmp((const void *)tr.mapping,tr.reference_source[i],CODE_BYTES)&&!li2_lifecycle_fetch_release(&tr_ref),431);
    n->released=*li2_lifecycle_fetch_progress();if(n->complete)++tr.native_completed;else ++tr.native_faults;
}
static void tr_equal(const struct state *a,const struct state *b) {
    for(unsigned i=0;i<16;i++)need(a->frame.greg[regs[i]]==b->frame.greg[regs[i]],432);
    compare_memory(a,b,433);need(a->fs==b->fs&&a->gs==b->gs&&a->frame.mask==b->frame.mask&&
        a->frame.greg[REG_CSGSFS]==b->frame.greg[REG_CSGSFS]&&a->frame.initialized==a->frame.fp_bytes&&
        b->frame.initialized==b->frame.fp_bytes&&a->frame.fp_bytes==b->frame.fp_bytes&&
        !memcmp(a->frame.fp,b->frame.fp,FP_CAPACITY),434);
}
static void tr_compare(void) {
    const struct tr_native *p=&tr.native[0],*b=&tr.native[1],*whole=&tr.native[2];
    need(tr.native_completed==3&&!tr.native_faults&&tr.completed_runs==2,435);
    tr_equal(&p->before.state,&whole->before.state);tr_equal(&p->after.state,&b->before.state);
    tr_equal(&b->after.state,&whole->after.state);
    need((uint64_t)p->after.state.frame.greg[REG_RAX]==UINT64_C(0x8000000000000000)&&
         (uint64_t)p->after.state.frame.greg[REG_EFL]==UINT64_C(0xa96),436);
    for(unsigned j=0;j<2;j++) {
        const struct tr_lane *l=&tr.lanes[j];
        tr_equal(&l->before.state,&p->before.state);tr_equal(&l->trace.state,&p->after.state);
        tr_equal(&l->closed.state,&p->after.state);tr_equal(&l->input.state,&b->before.state);
        tr_equal(&l->after.state,&b->after.state);
        need(l->events==3&&l->returns==3&&l->nx==2&&l->trace_events==1&&l->complete&&l->reset,437);
        need((uint64_t)l->trace.state.frame.greg[REG_EFL]==(UINT64_C(0xa96)|LI2_STEP_TF)&&
             (uint64_t)l->input.state.frame.greg[REG_EFL]==UINT64_C(0xa96)&&
             (uint64_t)l->after.state.frame.greg[REG_EFL]==(UINT64_C(0xa96)|LI2_STEP_RF),438);
        for(unsigned i=0;i<16;i++) {
            uint64_t want=(i==0||i==1)?UINT64_C(0x12345678):(uint64_t)p->after.state.frame.greg[regs[i]];
            need((uint64_t)l->after.state.frame.greg[regs[i]]==want,439);
        }
        need(l->published.last_attempt.hit==j&&l->published.slots_used==1&&
             l->history_after==l->history_before+1&&l->consumed.consumed==1&&
             l->consumed.consume_attempted==1&&!l->consumed.result,440);
        for(unsigned e=0;e<2;e++) {
            const struct live *live=&l->live[e];const struct state *s=e?&l->after.state:&l->before.state;
            need(live->started==1&&live->complete==1&&!live->reserved&&
                live->rflags==(e?UINT64_C(0xa96):UINT64_C(0x247)),441);
            for(unsigned i=0;i<16;i++)need(live->gpr[i]==(uint64_t)s->frame.greg[regs[i]],442);
            need(!memcmp(live->selectors,whole->live[e].selectors,sizeof(live->selectors))&&
                !memcmp(l->fp[e],whole->fp[e],FP_CAPACITY),443);
        }
    }
    need(tr.lanes[0].publication.entry==tr.lanes[1].publication.entry&&
        tr.lanes[0].publication.generation==tr.lanes[1].publication.generation&&
        tr.history.completed_runs==2&&tr.history.copied_instructions==4&&!tr.history.first_error,444);
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(tr)+sizeof(samples[0])<16*1024*1024,"complete fixed TRACE oracle below16MiB");
    const char *const *env=(const void *)(stack+3);unsigned found=0;
    need(stack[0]==1,445);
    static const char key[]="LI2_TRACE_RUN_MODE=";
    const size_t key_bytes=sizeof(key)-1;
    for(size_t i=0;env[i];i++)if(length(env[i])>=key_bytes&&!memcmp(env[i],key,key_bytes)) {
        need(!found&&length(env[i])==key_bytes+1&&env[i][key_bytes]>='0'&&
             env[i][key_bytes]<'0'+TR_MODES&&!env[i][key_bytes+1],446);
        tr_mode=(unsigned)(env[i][key_bytes]-'0');++found;
    }
    need(found==1,447);setup(stack);
    size_t done=0,failed=0;uint32_t rc=0;
    need(!li2_tf_refusal_controls(&done,&failed,&rc,&refused_last)&&done==47&&failed==SIZE_MAX&&!rc,448);tr.old_refusals=done;
    prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,449);tr.startup_pairs=1;
    need(!li2_tf_chain_init(&tr_chain,&session,tr_chain_failure)&&
         !li2_run_cache_initialize(&session,&tr_protection,&tr_cache)&&
         !li2_decoder_stats(&tr.initial_stats),450);
    tr.pid=(uint64_t)session.pid;tr.tid=(uint64_t)session.tid;
    tr.uid=(uint64_t)RAW(SYS_getuid,0,0,0,0,0,0);
    long base=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(base>0,451);
    tr.mapping=(uintptr_t)base+PAGE;tr.pc=tr.mapping+128;
    tr.run_pc=tr.pc+(tr_mode==TR_FAULT?3:4);tr.guard=tr.run_pc+7;
    tr.subject_address=subject;tr.data_address=data_page;tr.fault_address=data_fault;
    memset(tr.literal,0xcc,CODE_BYTES);
    const unsigned char pred[]={0x48,0x83,0xc0,1},fault[]={0x48,0x8b,0x06};
    const unsigned char body[]={0xb8,0x78,0x56,0x34,0x12,0x89,0xc1,0x01,0xc0};
    memcpy(tr.literal+128,tr_mode==TR_FAULT?fault:pred,tr_mode==TR_FAULT?sizeof(fault):sizeof(pred));
    memcpy(tr.literal+tr.run_pc-tr.mapping,body,sizeof(body));tr_install();
    for(unsigned i=0;i<(tr_mode==TR_FAULT?1U:3U);i++)tr_reference(i);
    tr_replace(tr.literal);tr_source_closed();tr_native_mode=0;
    for(unsigned i=0;i<(tr_mode?1U:2U);i++) {
        tr_which=i;tr_phase=0;tr.lanes[i].started=1;tr_inputs(0);fixture_target=tr.pc;fixture_enter();
        need(!tr_mode&&tr.lanes[i].complete&&!li2_lifecycle_fetch_interlock()&&!tr_chain.pending,452);
        tr.lanes[i].live[0]=fixture_live_before;tr.lanes[i].live[1]=fixture_live_after;
        memcpy(tr.lanes[i].fp[0],fixture_fp_before,xsave_bytes);memcpy(tr.lanes[i].fp[1],fixture_fp_after,xsave_bytes);
    }
    tr_compare();need(!li2_decoder_stats(&tr.final_stats)&&!memcmp(&tr.initial_stats,&tr.final_stats,sizeof(tr.initial_stats)),453);
    tr.complete=1;need(tr_dump(),454);output("LI2_TRACE_RUN_PASS native=3 miss=1 hit=1 predecessor=2 run=2\n");return 0;
}
