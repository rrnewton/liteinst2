/* Opt-in rotating-cache oracle. The old TRACE/native helpers and machine are
   included through two exact definition renames, never weakened or rerun as
   fabricated events. Intermediate whole-state comparisons are in-process;
   only six named focal observations are retained for independent replay. */
#include "reuse_trace_support.inc"
#include "register_run_reuse.h"
#include "sha256.h"
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sys/prctl.h>

enum { RU_POSITIVE,RU_STALE_A,RU_STALE_C,RU_STALE_B,RU_CLONE,RU_DIRECT,
       RU_DUP_ARM,RU_DUP_RESET,RU_DUP_QUIESCE,RU_PENDING,RU_ACTIVE,RU_RELEASED,
       RU_FORGED,RU_RAW_REVOKE,RU_RAW_SYNC,RU_NESTED_INSTALLED,RU_NESTED_WRITABLE,
       RU_KERNEL_REVOKE,RU_KERNEL_SYNC,RU_EARLY_QUIESCE,RU_GENERATION_OVERFLOW,
       RU_ATTEMPT_OVERFLOW,RU_COMPLETION_OVERFLOW,RU_COPIED_OVERFLOW,RU_HELD_QUIESCE,RU_ARMED_CLONE,RU_MODES };
#define RU_RUNS 130U
#define RU_FOCAL 6U
struct ru_case {
    uint64_t ordinal,route,native_observed,checked;
    uintptr_t mapping,pc,run_pc,guard;
    unsigned char literal[CODE_BYTES],reference_source[3][CODE_BYTES];
    struct tr_native native[3];
    struct tr_lane lane;
    struct li2_fetch_page pages[2];
    struct li2_fetch_backing backing[2];
    struct li2_run_handle handle;
};
struct ru_ledger {
    uint64_t ordinal,route,started,checked,reset,quiesced,native_observed;
    uintptr_t pc,entry;
    struct li2_run_handle handle;
    struct li2_fetch_page page;
    struct li2_fetch_progress released;
    struct li2_run_cache_diagnostic published,finished;
    uint64_t before_generation,before_completions,before_retirements;
    struct li2_run_reuse_observation after;
    unsigned char plan_sha256[32],full_case_sha256[32];
};
struct ru_raw_event {
    long number,args[6],actual_result,returned_result;
    unsigned issued,complete,injected,signal_sent,kernel_filter;
};
struct ru_record {
    uint64_t magic,version,bytes,mode,pid,tid,uid,xcr0,xsave_bytes;
    uintptr_t subject_address,data_address,fault_address;
    uint64_t started,checked,native_completed,retained,complete,verified_failure;
    uint64_t old_refusals,startup_pairs,error,detail_abs,detail_negative,fixture_failure;
    uint64_t supplied_mutations,raw_injections,real_signals,kernel_filters,raw_count;
    uint64_t runtime_calls[3],runtime_failures;
    struct li2_run_handle saved[3],supplied,current;
    uintptr_t direct_publication;
    struct li2_run_publisher direct_publisher;
    struct ru_case focal[RU_FOCAL];
    struct ru_ledger ledger[RU_RUNS];
    struct ru_raw_event raw[32];
    struct tr_snapshot delivered,failure_frame;
    struct li2_run_owner final_owner,clone;
    struct li2_run_completion_history final_history;
    struct li2_run_reuse_observation final_reuse;
    struct li2_run_cache_diagnostic final_cache;
    struct li2_fetch_progress final_fetch;
    struct li2_decoder_stats initial_stats,final_stats;
};
static struct ru_record ru;
static struct ru_case working;
static struct li2_run_handle handle;
static unsigned ru_route,ru_publishing,ru_triggered,ru_control_used,ru_index;
static unsigned char ru_whole_page[PAGE];
static ucontext_t *ru_uc;static siginfo_t *ru_si;static int ru_signal;
void li2_reuse_supplied_counter(unsigned mode);
static int ru_focal_index(unsigned ordinal) {
    const unsigned v[RU_FOCAL]={0,1,64,65,66,129};
    for(unsigned i=0;i<RU_FOCAL;i++)if(v[i]==ordinal)return (int)i;
    return -1;
}
static void ru_case_copy(struct ru_case *out) {
    out->ordinal=ru_index;out->route=ru_route?ru_route:working.route;
    out->mapping=tr.mapping;out->pc=tr.pc;out->run_pc=tr.run_pc;out->guard=tr.guard;
    memcpy(out->literal,tr.literal,CODE_BYTES);memcpy(out->reference_source,tr.reference_source,sizeof(out->reference_source));
    memcpy(out->native,tr.native,sizeof(out->native));out->lane=tr.lanes[0];out->handle=handle;
    if(tr_owner.page_count) {
        memcpy(out->pages,tr_owner.pages,sizeof(out->pages));memcpy(out->backing,tr_owner.backing,sizeof(out->backing));
    } else if(out->lane.complete_owner.page_count) {
        memcpy(out->pages,out->lane.complete_owner.pages,sizeof(out->pages));
        memcpy(out->backing,out->lane.complete_owner.backing,sizeof(out->backing));
    }
}
static int tr_dump(void) {
    (void)tr_dump_base;
    ru.magic=UINT64_C(0x315553455252324c);ru.version=1;ru.bytes=sizeof(ru);
    ru.fixture_failure=result.fixture_failure;ru.final_owner=tr_owner;ru.final_history=tr.history;
    ru.final_fetch=*li2_lifecycle_fetch_progress();
    if(tr_cache) {ru.final_cache=*li2_run_cache_diagnostic(tr_cache);
        (void)li2_run_reuse_snapshot(tr_cache,&ru.final_reuse);}
    if(ru.started>ru.checked) {
        int i=ru_focal_index(ru_index);
        if(i<0)i=RU_FOCAL-1;
        ru_case_copy(&working);ru.focal[i]=working;
    }
    return write_all(3,&ru,sizeof(ru))&&write_all(3,&samples[0],sizeof(samples[0]));
}
static unsigned ru_expected(void) {
    if(ru.mode==RU_DUP_RESET)return LI2_CACHE_RESET;
    if(ru.mode==RU_RAW_REVOKE||ru.mode==RU_KERNEL_REVOKE)return LI2_CACHE_WRITE;
    if(ru.mode==RU_RAW_SYNC||ru.mode==RU_KERNEL_SYNC)return LI2_CACHE_SYNC;
    if(ru.mode==RU_NESTED_INSTALLED||ru.mode==RU_NESTED_WRITABLE)return LI2_CACHE_REENTRY;
    return LI2_CACHE_REUSE;
}
static _Noreturn void ru_failed(unsigned code,long detail) {
    ru.error=code;ru.detail_abs=detail<0?0ULL-(uint64_t)detail:(uint64_t)detail;ru.detail_negative=detail<0;
    ru.current=handle;
    if(ru_uc&&ru_si)tr_snap(&ru.failure_frame,ru_signal,ru_si,ru_uc);
    if(ru.mode&&code==ru_expected()&&!result.fixture_failure)ru.verified_failure=1;
    (void)li2_decoder_stats(&ru.final_stats);
    need(tr_dump(),600);output(ru.verified_failure?"LI2_REUSE_EXPECTED_FAILURE\n":"LI2_REUSE_UNEXPECTED_FAILURE\n");
    (void)RAW(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
void li2_run_reuse_runtime_failure(const struct li2_run_owner *o) {
    ru_failed(o?o->first_error:LI2_CACHE_REUSE,o?o->first_detail:0);
}
/* This linked adapter reads real fixture owners and held source. No test-mode
   switch/allow Boolean can construct a permit or suppress the old checks. */
int li2_run_reuse_runtime(enum li2_run_reuse_stage stage,const struct li2_fetch_ref *fresh) {
    if(stage<LI2_REUSE_PUBLISH||stage>LI2_REUSE_QUIESCE)return 601;
    ++ru.runtime_calls[stage-1];
    const struct li2_fetch_progress *f=li2_lifecycle_fetch_progress();
    int bad=tr_native_mode||!tr_handling||tr_chain.pending||tr_chain.in_handler||tr_chain.first_error||
        tr_owner.phase!=LI2_RUN_EMPTY||tr_owner.first_error||!session.self_test_complete||!f;
    if(stage==LI2_REUSE_QUIESCE) {
        bad|=fresh!=0||ru_route!=0||li2_lifecycle_fetch_interlock()!=0||f->held||!f->complete||f->first_error||
             !tr.history.reset_complete||!tr.history.completed_runs||tr.history.first_error;
    } else {
        struct li2_fetch_view v={0};
        bad|=!ru_publishing||ru_route==0||!fresh||!f->held||!f->complete||f->first_error;
        if(fresh)bad|=memcmp(fresh,&tr_ref,sizeof(tr_ref))!=0||f->sequence!=fresh->sequence||
            li2_lifecycle_fetch_view(fresh,&v)!=0||v.pc!=tr.run_pc||v.length!=15||v.page_count!=1||
            v.pid!=session.pid||v.tid!=session.tid||!v.identity_observed;
    }
    if(bad)++ru.runtime_failures;
    return bad?602:0;
}
static void ru_check_rc(int rc) {
    if(rc) {const struct li2_run_cache_diagnostic *c=li2_run_cache_diagnostic(tr_cache);
        ru_failed((unsigned)rc,c?c->first_detail:0);}
}
/* Real kernel denial of the unchanged syscall, not a substituted raw return.
   This filter intentionally also applies to cleanup: preserve any incomplete
   cleanup rather than claiming revocation/sync succeeded. */
static void ru_filter(long syscall_number) {
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)syscall_number,0,3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args)+(syscall_number==SYS_mprotect?16:0)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)(syscall_number==SYS_mprotect?PROT_READ:32),0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
    struct sock_fprog p={(unsigned short)(sizeof(code)/sizeof(code[0])),code};
    need(!RAW(SYS_prctl,PR_SET_NO_NEW_PRIVS,1,0,0,0,0)&&
         !RAW(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&p,0,0,0),603);++ru.kernel_filters;
}
long li2_reuse_control_raw(long n,long a,long b,long c,long d,long e,long f) {
    struct li2_run_reuse_observation s={0};
    if(tr_cache)(void)li2_run_reuse_snapshot(tr_cache,&s);
    int target=ru_index==64&&ru_publishing&&s.retirement.consumed;
    struct ru_raw_event *v=0;
    if(target&&ru.mode>=RU_RAW_REVOKE&&ru.mode<=RU_KERNEL_SYNC) {
        need(ru.raw_count<32,604);v=&ru.raw[ru.raw_count++];
        *v=(struct ru_raw_event){.number=n,.args={a,b,c,d,e,f}};
    }
    int revoke=target&&n==SYS_mprotect&&a==(long)s.retirement.entry&&b==PAGE&&c==PROT_READ&&
        s.retirement.phase==LI2_RETIRE_INSTALLED&&!s.retirement.cleanup_started;
    int sync=target&&n==SYS_membarrier&&a==32&&s.retirement.phase==LI2_RETIRE_INSTALLED&&
        s.retirement.sync_started&&!s.retirement.cleanup_started;
    int writable=target&&s.retirement.phase==LI2_RETIRE_WRITABLE&&!s.retirement.cleanup_started;
    if(!ru_triggered&&((ru.mode==RU_RAW_REVOKE&&revoke)||(ru.mode==RU_RAW_SYNC&&sync))) {
        need(v!=0,605);ru_triggered=1;++ru.raw_injections;v->injected=1;v->complete=1;
        v->returned_result=ru.mode==RU_RAW_REVOKE?-EACCES:-EIO;return v->returned_result;
    }
    if(!ru_triggered&&((ru.mode==RU_NESTED_INSTALLED&&revoke)||(ru.mode==RU_NESTED_WRITABLE&&writable))) {
        need(v!=0,606);ru_triggered=1;++ru.real_signals;v->signal_sent=1;
        (void)RAW(SYS_tgkill,session.pid,session.tid,SIGTRAP,0,0,0);die(607);
    }
    if(!ru_triggered&&((ru.mode==RU_KERNEL_REVOKE&&revoke)||(ru.mode==RU_KERNEL_SYNC&&sync))) {
        need(v!=0,608);ru_triggered=1;ru_filter(n);v->kernel_filter=1;
    }
    if(v)v->issued=1;
    long answer=li2_step_raw(n,a,b,c,d,e,f);
    if(v){v->actual_result=answer;v->returned_result=answer;v->complete=1;}
    return answer;
}
static void ru_arm_control(ucontext_t *uc) {
    if(ru_control_used)return;
    int active=ru.mode>=RU_STALE_A&&ru.mode<=RU_FORGED;
    if(!active)return;
    ru_control_used=1;int rc=0;
    struct li2_run_handle supplied=handle;
    if(ru.mode==RU_STALE_A)supplied=ru.saved[0];
    if(ru.mode==RU_STALE_C)supplied=ru.saved[1];
    if(ru.mode==RU_STALE_B)supplied=ru.saved[2];
    if(ru.mode==RU_FORGED){supplied.opaque[2]=UINT64_MAX;++ru.supplied_mutations;}
    ru.supplied=supplied;
    if(ru.mode==RU_PENDING) {
        struct li2_run_handle ignored;
        rc=li2_run_reuse_publish(tr_cache,&tr_ref,&tr.lanes[0].plan,&ignored);
        need(rc!=0,609);ru_check_rc(rc);
    }
    if(ru.mode==RU_RELEASED)need(!li2_lifecycle_fetch_release(&tr_ref),611);
    if(ru.mode==RU_CLONE) {ru.clone=tr_owner;++ru.supplied_mutations;}
    if(ru.mode<=RU_CLONE||ru.mode==RU_RELEASED||ru.mode==RU_FORGED) {
        rc=li2_run_reuse_arm(tr_cache,supplied,ru.mode==RU_CLONE?&ru.clone:&tr_owner,&tr_ref,UINT64_C(0xa96));
        need(rc!=0,612);ru_check_rc(rc);
    }
    (void)uc;
}
static void ru_begin(int sig,siginfo_t *si,ucontext_t *uc) {
    struct tr_lane *l=&tr.lanes[0];
    if(ru_route==2) {
        tr_origin=li2_tf_chain_run_entry(&tr_chain);need(tr_origin!=0,613);
        const struct li2_tf_run_origin *o=li2_tf_chain_run_snapshot(&tr_chain);need(o!=0,614);
        l->offered=*o;tr_snap(&l->closed,sig,si,uc);l->closed_chain=tr_chain;
    }
    tr_fetch(tr.run_pc);l->fresh=*li2_lifecycle_fetch_progress();
    need(!li2_run_plan_bytes(tr.run_pc,tr_view.bytes,tr_view.length,&l->plan)&&
         l->plan.instruction_count==2&&l->plan.run_length==7&&l->plan.stop==tr.guard,615);
    l->history_before=tr.history.completed_runs;ru_publishing=1;
    struct li2_run_reuse_observation before;
    need(!li2_run_reuse_snapshot(tr_cache,&before)&&!before.lookup&&!before.lease&&!before.reset_pending,616);
    ru.ledger[ru_index].before_generation=before.generation;
    ru.ledger[ru_index].before_completions=before.completions;
    ru.ledger[ru_index].before_retirements=before.retirements;
    if(ru.mode>=RU_GENERATION_OVERFLOW&&ru.mode<=RU_COPIED_OVERFLOW) {
        ++ru.supplied_mutations;li2_reuse_supplied_counter((unsigned)ru.mode);
    }
    int rc=li2_run_reuse_publish(tr_cache,&tr_ref,&l->plan,&handle);
    ru_publishing=0;l->published=*li2_run_cache_diagnostic(tr_cache);
    ru_check_rc(rc);need(!li2_run_reuse_publication(tr_cache,handle,&l->publication),617);
    ru.current=handle;
    if((ru.mode==RU_STALE_C&&ru_index==67)||
       ((ru.mode==RU_STALE_A||ru.mode==RU_STALE_B)&&ru_index==129)||
       (ru.mode>=RU_CLONE&&ru.mode<=RU_FORGED&&ru_index==0))ru_arm_control(uc);
    ru_check_rc(li2_run_reuse_arm(tr_cache,handle,&tr_owner,&tr_ref,UINT64_C(0xa96)));
    if(ru.mode==RU_ARMED_CLONE&&ru_index==0) {
        /* Copy the genuine armed owner with its actual publisher, opaque
           publication, borrow and plan; never change the registered original. */
        ru.clone=tr_owner;++ru.supplied_mutations;
        li2_run_begin(&ru.clone,sig,si,uc);die(659);
    }
    if(ru.mode==RU_DIRECT&&ru_index==0) {
        /* Genuine publication/publisher from the registered actual arm; the
           cloned recipient is zero. The real owner is never cleared/cancelled. */
        ru.direct_publication=(uintptr_t)tr_owner.publication;ru.direct_publisher=tr_owner.publisher;
        ++ru.supplied_mutations;
        rc=li2_run_arm(&ru.clone,&session,&tr_ref,UINT64_C(0xa96),&ru.direct_publisher,
            (const struct li2_run_publication *)ru.direct_publication);
        need(rc!=0,610);ru_check_rc(rc);
    }
    if(!ru_control_used&&ru.mode==RU_EARLY_QUIESCE) {
        ru_control_used=1;rc=li2_run_reuse_quiesce(tr_cache,&tr.history,uc);
        need(rc!=0,618);ru_check_rc(rc);
    }
    if(ru.mode==RU_DUP_ARM&&ru_index==0) {
        rc=li2_run_reuse_arm(tr_cache,handle,&tr_owner,&tr_ref,UINT64_C(0xa96));
        need(rc!=0,619);ru_check_rc(rc);
    }
    if(ru.mode==RU_ACTIVE&&ru_index==0) {
        struct li2_run_handle ignored;ru_publishing=1;
        rc=li2_run_reuse_publish(tr_cache,&tr_ref,&l->plan,&ignored);
        need(rc!=0,620);ru_check_rc(rc);
    }
    tr_snap(&l->input,sig,si,uc);
    if(ru_route==2) {
        ++tr.consume_calls;li2_run_begin_trace(&tr_owner,tr_origin,sig,si,uc);
        const struct li2_tf_run_origin *o=li2_tf_chain_run_snapshot(&tr_chain);need(o!=0,621);l->consumed=*o;
    } else li2_run_begin(&tr_owner,sig,si,uc);
    tr_snap(&l->redirected,sig,si,uc);
}
static void ru_handler(int sig,siginfo_t *si,void *frame_) {
    ucontext_t *uc=frame_;li2_tf_chain_event_boundary(&tr_chain);
    if(tr_handling) {
        tr_snap(&ru.delivered,sig,si,uc);
        if(ru_publishing) {
            int rc=li2_run_cache_interrupt(tr_cache,LI2_CACHE_REENTRY,sig);
            need(rc==LI2_CACHE_REENTRY,622);ru_failed((unsigned)rc,sig);
        }
        li2_run_unexpected(&tr_owner,sig,si,uc);
    }
    tr_handling=1;need(si&&uc,623);ru_uc=uc;ru_si=si;ru_signal=sig;
    if(tr_native_mode)tr_native_handler(sig,si,uc);
    else {
        struct tr_lane *l=&tr.lanes[0];greg_t *g=uc->uc_mcontext.gregs;
        ++l->events;if(sig==SIGSEGV)++l->nx;if(sig==SIGTRAP&&si->si_code==TRAP_TRACE)++l->trace_events;
        if(tr_owner.phase==LI2_RUN_RUNNING) {
            tr_snap(&l->after,sig,si,uc);li2_run_exit(&tr_owner,sig,si,uc);l->complete_owner=tr_owner;
            int rc=li2_run_complete_reset(&tr_owner,&tr.history,&tr_protection,uc);
            if(rc)ru_failed((unsigned)rc,tr.history.first_detail);
            l->reset=1;l->history_after=tr.history.completed_runs;
            l->final_fetch=*li2_lifecycle_fetch_progress();l->finished=*li2_run_cache_diagnostic(tr_cache);
            if(ru.mode==RU_DUP_RESET&&ru_index==0) {
                rc=li2_run_complete_reset(&tr_owner,&tr.history,&tr_protection,uc);
                need(rc!=0,624);ru_failed((unsigned)rc,tr.history.first_detail);
            }
            /* Consume observation/accounting and clear actual route before
               minting the permit, while the original endpoint is unchanged. */
            ++tr.completed_runs;ru_route=0;
            if(ru.mode==RU_HELD_QUIESCE&&ru_index==0) {
                /* Actual unrelated live source borrow after the real reset. */
                tr_fetch(tr.pc);
            }
            ru_check_rc(li2_run_reuse_quiesce(tr_cache,&tr.history,uc));
            if(ru.mode==RU_DUP_QUIESCE&&ru_index==0) {
                rc=li2_run_reuse_quiesce(tr_cache,&tr.history,uc);need(rc!=0,625);ru_check_rc(rc);
            }
            need(!li2_run_reuse_snapshot(tr_cache,&ru.ledger[ru_index].after),626);
            l->complete=1;tr_source_closed();g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
        } else if(tr_chain.pending) {
            tr_snap(&l->trace,sig,si,uc);
            if(sig!=SIGTRAP||si->si_code!=TRAP_TRACE)li2_tf_chain_unexpected(&tr_chain,sig,si,uc);
            need(li2_tf_chain_trace(&tr_chain,sig,si,uc)==LI2_CHAIN_NX_FALLBACK&&
                 tr_chain.slots[tr_chain.active].fallback==LI2_CHAIN_OLD_STEP&&!tr_chain.pending,627);
            ru_begin(sig,si,uc);
        } else {
            need(!tr_phase&&nx(sig,si,g,ru_route==2?tr.pc:tr.run_pc),628);tr_phase=1;
            tr_snap(&l->before,sig,si,uc);
            if(ru_route==2) {tr_fetch(tr.pc);li2_tf_chain_begin_nx(&tr_chain,&tr_ref,&tr_decoded,fixture_flags,sig,si,uc);}
            else ru_begin(sig,si,uc);
        }
        ++l->returns;
    }
    fixture_vector_clobber();li2_tf_chain_handler_end(&tr_chain);tr_handling=0;
}
static void ru_install(void) {
    struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} a;
    a.handler=ru_handler;a.flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL;a.restorer=step_restorer;a.mask=mask;
    need(!RAW(SYS_rt_sigaction,SIGSEGV,&a,0,8,0,0)&&!RAW(SYS_rt_sigaction,SIGTRAP,&a,0,8,0,0)&&
         !RAW(SYS_rt_sigaction,SIGSYS,&a,0,8,0,0),629);
}
static void ru_compare(void) {
    const struct tr_native *p=&tr.native[0],*b=&tr.native[1],*whole=&tr.native[2];
    const struct tr_lane *l=&tr.lanes[0];
    need(tr.native_completed==3&&!tr.native_faults&&l->complete&&l->reset,630);
    tr_equal(&p->before.state,&whole->before.state);tr_equal(&p->after.state,&b->before.state);
    tr_equal(&b->after.state,&whole->after.state);
    need((uint64_t)p->after.state.frame.greg[REG_RAX]==UINT64_C(0x8000000000000000)&&
         (uint64_t)p->after.state.frame.greg[REG_EFL]==UINT64_C(0xa96),631);
    if(working.route==2) {
        tr_equal(&l->before.state,&p->before.state);tr_equal(&l->trace.state,&p->after.state);
        tr_equal(&l->closed.state,&p->after.state);tr_equal(&l->input.state,&b->before.state);
        need(l->events==3&&l->returns==3&&l->nx==2&&l->trace_events==1&&
             (uint64_t)l->trace.state.frame.greg[REG_EFL]==(UINT64_C(0xa96)|LI2_STEP_TF)&&
             (uint64_t)l->input.state.frame.greg[REG_EFL]==UINT64_C(0xa96)&&
             l->consumed.consumed==1&&l->consumed.consume_attempted==1&&!l->consumed.result,632);
    } else {
        tr_equal(&l->before.state,&b->before.state);tr_equal(&l->input.state,&b->before.state);
        need(l->events==2&&l->returns==2&&l->nx==2&&!l->trace_events&&
             (uint64_t)l->input.state.frame.greg[REG_EFL]==(UINT64_C(0xa96)|LI2_STEP_RF),633);
    }
    tr_equal(&l->after.state,&b->after.state);tr_equal(&l->after.state,&whole->after.state);
    need((uint64_t)l->after.state.frame.greg[REG_EFL]==(UINT64_C(0xa96)|LI2_STEP_RF)&&
         l->history_after==l->history_before+1,634);
    for(unsigned i=0;i<16;i++) {
        uint64_t want=(i==0||i==1)?UINT64_C(0x12345678):(uint64_t)p->after.state.frame.greg[regs[i]];
        need((uint64_t)l->after.state.frame.greg[regs[i]]==want,635);
    }
    for(unsigned e=0;e<2;e++) {
        const struct live *v=&l->live[e];const struct state *s=e?&l->after.state:&l->before.state;
        const struct tr_native *n=working.route==2?whole:b;
        need(v->started==1&&v->complete==1&&!v->reserved&&
             v->rflags==(e||working.route==1?UINT64_C(0xa96):UINT64_C(0x247)),636);
        for(unsigned i=0;i<16;i++)need(v->gpr[i]==(uint64_t)s->frame.greg[regs[i]],637);
        need(!memcmp(v->selectors,n->live[e].selectors,sizeof(v->selectors))&&
             !memcmp(l->fp[e],n->fp[e],FP_CAPACITY),638);
    }
    const struct li2_run_owner *o=&l->complete_owner;
    need(o->phase==LI2_RUN_COMPLETE&&!o->first_error&&!o->in_handler&&o->redirected&&o->exit_seen&&
         o->release_started&&o->release_complete&&!o->release_result&&
         !memcmp(&o->after,&l->after.state.frame,sizeof(o->after))&&
         !memcmp(&o->before,&l->input.state.frame,sizeof(o->before)),639);
    need(actual_protection(l->publication.entry,0)==(PROT_READ|PROT_EXEC),640);
    memcpy(ru_whole_page,(const void *)l->publication.entry,PAGE);
    for(unsigned i=0;i<PAGE;i++)need(ru_whole_page[i]==(i<l->plan.generated_length?l->plan.generated[i]:0xcc),641);
    tr_source_closed();working.checked=1;
}
static void ru_new_source(void) {
    long base=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(base>0,642);
    tr.mapping=(uintptr_t)base+PAGE;tr.pc=tr.mapping+128;tr.run_pc=tr.pc+4;tr.guard=tr.run_pc+7;
    memset(tr.literal,0xcc,CODE_BYTES);
    const unsigned char pred[]={0x48,0x83,0xc0,1},body[]={0xb8,0x78,0x56,0x34,0x12,0x89,0xc1,0x01,0xc0};
    memcpy(tr.literal+128,pred,sizeof(pred));memcpy(tr.literal+132,body,sizeof(body));
    memset(tr.native,0,sizeof(tr.native));tr.native_completed=0;tr.native_faults=0;
    for(unsigned i=0;i<3;i++)tr_reference(i);
    tr_replace(tr.literal);tr_source_closed();tr_native_mode=0;
    ru.native_completed+=3;working.native_observed=3;
}
static void ru_load(unsigned index) {
    need(index<RU_FOCAL&&ru.focal[index].checked,643);const struct ru_case *p=&ru.focal[index];
    tr.mapping=p->mapping;tr.pc=p->pc;tr.run_pc=p->run_pc;tr.guard=p->guard;
    memcpy(tr.literal,p->literal,CODE_BYTES);memcpy(tr.reference_source,p->reference_source,sizeof(tr.reference_source));
    memcpy(tr.native,p->native,sizeof(tr.native));tr.native_completed=3;tr.native_faults=0;
    tr_native_mode=0;working.native_observed=0;tr_source_closed();
}
static void ru_run(unsigned ordinal) {
    ru_index=ordinal;memset(&working,0,sizeof(working));memset(tr.lanes,0,sizeof(tr.lanes));
    working.route=(ordinal==1||ordinal==64||ordinal==66)?2:1;
    if(ordinal==65)ru_load(2);else if(ordinal==129)ru_load(0);else ru_new_source();
    tr_which=0;tr_phase=0;ru_route=(unsigned)working.route;tr.lanes[0].started=1;
    ++ru.started;ru.ledger[ordinal].started=1;ru.ledger[ordinal].ordinal=ordinal;
    ru.ledger[ordinal].route=working.route;ru.ledger[ordinal].native_observed=working.native_observed;
    ru.ledger[ordinal].pc=tr.run_pc;tr_inputs(ru_route==1);
    fixture_target=ru_route==2?tr.pc:tr.run_pc;fixture_enter();
    need(tr.lanes[0].complete&&!li2_lifecycle_fetch_interlock()&&!tr_chain.pending&&!ru_route,644);
    tr.lanes[0].live[0]=fixture_live_before;tr.lanes[0].live[1]=fixture_live_after;
    memcpy(tr.lanes[0].fp[0],fixture_fp_before,xsave_bytes);memcpy(tr.lanes[0].fp[1],fixture_fp_after,xsave_bytes);
    ru_compare();ru_case_copy(&working);
    struct ru_ledger *q=&ru.ledger[ordinal];
    q->ordinal=ordinal;q->route=working.route;q->checked=working.checked;q->reset=tr.lanes[0].reset;
    q->quiesced=1;q->native_observed=working.native_observed;q->pc=tr.run_pc;q->entry=working.lane.publication.entry;
    q->handle=handle;q->page=working.pages[0];q->released=working.lane.final_fetch;
    q->published=working.lane.published;q->finished=working.lane.finished;
    digest((const unsigned char *)&working.lane.plan,sizeof(working.lane.plan),q->plan_sha256);
    digest((const unsigned char *)&working,sizeof(working),q->full_case_sha256);
    unsigned generation=ordinal<65?ordinal+1:ordinal;
    unsigned slot=ordinal<64?ordinal:ordinal<=65?0:(ordinal-1)%64;
    need(handle.opaque[0]==1&&handle.opaque[1]==slot&&handle.opaque[2]==generation&&
         handle.opaque[3]==ordinal+1&&q->after.completions==ordinal+1&&!q->after.lookup&&!q->after.lease&&!q->after.reset_pending&&
         q->published.last_attempt.hit==(ordinal==65)&&q->after.retirements==(ordinal<64?0:ordinal==64?1:ordinal-64),645);
    if(ordinal==0)ru.saved[0]=handle;
    if(ordinal==1)ru.saved[1]=handle;
    if(ordinal==64)ru.saved[2]=handle;
    int at=ru_focal_index(ordinal);if(at>=0){ru.focal[at]=working;++ru.retained;}
    ++ru.checked;
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(ru)+sizeof(samples[0])<16*1024*1024,"whole reuse capture retains original16MiB bound");
    _Static_assert(sizeof(ru.ledger)+sizeof(ru.raw)+sizeof(ru.delivered)+sizeof(ru.final_owner)+
        sizeof(ru.final_history)+sizeof(ru.clone)+sizeof(ru.failure_frame)<1024*1024,"bounded ledger/failure metadata");
    need(stack[0]==1,646);const char *const *env=(const void *)(stack+3);unsigned found=0;
    const char key[]="LI2_RUN_REUSE_MODE=";size_t k=sizeof(key)-1;
    for(size_t i=0;env[i];i++)if(length(env[i])>=k&&!memcmp(env[i],key,k)) {
        need(!found,647);unsigned n=0;const char *p=env[i]+k;need(*p,648);
        while(*p){need(*p>='0'&&*p<='9'&&n<100,649);n=n*10+(unsigned)(*p++-'0');}
        need(n<RU_MODES,650);ru.mode=n;++found;
    }
    need(found==1,651);setup(stack);size_t done=0,failed=0;uint32_t rc=0;
    need(!li2_tf_refusal_controls(&done,&failed,&rc,&refused_last)&&done==47&&failed==SIZE_MAX&&!rc,652);
    ru.old_refusals=done;prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,653);ru.startup_pairs=1;
    need(!li2_tf_chain_init(&tr_chain,&session,tr_chain_failure)&&
         !li2_run_reuse_initialize(&session,&tr_protection,&tr_owner,&tr.history,&tr_cache)&&
         !li2_decoder_stats(&ru.initial_stats),654);
    ru.pid=tr.pid=(uint64_t)session.pid;ru.tid=tr.tid=(uint64_t)session.tid;
    ru.uid=tr.uid=(uint64_t)RAW(SYS_getuid,0,0,0,0,0,0);
    ru.xcr0=fixture_xcr0;ru.xsave_bytes=xsave_bytes;
    ru.subject_address=tr.subject_address=subject;ru.data_address=tr.data_address=data_page;
    ru.fault_address=tr.fault_address=data_fault;ru_install();
    for(unsigned i=0;i<RU_RUNS;i++)ru_run(i);
    need(!ru.mode&&ru.checked==130&&ru.native_completed==384&&ru.retained==6&&
         tr.history.completed_runs==130&&tr.history.copied_instructions==260,655);
    struct li2_run_reuse_observation last;need(!li2_run_reuse_snapshot(tr_cache,&last)&&
        last.generation==129&&last.completions==130&&last.retirements==65&&last.cursor==1,656);
    need(!li2_decoder_stats(&ru.final_stats)&&!memcmp(&ru.initial_stats,&ru.final_stats,sizeof(ru.initial_stats)),657);
    ru.complete=1;need(tr_dump(),658);
    output("LI2_REUSE_PASS fills=64 runs=130 publications=129 retirements=65 hits=1 focal=6\n");return 0;
}
