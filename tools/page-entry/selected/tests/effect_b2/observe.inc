/* Additive finite observer. No source/frame/permission/result writes. */
#include "be_record.h"
#include "b2-script.h"
#include "b2_format.inc"
#if LI2_EFFECT_PROVIDER != 1 || LI2_ONESHOT_REUSABLE != 1
#error "all-class reference needs the real reusable effect profile"
#endif
_Static_assert(SELECTED_MASK==UINT64_C(0xffffffffbffbfae7),"new exact UD2-compatible B2 application mask");
static struct be_record be_record;
static unsigned be_initialized,be_emitted,be_index,be_bases,be_pending,be_final_pending;
static int be_signal;
static const siginfo_t *be_si;
static ucontext_t *be_context;
static long be_actual_base(unsigned which,uintptr_t *value) {
    if(be_bases>=32 || li2_lifecycle_fetch_interlock() || selected_oneshot_active)return -1;
    uint64_t *p=be_record.bases[be_bases++];p[0]=which;p[1]=1;
    __asm__ volatile("":::"memory");
    long result=raw(SYS_arch_prctl,which,(long)value,0,0,0,0);
    p[3]=(uint64_t)result;if(!result)p[4]=*value;
    __asm__ volatile("":::"memory");p[2]=1;return result;
}
static void be_snapshot(struct b2_snapshot *out,const ucontext_t *uc) {
    checked(!b2_capture(out,be_signal,be_si,uc,(uintptr_t)fork_gate_stack.ss_sp,
        fork_gate_stack.ss_size,be_actual_base),1800,0);
}
static void be_held_snapshot(struct b2_snapshot *out,const ucontext_t *uc) {
    /* All ranges are qualified before reads, exactly as the original capture.
       Unlike it, this copy-only form does not observe FS/GS bases. */
    uintptr_t lo=(uintptr_t)fork_gate_stack.ss_sp;size_t extent=fork_gate_stack.ss_size;
    checked(be_si && b2_inside((uintptr_t)be_si,sizeof(*be_si),lo,extent) &&
        b2_inside((uintptr_t)uc,sizeof(*uc),lo,extent) &&
        sizeof(*uc)<=sizeof out->uc && (uintptr_t)out<=UINTPTR_MAX-sizeof *out &&
        lo<=UINTPTR_MAX-extent && !b2_overlap((uintptr_t)out,sizeof *out,lo,extent) &&
        !b2_overlap((uintptr_t)out,sizeof *out,UINT64_C(0x200400000),20480) &&
        !b2_overlap((uintptr_t)out,sizeof *out,UINT64_C(0x200600000),8192),1801,0);
    uintptr_t fp=(uintptr_t)uc->uc_mcontext.fpregs;
    checked(!(fp&15) && b2_inside(fp,512,lo,extent),1801,1);
    const unsigned char *p=(const void *)fp;size_t n=512;
    if(b2_u32(p+464)==UINT32_C(0x46505853)) {
        n=b2_u32(p+468);size_t x=b2_u32(p+480);
        checked(n>=580 && n<=sizeof out->fp && x>=576 && x==n-4 &&
            b2_inside(fp,n,lo,extent) && b2_u32(p+n-4)==UINT32_C(0x46505845),1801,2);
    }
    unsigned short ds,es;__asm__ volatile("mov %%ds,%0; mov %%es,%1":"=r"(ds),"=r"(es)::"memory");
    out->h[0]=sizeof *uc;out->h[1]=n;out->h[2]=(uintptr_t)uc;out->h[3]=fp;
    out->h[6]=ds;out->h[7]=es;out->h[8]=offsetof(ucontext_t,uc_mcontext.gregs);
    out->h[9]=offsetof(ucontext_t,uc_mcontext.fpregs);out->h[10]=offsetof(ucontext_t,uc_sigmask);
    out->h[12]=(unsigned)be_signal;out->h[13]=(uintptr_t)be_si;out->h[14]=sizeof *be_si;out->h[15]=1;
    b2_copy(out->si,be_si,sizeof *be_si);b2_copy(out->uc,uc,sizeof *uc);b2_copy(out->fp,p,n);
    b2_copy(out->source,(const void *)(uintptr_t)UINT64_C(0x200400000),sizeof out->source);
    b2_copy(out->data,(const void *)(uintptr_t)UINT64_C(0x200600000),sizeof out->data);
}
static void be_emit(unsigned status,unsigned code,long detail) {
    if(!be_initialized || be_emitted)return;
    be_emitted=1;uint64_t *h=be_record.h;
    h[4]=status;h[5]=code;h[6]=(uint64_t)detail;h[7]=be_index;h[8]=be_pending;h[9]=be_bases;
    h[10]=li2_lifecycle_fetch_interlock();h[11]=selected_step_pending;h[12]=selected_pending_route;
    h[13]=be_policy_context.entered;h[14]=be_policy_context.posted;
    h[15]=selected_effect_runtime.attempts;h[16]=selected_effect_runtime.commits;
    h[17]=selected_effect_runtime.completed;h[18]=selected_effect_runtime.native_completed;
    h[19]=selected_effect_runtime.scripted_completed;
    h[20]=selected_oneshot_counts.published;h[21]=selected_oneshot_counts.restored;
    h[22]=selected_oneshot_counts.completed;h[23]=selected_oneshot_counts.retired;
    h[24]=selected_oneshot_counts.refused;h[25]=selected_oneshot_active!=0;
    size_t at=0;while(at<sizeof be_record) {
        long n=raw(SYS_write,3,(long)((const unsigned char *)&be_record+at),sizeof be_record-at,0,0,0);
        if(n<=0 || (size_t)n>sizeof be_record-at)return;
        at+=(size_t)n;
    }
    b2_format_emit();
}
static void be_initialize(void) {
    volatile unsigned char *p=(void *)&be_record;for(size_t i=0;i<sizeof be_record;i++)p[i]=0;
    checked(!be_initialized && B2_SCRIPT_ROWS>=2 && B2_SCRIPT_ROWS<=4 &&
        original_main.entry==UINT64_C(0x200404000),1802,0);
    be_record.h[0]=UINT64_C(0x3146454232494c);be_record.h[1]=1;
    be_record.h[2]=sizeof be_record;be_record.h[3]=B2_SCRIPT_ROWS;
    be_record.h[26]=(uintptr_t)fork_gate_stack.ss_sp;be_record.h[27]=fork_gate_stack.ss_size;
    be_record.h[28]=bridge_runtime_image()->bias;
    be_record.h[29]=(uintptr_t)be_policy_callback;be_record.h[30]=(uintptr_t)be_policy_post;
    be_record.h[31]=(uintptr_t)&be_policy_context;
    copy(&be_record.hardware,&selected_hardware,sizeof be_record.hardware);
    be_initialized=1;b2_format_initialize();
}
static void be_entry(int sig,const siginfo_t *si,ucontext_t *uc) {
    if(selected_selftesting)return;
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    checked(be_initialized && !be_pending && !be_emitted && be_index<=B2_SCRIPT_ROWS,1803,0);
    if(be_index<B2_SCRIPT_ROWS && pc!=b2_script[be_index].pc)return;
    be_signal=sig;be_si=si;be_context=uc;
    if(be_index==B2_SCRIPT_ROWS) {
        checked(pc==b2_script[be_index-1].next && !selected_oneshot_active &&
            !li2_lifecycle_fetch_interlock() && !selected_step_pending,1803,1);
        be_snapshot(&be_record.final,uc);be_final_pending=1;return;
    }
    struct be_row *r=&be_record.rows[be_index];r->h[0]=1;r->h[1]=be_index;
    r->h[2]=b2_script[be_index].kind;
    be_snapshot(&r->entry,uc);be_pending=1;
}
static void be_prepared(int sig,const siginfo_t *si,ucontext_t *uc) {
    if(selected_selftesting || !be_final_pending)return;
    checked(be_index==B2_SCRIPT_ROWS && sig==be_signal && si==be_si && uc==be_context &&
        selected_decoded.pc==b2_script[be_index-1].next && selected_decoded.kind==LI2_NONE &&
        !selected_step_pending && li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY &&
        equal(uc,be_record.final.uc,sizeof *uc),1804,0);
    selected_release();li2_lifecycle_native_close();
    checked(!li2_lifecycle_fetch_interlock() && !selected_oneshot_active && !selected_step_pending,1804,1);
    be_final_pending=0;b2_format_sample(1);be_emit(0,0,0);
    (void)raw(SYS_exit_group,0,0,0,0,0,0);__builtin_trap();
}
static void be_landed(int sig,const siginfo_t *si,ucontext_t *uc) {
    checked(be_pending && be_index<B2_SCRIPT_ROWS && !be_record.rows[be_index].h[4] &&
        selected_oneshot_active && selected_oneshot_active->state.phase==LI2_ONESHOT_RESTORED,
        1805,0);
    be_signal=sig;be_si=si;be_context=uc;be_record.rows[be_index].h[3]=1;
}
static void be_begin(void) {
    __typeof__(selected_effect_runtime) *p=&selected_effect_runtime;
    checked(be_pending && be_index<B2_SCRIPT_ROWS && p->frame==be_context && p->stage==2 &&
        p->input.decoded.pc==b2_script[be_index].pc && !be_record.rows[be_index].h[4],1806,0);
    struct be_row *r=&be_record.rows[be_index];be_held_snapshot(&r->before,p->frame);
    checked(equal(r->before.uc,&p->before,sizeof p->before) && r->before.h[1]==p->fp_bytes &&
        p->before_initialized==p->fp_bytes && equal(r->before.fp,p->before_fp,p->fp_bytes),1806,1);
    r->h[4]=1;r->h[13]=li2_lifecycle_fetch_interlock();
}
static void be_returned(void) {
    struct be_row *r=&be_record.rows[be_index];
    checked(be_pending && r->h[4]==1 && r->h[5]==1 && !selected_oneshot_active &&
        !li2_lifecycle_fetch_interlock() && !selected_step_pending,1807,0);
    be_snapshot(&r->after,be_context);
    checked(equal(r->after.uc,&selected_effect_runtime.after,sizeof(ucontext_t)) &&
        r->after.h[1]==selected_effect_runtime.fp_bytes &&
        equal(r->after.fp,selected_effect_runtime.after_fp,r->after.h[1]),1807,1);
    r->h[0]=2;++be_index;be_pending=0;be_context=0;be_si=0;be_signal=0;
}
static void be_finished(void) {
    __typeof__(selected_effect_runtime) *p=&selected_effect_runtime;
    checked(be_pending && be_index<B2_SCRIPT_ROWS && p->frame==be_context && p->stage==8 &&
        !p->busy && p->finished && !be_record.rows[be_index].h[5],1808,0);
    struct be_row *r=&be_record.rows[be_index];copy(&r->owner,&p->owner,sizeof r->owner);
    copy(&r->applied,&p->applied,sizeof r->applied);
    r->h[5]=1;r->h[8]=p->attempts;r->h[9]=p->commits;r->h[10]=p->completed;
    r->h[11]=p->native_completed;r->h[12]=p->scripted_completed;
    r->h[14]=li2_lifecycle_fetch_interlock();r->h[15]=p->busy;r->h[16]=p->finished;
    r->h[17]=p->stage;r->h[18]=p->first_error;r->h[19]=p->owner.native_returned;
    unsigned kind=p->input.decoded.kind;
    if(kind>=LI2_RDRAND && kind<=LI2_RDPID) {
        copy(&r->random,&selected_completion,sizeof r->random);
        r->h[20]=p->random_backend_returned;r->h[21]=(uint64_t)p->random_backend_status;
    } else if(kind!=LI2_SYSCALL)copy(&r->builtin,&selected_builtin_prefix,sizeof r->builtin);
    if(kind==LI2_CPUID) {
        const __typeof__(selected_cpuid_nx) *c=&selected_cpuid_nx;uint64_t *b=r->backend;
        b[0]=c->phase;b[1]=c->hardware_entered;b[2]=c->hardware_returned;
        b[3]=c->attempts;b[4]=c->samples;b[5]=c->commits;b[6]=c->pc;b[7]=c->next_pc;
        b[8]=c->leaf;b[9]=c->subleaf;
        for(unsigned j=0;j<4;j++){b[10+j]=c->raw[j];b[14+j]=c->result[j];}
    } else if(kind==LI2_SYSCALL) {
        r->backend[0]=selected_effect_raw.entered;r->backend[1]=selected_effect_raw.returned;
        r->backend[2]=(uint64_t)selected_effect_raw.number;r->backend[3]=(uint64_t)selected_effect_raw.result;
    }
    if(!selected_oneshot_active)be_returned();
}
static void be_retired(const struct li2_oneshot_owner *o) {
    checked(be_pending && be_index<B2_SCRIPT_ROWS && be_record.rows[be_index].h[3]==1 &&
        be_record.rows[be_index].h[5]==1 && o==selected_oneshot_active &&
        o->state.phase==LI2_ONESHOT_COMPLETED && !li2_lifecycle_oneshot_interlock(),1809,0);
    struct be_row *r=&be_record.rows[be_index];copy(&r->plan,&o->plan,sizeof r->plan);
    uint64_t *p=r->publication;
    p[0]=o->state.phase;p[1]=o->state.mutation_started;p[2]=o->state.published;p[3]=o->state.restored;
    p[4]=o->source_copied;p[5]=o->landing_observed;p[6]=o->source_write_started;
    p[7]=o->write_attempted_mask;p[8]=o->write_completed_mask;p[9]=o->restore_started;
    p[10]=o->restore_attempted_mask;p[11]=o->restore_completed_mask;
    p[12]=o->release.call.started;p[13]=o->release.call.returned;p[14]=o->release.call.verified;
    p[15]=(uint64_t)o->release.call.result;p[16]=o->release.transaction_live;p[17]=o->state.sequence;
    p[18]=o->current_generation[0];p[19]=o->current_generation[1];
    p[20]=selected_oneshot_counts.published;p[21]=selected_oneshot_counts.restored;
    p[22]=selected_oneshot_counts.completed;p[23]=selected_oneshot_counts.retired;
    p[24]=o->state.first_error;p[25]=(uint64_t)o->state.first_detail;
    r->h[6]=1;
}
