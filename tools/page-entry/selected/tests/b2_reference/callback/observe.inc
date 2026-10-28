/* Fixture-only NX reference observation. Real provider code performs every
   effect; the immutable script supplies scalar results and never a frame. */
#include "b2_capture.h"
#include "b2_format.inc"
#if !defined(LI2_CPUID_NX_ONLY) || defined(LI2_ONESHOT_PUBLICATION)
#error "Finite reference requires actual native-page CPUID-NX and no one-shot profile"
#endif
_Static_assert(SELECTED_MASK==UINT64_C(0xffffffffbffbfaef),"exact reference application mask");
#define B2_ROWS 4
#define B2_BASES 32
struct b2_row {
    uint64_t h[16],progress[64];
    struct b2_snapshot entry,before,after;
};
struct b2_record {
    uint64_t h[32];
    uint64_t bases[B2_BASES][5];
    struct b2_row rows[B2_ROWS];
    struct b2_snapshot final;
};
_Static_assert(sizeof(struct b2_record)<(2U<<20),"bounded complete four-row record");
static struct b2_record b2_record;
static unsigned b2_initialized,b2_observation_pending,b2_before_seen,b2_finished,b2_bases,b2_final_pending;
static const siginfo_t *b2_si;
static const ucontext_t *b2_context;
static int b2_signal;
static void b2_progress(struct b2_row *row) {
    uint64_t *p=row->progress;unsigned kind=(unsigned)row->h[2];
    /* Progress comes from production, independently of script counters. */
    if(kind==LI2_CPUID) {
        const __typeof__(selected_provider_state.cpuid) *s=&selected_provider_state.cpuid;
        row->h[4]=s->entered;row->h[5]=s->returned;row->h[6]=s->committed;
        p[0]=(uint64_t)s->callback_status;p[1]=s->input.leaf;p[2]=s->input.subleaf;
        for(unsigned j=0;j<4;j++)p[3+j]=s->input.native[j];
        p[7]=s->result.eax;p[8]=s->result.ebx;p[9]=s->result.ecx;p[10]=s->result.edx;
        p[11]=selected_builtin_prefix.phase;p[12]=(uint64_t)selected_builtin_prefix.enable_result;
        p[13]=(uint64_t)selected_builtin_prefix.restore_result;
        p[14]=selected_cpuid_nx.hardware_entered;p[15]=selected_cpuid_nx.hardware_returned;
        p[16]=selected_cpuid_nx.phase;p[17]=selected_cpuid_nx.attempts;
        p[18]=selected_cpuid_nx.samples;p[19]=selected_cpuid_nx.commits;
        p[20]=selected_cpuid_nx.pc;p[21]=selected_cpuid_nx.next_pc;
        p[22]=selected_cpuid_nx.leaf;p[23]=selected_cpuid_nx.subleaf;
        for(unsigned j=0;j<4;j++){p[24+j]=selected_cpuid_nx.raw[j];p[28+j]=selected_cpuid_nx.result[j];}
        p[32]=selected_builtin_prefix.a;p[33]=selected_builtin_prefix.b;
        p[34]=selected_builtin_prefix.c;p[35]=selected_builtin_prefix.d;
    } else if(kind>=LI2_RDRAND && kind<=LI2_RDPID) {
        const struct li2_selected_callback_progress *s=&selected_provider_state.random;
        row->h[4]=s->entered;row->h[5]=s->returned;row->h[6]=s->committed;
        p[0]=s->first_error;p[1]=(uint64_t)s->callback_status;
        p[2]=s->input.abi_version;p[3]=s->input.kind;p[4]=s->input.width_bits;
        p[5]=s->input.destination;p[6]=s->input.pc;p[7]=s->input.next_pc;
        p[8]=s->input.logical_flags;p[9]=s->input.input_destination;
        p[10]=s->script.kind;p[11]=s->script.width_bits;p[12]=s->script.carry;
        p[13]=s->script.reserved;p[14]=s->script.value;p[15]=selected_completion.native_attempts;
    } else if(kind==LI2_RDTSC || kind==LI2_RDTSCP) {
        const __typeof__(selected_builtin_policy.clock) *s=&selected_builtin_policy.clock;
        row->h[4]=s->entered;row->h[5]=s->returned;row->h[6]=s->committed;
        p[0]=(uint64_t)s->status;p[1]=s->input.abi_version;p[2]=s->input.kind;
        p[3]=s->input.pc;p[4]=s->input.next_pc;p[5]=s->input.logical_flags;p[6]=s->input.ordinal;
        p[7]=s->result.value;p[8]=s->result.aux;p[9]=s->result.reserved;
    } else if(kind==LI2_SYSCALL) {
        const __typeof__(selected_builtin_policy.syscall) *s=&selected_builtin_policy.syscall;
        row->h[4]=s->entered;row->h[5]=s->returned;row->h[6]=s->committed;
        p[0]=(uint64_t)s->status;p[1]=s->prepared;p[2]=s->pre_dispatch_guards_complete;
        p[3]=s->native_dispatch_entered;p[4]=s->raw_entered;p[5]=s->raw_returned;
        p[6]=s->replacement_selected;p[7]=s->dispatch_returned;p[8]=s->exit_selected;
        p[9]=s->actual_result;p[10]=s->input.abi_version;p[11]=s->input.reserved;
        p[12]=s->input.pc;p[13]=s->input.next_pc;p[14]=s->input.logical_flags;p[15]=s->input.number;
        for(unsigned j=0;j<6;j++)p[16+j]=s->input.args[j];
        p[22]=s->input.input_rcx;p[23]=s->input.input_r11;
        p[24]=s->result.action;p[25]=s->result.reserved;p[26]=s->result.value;
    }
    row->h[7]=(uint64_t)b2_script_prepared;row->h[8]=(uint64_t)b2_script_accepted;
    row->h[9]=(uint64_t)b2_script_committed;row->h[10]=li2_lifecycle_fetch_interlock();
    row->h[11]=selected_step_pending;
}
static long b2_actual_base(unsigned which,uintptr_t *value) {
    if(b2_bases>=B2_BASES)return -1;
    uint64_t *p=b2_record.bases[b2_bases++];p[0]=which;p[1]=1;
    __asm__ volatile("":::"memory");
    long result=raw(SYS_arch_prctl,which,(long)value,0,0,0,0);
    p[3]=(uint64_t)result;if(!result)p[4]=*value;
    __asm__ volatile("":::"memory");p[2]=1;
    return result;
}
static void b2_snapshot(struct b2_snapshot *out,const ucontext_t *uc) {
    checked(!b2_capture(out,b2_signal,b2_si,uc,(uintptr_t)fork_gate_stack.ss_sp,
                       fork_gate_stack.ss_size,b2_actual_base),1700,0);
}
static void b2_emit(unsigned status,unsigned code,long detail) {
    if(!b2_initialized || b2_finished)return;
    b2_finished=1;
    b2_record.h[4]=status;b2_record.h[5]=code;b2_record.h[6]=(uint64_t)detail;
    b2_record.h[7]=(uint64_t)b2_script_prepared;b2_record.h[8]=(uint64_t)b2_script_accepted;
    b2_record.h[9]=(uint64_t)b2_script_committed;b2_record.h[10]=b2_observation_pending;
    b2_record.h[11]=b2_bases;b2_record.h[12]=li2_lifecycle_fetch_interlock();
    b2_record.h[13]=selected_step_pending;b2_record.h[14]=selected_pending_route;
    b2_record.h[17]=selected_provider_state.attempts;b2_record.h[18]=selected_builtin_policy.attempts;
    b2_record.h[19]=selected_builtin_policy.syscall_replaced;b2_record.h[20]=selected_builtin_policy.syscall_forwarded;
    if(b2_observation_pending && b2_script_committed<B2_SCRIPT_ROWS)b2_progress(&b2_record.rows[b2_script_committed]);
    size_t at=0;
    while(at<sizeof b2_record) {
        long n=raw(SYS_write,3,(long)((const unsigned char *)&b2_record+at),sizeof b2_record-at,0,0,0);
        if(n<=0 || (size_t)n>sizeof b2_record-at)return;
        at+=(size_t)n;
    }
    b2_format_emit();
}
static void b2_initialize(void) {
    volatile unsigned char *p=(void *)&b2_record;
    for(size_t i=0;i<sizeof b2_record;i++)p[i]=0;
    checked(!b2_initialized && B2_SCRIPT_ROWS>=2 && B2_SCRIPT_ROWS<=B2_ROWS &&
            selected_provider_state.mode==1 && selected_provider_builtins_enabled &&
            original_main.entry==UINT64_C(0x200404000),1701,0);
    b2_record.h[0]=UINT64_C(0x314652434232494c);b2_record.h[1]=1;
    b2_record.h[2]=sizeof b2_record;b2_record.h[3]=B2_SCRIPT_ROWS;
    b2_record.h[21]=(uintptr_t)fork_gate_stack.ss_sp;b2_record.h[22]=fork_gate_stack.ss_size;
    b2_initialized=1;
    b2_format_initialize();
}
static void b2_entry(int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(selected_selftesting)return;
    checked(b2_initialized && !b2_observation_pending && !b2_before_seen && !b2_finished,1702,0);
    unsigned i=(unsigned)b2_script_committed;uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    b2_signal=sig;b2_si=si;b2_context=uc;
    if(i==B2_SCRIPT_ROWS) {
        /* All selected effects actually returned through sigreturn. Observe
           the next genuine NX entry without executing its ordinary opcode. */
        checked(pc==b2_script[i-1].next && b2_script_prepared==(sig_atomic_t)i &&
                b2_script_accepted==(sig_atomic_t)i && !li2_lifecycle_fetch_interlock() &&
                !selected_step_pending && selected_pending_route==SELECTED_NO_STEP,1702,1);
        b2_snapshot(&b2_record.final,uc);b2_final_pending=1;
        return; /* original source prepare/decode/generation/range guards follow */
    }
    checked(i<B2_SCRIPT_ROWS,1702,3);
    if(pc!=b2_script[i].pc)return; /* ordinary bytes remain owned by the old routes */
    struct b2_row *row=&b2_record.rows[i];row->h[0]=1;row->h[1]=i;
    row->h[2]=b2_script[i].kind;row->h[3]=pc;
    b2_snapshot(&row->entry,uc);b2_observation_pending=1;
}
static void b2_before(int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(selected_selftesting)return;
    unsigned i=(unsigned)b2_script_committed;
    if(b2_final_pending) {
        checked(i==B2_SCRIPT_ROWS && sig==b2_signal && si==b2_si && uc==b2_context &&
                selected_decoded.pc==b2_script[i-1].next && !selected_step_pending &&
                li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY &&
                equal(b2_record.final.uc,uc,sizeof *uc),1702,4);
        selected_release(); /* exact original validated borrow release */
        li2_lifecycle_native_close();
        checked(!li2_lifecycle_fetch_interlock() && !selected_step_pending,1702,2);
        b2_final_pending=0;b2_record.h[15]=1;b2_record.h[16]=1;
        b2_format_sample(1);
        b2_emit(0,0,0);
        (void)raw(SYS_exit_group,0,0,0,0,0,0);__builtin_trap();
    }
    if(selected_decoded.kind<LI2_CPUID || selected_decoded.kind>LI2_SYSCALL)return;
    checked(b2_observation_pending && !b2_before_seen && i<B2_SCRIPT_ROWS && sig==b2_signal && si==b2_si && uc==b2_context &&
            selected_decoded.kind==b2_script[i].kind && selected_decoded.length==b2_script[i].length &&
            selected_view.length>=selected_decoded.length && !selected_step_pending &&
            li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,1703,0);
    checked(!b2_script_before(uc,selected_view.bytes,selected_decoded.length,selected_decoded.pc,selected_logical_flags),1703,1);
    b2_snapshot(&b2_record.rows[i].before,uc);b2_before_seen=1;
}
static void b2_after(const ucontext_t *uc) {
    unsigned i=(unsigned)b2_script_committed;
    checked(b2_observation_pending && b2_before_seen && i<B2_SCRIPT_ROWS && uc==b2_context,1704,0);
    struct b2_row *row=&b2_record.rows[i];b2_progress(row);
    checked(row->h[4]==1 && row->h[5]==1 && row->h[6]==1 && !selected_step_pending &&
            row->h[10]==(row->h[2]==LI2_SYSCALL?0:LI2_FETCH_BUSY),1704,1);
    b2_snapshot(&row->after,uc);
    checked(!b2_script_after(uc),1704,2);row->h[9]=(uint64_t)b2_script_committed;row->h[0]=2;
    b2_observation_pending=0;b2_before_seen=0;b2_context=0;b2_si=0;b2_signal=0;
}
