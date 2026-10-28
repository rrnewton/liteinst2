/* Observation-only real-frame copies. NX and restored UD2 remain distinct.
   All fixed storage is prefaulted before first application entry. */
#define PB_MAIN UINT64_C(0x200401000)
#define PB_DATA UINT64_C(0x200403000)
#define PB_UC 2048
#define PB_FP 65536
#define PB_ROWS 16
struct pb_state {
    uint64_t h[8];
    unsigned char uc[PB_UC],fp[PB_FP];
    unsigned char source[2][8192],data[2][16384],startup_stack[256];
};
struct pb_sample {
    uint64_t h[64],landing[16],policy[96];
    struct pb_state nx,effect,after;
};
struct pb_record {
    uint64_t h[64];
    struct li2_selected_hardware hardware;
    uint64_t xstate[4][4];
    struct pb_sample samples[PB_ROWS];
    uint64_t owners[8][32],nested[16];
    unsigned char nested_uc[PB_UC],nested_fp[PB_FP];
    unsigned char terminal_source[2][8192],terminal_data[2][16384];
};
_Static_assert(sizeof(ucontext_t)<=PB_UC && sizeof(struct pb_record)<(16U<<20),"bounded complete builtin record");
extern unsigned char pb_clock_fault[],pb_syscall_fault[];
static struct pb_record pb_record;
static unsigned pb_pending,pb_effect_seen,pb_finished;
static uintptr_t pb_startup_stack;
static const ucontext_t *pb_frame;
static void pb_copy(void *dst,const void *src,size_t n) {
    unsigned char *d=dst;const volatile unsigned char *s=src;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static uint32_t pb_u32(const unsigned char *s) {
    return (uint32_t)s[0]|(uint32_t)s[1]<<8|(uint32_t)s[2]<<16|(uint32_t)s[3]<<24;
}
static size_t pb_fp(const ucontext_t *u,unsigned char *out) {
    uintptr_t p=(uintptr_t)u->uc_mcontext.fpregs,lo=(uintptr_t)fork_gate_stack.ss_sp;
    size_t bytes=fork_gate_stack.ss_size;
    checked(p>=lo && bytes>=512 && p-lo<=bytes-512 && !(p&15),1690,0);
    const unsigned char *b=(const void *)p;size_t n=512;
    if(pb_u32(b+464)==UINT32_C(0x46505853)) {
        n=pb_u32(b+468);size_t x=pb_u32(b+480);
        checked(n>=580 && n<=PB_FP && n<=bytes-(p-lo) && x>=576 && x<=n-4 &&
            pb_u32(b+n-4)==UINT32_C(0x46505845),1690,1);
    }
    pb_copy(out,b,n);return n;
}
static void pb_memory(unsigned char source[2][8192],unsigned char data[2][16384]) {
    pb_copy(source[0],(const void *)(uintptr_t)PB_MAIN,8192);
    pb_copy(source[1],(const void *)(uintptr_t)original_interpreter.entry,8192);
    pb_copy(data[0],(const void *)(uintptr_t)PB_DATA,16384);
    pb_copy(data[1],(const void *)(uintptr_t)(original_interpreter.bias+12288),16384);
}
static void pb_capture(struct pb_state *s,const ucontext_t *uc) {
    s->h[0]=(uintptr_t)uc;s->h[1]=sizeof *uc;
    pb_copy(s->uc,uc,sizeof *uc);s->h[2]=pb_fp(uc,s->fp);
    pb_memory(s->source,s->data);
    s->h[3]=pb_startup_stack;pb_copy(s->startup_stack,(const void *)pb_startup_stack,256);
    s->h[4]=1;
}
static void pb_initialize(void) {
    volatile unsigned char *p=(void *)&pb_record;
    for(size_t i=0;i<sizeof pb_record;i++)p[i]=0;
    pb_record.h[0]=UINT64_C(0x314e49544c554250);pb_record.h[1]=1;pb_record.h[2]=sizeof pb_record;
    pb_record.h[3]=sizeof(ucontext_t);pb_record.h[4]=sizeof(struct pb_sample);
    pb_record.h[21]=original_interpreter.entry;pb_record.h[22]=original_interpreter.bias;
    checked(original_interpreter.entry==original_interpreter.bias+4096 &&
        !(original_interpreter.entry&4095) && original_main.entry==PB_MAIN,1693,2);
    pb_copy(&pb_record.hardware,&selected_hardware,sizeof selected_hardware);
    checked(selected_hardware.leaf0[0]>=13 &&
        (selected_hardware.leaf1[2]&UINT32_C(0x18000000))==UINT32_C(0x18000000) &&
        (selected_hardware.leaf7[1]&UINT32_C(0x40010000))==UINT32_C(0x40010000),1693,0);
    uint32_t low,high;
    __asm__ volatile("xgetbv":"=a"(low),"=d"(high):"c"(0):"memory");
    pb_record.h[20]=(uint64_t)low|((uint64_t)high<<32);
    checked((pb_record.h[20]&UINT64_C(0xe7))==UINT64_C(0xe7),1693,1);
    const unsigned bits[4]={2,5,6,7};
    for(unsigned i=0;i<4;i++) {
        uint32_t a=13,b,c=bits[i],d;
        __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d)::"memory");
        pb_record.xstate[i][0]=bits[i];pb_record.xstate[i][1]=b;
        pb_record.xstate[i][2]=a;pb_record.xstate[i][3]=c;
    }
    uint64_t mode=*(const volatile uint64_t *)(uintptr_t)(PB_DATA+104);
    checked(mode<=12,1693,3);pb_negative=(unsigned)mode;pb_record.h[23]=mode;
    pb_record.h[24]=selected_provider_builtins_enabled;
    pb_record.h[26]=(uintptr_t)pb_clock_fault;pb_record.h[27]=(uintptr_t)pb_syscall_fault;
    pb_record.h[28]=bridge_runtime_image()->bias;
    pb_record.h[29]=(uintptr_t)fork_gate_stack.ss_sp;pb_record.h[30]=fork_gate_stack.ss_size;
    pb_record.h[5]=1;
}
static void pb_before(int sig,const siginfo_t *si,const ucontext_t *uc) {
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    if(selected_decoded.kind<LI2_RDTSC || selected_decoded.kind>LI2_SYSCALL)return;
    if(!((pc>=PB_MAIN && pc<PB_MAIN+4096) ||
         (pc>=original_interpreter.entry && pc<original_interpreter.entry+4096)))return;
    checked(!pb_pending && pb_used<PB_ROWS && pb_record.h[5] &&
        (pb_used!=0 || pc==original_interpreter.entry),1691,0);
    if(!pb_used) {
        uintptr_t sp=(uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
        checked(sp>=128 && sp<=UINTPTR_MAX-128,1691,1);pb_startup_stack=sp-128;
        pb_record.h[25]=pb_startup_stack;
    }
    struct pb_sample *s=&pb_record.samples[pb_used];pb_pending=1;pb_frame=uc;
    s->h[0]=1;s->h[1]=pb_used;s->h[2]=pc;s->h[3]=selected_decoded.next_pc;
    s->h[4]=selected_decoded.kind;s->h[5]=selected_decoded.length;s->h[6]=selected_decoded.code;
    s->h[7]=selected_logical_flags;s->h[8]=(unsigned)sig;s->h[9]=(unsigned)si->si_signo;
    s->h[10]=(unsigned)si->si_code;s->h[11]=(unsigned)si->si_errno;s->h[12]=(uintptr_t)si->si_addr;
    s->h[13]=selected_builtin_policy.attempts;s->h[14]=selected_oneshot_used;
    pb_capture(&s->nx,uc);
}
static void pb_landed(int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(!pb_pending)return;
    checked(pb_used<PB_ROWS && !pb_effect_seen && selected_oneshot_active,1692,0);
    struct pb_sample *s=&pb_record.samples[pb_used];const struct li2_oneshot_owner *o=selected_oneshot_active;
    uint64_t *r=s->landing;
    r[0]=(unsigned)sig;r[1]=(unsigned)si->si_signo;r[2]=(unsigned)si->si_code;
    r[3]=(unsigned)si->si_errno;r[4]=(uintptr_t)si->si_addr;r[5]=o->plan.landing;
    r[6]=o->state.phase;r[7]=o->state.restored;r[8]=o->plan.pc;r[9]=o->plan.next_pc;
    r[10]=o->plan.sequence;r[11]=selected_oneshot_handoff.logical_flags;
    r[12]=o->restore_attempted_mask;r[13]=o->restore_completed_mask;
    r[14]=(uintptr_t)uc;r[15]=selected_oneshot_handoff.actual_landing_frame==uc;
}
static void pb_effect(const ucontext_t *uc) {
    if(!pb_pending)return;
    checked(!pb_effect_seen && pb_used<PB_ROWS && selected_decoded.pc==pb_record.samples[pb_used].h[2],1692,1);
    struct pb_sample *s=&pb_record.samples[pb_used];pb_frame=uc;
    pb_capture(&s->effect,uc);pb_effect_seen=1;s->h[15]=1;
}
static void pb_policy(struct pb_sample *s) {
    uint64_t *r=s->policy;
    r[0]=selected_builtin_policy.busy;r[1]=selected_builtin_policy.first_error;
    r[2]=(uint64_t)selected_builtin_policy.first_detail;r[3]=selected_builtin_policy.attempts;
    r[4]=selected_builtin_policy.clock_completed[0];r[5]=selected_builtin_policy.clock_completed[1];
    r[6]=selected_builtin_policy.syscall_replaced;r[7]=selected_builtin_policy.syscall_forwarded;
    r[8]=pb_callback_hits;r[9]=selected_provider_builtins_enabled;
    if(s->h[4]!=LI2_SYSCALL) {
        const __typeof__(selected_builtin_policy.clock) *p=&selected_builtin_policy.clock;
        r[10]=p->entered;r[11]=p->returned;r[12]=p->committed;r[13]=(uint64_t)p->status;
        r[16]=p->input.abi_version;r[17]=p->input.kind;r[18]=p->input.pc;r[19]=p->input.next_pc;
        r[20]=p->input.logical_flags;r[21]=p->input.ordinal;
        r[24]=p->result.value;r[25]=p->result.aux;r[26]=p->result.reserved;
        const struct selected_builtin_prefix *q=&selected_builtin_prefix;
        r[32]=q->kind;r[33]=q->phase;r[34]=(uint64_t)q->enable_result;r[35]=(uint64_t)q->restore_result;
        r[36]=q->a;r[37]=q->b;r[38]=q->c;r[39]=q->d;
    } else {
        const __typeof__(selected_builtin_policy.syscall) *p=&selected_builtin_policy.syscall;
        r[10]=p->prepared;r[11]=p->entered;r[12]=p->returned;r[13]=p->pre_dispatch_guards_complete;
        r[14]=p->native_dispatch_entered;r[15]=p->raw_entered;r[16]=p->raw_returned;
        r[17]=p->replacement_selected;r[18]=p->dispatch_returned;r[19]=p->committed;r[20]=p->exit_selected;
        r[21]=(uint64_t)p->status;r[22]=p->actual_result;
        r[24]=p->input.abi_version;r[25]=p->input.reserved;r[26]=p->input.pc;r[27]=p->input.next_pc;
        r[28]=p->input.logical_flags;r[29]=p->input.number;
        for(unsigned i=0;i<6;i++)r[30+i]=p->input.args[i];
        r[36]=p->input.input_rcx;r[37]=p->input.input_r11;
        r[40]=p->result.action;r[41]=p->result.reserved;r[42]=p->result.value;
    }
    s->h[16]=selected_oneshot_active?selected_oneshot_active->state.phase:0;
    s->h[17]=li2_lifecycle_fetch_interlock();s->h[18]=selected_step_pending;
}
static void pb_after(const ucontext_t *uc) {
    if(!pb_pending)return;
    checked(pb_effect_seen && pb_frame==uc && pb_used<PB_ROWS,1692,2);
    struct pb_sample *s=&pb_record.samples[pb_used];pb_capture(&s->after,uc);pb_policy(s);
    s->h[0]=2;++pb_used;pb_pending=0;pb_effect_seen=0;pb_frame=0;
}
static void pb_event(int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(!pb_pending || !handling || !pb_record.h[5] || pb_finished)return;
    checked(si && uc && !pb_record.nested[0],1692,3);
    uint64_t *r=pb_record.nested;
    r[0]=1;r[1]=(unsigned)sig;r[2]=(unsigned)si->si_signo;r[3]=(unsigned)si->si_code;
    r[4]=(unsigned)si->si_errno;r[5]=(uintptr_t)si->si_addr;r[6]=(uintptr_t)uc;
    pb_copy(pb_record.nested_uc,uc,sizeof *uc);r[7]=pb_fp(uc,pb_record.nested_fp);
}
static void pb_terminal(unsigned status,unsigned code,long detail) {
    if(pb_finished || !pb_record.h[5])return;
    pb_finished=1;pb_record.h[6]=status;pb_record.h[7]=code;pb_record.h[8]=(uint64_t)detail;
    pb_record.h[9]=pb_used;pb_record.h[10]=pb_pending;pb_record.h[11]=selected_oneshot_used;
    pb_record.h[12]=selected_builtin_policy.attempts;pb_record.h[13]=selected_builtin_policy.busy;
    pb_record.h[14]=selected_builtin_policy.clock_completed[0];pb_record.h[15]=selected_builtin_policy.clock_completed[1];
    pb_record.h[16]=selected_builtin_policy.syscall_replaced;pb_record.h[17]=selected_builtin_policy.syscall_forwarded;
    pb_record.h[18]=pb_callback_hits;pb_record.h[19]=pb_effect_seen;
    if(pb_pending && pb_effect_seen) {
        struct pb_sample *s=&pb_record.samples[pb_used];pb_capture(&s->after,pb_frame);pb_policy(s);s->h[0]=3;
    }
    if(pb_used || pb_pending)pb_memory(pb_record.terminal_source,pb_record.terminal_data);
    for(unsigned i=0;i<selected_oneshot_used && i<8;i++) {
        const struct li2_oneshot_owner *o=&selected_oneshot_owners[i];uint64_t *r=pb_record.owners[i];
        r[0]=o->state.phase;r[1]=o->state.published;r[2]=o->state.restored;r[3]=o->state.first_error;
        r[4]=o->plan.pc;r[5]=o->plan.next_pc;r[6]=o->plan.kind;r[7]=o->plan.sequence;
        r[8]=o->write_attempted_mask;r[9]=o->write_completed_mask;
        r[10]=o->restore_attempted_mask;r[11]=o->restore_completed_mask;
        r[12]=selected_oneshot_effect_started[i];r[13]=selected_oneshot_effect_returned[i];
        if(o->state.restored) {pb_copy(&r[14],o->plan.original,5);pb_copy(&r[15],(const void *)(uintptr_t)o->plan.pc,5);}
    }
    size_t at=0;
    while(at<sizeof pb_record) {
        long n=raw(SYS_write,3,(long)((const unsigned char *)&pb_record+at),sizeof pb_record-at,0,0,0);
        if(n<=0 || (size_t)n>sizeof pb_record-at)return;
        at+=(size_t)n;
    }
}
