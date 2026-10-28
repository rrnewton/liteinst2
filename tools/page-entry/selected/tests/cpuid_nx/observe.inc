/* Observation only, included after the actual controller definitions. */
#define NX_MAIN UINT64_C(0x200401000)
#define NX_DATA UINT64_C(0x200420000)
#define PL_FP 65536
#define PL_UC 2048
#define NX_ROWS 6
struct nx_sample {
    uint64_t h[80];
    unsigned char before_uc[PL_UC],after_uc[PL_UC];
    unsigned char before_fp[PL_FP],after_fp[PL_FP];
    unsigned char before_source[65536],after_source[65536];
    unsigned char before_interpreter[4096],after_interpreter[4096];
    unsigned char before_data[32768],after_data[32768];
};
struct nx_record {
    uint64_t h[64];
    struct li2_selected_hardware hardware;
    uint64_t xstate[4][4];
    struct nx_sample samples[NX_ROWS];
    unsigned char terminal_data[32768],terminal_source[65536];
};
_Static_assert(sizeof(ucontext_t)<=PL_UC && sizeof(struct nx_record)<(16U<<20),"whole bounded observation");
static struct nx_record nx_record;
static unsigned nx_used,nx_pending,nx_finished;
static const ucontext_t *nx_frame;
static void pl_copy(void *dst,const void *src,size_t n) {
    unsigned char *d=dst;const volatile unsigned char *s=src;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static uint32_t pl_u32(const unsigned char *s) {
    return (uint32_t)s[0]|(uint32_t)s[1]<<8|(uint32_t)s[2]<<16|(uint32_t)s[3]<<24;
}
static size_t pl_fp(const ucontext_t *u,unsigned char *out) {
    uintptr_t p=(uintptr_t)u->uc_mcontext.fpregs,lo=(uintptr_t)fork_gate_stack.ss_sp;
    size_t bytes=fork_gate_stack.ss_size;
    checked(p>=lo && bytes>=512 && p-lo<=bytes-512 && !(p&15),1690,0);
    const unsigned char *b=(const void *)p;size_t n=512;
    if(pl_u32(b+464)==UINT32_C(0x46505853)) {
        n=pl_u32(b+468);size_t x=pl_u32(b+480);
        checked(n>=580 && n<=PL_FP && n<=bytes-(p-lo) && x>=576 && x<=n-4 &&
            pl_u32(b+n-4)==UINT32_C(0x46505845),1690,1);
    }
    pl_copy(out,b,n);return n;
}

static void nx_initialize(void) {
    volatile unsigned char *p=(void *)&nx_record;
    for(size_t i=0;i<sizeof nx_record;i++)p[i]=0;
    nx_record.h[0]=UINT64_C(0x3151454449555043);nx_record.h[1]=1;
    nx_record.h[2]=sizeof nx_record;nx_record.h[3]=sizeof(ucontext_t);
    nx_record.h[4]=sizeof(struct nx_sample);
    nx_record.h[21]=original_interpreter.entry;nx_record.h[22]=original_interpreter.bias;
    checked(original_interpreter.entry==original_interpreter.bias+4096 && !(original_interpreter.entry&4095),1693,2);
    pl_copy(&nx_record.hardware,&selected_hardware,sizeof selected_hardware);
    checked(selected_hardware.leaf0[0]>=13 &&
        (selected_hardware.leaf1[2]&UINT32_C(0x18000000))==UINT32_C(0x18000000) &&
        (selected_hardware.leaf7[1]&UINT32_C(0x40010000))==UINT32_C(0x40010000),1693,0);
    uint32_t low,high;
    __asm__ volatile("xgetbv":"=a"(low),"=d"(high):"c"(0):"memory");
    nx_record.h[20]=(uint64_t)low|((uint64_t)high<<32);
    checked((nx_record.h[20]&UINT64_C(0xe7))==UINT64_C(0xe7),1693,1);
    const unsigned bits[4]={2,5,6,7};
    for(unsigned i=0;i<4;i++) {
        uint32_t a=13,b,c=bits[i],d;
        __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d)::"memory");
        nx_record.xstate[i][0]=bits[i];nx_record.xstate[i][1]=b;
        nx_record.xstate[i][2]=a;nx_record.xstate[i][3]=c;
    }

#ifdef LI2_CPUID_NX_ONLY
    nx_record.h[23]=1;
#endif
#ifdef LI2_SELECTED_PROVIDER
    nx_record.h[24]=selected_provider_state.mode;
#endif
    nx_record.h[5]=1;
}
static void nx_before(int sig,const siginfo_t *si,const ucontext_t *uc) {
    uint64_t pc=(uint64_t)uc->uc_mcontext.gregs[REG_RIP];
    if(selected_decoded.kind!=LI2_CPUID ||
       (pc!=original_interpreter.entry && (pc<NX_MAIN || pc>=NX_MAIN+65536)))return;
    checked((nx_used==0)==(pc==original_interpreter.entry) && !nx_pending && nx_used<NX_ROWS && nx_record.h[5],1691,0);
    checked(original_main.entry==NX_MAIN && image_code(&original_main,NX_MAIN) &&
        *(const volatile uint64_t *)(uintptr_t)NX_DATA==UINT64_C(0x31584e4449555043),1691,1);
    struct nx_sample *s=&nx_record.samples[nx_used];nx_frame=uc;nx_pending=1;
    s->h[0]=1;s->h[1]=nx_used;s->h[2]=pc;s->h[3]=selected_decoded.next_pc;
    s->h[4]=selected_decoded.kind;s->h[5]=selected_decoded.width_bits;s->h[6]=selected_decoded.destination;
    s->h[7]=selected_decoded.code;s->h[8]=selected_decoded.length;
    s->h[9]=(unsigned)sig;s->h[10]=(unsigned)si->si_signo;s->h[11]=(unsigned)si->si_code;
    s->h[12]=(unsigned)si->si_errno;s->h[13]=(uintptr_t)si->si_addr;s->h[14]=selected_logical_flags;
    s->h[15]=cpuid_count;s->h[30]=(uint32_t)uc->uc_mcontext.gregs[REG_RAX];
    s->h[31]=(uint32_t)uc->uc_mcontext.gregs[REG_RCX];
    pl_copy(s->before_uc,uc,sizeof *uc);s->h[16]=pl_fp(uc,s->before_fp);
    pl_copy(s->before_source,(const void *)(uintptr_t)NX_MAIN,65536);
    pl_copy(s->before_interpreter,(const void *)(uintptr_t)original_interpreter.entry,4096);
    pl_copy(s->before_data,(const void *)(uintptr_t)NX_DATA,32768);s->h[18]=1;
    s->h[52]=selected_view.page_count;s->h[53]=selected_chain.steps;s->h[54]=selected_chain.trace_entries;
    const struct li2_tf_chain_slot *previous=&selected_chain.slots[selected_chain.active^1];
    s->h[55]=previous->decoded.pc;s->h[56]=previous->owner.step.phase;
    s->h[57]=previous->owner.step.trace_seen;s->h[58]=previous->release.complete;
    s->h[59]=previous->owner.actual_post_pc;
    s->h[60]=selected_run_history.completed_runs;
    s->h[61]=selected_run_history.last_complete.phase;
    s->h[62]=selected_run_history.last_complete.plan.pc;
    s->h[63]=selected_run_history.last_complete.plan.stop;
    s->h[64]=selected_run_history.last_complete.plan.instruction_count;
    s->h[65]=selected_run_history.reset_complete;
    s->h[66]=native_main_refaults;s->h[67]=native_main_admissions;
}
static void nx_after(const ucontext_t *uc) {
    if(!nx_pending)return;
    checked(nx_frame==uc && nx_used<NX_ROWS,1692,0);
    struct nx_sample *s=&nx_record.samples[nx_used];
    pl_copy(s->after_uc,uc,sizeof *uc);s->h[17]=pl_fp(uc,s->after_fp);
    pl_copy(s->after_source,(const void *)(uintptr_t)NX_MAIN,65536);
    pl_copy(s->after_interpreter,(const void *)(uintptr_t)original_interpreter.entry,4096);
    pl_copy(s->after_data,(const void *)(uintptr_t)NX_DATA,32768);
    s->h[19]=cpuid_count;
    s->h[40]=selected_builtin_prefix.kind;s->h[41]=selected_builtin_prefix.phase;
    s->h[42]=(uint64_t)selected_builtin_prefix.enable_result;s->h[43]=(uint64_t)selected_builtin_prefix.restore_result;
    s->h[44]=selected_builtin_prefix.a;s->h[45]=selected_builtin_prefix.b;
    s->h[46]=selected_builtin_prefix.c;s->h[47]=selected_builtin_prefix.d;
#ifdef LI2_CPUID_NX_ONLY
    s->h[25]=selected_cpuid_nx.phase;s->h[26]=selected_cpuid_nx.attempts;
    s->h[27]=selected_cpuid_nx.samples;s->h[28]=selected_cpuid_nx.commits;
    for(unsigned i=0;i<4;i++)s->h[32+i]=selected_cpuid_nx.raw[i];
    s->h[68]=selected_cpuid_nx.pc;s->h[69]=selected_cpuid_nx.next_pc;
    s->h[70]=selected_cpuid_nx.leaf;s->h[71]=selected_cpuid_nx.subleaf;
    for(unsigned i=0;i<4;i++)s->h[72+i]=selected_cpuid_nx.result[i];
#else
    s->h[32]=selected_builtin_prefix.a;s->h[33]=selected_builtin_prefix.b;
    s->h[34]=selected_builtin_prefix.c;s->h[35]=selected_builtin_prefix.d;
#endif
    s->h[36]=(uint64_t)uc->uc_mcontext.gregs[REG_RAX];s->h[37]=(uint64_t)uc->uc_mcontext.gregs[REG_RBX];
    s->h[38]=(uint64_t)uc->uc_mcontext.gregs[REG_RCX];s->h[39]=(uint64_t)uc->uc_mcontext.gregs[REG_RDX];
#ifdef LI2_SELECTED_PROVIDER
    if(selected_provider_state.mode) {
        const __typeof__(selected_provider_state.cpuid) *p=&selected_provider_state.cpuid;
        s->h[20]=selected_provider_state.busy;s->h[21]=p->entered;s->h[22]=p->returned;s->h[23]=p->committed;
        s->h[24]=(uint64_t)p->callback_status;s->h[48]=selected_provider_state.attempts;
        s->h[49]=selected_provider_state.completed[0];
        checked(p->input.leaf==s->h[30] && p->input.subleaf==s->h[31],1692,2);
        for(unsigned i=0;i<4;i++)checked(p->input.native[i]==s->h[32+i],1692,3);
    }
#endif
    s->h[0]=2;++nx_used;nx_pending=0;nx_frame=0;
}
static void nx_terminal(unsigned status,unsigned code,long detail) {
    if(nx_finished || !nx_record.h[5])return;
    nx_finished=1;nx_record.h[6]=status;nx_record.h[7]=code;nx_record.h[8]=(uint64_t)detail;
    nx_record.h[9]=nx_used;nx_record.h[10]=nx_pending;nx_record.h[12]=cpuid_count;
    if(nx_used || nx_pending) {
        pl_copy(nx_record.terminal_data,(const void *)(uintptr_t)NX_DATA,32768);
        pl_copy(nx_record.terminal_source,(const void *)(uintptr_t)NX_MAIN,65536);nx_record.h[18]=1;
    }
    size_t at=0;
    while(at<sizeof nx_record) {
        long n=raw(SYS_write,3,(long)((const unsigned char *)&nx_record+at),sizeof nx_record-at,0,0,0);
        if(n<=0 || (size_t)n>sizeof nx_record-at)return;
        at+=(size_t)n;
    }
}
