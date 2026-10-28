/* Fixture-only copies. No input frame, source byte, policy, guard or result is
   modified. This include is installed only by the exact observation adapter. */
#define PL_MAIN UINT64_C(0x200401000)
#define PL_DATA UINT64_C(0x200403000)
#define PL_FP 65536
#define PL_UC 2048
#define PL_ROWS 18
struct pl_sample {
    uint64_t h[64];
    unsigned char before_uc[PL_UC],after_uc[PL_UC];
    unsigned char before_fp[PL_FP],after_fp[PL_FP];
    unsigned char before_source[8192],after_source[8192];
    unsigned char before_interpreter[4096],after_interpreter[4096];
    unsigned char before_data[16384],after_data[16384];
};
struct pl_record {
    uint64_t h[64];
    struct li2_selected_hardware hardware;
    uint64_t xstate[4][4];
    struct pl_sample samples[PL_ROWS];
    uint64_t owners[6][32];
    unsigned char terminal_data[16384],terminal_source[8192];
};
_Static_assert(sizeof(ucontext_t)<=PL_UC && sizeof(struct pl_record)<(16U<<20),"bounded complete observer record");
static struct pl_record pl_record;
static unsigned pl_used,pl_pending,pl_finished;
static const ucontext_t *pl_frame;
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
static void pl_initialize(void) {
    volatile unsigned char *p=(void *)&pl_record;
    for(size_t i=0;i<sizeof pl_record;i++)p[i]=0; /* actual pre-entry prefault */
    pl_record.h[0]=UINT64_C(0x314e55414c565250);pl_record.h[1]=1;pl_record.h[2]=sizeof pl_record;
    pl_record.h[3]=sizeof(ucontext_t);pl_record.h[4]=sizeof(struct pl_sample);
    pl_record.h[21]=original_interpreter.entry;pl_record.h[22]=original_interpreter.bias;
    checked(original_interpreter.entry==original_interpreter.bias+4096 &&
        !(original_interpreter.entry&4095),1693,2);
    pl_copy(&pl_record.hardware,&selected_hardware,sizeof selected_hardware);
    checked(selected_hardware.leaf0[0]>=13 &&
        (selected_hardware.leaf1[2]&UINT32_C(0x18000000))==UINT32_C(0x18000000) &&
        (selected_hardware.leaf7[1]&UINT32_C(0x40010000))==UINT32_C(0x40010000),1693,0);
    uint32_t low,high;
    __asm__ volatile("xgetbv":"=a"(low),"=d"(high):"c"(0):"memory");
    pl_record.h[20]=(uint64_t)low|((uint64_t)high<<32);
    checked((pl_record.h[20]&UINT64_C(0xe7))==UINT64_C(0xe7),1693,1);
    const unsigned bits[4]={2,5,6,7};
    for(unsigned i=0;i<4;i++) {
        uint32_t a=13,b,c=bits[i],d;
        __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d)::"memory");
        pl_record.xstate[i][0]=bits[i];pl_record.xstate[i][1]=b;
        pl_record.xstate[i][2]=a;pl_record.xstate[i][3]=c;
    }
    pl_record.h[5]=1;
}
static void pl_before(int sig,const siginfo_t *si,const ucontext_t *uc) {
    uint64_t pc=(uint64_t)uc->uc_mcontext.gregs[REG_RIP];
    if((pc!=original_interpreter.entry && (pc<PL_MAIN || pc>=PL_MAIN+4096)) ||
        selected_decoded.kind<LI2_CPUID || selected_decoded.kind>LI2_RDPID)return;
    checked((pl_used==0)==(pc==original_interpreter.entry),1691,2);
    checked(!pl_pending && pl_used<PL_ROWS && pl_record.h[5] && selected_provider_state.mode==1,1691,0);
    checked(original_main.entry==PL_MAIN && image_code(&original_main,PL_MAIN) &&
        *(const volatile uint64_t *)(uintptr_t)PL_DATA==UINT64_C(0x31504c5244565250),1691,1);
    struct pl_sample *s=&pl_record.samples[pl_used];pl_frame=uc;pl_pending=1;
    s->h[0]=1;s->h[1]=pl_used;s->h[2]=pc;s->h[3]=selected_decoded.next_pc;
    s->h[4]=selected_decoded.kind;s->h[5]=selected_decoded.width_bits;s->h[6]=selected_decoded.destination;
    s->h[7]=selected_decoded.code;s->h[8]=selected_decoded.length;
    s->h[9]=(unsigned)sig;s->h[10]=(unsigned)si->si_signo;s->h[11]=(unsigned)si->si_code;
    s->h[12]=(unsigned)si->si_errno;s->h[13]=(uintptr_t)si->si_addr;s->h[14]=selected_logical_flags;
    s->h[15]=selected_provider_state.attempts;
    pl_copy(s->before_uc,uc,sizeof *uc);s->h[16]=pl_fp(uc,s->before_fp);
    pl_copy(s->before_source,(const void *)(uintptr_t)PL_MAIN,8192);
    pl_copy(s->before_interpreter,(const void *)(uintptr_t)original_interpreter.entry,4096);
    pl_copy(s->before_data,(const void *)(uintptr_t)PL_DATA,16384);
    s->h[18]=1;
}
static void pl_after(const ucontext_t *uc) {
    if(!pl_pending)return;
    checked(pl_frame==uc && pl_used<PL_ROWS,1692,0);
    struct pl_sample *s=&pl_record.samples[pl_used];
    pl_copy(s->after_uc,uc,sizeof *uc);s->h[17]=pl_fp(uc,s->after_fp);
    pl_copy(s->after_source,(const void *)(uintptr_t)PL_MAIN,8192);
    pl_copy(s->after_interpreter,(const void *)(uintptr_t)original_interpreter.entry,4096);
    pl_copy(s->after_data,(const void *)(uintptr_t)PL_DATA,16384);
    s->h[19]=selected_provider_state.attempts;
    s->h[20]=selected_provider_state.busy;
    if(s->h[4]==LI2_CPUID) {
        const __typeof__(selected_provider_state.cpuid) *p=&selected_provider_state.cpuid;
        s->h[21]=p->entered;s->h[22]=p->returned;s->h[23]=p->committed;s->h[24]=(uint64_t)p->callback_status;
        s->h[30]=p->input.leaf;s->h[31]=p->input.subleaf;
        for(unsigned i=0;i<4;i++)s->h[32+i]=p->input.native[i];
        s->h[36]=p->result.eax;s->h[37]=p->result.ebx;s->h[38]=p->result.ecx;s->h[39]=p->result.edx;
        s->h[40]=selected_builtin_prefix.kind;s->h[41]=selected_builtin_prefix.phase;
        s->h[42]=(uint64_t)selected_builtin_prefix.enable_result;s->h[43]=(uint64_t)selected_builtin_prefix.restore_result;
        s->h[44]=selected_builtin_prefix.a;s->h[45]=selected_builtin_prefix.b;
        s->h[46]=selected_builtin_prefix.c;s->h[47]=selected_builtin_prefix.d;
    } else {
        const struct li2_selected_callback_progress *p=&selected_provider_state.random;
        s->h[21]=p->entered;s->h[22]=p->returned;s->h[23]=p->committed;s->h[24]=(uint64_t)p->callback_status;
        s->h[25]=p->first_error;s->h[26]=selected_completion.phase;
        s->h[27]=selected_completion.status;s->h[28]=selected_completion.native_attempts;s->h[29]=selected_completion.mechanism;
        s->h[30]=p->input.abi_version;s->h[31]=p->input.kind;s->h[32]=p->input.width_bits;s->h[33]=p->input.destination;
        s->h[34]=p->input.pc;s->h[35]=p->input.next_pc;s->h[36]=p->input.logical_flags;s->h[37]=p->input.input_destination;
        s->h[38]=p->script.kind;s->h[39]=p->script.width_bits;s->h[40]=p->script.carry;
        s->h[41]=p->script.reserved;s->h[42]=p->script.value;
        s->h[43]=selected_completion.input_destination;s->h[44]=selected_completion.output_destination;
        s->h[45]=selected_completion.value;s->h[46]=selected_completion.output_flags;
    }
    for(unsigned i=0;i<4;i++)s->h[48+i]=selected_provider_state.completed[i];
    s->h[0]=2;++pl_used;pl_pending=0;pl_frame=0;
}
static void pl_terminal(unsigned status,unsigned code,long detail) {
    if(pl_finished || !pl_record.h[5])return;
    pl_finished=1;pl_record.h[6]=status;pl_record.h[7]=code;pl_record.h[8]=(uint64_t)detail;
    pl_record.h[9]=pl_used;pl_record.h[10]=pl_pending;pl_record.h[11]=selected_oneshot_used;
    pl_record.h[12]=selected_provider_state.attempts;pl_record.h[13]=selected_provider_state.busy;
    for(unsigned i=0;i<4;i++)pl_record.h[14+i]=selected_provider_state.completed[i];
    if(pl_used || pl_pending) {
        pl_copy(pl_record.terminal_data,(const void *)(uintptr_t)PL_DATA,16384);
        pl_copy(pl_record.terminal_source,(const void *)(uintptr_t)PL_MAIN,8192);
        pl_record.h[18]=1;
    }
    for(unsigned i=0;i<selected_oneshot_used && i<6;i++) {
        const struct li2_oneshot_owner *o=&selected_oneshot_owners[i];uint64_t *r=pl_record.owners[i];
        r[0]=o->state.phase;r[1]=o->state.published;r[2]=o->state.restored;r[3]=o->state.first_error;
        r[4]=o->plan.pc;r[5]=o->plan.next_pc;r[6]=o->plan.kind;r[7]=o->plan.sequence;
        r[8]=o->write_attempted_mask;r[9]=o->write_completed_mask;
        r[10]=o->restore_attempted_mask;r[11]=o->restore_completed_mask;
        r[12]=selected_oneshot_effect_started[i];r[13]=selected_oneshot_effect_returned[i];
        if(o->state.restored) {
            pl_copy(&r[14],o->plan.original,5);
            pl_copy(&r[15],(const void *)(uintptr_t)o->plan.pc,5);
        }
    }
    size_t at=0;
    while(at<sizeof pl_record) {
        long n=raw(SYS_write,3,(long)((const unsigned char *)&pl_record+at),sizeof pl_record-at,0,0,0);
        if(n<=0 || (size_t)n>sizeof pl_record-at)return; /* truncated capture fails reader */
        at+=(size_t)n;
    }
}
