/* Additive CPUID evidence. The original oi_record is emitted first, unchanged.
   All snapshots are real current frames; no frame or application state is edited. */
#define OC_MAIN UINT64_C(0x200401000)
#define OC_DATA UINT64_C(0x200420000)
#define OC_ROWS 40
struct oc_sample {
    uint64_t h[64];
    struct oi_frame before,after;
    struct li2_fetch_view view;
    struct li2_fetch_page pages[2];
    unsigned char borrowed[16];
    struct selected_builtin_prefix prior,builtin;
    unsigned char source_before[2][PAGE],source_after[2][PAGE];
    unsigned char data_before[32768],data_after[32768];
};
struct oc_record {
    uint64_t h[32];
    struct li2_selected_hardware hardware;
    uint64_t xstate[4][4];
    struct oc_sample samples[OC_ROWS];
    struct oi_frame main_entry;
    uint64_t startup[256];
    unsigned char terminal_source[65536],terminal_data[32768];
};
_Static_assert(sizeof(struct oi_record)+sizeof(struct oc_record)<(16U<<20),"complete two-record cap");
static struct oc_record oc_record;
static unsigned oc_used,oc_pending,oc_finished,oc_finite,oc_registered;
static const siginfo_t *oc_si;
static const ucontext_t *oc_uc;
static void oc_initialize(void) {
    volatile unsigned char *p=(void *)&oc_record;
    for(size_t i=0;i<sizeof oc_record;i++)p[i]=0;
    oc_record.h[0]=UINT64_C(0x31584e50434f324c);oc_record.h[1]=1;oc_record.h[2]=sizeof oc_record;
    oc_record.h[3]=sizeof(struct oc_sample);oc_record.h[4]=sizeof(struct oi_record);
    oc_record.h[5]=1;oc_record.h[12]=selected_session.pid;oc_record.h[13]=selected_session.tid;
    oc_record.h[14]=original_main.entry;oc_record.h[15]=original_interpreter.entry;
    oc_record.h[16]=original_main.bias;oc_record.h[17]=original_interpreter.bias;
    oc_finite=original_main.entry==OC_MAIN;oc_registered=!oc_finite&&original_interpreter.source_size==12288;oc_record.h[18]=oc_finite?1:oc_registered?2:0;
    oi_copy(&oc_record.hardware,&selected_hardware,sizeof selected_hardware);
    uint32_t low,high;__asm__ volatile("xgetbv":"=a"(low),"=d"(high):"c"(0):"memory");
    oc_record.h[19]=(uint64_t)low|((uint64_t)high<<32);
    const unsigned bits[4]={2,5,6,7};
    for(unsigned i=0;i<4;i++) {
        uint32_t a=13,b,c=bits[i],d;
        __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d)::"memory");
        oc_record.xstate[i][0]=bits[i];oc_record.xstate[i][1]=b;
        oc_record.xstate[i][2]=a;oc_record.xstate[i][3]=c;
    }
}
static void oc_before(int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(oc_registered&&selected_decoded.pc==original_main.entry) {
        checked(!oc_record.main_entry.h[0],1697,7);oi_frame(&oc_record.main_entry,sig,si,uc);oc_record.h[25]=1;
    }
    if(selected_decoded.kind!=LI2_CPUID)return;
    checked(!oc_pending&&!oc_finished&&oc_record.h[5]&&oc_used<OC_ROWS,1697,1);
    checked(!selected_oneshot_active&&!selected_step_pending&&
        li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,1697,2);
    struct oc_sample *s=&oc_record.samples[oc_used];
    s->h[0]=1;s->h[1]=oc_used;s->h[2]=selected_decoded.pc;s->h[3]=selected_decoded.next_pc;
    s->h[4]=selected_decoded.kind;s->h[5]=selected_decoded.code;s->h[6]=selected_decoded.length;
    s->h[7]=selected_decoded.width_bits;s->h[8]=selected_decoded.destination;
    s->h[9]=selected_logical_flags;s->h[10]=cpuid_count;s->h[11]=selected_oneshot_used;
    s->h[12]=selected_view.page_count;s->h[13]=li2_lifecycle_fetch_interlock();
    s->h[14]=selected_step_pending;s->h[15]=selected_pending_route;
    s->h[16]=(uint32_t)uc->uc_mcontext.gregs[REG_RAX];s->h[17]=(uint32_t)uc->uc_mcontext.gregs[REG_RCX];
    checked(s->h[12]>=1&&s->h[12]<=2,1697,3);
    oi_copy(&s->view,&selected_view,sizeof selected_view);
    checked(selected_view.length>=2&&selected_view.length<=15,1697,6);
    oi_copy(s->pages,selected_view.pages,sizeof s->pages[0]*selected_view.page_count);
    oi_copy(s->borrowed,selected_view.bytes,selected_view.length);
    oi_copy(&s->prior,&selected_builtin_prefix,sizeof selected_builtin_prefix);
    oi_frame(&s->before,sig,si,uc);
    if(oc_registered&&oc_used==0) {
        const volatile uint64_t *stack=(const void *)(uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
        size_t argc=stack[0];checked(argc==1,1697,8);size_t end=argc+2;
        checked(!stack[argc+1],1697,9);
        while(end<126&&stack[end])++end;
        checked(end<126,1697,10);++end;
        while(end+1<256&&stack[end])end+=2;
        checked(end+1<256&&!stack[end]&&!stack[end+1],1697,11);end+=2;
        for(size_t j=0;j<end;j++)oc_record.startup[j]=stack[j];oc_record.h[24]=end;
    }
    for(unsigned i=0;i<s->h[12];i++)oi_copy(s->source_before[i],(const void *)selected_view.pages[i].address,PAGE);
    if(oc_finite)oi_copy(s->data_before,(const void *)(uintptr_t)OC_DATA,32768);
    oc_si=si;oc_uc=uc;oc_pending=1;
}
static void oc_after(const ucontext_t *uc) {
    if(!oc_pending)return;
    checked(uc==oc_uc&&oc_used<OC_ROWS&&selected_decoded.kind==LI2_CPUID,1697,4);
    struct oc_sample *s=&oc_record.samples[oc_used];
    oi_frame(&s->after,SIGSEGV,oc_si,uc);oi_copy(&s->builtin,&selected_builtin_prefix,sizeof selected_builtin_prefix);
    checked(selected_view.page_count==s->h[12],1697,5);
    for(unsigned i=0;i<s->h[12];i++)oi_copy(s->source_after[i],(const void *)selected_view.pages[i].address,PAGE);
    if(oc_finite)oi_copy(s->data_after,(const void *)(uintptr_t)OC_DATA,32768);
    s->h[18]=cpuid_count;s->h[19]=selected_cpuid_nx.phase;
    s->h[20]=selected_cpuid_nx.hardware_entered;s->h[21]=selected_cpuid_nx.hardware_returned;
    s->h[22]=selected_cpuid_nx.attempts;s->h[23]=selected_cpuid_nx.samples;s->h[24]=selected_cpuid_nx.commits;
    s->h[25]=selected_cpuid_nx.pc;s->h[26]=selected_cpuid_nx.next_pc;
    s->h[27]=selected_cpuid_nx.leaf;s->h[28]=selected_cpuid_nx.subleaf;
    for(unsigned i=0;i<4;i++){s->h[29+i]=selected_cpuid_nx.raw[i];s->h[33+i]=selected_cpuid_nx.result[i];}
    s->h[37]=selected_oneshot_used;s->h[38]=selected_oneshot_active!=0;
    s->h[39]=li2_lifecycle_fetch_interlock();s->h[40]=selected_step_pending;s->h[41]=selected_pending_route;
    s->h[0]=2;++oc_used;oc_pending=0;oc_si=0;oc_uc=0;
}
static void oc_terminal(unsigned status,unsigned code,long detail) {
    if(oc_finished||!oc_record.h[5])return;
    oc_finished=1;oc_record.h[6]=status;oc_record.h[7]=code;oc_record.h[8]=(uint64_t)detail;
    oc_record.h[9]=oc_used;oc_record.h[10]=oc_pending;oc_record.h[11]=cpuid_count;
    oc_record.h[20]=selected_cpuid_nx.attempts;oc_record.h[21]=selected_cpuid_nx.samples;oc_record.h[22]=selected_cpuid_nx.commits;
    if(oc_finite&&oc_used) {
        oi_copy(oc_record.terminal_source,(const void *)(uintptr_t)OC_MAIN,65536);
        oi_copy(oc_record.terminal_data,(const void *)(uintptr_t)OC_DATA,32768);oc_record.h[23]=1;
    }
    size_t at=0;
    while(at<sizeof oc_record) {
        long n=raw(SYS_write,3,(long)((const unsigned char *)&oc_record+at),sizeof oc_record-at,0,0,0);
        if(n<=0||(size_t)n>sizeof oc_record-at)return;
        at+=(size_t)n;
    }
}
