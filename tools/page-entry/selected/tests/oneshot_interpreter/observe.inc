/* Observation-only adapter. Original frames, callbacks and permits are untouched. */
struct oi_frame {
    uint64_t h[12];
    siginfo_t si;
    ucontext_t uc;
    unsigned char fp[LI2_STEP_FP_BYTES];
};
struct oi_owner {
    uint64_t h[32];
    struct li2_oneshot_plan request;
    struct li2_oneshot_owner owner;
    struct li2_oneshot_lifecycle_progress backend;
    struct oi_frame frames[5];
    unsigned char published[2][PAGE],restored[2][PAGE];
};
struct oi_record {
    uint64_t h[32];
    struct oi_owner owners[LI2_ONESHOT_LIFECYCLE_SLOTS];
    struct li2_tf_chain_slot continuation;
    struct oi_frame trace;
};
_Static_assert(LI2_ONESHOT_LIFECYCLE_SLOTS==8 && sizeof(struct oi_record)<(16U<<20),"eight complete owners and one continuation within existing cap");
static struct oi_record oi_record;
static unsigned oi_finished;
static const siginfo_t *oi_si[8];
static const ucontext_t *oi_uc[8];
static void oi_copy(void *dst,const void *src,size_t n) {
    unsigned char *d=dst;const volatile unsigned char *s=src;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static uint32_t oi_u32(const unsigned char *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static int oi_range(const void *p,size_t n) {
    uintptr_t a=(uintptr_t)p,lo=(uintptr_t)fork_gate_stack.ss_sp;size_t cap=fork_gate_stack.ss_size;
    return p && n && lo<=a && a-lo<=cap && n<=cap-(a-lo);
}
static void oi_frame(struct oi_frame *f,int sig,const siginfo_t *si,const ucontext_t *uc) {
    checked(oi_range(si,sizeof *si)&&oi_range(uc,sizeof *uc),1696,1);
    const unsigned char *p=(const void *)uc->uc_mcontext.fpregs;
    checked(!((uintptr_t)p&15)&&oi_range(p,512),1696,2);size_t n=512;
    if(oi_u32(p+464)==UINT32_C(0x46505853)) {
        n=oi_u32(p+468);size_t x=oi_u32(p+480);
        checked(n>=580&&n<=LI2_STEP_FP_BYTES&&x>=576&&x<=n-4&&oi_range(p,n)&&
                oi_u32(p+n-4)==UINT32_C(0x46505845),1696,3);
    }
    f->h[1]=(unsigned)sig;f->h[2]=(uintptr_t)si;f->h[3]=(uintptr_t)uc;
    f->h[4]=(uintptr_t)p;f->h[5]=n;f->h[6]=sizeof *si;f->h[7]=sizeof *uc;
    unsigned short fs,gs;__asm__ volatile("mov %%fs,%0; mov %%gs,%1":"=r"(fs),"=r"(gs)::"memory");
    f->h[8]=fs;f->h[9]=gs;
    oi_copy(&f->si,si,sizeof *si);oi_copy(&f->uc,uc,sizeof *uc);oi_copy(f->fp,p,n);f->h[0]=1;
}
static void oi_initialize(void) {
    volatile unsigned char *p=(void *)&oi_record;
    for(size_t i=0;i<sizeof oi_record;i++)p[i]=0;
    oi_record.h[0]=UINT64_C(0x31504c49534f324c);oi_record.h[1]=1;oi_record.h[2]=sizeof oi_record;
    oi_record.h[3]=sizeof(ucontext_t);oi_record.h[4]=sizeof(siginfo_t);oi_record.h[5]=1;
    oi_record.h[12]=original_main.bias;oi_record.h[13]=original_main.entry;
    oi_record.h[14]=original_main.source_size;oi_record.h[15]=original_interpreter.bias;
    oi_record.h[16]=original_interpreter.entry;oi_record.h[17]=original_interpreter.source_size;
    oi_record.h[18]=selected_session.pid;oi_record.h[19]=selected_session.tid;
    oi_record.h[20]=(uintptr_t)selected_oneshot_owners;oi_record.h[21]=(uintptr_t)&selected_session;
    oi_record.h[22]=bridge_runtime_image()->bias;
}
static struct oi_owner *oi_row(const struct li2_oneshot_owner *o) {
    size_t i=(size_t)(o-selected_oneshot_owners);
    checked(oi_record.h[5]&&!oi_finished&&i<8&&i<selected_oneshot_used,1696,4);
    return &oi_record.owners[i];
}
static void oi_begin(struct li2_oneshot_owner *o,const struct li2_oneshot_plan *p,int sig,siginfo_t *si,ucontext_t *uc) {
    struct oi_owner *r=oi_row(o);size_t i=(size_t)(o-selected_oneshot_owners);
    checked(!r->h[0],1696,5);r->h[0]=1;r->h[1]=i;r->h[4]=selected_logical_flags;
    int main=image_code(&original_main,p->pc),interp=image_code(&original_interpreter,p->pc);
    checked(main+interp==1,1696,6);r->h[2]=main?1:2;r->h[3]=main?original_main.bias:original_interpreter.bias;
    oi_copy(&r->request,p,sizeof *p);oi_frame(&r->frames[0],sig,si,uc);
    oi_si[i]=si;oi_uc[i]=uc;
}
static void oi_nx_return(struct li2_oneshot_owner *o,int result,int sig,siginfo_t *si,ucontext_t *uc) {
    struct oi_owner *r=oi_row(o);r->h[5]=1;r->h[6]=(uint64_t)(int64_t)result;
    oi_frame(&r->frames[1],sig,si,uc);
    if(!result&&o->state.phase==LI2_ONESHOT_PUBLISHED) {
        for(unsigned j=0;j<o->plan.page_count&&j<2;j++)oi_copy(r->published[j],(const void *)(uintptr_t)o->plan.pages[j].address,PAGE);
    }
}
static void oi_ud_before(struct li2_oneshot_owner *o,int sig,siginfo_t *si,ucontext_t *uc) {
    struct oi_owner *r=oi_row(o);size_t i=(size_t)(o-selected_oneshot_owners);
    checked(!r->h[7],1696,7);r->h[7]=1;oi_frame(&r->frames[2],sig,si,uc);oi_si[i]=si;oi_uc[i]=uc;
}
static void oi_ud_return(struct li2_oneshot_owner *o,int result,int sig,siginfo_t *si,ucontext_t *uc) {
    struct oi_owner *r=oi_row(o);r->h[8]=1;r->h[9]=(uint64_t)(int64_t)result;
    oi_frame(&r->frames[3],sig,si,uc);
    if(!result&&o->state.phase==LI2_ONESHOT_RESTORED) {
        for(unsigned j=0;j<o->plan.page_count&&j<2;j++)oi_copy(r->restored[j],(const void *)(uintptr_t)o->plan.pages[j].address,PAGE);
    }
}
static void oi_effect_begin(struct li2_oneshot_owner *o) {oi_row(o)->h[10]=1;}
static void oi_effect_done(struct li2_oneshot_owner *o,ucontext_t *uc) {
    struct oi_owner *r=oi_row(o);size_t i=(size_t)(o-selected_oneshot_owners);
    checked(uc==oi_uc[i],1696,8);oi_frame(&r->frames[4],SIGILL,oi_si[i],uc);r->h[11]=1;
    if(o->plan.kind==LI2_ONESHOT_RDTSC) {
        r->h[23]=selected_builtin_prefix.phase;r->h[24]=(uint64_t)selected_builtin_prefix.enable_result;
        r->h[25]=(uint64_t)selected_builtin_prefix.restore_result;r->h[26]=selected_builtin_prefix.a;
        r->h[27]=selected_builtin_prefix.b;r->h[28]=selected_builtin_prefix.c;r->h[29]=selected_builtin_prefix.d;
    }
}
static void oi_syscall_begin(long n,const ucontext_t *uc) {
    if(!selected_oneshot_active)return;
    struct oi_owner *r=oi_row(selected_oneshot_active);const greg_t *g=uc->uc_mcontext.gregs;
    checked(r->h[10]&&!r->h[13],1696,9);r->h[13]=1;r->h[15]=(uint64_t)n;
    const unsigned indices[6]={REG_RDI,REG_RSI,REG_RDX,REG_R10,REG_R8,REG_R9};
    for(unsigned i=0;i<6;i++)r->h[16+i]=(uint64_t)g[indices[i]];
    r->h[30]=(uintptr_t)uc;
}
static void oi_syscall_result(long n,const long a[6],long result,const ucontext_t *uc) {
    if(!selected_oneshot_active)return;
    struct oi_owner *r=oi_row(selected_oneshot_active);
    checked(r->h[13]&&!r->h[14]&&r->h[15]==(uint64_t)n&&r->h[30]==(uintptr_t)uc,1696,10);
    for(unsigned i=0;i<6;i++)checked(r->h[16+i]==(uint64_t)a[i],1696,11);
    r->h[22]=(uint64_t)result;r->h[14]=1;
}
static void oi_trace_before(int sig,const siginfo_t *si,const ucontext_t *uc) {
    const struct li2_tf_chain_slot *s=&selected_chain.slots[selected_chain.active];
    if(s->decoded.pc!=original_interpreter.bias+UINT64_C(0x1fd9a))return;
    checked(!oi_record.trace.h[0],1696,12);oi_frame(&oi_record.trace,sig,si,uc);
}
static void oi_trace(const struct li2_tf_chain_slot *s) {
    if(s->decoded.pc!=original_interpreter.bias+UINT64_C(0x1fd9a))return;
    checked(!oi_record.h[23],1696,12);
    checked(oi_record.trace.h[0],1696,13);
    oi_copy(&oi_record.continuation,s,sizeof *s);oi_record.h[23]=1;
}
static void oi_terminal(unsigned status,unsigned code,long detail) {
    if(oi_finished||!oi_record.h[5])return;
    oi_finished=1;
    oi_record.h[6]=status;oi_record.h[7]=code;oi_record.h[8]=(uint64_t)detail;
    oi_record.h[9]=selected_oneshot_used;oi_record.h[10]=selected_step_pending;
    oi_record.h[11]=selected_oneshot_active?(uint64_t)(selected_oneshot_active-selected_oneshot_owners)+1:0;
    for(unsigned i=0;i<selected_oneshot_used&&i<8;i++) {
        struct oi_owner *r=&oi_record.owners[i];const struct li2_oneshot_owner *o=&selected_oneshot_owners[i];
        oi_copy(&r->owner,o,sizeof *o);
        const struct li2_oneshot_lifecycle_progress *p=li2_lifecycle_oneshot_progress(o->hooks.context);
        if(p)oi_copy(&r->backend,p,sizeof *p);
        r->h[12]=1;
    }
    oi_record.h[24]=1;size_t at=0;
    while(at<sizeof oi_record) {
        long n=raw(SYS_write,3,(long)((const unsigned char *)&oi_record+at),sizeof oi_record-at,0,0,0);
        if(n<=0||(size_t)n>sizeof oi_record-at)return;
        at+=(size_t)n;
    }
}
