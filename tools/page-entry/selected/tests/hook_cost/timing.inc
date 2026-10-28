/* Additive timing observer, never an application-callable clock service.
   Original full-state observer definitions precede this include unchanged. */
#define HC_MAGIC UINT64_C(0x315443484932494c)
struct hc_row { uint64_t v[32]; };
struct hc_record { uint64_t h[32];struct hc_row rows[4];uint64_t calibration[64][2]; };
_Static_assert(sizeof(struct hc_record)==2304,"complete fixed timing record");
static struct hc_record hc_record;
static struct { long sec,nsec; } hc_clock_value;
static unsigned hc_initialized,hc_mode,hc_emitted,hc_active,hc_index,hc_pending,hc_pending_index;
static int hc_word(const char *actual,const char *expected) {
    size_t i=0;while(expected[i] && actual[i]==expected[i])++i;
    return !actual[i] && !expected[i];
}
static __attribute__((noinline,noclone)) uint64_t hc_clock(void) {
    checked(hc_record.h[13]!=UINT64_MAX,1760,0);
    ++hc_record.h[13];__asm__ volatile("":::"memory");
    long result=raw(SYS_clock_gettime,4,(long)&hc_clock_value,0,0,0,0);
    checked(!result && hc_clock_value.sec>=0 && hc_clock_value.nsec>=0 &&
        hc_clock_value.nsec<1000000000L &&
        (uint64_t)hc_clock_value.sec<=(UINT64_MAX-999999999)/1000000000,1760,result);
    __asm__ volatile("":::"memory");++hc_record.h[14];
    return (uint64_t)hc_clock_value.sec*1000000000+(uint64_t)hc_clock_value.nsec;
}
static void hc_emit(unsigned status,unsigned code,long detail) {
    if(!hc_initialized || hc_emitted)return;
    hc_emitted=1;
    uint64_t *h=hc_record.h;
    h[5]=status;h[6]=code;h[7]=(uint64_t)detail;
    h[9]=(uint64_t)b2_script_prepared;h[10]=(uint64_t)b2_script_accepted;
    h[11]=(uint64_t)b2_script_committed;h[12]=hc_pending;h[18]=1;h[21]=hc_active;
    const struct li2_native_counts *nc=li2_lifecycle_native_counts();
    h[22]=faults;h[23]=selected_steps;h[24]=selected_tf_steps;h[25]=selected_repeat_steps;
    h[26]=nc->attempts;h[27]=nc->admissions;h[28]=nc->closed;
    h[29]=nc->blocked;h[30]=nc->low_address_refusals;h[31]=selected_run_plan_misses;
    size_t at=0;
    while(at<sizeof hc_record) {
        long n=raw(SYS_write,3,(long)((const unsigned char *)&hc_record+at),sizeof hc_record-at,0,0,0);
        if(n<=0 || (size_t)n>sizeof hc_record-at)return;
        at+=(size_t)n;
    }
    if(hc_mode)b2_format_emit();
}
static void b2_emit(unsigned status,unsigned code,long detail) {
    if(!hc_mode)hc_original_emit(status,code,detail);
    hc_emit(status,code,detail);
}
static void b2_initialize(void) {
    const char key[]="LI2_SELECTED_HOOK_COST=";
    const char *const *env=bridge_environment();unsigned found=0;
    for(size_t i=0;env[i];i++) {
        checked(i<8192,1761,0);size_t j=0;
        while(j<sizeof key-1 && env[i][j]==key[j])++j;
        if(j!=sizeof key-1)continue;
        checked(!found++,1761,1);const char *v=env[i]+j;
        if(hc_word(v,"qualify"))hc_mode=0;
        else {checked(hc_word(v,"measure"),1761,2);hc_mode=1;}
    }
    checked(found==1 && !hc_initialized,1761,3);
    hc_original_initialize();
    volatile unsigned char *bytes=(void *)&hc_record;
    for(size_t i=0;i<sizeof hc_record;i++)bytes[i]=0;
    hc_clock_value.sec=hc_clock_value.nsec=0;
    uint64_t *h=hc_record.h;
    h[0]=HC_MAGIC;h[1]=1;h[2]=sizeof hc_record;h[3]=hc_mode;h[4]=B2_SCRIPT_ROWS;
    h[15]=4;h[16]=64;h[17]=1;
    h[19]=b2_format_record.sample[0].h[5];h[20]=b2_format_record.sample[0].h[6];
    hc_initialized=1;
    for(unsigned i=0;i<64;i++) {
        hc_record.calibration[i][0]=hc_clock();hc_record.calibration[i][1]=hc_clock();
        checked(hc_record.calibration[i][0]<=hc_record.calibration[i][1],1761,4);
    }
}
static __attribute__((noinline,noclone)) void hc_handler_enter(int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(!hc_initialized || selected_selftesting || hc_emitted)return;
    checked(!hc_active && si && uc,1762,0);
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    unsigned i=(unsigned)b2_script_committed;
    unsigned start=i<B2_SCRIPT_ROWS && pc==b2_script[i].pc;
    if(!hc_pending && !start)return;
    uint64_t now=hc_clock();
    if(hc_pending) {
        uint64_t *v=hc_record.rows[hc_pending_index].v;
        checked(hc_pending==1 && v[0]==4,1762,1);
        v[9]=now;v[14]=(uint64_t)sig;v[15]=(uint64_t)si->si_code;
        v[16]=(uint64_t)uc->uc_mcontext.gregs[REG_TRAPNO];
        v[17]=(uint64_t)uc->uc_mcontext.gregs[REG_ERR];v[18]=pc;
        v[19]=(uint64_t)uc->uc_mcontext.gregs[REG_EFL];
        copy(&v[20],&uc->uc_sigmask,8);v[21]=(uintptr_t)si->si_addr;
        checked(sig==SIGSEGV && si->si_signo==SIGSEGV && si->si_code==SEGV_ACCERR &&
            !si->si_errno && v[16]==14 && v[17]==21 && pc==v[4] &&
            v[19]==(v[24]|SELECTED_RF) && v[20]==SELECTED_MASK,1762,2);
        hc_pending=2; /* actual event retained, original source validation follows */
    }
    if(start) {
        uint64_t *v=hc_record.rows[i].v;
        checked(!v[0] && b2_script_prepared==(sig_atomic_t)i &&
                b2_script_accepted==(sig_atomic_t)i,1762,3);
        v[1]=i;v[2]=b2_script[i].kind;v[3]=pc;v[4]=b2_script[i].next;v[5]=now;
        __asm__ volatile("":::"memory");v[0]=1;hc_active=1;hc_index=i;
    }
}
static void hc_next_validated(void) {
    if(!hc_pending)return;
    uint64_t *v=hc_record.rows[hc_pending_index].v;
    checked(hc_pending==2 && v[0]==4 && selected_decoded.pc==v[4] &&
        selected_decoded.length>=1 && selected_decoded.length<=15 &&
        v[21]>=v[4] && v[21]<selected_decoded.next_pc &&
        li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY && !selected_step_pending,1763,0);
    v[23]=selected_decoded.length;v[22]=1;
    __asm__ volatile("":::"memory");v[0]=5;++hc_record.h[8];hc_pending=0;
}
static void hc_callback_enter(unsigned kind) {
    checked(hc_active && hc_index<B2_SCRIPT_ROWS && hc_index==(unsigned)b2_script_committed,1764,0);
    uint64_t *v=hc_record.rows[hc_index].v;
    checked(v[0]==1 && v[2]==kind,1764,1);
    v[6]=hc_clock();__asm__ volatile("":::"memory");v[0]=2;
}
static int hc_callback_return(int status) {
    uint64_t *v=hc_record.rows[hc_index].v;
    checked(hc_active && v[0]==2,1764,2);
    v[13]=(uint64_t)(long)status;v[7]=hc_clock();
    __asm__ volatile("":::"memory");v[0]=3;return status;
}
static __attribute__((noinline,noclone)) int hc_random_callback(const struct li2_selected_callback_input *in,struct li2_selected_script *out) {
    hc_callback_enter(in?in->kind:0);return hc_callback_return(b2_random_callback(in,out));
}
static __attribute__((noinline,noclone)) int hc_cpuid_callback(const struct li2_selected_cpuid_input *in,struct li2_selected_cpuid_result *out) {
    hc_callback_enter(LI2_CPUID);return hc_callback_return(b2_cpuid_callback(in,out));
}
static __attribute__((noinline,noclone)) int hc_clock_callback(const struct li2_selected_clock_input *in,struct li2_selected_clock_result *out) {
    hc_callback_enter(in?in->kind:0);return hc_callback_return(b2_clock_callback(in,out));
}
static __attribute__((noinline,noclone)) int hc_syscall_callback(const struct li2_selected_syscall_input *in,struct li2_selected_syscall_result *out) {
    hc_callback_enter(LI2_SYSCALL);return hc_callback_return(b2_syscall_callback(in,out));
}
static void b2_entry(int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(!hc_mode) {hc_original_entry(sig,si,uc);return;}
    if(selected_selftesting)return;
    checked(b2_initialized && !b2_observation_pending && !b2_before_seen && !b2_finished,1765,0);
    unsigned i=(unsigned)b2_script_committed;uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    b2_signal=sig;b2_si=si;b2_context=uc;
    if(i==B2_SCRIPT_ROWS) {
        checked(pc==b2_script[i-1].next && b2_script_prepared==(sig_atomic_t)i &&
            b2_script_accepted==(sig_atomic_t)i && !li2_lifecycle_fetch_interlock() &&
            !selected_step_pending && selected_pending_route==SELECTED_NO_STEP,1765,1);
        b2_final_pending=1;return;
    }
    checked(i<B2_SCRIPT_ROWS,1765,2);
    if(pc!=b2_script[i].pc)return;
    struct b2_row *row=&b2_record.rows[i];row->h[0]=1;row->h[1]=i;row->h[2]=b2_script[i].kind;row->h[3]=pc;
    b2_observation_pending=1;
}
static void b2_before(int sig,const siginfo_t *si,const ucontext_t *uc) {
    hc_next_validated();
    if(!hc_mode) {hc_original_before(sig,si,uc);return;}
    if(selected_selftesting)return;
    unsigned i=(unsigned)b2_script_committed;
    if(b2_final_pending) {
        checked(i==B2_SCRIPT_ROWS && hc_record.h[8]==i && !hc_pending && !hc_active &&
            sig==b2_signal && si==b2_si && uc==b2_context && selected_decoded.pc==b2_script[i-1].next &&
            !selected_step_pending && li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,1766,0);
        selected_release();li2_lifecycle_native_close();
        checked(!li2_lifecycle_fetch_interlock() && !selected_step_pending,1766,1);
        b2_final_pending=0;b2_format_sample(1);b2_emit(0,0,0);
        (void)raw(SYS_exit_group,0,0,0,0,0,0);__builtin_trap();
    }
    if(selected_decoded.kind<LI2_CPUID || selected_decoded.kind>LI2_SYSCALL)return;
    checked(b2_observation_pending && !b2_before_seen && i<B2_SCRIPT_ROWS && sig==b2_signal &&
        si==b2_si && uc==b2_context && selected_decoded.kind==b2_script[i].kind &&
        selected_decoded.length==b2_script[i].length && selected_view.length>=selected_decoded.length &&
        !selected_step_pending && li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,1766,2);
    checked(!b2_script_before(uc,selected_view.bytes,selected_decoded.length,selected_decoded.pc,selected_logical_flags),1766,3);
    b2_before_seen=1;
}
static void b2_after(const ucontext_t *uc) {
    unsigned i=(unsigned)b2_script_committed;
    if(!hc_mode)hc_original_after(uc);
    else {
        checked(b2_observation_pending && b2_before_seen && i<B2_SCRIPT_ROWS && uc==b2_context,1767,0);
        struct b2_row *row=&b2_record.rows[i];b2_progress(row);
        checked(row->h[4]==1 && row->h[5]==1 && row->h[6]==1 && !selected_step_pending &&
            row->h[10]==(row->h[2]==LI2_SYSCALL?0:LI2_FETCH_BUSY),1767,1);
        checked(!b2_script_after(uc),1767,2);row->h[9]=(uint64_t)b2_script_committed;row->h[0]=2;
        b2_observation_pending=0;b2_before_seen=0;b2_context=0;b2_si=0;b2_signal=0;
    }
    checked(hc_active && hc_index==i && hc_record.rows[i].v[0]==3,1767,3);
    uint64_t *v=hc_record.rows[i].v;const uint64_t *h=b2_record.rows[i].h;
    v[10]=h[4];v[11]=h[5];v[12]=h[6];v[24]=(uint64_t)uc->uc_mcontext.gregs[REG_EFL];
    v[25]=(uint64_t)b2_script_prepared;v[26]=(uint64_t)b2_script_accepted;v[27]=(uint64_t)b2_script_committed;
}
static __attribute__((noinline,noclone)) void hc_handler_leave(void) {
    if(!hc_initialized || selected_selftesting || !hc_active)return;
    uint64_t *v=hc_record.rows[hc_index].v;
    v[28]=li2_lifecycle_fetch_interlock();v[29]=selected_step_pending;v[30]=selected_pending_route;
    checked(v[0]==3 && !hc_pending && v[10]==1 && v[11]==1 && v[12]==1 && !v[13] &&
        v[24]==b2_script[hc_index].after_flags && v[25]==hc_index+1 && v[26]==hc_index+1 &&
        v[27]==hc_index+1 && !v[28] && !v[29] && !v[30],1768,0);
    v[8]=hc_clock();__asm__ volatile("":::"memory");v[0]=4;
    hc_pending_index=hc_index;hc_pending=1;hc_active=0;
}
