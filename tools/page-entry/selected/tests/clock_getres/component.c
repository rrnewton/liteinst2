/* Actual syscall-state component, not the production dispatcher. The NX lane
   uses the actual guard TU with supplied inactive-pin state. Real registration
   and dispatch are tested separately by the normal-loader applications. */
#define _GNU_SOURCE
#include "../provider/fixture.h"
#include "../../rseq_guard.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define PAGE 4096
#define ALT (256*1024)
#define RF UINT64_C(0x10000)
#define MAGIC UINT64_C(0x31534552474b4c43)
_Static_assert(640+2*(128+384+4*FP_BYTES+2*UC_BYTES+1024+8192+16384)<16*1024*1024,"complete fixed record below original16MiB cap");
static unsigned char *code,*output,*stack_mem,*alt;
static uint64_t supplied[4] __attribute__((aligned(32)));
static unsigned mode,lane,faults,issued;
static uint64_t mask,header[64],lh[16];
static unsigned char kb[FP_BYTES],ka[FP_BYTES],ub[UC_BYTES],ua[UC_BYTES];
static unsigned char sb[512],sa[512],ob[PAGE],oa[PAGE],cb[2*PAGE],ca[2*PAGE];
extern void fixture_restorer(void);
struct action {void (*handler)(int,siginfo_t *,void *);uint64_t flags;void (*restorer)(void);uint64_t mask;};
long raw(long n,long a,long b,long c,long d,long e,long f) {
    register long r10 __asm__("r10")=d;register long r8 __asm__("r8")=e;register long r9 __asm__("r9")=f;
    long v;__asm__ volatile("syscall":"=a"(v):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return v;
}
#define RAW(n,a,b,c,d,e,f) raw(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
void fixture_copy(void *a,const void *b,size_t n){volatile unsigned char *x=a;const volatile unsigned char *y=b;for(size_t i=0;i<n;i++)x[i]=y[i];}
int fixture_equal(const void *a,const void *b,size_t n){const volatile unsigned char *x=a,*y=b;for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;return 1;}
static void write_all(const void *v,size_t n){const unsigned char *p=v;while(n){long k=RAW(SYS_write,3,p,n,0,0,0);if(k<=0||(size_t)k>n)_exit(124);p+=k;n-=(size_t)k;}}
_Noreturn void fixture_die(unsigned code_value,unsigned detail){uint64_t h[4]={MAGIC,code_value,detail,lane};write_all(h,sizeof h);_exit(125);}
#define REQUIRE(v) do {if(!(v))fixture_die(__LINE__,mode);}while(0)
static uint32_t word(const unsigned char *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static size_t capture(ucontext_t *u,unsigned char *out){
    uintptr_t p=(uintptr_t)u->uc_mcontext.fpregs,lo=(uintptr_t)alt+PAGE,hi=lo+ALT;
    REQUIRE(p>=lo&&p<=hi-512&&!(p&15));const unsigned char *b=(const void *)p;size_t n=512;
    if(word(b+464)==UINT32_C(0x46505853)){n=word(b+468);size_t x=word(b+480);REQUIRE(n>=580&&n<=FP_BYTES&&n<=hi-p&&x>=576&&x==n-4&&word(b+n-4)==UINT32_C(0x46505845));}
    fixture_copy(out,b,n);return n;
}
static void handler(int sig,siginfo_t *si,void *opaque){
    ucontext_t *u=opaque;REQUIRE(lane==1&&faults++==0&&sig==SIGSEGV&&si&&u&&si->si_signo==11&&si->si_code==2&&!si->si_errno&&
        (uintptr_t)si->si_addr==fixture_target&&(uintptr_t)u->uc_mcontext.gregs[REG_RIP]==fixture_target&&
        u->uc_mcontext.gregs[REG_TRAPNO]==14&&u->uc_mcontext.gregs[REG_ERR]==21&&
        (uint64_t)u->uc_mcontext.gregs[REG_EFL]==(fixture_pre[16]|RF));
    fixture_copy(ub,u,sizeof *u);lh[5]=capture(u,kb);lh[7]=(uintptr_t)u->uc_mcontext.fpregs;
    struct li2_rseq_state before=state;long args[6]={u->uc_mcontext.gregs[REG_RDI],u->uc_mcontext.gregs[REG_RSI],u->uc_mcontext.gregs[REG_RDX],u->uc_mcontext.gregs[REG_R10],u->uc_mcontext.gregs[REG_R8],u->uc_mcontext.gregs[REG_R9]};
    long saved_args[6];fixture_copy(saved_args,args,sizeof args);
    int guard=li2_rseq_before_syscall(SYS_clock_getres,args);lh[8]=(unsigned)guard;
    struct li2_rseq_state wanted=before;wanted.syscall_checks++;
    if(args[1]){wanted.range_checks++;wanted.last_first=(uintptr_t)args[1];wanted.last_end=(uintptr_t)args[1]+16;}
    REQUIRE(!guard&&fixture_equal(&state,&wanted,sizeof state)&&fixture_equal(args,saved_args,sizeof args)&&fixture_equal(ub,u,sizeof *u));
    lh[9]=state.syscall_checks;lh[10]=state.range_checks;lh[11]=state.last_first;lh[12]=state.last_end;
    issued++;long result=raw(SYS_clock_getres,args[0],args[1],args[2],args[3],args[4],args[5]);
    REQUIRE(!li2_rseq_after_syscall(SYS_clock_getres,args)&&fixture_equal(&state,&wanted,sizeof state)&&fixture_equal(args,saved_args,sizeof args));
    u->uc_mcontext.gregs[REG_RAX]=result;u->uc_mcontext.gregs[REG_RCX]=(greg_t)(fixture_target+2);
    u->uc_mcontext.gregs[REG_R11]=(greg_t)fixture_pre[16];u->uc_mcontext.gregs[REG_RIP]=(greg_t)(fixture_target+2);
    u->uc_mcontext.gregs[REG_EFL]=(greg_t)fixture_pre[16];
    fixture_copy(ua,u,sizeof *u);lh[6]=capture(u,ka);REQUIRE(lh[5]==lh[6]&&fixture_equal(kb,ka,FP_BYTES));
}
static void emit_lane(void){
    write_all(lh,sizeof lh);write_all(fixture_pre,sizeof fixture_pre);write_all(fixture_post,sizeof fixture_post);
    write_all(fixture_pre_fp,FP_BYTES);write_all(fixture_post_fp,FP_BYTES);write_all(kb,FP_BYTES);write_all(ka,FP_BYTES);
    write_all(ub,UC_BYTES);write_all(ua,UC_BYTES);write_all(sb,sizeof sb);write_all(sa,sizeof sa);
    write_all(ob,sizeof ob);write_all(oa,sizeof oa);write_all(cb,sizeof cb);write_all(ca,sizeof ca);
}
int main(int argc,char **argv){
    if(argc!=2||argv[1][0]<'0'||argv[1][0]>'4'||argv[1][1])return 2;
    mode=(unsigned)(argv[1][0]-'0');
    REQUIRE(RAW(SYS_getpid,0,0,0,0,0,0)==RAW(SYS_gettid,0,0,0,0,0,0)&&!fixture_xstate_prepare());
    REQUIRE(sizeof(ucontext_t)<=UC_BYTES&&NGREG==23);
    code=mmap(0,2*PAGE,3,0x22,-1,0);output=mmap(0,PAGE,3,0x22,-1,0);stack_mem=mmap(0,4*PAGE,3,0x22,-1,0);
    alt=mmap(0,ALT+2*PAGE,PROT_NONE,0x22,-1,0);REQUIRE(code!=MAP_FAILED&&output!=MAP_FAILED&&stack_mem!=MAP_FAILED&&alt!=MAP_FAILED&&!mprotect(alt+PAGE,ALT,3));
    fixture_target=(uintptr_t)code+PAGE-2;code[PAGE-2]=15;code[PAGE-1]=5;
    const unsigned char jump[6]={0xff,0x25,0,0,0,0};fixture_copy(code+PAGE,jump,6);uintptr_t endpoint=(uintptr_t)fixture_post_entry;fixture_copy(code+PAGE+6,&endpoint,8);
    REQUIRE(!mprotect(code+PAGE,PAGE,5));
    uint64_t prior_mask=0;stack_t prior_alt;struct action prior={0};
    REQUIRE(!RAW(SYS_rt_sigprocmask,SIG_SETMASK,0,&prior_mask,8,0,0)&&!RAW(SYS_sigaltstack,0,&prior_alt,0,0,0,0)&&
        (prior_alt.ss_flags&SS_DISABLE)&&!RAW(SYS_rt_sigaction,SIGSEGV,0,&prior,8,0,0)&&!prior.handler);
    mask=UINT64_MAX&~((UINT64_C(1)<<10)|(UINT64_C(1)<<8)|(UINT64_C(1)<<18));
    stack_t ss={.ss_sp=alt+PAGE,.ss_size=ALT};struct action a={handler,SA_SIGINFO|SA_ONSTACK|SA_NODEFER|UINT64_C(0x04000000),fixture_restorer,mask};
    REQUIRE(!RAW(SYS_sigaltstack,&ss,0,0,0,0,0)&&!RAW(SYS_rt_sigaction,SIGSEGV,&a,0,8,0,0)&&!RAW(SYS_rt_sigprocmask,SIG_SETMASK,&mask,0,8,0,0));
    header[0]=MAGIC;header[1]=1;header[2]=mode;header[3]=fixture_target;header[4]=(uintptr_t)output;header[5]=fixture_enabled;header[6]=fixture_mask;
    header[7]=sizeof(ucontext_t);header[8]=offsetof(ucontext_t,uc_mcontext.gregs);header[9]=offsetof(ucontext_t,uc_mcontext.fpregs);header[10]=offsetof(ucontext_t,uc_sigmask);header[11]=mask;
    header[12]=(uintptr_t)supplied+8;header[13]=sizeof(struct li2_rseq_state);header[14]=2;
    write_all(header,sizeof header);write_all(fixture_components,sizeof fixture_components);
    unsigned char native_page[PAGE];uint64_t native_post[24];
    for(lane=0;lane<2;lane++){
        memset(lh,0,sizeof lh);memset(kb,0,sizeof kb);memset(ka,0,sizeof ka);memset(ub,0,sizeof ub);memset(ua,0,sizeof ua);
        memset(fixture_pre_fp,0,FP_BYTES);memset(fixture_post_fp,0,FP_BYTES);memset(fixture_pre,0,sizeof fixture_pre);memset(fixture_post,0,sizeof fixture_post);
        REQUIRE(!mprotect(output,PAGE,3));memset(output,0xa5,PAGE);if(mode==4)REQUIRE(!mprotect(output,PAGE,1));
        state=(struct li2_rseq_state){0};state.initialized=state.registered=state.held=state.tls_complete=1;state.phase=LI2_RSEQ_ACTIVE;state.address=(uintptr_t)supplied;
        for(unsigned i=0;i<16;i++)fixture_input[i]=UINT64_C(0xa112233445566700)+i*UINT64_C(0x01010101010101);
        fixture_input[0]=SYS_clock_getres;fixture_input[4]=(uintptr_t)stack_mem+2*PAGE;fixture_input[7]=mode==2||mode==3?UINT64_MAX:4;
        fixture_input[6]=mode==1||mode==3?0:(uintptr_t)output;fixture_input[16]=UINT64_C(0xad7);
        for(size_t i=0;i<512;i++)((unsigned char *)(uintptr_t)fixture_input[4]-256)[i]=(unsigned char)(19+i*29);
        fixture_copy(sb,(const void *)(uintptr_t)(fixture_input[4]-256),512);fixture_copy(ob,output,PAGE);fixture_copy(cb,code,2*PAGE);
        REQUIRE(!mprotect(code,PAGE,lane?1:5));faults=issued=0;fixture_enter();
        REQUIRE(fixture_equal(fixture_pre,fixture_input,sizeof fixture_input));
        long expected=mode==2||mode==3?-22:mode==4?-14:0;REQUIRE((long)fixture_post[0]==expected);
        uint64_t wanted[17];fixture_copy(wanted,fixture_input,sizeof wanted);wanted[0]=(uint64_t)expected;wanted[1]=fixture_target+2;wanted[11]=fixture_input[16];
        REQUIRE(fixture_equal(wanted,fixture_post,sizeof wanted)&&faults==lane&&issued==lane&&!supplied[1]);
        fixture_copy(sa,(const void *)(uintptr_t)(fixture_input[4]-256),512);fixture_copy(oa,output,PAGE);fixture_copy(ca,code,2*PAGE);
        REQUIRE(fixture_equal(sb,sa,512)&&fixture_equal(cb,ca,2*PAGE));
        if(mode==0){struct timespec t;fixture_copy(&t,oa,16);REQUIRE(t.tv_sec>=0&&t.tv_nsec>=0&&t.tv_nsec<1000000000&&(t.tv_sec||t.tv_nsec)&&fixture_equal(ob+16,oa+16,PAGE-16));}
        else REQUIRE(fixture_equal(ob,oa,PAGE));
        if(!lane){fixture_copy(native_page,oa,PAGE);fixture_copy(native_post,fixture_post,sizeof native_post);}
        else REQUIRE(fixture_equal(native_page,oa,PAGE)&&fixture_equal(native_post,fixture_post,sizeof native_post));
        lh[0]=lane;lh[1]=(uint64_t)expected;lh[2]=faults;lh[3]=issued;lh[4]=fixture_input[6];emit_lane();
    }
    REQUIRE(!RAW(SYS_rt_sigaction,SIGSEGV,&prior,0,8,0,0)&&!RAW(SYS_sigaltstack,&prior_alt,0,0,0,0,0)&&!RAW(SYS_rt_sigprocmask,SIG_SETMASK,&prior_mask,0,8,0,0));
    struct action actual={0};stack_t actual_alt;uint64_t actual_mask=0;
    REQUIRE(!RAW(SYS_rt_sigaction,SIGSEGV,0,&actual,8,0,0)&&fixture_equal(&actual,&prior,sizeof prior)&&
        !RAW(SYS_sigaltstack,0,&actual_alt,0,0,0,0)&&actual_alt.ss_sp==prior_alt.ss_sp&&actual_alt.ss_size==prior_alt.ss_size&&actual_alt.ss_flags==prior_alt.ss_flags&&
        !RAW(SYS_rt_sigprocmask,SIG_SETMASK,0,&actual_mask,8,0,0)&&actual_mask==prior_mask);
    REQUIRE(!munmap(code,2*PAGE)&&!munmap(output,PAGE)&&!munmap(stack_mem,4*PAGE)&&!munmap(alt,ALT+2*PAGE));
    puts("LI2_CLOCK_GETRES_COMPONENT 1");return 0;
}
