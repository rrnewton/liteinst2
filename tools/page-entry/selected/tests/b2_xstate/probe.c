#define _GNU_SOURCE
#include <asm/prctl.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error "This observation probe requires Linux x86-64"
#endif
#define CAP 65536U
#define ALT (128U*1024U)
#define MAGIC UINT64_C(0x315053584232494c)
struct capture {
    volatile uint64_t h[64];
    uint64_t hardware[32];
    uint32_t cpuid[67][6]; /* actual leaf0, leaf1, leaf7.0, then D.0..D.63 */
    unsigned char parent_regs[216],parent_si[128],parent_xstate[CAP];
    unsigned char child_si[128],child_uc[2048],child_fp[CAP],source[4096];
};
_Static_assert(sizeof(struct capture)==140064,"explicit complete wire size");
_Static_assert(sizeof(struct user_regs_struct)==216 && sizeof(siginfo_t)==128,"raw ptrace layouts");
_Static_assert(sizeof(ucontext_t)==968 && offsetof(ucontext_t,uc_mcontext.gregs)==40 &&
    offsetof(ucontext_t,uc_mcontext.fpregs)==224 && offsetof(ucontext_t,uc_sigmask)==296,
    "closed actual libc signal layout; refuse a different header ABI");
_Static_assert(offsetof(siginfo_t,si_addr)==16,"raw siginfo address field");
static struct capture *record;
static unsigned char *source,*alt;
extern void b2_probe_enter(void *) __attribute__((noreturn));

static long raw4(long n,long a,long b,long c,long d) {
    long result;
    register long fourth __asm__("r10")=d;
    register long fifth __asm__("r8")=0,sixth __asm__("r9")=0;
    __asm__ volatile("syscall":"=a"(result):"0"(n),"D"(a),"S"(b),"d"(c),"r"(fourth),"r"(fifth),"r"(sixth):"rcx","r11","cc","memory");
    return result;
}
static long raw3(long n,long a,long b,long c) {return raw4(n,a,b,c,0);}
static void bytes(void *to,const void *from,size_t n) {
    volatile unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static uint32_t word(const unsigned char *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static int inside(uintptr_t at,size_t n) {
    uintptr_t lo=(uintptr_t)alt;
    return at>=lo && n<=ALT && at-lo<=ALT-n;
}
static void cpuid(unsigned index,uint32_t leaf,uint32_t sub) {
    uint32_t a,b,c,d;
    __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"0"(leaf),"2"(sub):"memory");
    uint32_t *r=record->cpuid[index];r[0]=leaf;r[1]=sub;r[2]=a;r[3]=b;r[4]=c;r[5]=d;
}
static int hardware(void) {
    uint64_t *h=record->hardware;unsigned cpu=0,node=0;
    h[0]=(uint64_t)raw3(SYS_getpid,0,0,0);
    h[1]=(uint64_t)raw3(SYS_getcpu,(long)&cpu,(long)&node,0);h[2]=cpu;h[3]=node;
    cpuid(0,0,0);cpuid(1,1,0);cpuid(2,7,0);
    if(record->cpuid[0][2]<13 || (record->cpuid[1][4]&UINT32_C(0x0c000000))!=UINT32_C(0x0c000000))return 1;
    for(unsigned i=0;i<64;i++)cpuid(3+i,13,i);
    uint32_t lo,hi;
    __asm__ volatile("xgetbv":"=a"(lo),"=d"(hi):"c"(0):"memory");h[4]=((uint64_t)hi<<32)|lo;h[5]=1;
    uint64_t supported=0,permitted=0;
    h[6]=(uint64_t)raw3(SYS_arch_prctl,ARCH_GET_XCOMP_SUPP,(long)&supported,0);h[7]=supported;
    h[8]=(uint64_t)raw3(SYS_arch_prctl,ARCH_GET_XCOMP_PERM,(long)&permitted,0);h[9]=permitted;
    cpu=node=0;h[10]=(uint64_t)raw3(SYS_getcpu,(long)&cpu,(long)&node,0);h[11]=cpu;h[12]=node;
    if(h[1] || h[6] || h[8] || h[10] || h[2]!=h[11])return 2;
    __asm__ volatile("":::"memory");h[13]=1;return 0;
}
static void child_exit(int status) __attribute__((noreturn));
static void child_exit(int status) {
    (void)raw3(SYS_exit_group,status,0,0);__builtin_trap();
}
static void handler(int sig,siginfo_t *si,void *context) {
    ucontext_t *uc=context;volatile uint64_t *h=record->h;
    if(h[25])child_exit(112);
    h[25]=1;h[28]=(uint64_t)sig;h[29]=(uintptr_t)uc;h[30]=(uintptr_t)si;
    h[32]=sizeof *uc;h[33]=sizeof *si;h[35]=offsetof(ucontext_t,uc_mcontext.gregs);
    h[36]=offsetof(ucontext_t,uc_mcontext.fpregs);h[37]=offsetof(ucontext_t,uc_sigmask);
    if(!inside((uintptr_t)uc,sizeof *uc) || !inside((uintptr_t)si,sizeof *si)) {h[27]=1;child_exit(113);}
    bytes(record->child_si,si,sizeof *si);bytes(record->child_uc,uc,sizeof *uc);
    bytes((void *)&h[45],&uc->uc_sigmask,8);
    const unsigned char *fp=(const void *)uc->uc_mcontext.fpregs;h[31]=(uintptr_t)fp;
    if(!inside((uintptr_t)fp,512) || ((uintptr_t)fp&15)) {h[27]=2;child_exit(114);}
    size_t n=512;
    if(word(fp+464)==UINT32_C(0x46505853)) {
        n=word(fp+468);
        if(n<580 || n>CAP || !inside((uintptr_t)fp,n) || word(fp+480)!=n-4 ||
           word(fp+n-4)!=UINT32_C(0x46505845)) {h[27]=3;child_exit(115);}
    }
    h[34]=n;bytes(record->child_fp,fp,n);
    uint64_t supported=0,permitted=0,fs=0,gs=0;unsigned cpu=0,node=0;
    h[38]=(uint64_t)raw3(SYS_arch_prctl,ARCH_GET_XCOMP_SUPP,(long)&supported,0);h[40]=supported;
    h[39]=(uint64_t)raw3(SYS_arch_prctl,ARCH_GET_XCOMP_PERM,(long)&permitted,0);h[41]=permitted;
    h[42]=(uint64_t)raw3(SYS_getcpu,(long)&cpu,(long)&node,0);h[43]=cpu;h[44]=node;
    h[49]=(uint64_t)raw3(SYS_arch_prctl,ARCH_GET_FS,(long)&fs,0);h[50]=fs;
    h[51]=(uint64_t)raw3(SYS_arch_prctl,ARCH_GET_GS,(long)&gs,0);h[52]=gs;
    unsigned short ds,es;__asm__ volatile("mov %%ds,%0; mov %%es,%1":"=r"(ds),"=r"(es)::"memory");h[53]=ds;h[54]=es;
    if(sig!=SIGSEGV || si->si_signo!=SIGSEGV || si->si_errno || si->si_code!=SEGV_ACCERR ||
       si->si_addr!=source || uc->uc_mcontext.gregs[REG_RIP]!=(greg_t)(uintptr_t)source ||
       uc->uc_mcontext.gregs[REG_TRAPNO]!=14 || uc->uc_mcontext.gregs[REG_ERR]!=21 ||
       uc->uc_mcontext.gregs[REG_CR2]!=(greg_t)(uintptr_t)source || h[38] || h[39] || h[42] || h[49] || h[51]) {
        h[27]=4;child_exit(116);
    }
    __asm__ volatile("":::"memory");h[26]=1;h[55]=1;
    child_exit(0); /* Faulting instruction is never resumed or emulated. */
}
static uint64_t now(void) {
    struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;
    return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static int wait_until(pid_t pid,int *status,uint64_t deadline) {
    for(;;) {
        pid_t r=waitpid(pid,status,WNOHANG|__WALL);
        if(r==pid)return r;
        if(r<0 && errno!=EINTR)return -1;
        uint64_t t=now();if(!t || t>=deadline)return 0;
        const struct timespec pause={0,1000000};(void)nanosleep(&pause,0);
    }
}
static void problem(unsigned code) {
    if(!record->h[6]) {record->h[6]=code;record->h[7]=(uint64_t)errno;}
}
static int save(int dir) {
    int fd=openat(dir,"record.bin",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return -1;
    size_t at=0;
    while(at<sizeof *record) {
        ssize_t n=write(fd,(const unsigned char *)record+at,sizeof *record-at);
        if(n<0 && errno==EINTR)continue;
        if(n<=0) {close(fd);return -1;}at+=(size_t)n;
    }
    int error=fsync(fd);
    if(close(fd))error=-1;
    return error;
}
int main(int argc,char **argv) {
    if(argc!=2 || argv[1][0]!='/' || mkdir(argv[1],0700))return 2;
    int dir=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(dir<0)return 2;
    record=mmap(0,sizeof *record,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if(record==MAP_FAILED) {close(dir);return 2;}
    memset(record,0,sizeof *record);record->h[0]=MAGIC;record->h[1]=1;record->h[2]=sizeof *record;
    record->h[3]=(uint64_t)getpid();record->h[46]=now();
    unsigned char *area=mmap(0,ALT+8192,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    source=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(area==MAP_FAILED || source==MAP_FAILED) {problem(1);goto finish;}
    alt=area+4096;
    if(mprotect(alt,ALT,PROT_READ|PROT_WRITE)) {problem(2);goto finish;}
    for(size_t i=0;i<ALT;i+=4096)alt[i]=0;
    source[0]=0x90;source[1]=0x0f;source[2]=0x0b;bytes(record->source,source,4096);
    record->h[20]=(uintptr_t)source;record->h[21]=4096;record->h[23]=(uintptr_t)alt;record->h[24]=ALT;
    record->h[22]=(uint64_t)mprotect(source,4096,PROT_READ);
    if(record->h[22]) {problem(3);goto finish;}
    pid_t pid=fork();if(pid>0)record->h[4]=(uint64_t)pid;
    if(pid<0) {problem(4);goto finish;}
    if(!pid) {
        if(raw3(SYS_prctl,PR_SET_PDEATHSIG,SIGKILL,0) || raw3(SYS_getppid,0,0,0)!=(long)record->h[3])child_exit(120);
        stack_t stack={.ss_sp=alt,.ss_size=ALT};struct sigaction action={0};
        action.sa_sigaction=handler;action.sa_flags=SA_SIGINFO|SA_ONSTACK;sigfillset(&action.sa_mask);
        if(sigaltstack(&stack,0) || sigaction(SIGSEGV,&action,0))child_exit(121);
        uint64_t chosen=~((UINT64_C(1)<<(SIGSEGV-1))|(UINT64_C(1)<<(SIGKILL-1))|(UINT64_C(1)<<(SIGSTOP-1)));
        uint64_t old=0,actual=0;
        record->hardware[16]=(uint64_t)raw4(SYS_rt_sigprocmask,SIG_SETMASK,(long)&chosen,(long)&old,8);
        record->hardware[15]=old;record->hardware[17]=chosen;
        record->hardware[18]=(uint64_t)raw4(SYS_rt_sigprocmask,SIG_SETMASK,0,(long)&actual,8);
        record->hardware[19]=actual;
        if(record->hardware[16] || record->hardware[18] || actual!=chosen)child_exit(125);
        int error=hardware();if(error) {record->hardware[14]=(uint64_t)error;child_exit(122);}
        if(ptrace(PTRACE_TRACEME,0,0,0))child_exit(123);
        if(raw3(SYS_tgkill,(long)record->hardware[0],raw3(SYS_gettid,0,0,0),SIGSTOP))child_exit(124);
        b2_probe_enter(source);
    }
    int status=0,reaped=0;uint64_t deadline=record->h[46]+UINT64_C(8000000000);
    int got=wait_until(pid,&status,deadline);record->h[8]=(uint64_t)(unsigned)status;
    if(got==pid && (WIFEXITED(status)||WIFSIGNALED(status))) {reaped=1;record->h[16]=pid;record->h[10]=(unsigned)status;}
    if(got!=pid || !WIFSTOPPED(status) || WSTOPSIG(status)!=SIGSTOP) {problem(5);goto cleanup;}
    record->h[5]=1;
    if(ptrace(PTRACE_SETOPTIONS,pid,0,(void *)(uintptr_t)PTRACE_O_EXITKILL) || ptrace(PTRACE_CONT,pid,0,0)) {problem(6);goto cleanup;}
    got=wait_until(pid,&status,deadline);record->h[9]=(uint64_t)(unsigned)status;
    if(got==pid && (WIFEXITED(status)||WIFSIGNALED(status))) {reaped=1;record->h[16]=pid;record->h[10]=(unsigned)status;}
    if(got!=pid || !WIFSTOPPED(status) || WSTOPSIG(status)!=SIGSEGV) {problem(7);goto cleanup;}
    record->h[5]=2;
    record->h[11]=(uint64_t)ptrace(PTRACE_GETSIGINFO,pid,0,record->parent_si);
    record->h[12]=(uint64_t)ptrace(PTRACE_GETREGS,pid,0,record->parent_regs);
    struct iovec iov={record->parent_xstate,CAP};
    record->h[13]=(uint64_t)ptrace(PTRACE_GETREGSET,pid,(void *)(uintptr_t)NT_X86_XSTATE,&iov);record->h[14]=iov.iov_len;
    record->h[56]=(uint64_t)ptrace(0x420a,pid,(void *)(uintptr_t)8,(void *)&record->h[48]);
    if(record->h[11] || record->h[12] || record->h[13] || record->h[56] || iov.iov_len<576 || iov.iov_len>CAP ||
       record->cpuid[3][3]>CAP || record->cpuid[3][4]>CAP) {problem(8);goto cleanup;}
    record->h[5]=3; /* Complete actual pre-delivery ptrace observation. */
    record->h[15]=(uint64_t)ptrace(PTRACE_CONT,pid,0,(void *)(uintptr_t)SIGSEGV);
    if(record->h[15]) {problem(9);goto cleanup;}
    got=wait_until(pid,&status,deadline);record->h[10]=(uint64_t)(unsigned)status;
    if(got==pid && (WIFEXITED(status)||WIFSIGNALED(status))) {reaped=1;record->h[16]=pid;}
    if(got!=pid || !WIFEXITED(status) || WEXITSTATUS(status)!=0 || !record->h[26] || record->h[27])problem(10);
    else record->h[5]=4;
cleanup:
    if(!reaped) {
        record->h[17]=1;record->h[18]=(uint64_t)kill(pid,SIGKILL);
        got=wait_until(pid,&status,now()+UINT64_C(2000000000));record->h[10]=(uint64_t)(unsigned)status;
        if(got==pid && (WIFEXITED(status)||WIFSIGNALED(status))) {record->h[16]=pid;reaped=1;}
        else record->h[19]=1;
    }
    if(!reaped)problem(11);
finish:
    record->h[47]=now()-record->h[46];
    if(save(dir)) {close(dir);return 3;}close(dir);
    return record->h[6] || record->h[27] ? 1:0;
}
