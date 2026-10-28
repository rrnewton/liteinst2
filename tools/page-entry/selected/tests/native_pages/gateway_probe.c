#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/ucontext.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "native_seccomp.h"

/* Independent confinement probe. All tested vsyscall entries are actual
   CALL targets; the supplied argument controls below do not issue syscalls. */
extern unsigned char li2_gateway_start[],li2_gateway_end[];
extern unsigned char li2_gateway_syscall_return[],outside_syscall_return[],compat_syscall_return[];
extern long li2_raw6(long,long,long,long,long,long,long);
extern long outside_getpid(void),compat_getpid(void);
#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#define PR_SYS_DISPATCH_ON 1
#endif
#define VSBASE UINT64_C(0xffffffffff600000)
#define X32_BIT UINT32_C(0x40000000)
enum { PLAIN, FILTER, SUD, SUD_FILTER, MODES };
enum { VGETTIMEOFDAY, VTIME, VGETCPU, TRUSTED_GETPID, OUTSIDE_GETPID, COMPAT_GETPID, X32_GETPID, OPS };
struct event {
    uint64_t magic,mode,op,pid,kind,stage;
    int64_t result;
    uint64_t signal,code,error,arch,syscall,call_address,rip,rax,trap,error_code;
    int64_t values[4];
};
_Static_assert(sizeof(struct event)==168,"event extent");
_Static_assert(sizeof(struct sock_filter)==8,"BPF instruction extent");
_Static_assert(sizeof(struct sock_fprog)==16,"BPF program extent");
_Static_assert(sizeof(struct seccomp_data)==64,"seccomp record extent");
_Static_assert(offsetof(struct seccomp_data,nr)==0 && offsetof(struct seccomp_data,arch)==4 &&
               offsetof(struct seccomp_data,instruction_pointer)==8,"seccomp fields");
static unsigned mock_calls,mock_total,mock_bad;
static long mock_first,mock_second;
static long supplied_raw(long nr,long a,long b,long c,long d,long e,long f) {
    unsigned call=mock_calls++;mock_total++;
    if(call==0) {
        if(nr!=SYS_prctl || a!=PR_SET_NO_NEW_PRIVS || b!=1 || c || d || e || f)mock_bad=1;
        return mock_first;
    }
    if(call==1) {
        const struct sock_fprog *program=(const struct sock_fprog *)(uintptr_t)c;
        struct sock_filter expected[LI2_NATIVE_SECCOMP_INSTRUCTIONS];
        if(nr!=SYS_seccomp || a!=SECCOMP_SET_MODE_FILTER || b || !program || d || e || f)mock_bad=1;
        if(program && (li2_native_seccomp_construct(expected,LI2_NATIVE_SECCOMP_INSTRUCTIONS,0x400000,0x400040) ||
           program->len!=LI2_NATIVE_SECCOMP_INSTRUCTIONS || !program->filter ||
           memcmp(program->filter,expected,sizeof(expected))))mock_bad=1;
        return mock_second;
    }
    mock_bad=1;return -EIO;
}
static unsigned header_controls(void) {
    struct sock_filter out[LI2_NATIVE_SECCOMP_INSTRUCTIONS],saved[LI2_NATIVE_SECCOMP_INSTRUCTIONS];
    const uintptr_t ranges[][2]={{0,1},{0x400000,0x400000},{0x400001,0x400000},
        {0x400000,0x401001},{0xfffffff0,0x100000010},{UINT64_C(0x8000000000400000),UINT64_C(0x8000000000400040)}};
    unsigned checks=0;memset(out,0xa5,sizeof(out));memcpy(saved,out,sizeof(out));
    if(li2_native_seccomp_construct(0,LI2_NATIVE_SECCOMP_INSTRUCTIONS,0x400000,0x400040)!=-EINVAL)return 0;
    checks++;
    for(size_t n=12;n<=14;n+=2) {
        if(li2_native_seccomp_construct(out,n,0x400000,0x400040)!=-EINVAL || memcmp(out,saved,sizeof(out)))return 0;
        checks++;
    }
    for(size_t n=0;n<sizeof(ranges)/sizeof(ranges[0]);n++) {
        if(li2_native_seccomp_construct(out,LI2_NATIVE_SECCOMP_INSTRUCTIONS,ranges[n][0],ranges[n][1])!=-EINVAL ||
           memcmp(out,saved,sizeof(out)))return 0;
        checks++;
    }
    if(li2_native_seccomp_construct(out,LI2_NATIVE_SECCOMP_INSTRUCTIONS,0x400000,0x400040))return 0;
    checks++;
    if(li2_native_seccomp_install(0,0x400000,0x400040)!=-EINVAL || mock_total)return 0;
    checks++;
    if(li2_native_seccomp_install(supplied_raw,0,1)!=-EINVAL || mock_total)return 0;
    checks++;
    const long answers[][4]={{-EPERM,0,-EPERM,1},{1,0,-EPROTO,1},
        {0,-EACCES,-EACCES,2},{0,1,-EPROTO,2},{0,0,0,2}};
    for(size_t n=0;n<sizeof(answers)/sizeof(answers[0]);n++) {
        mock_calls=0;mock_first=answers[n][0];mock_second=answers[n][1];
        if(li2_native_seccomp_install(supplied_raw,0x400000,0x400040)!=answers[n][2] ||
           mock_bad || mock_calls!=(unsigned)answers[n][3])return 0;
        checks++;
    }
    return checks;
}
static struct event event;
static int report_fd;
static unsigned char altstack[65536] __attribute__((aligned(64)));
static struct timeval observed_tv;
static time_t observed_time;
static unsigned observed_cpu,observed_node;

static _Noreturn void emit(unsigned status) {
    if(event.op==VGETTIMEOFDAY){event.values[0]=observed_tv.tv_sec;event.values[1]=observed_tv.tv_usec;}
    else if(event.op==VTIME)event.values[0]=observed_time;
    else if(event.op==VGETCPU){event.values[0]=observed_cpu;event.values[1]=observed_node;}
    long n=li2_raw6(SYS_write,report_fd,(long)&event,sizeof(event),0,0,0);
    (void)li2_raw6(SYS_exit_group,n==(long)sizeof(event)?status:126,0,0,0,0,0);
    __builtin_trap();
}
static void caught(int sig,siginfo_t *si,void *raw) {
    const ucontext_t *uc=raw;
    event.kind=2;event.signal=(unsigned)sig;event.code=(uint32_t)si->si_code;
    event.error=(uint32_t)si->si_errno;
    if(sig==SIGSYS) {
        event.arch=si->si_arch;event.syscall=(uint32_t)si->si_syscall;
        event.call_address=(uintptr_t)si->si_call_addr;
    }
    event.rip=(uint64_t)uc->uc_mcontext.gregs[REG_RIP];
    event.rax=(uint64_t)uc->uc_mcontext.gregs[REG_RAX];
    event.trap=(uint64_t)uc->uc_mcontext.gregs[REG_TRAPNO];
    event.error_code=(uint64_t)uc->uc_mcontext.gregs[REG_ERR];
    emit(125);
}
static long install_filter(void) {
    return li2_native_seccomp_install(li2_raw6,(uintptr_t)li2_gateway_start,(uintptr_t)li2_gateway_end);
}
static _Noreturn void child(unsigned mode,unsigned op,int fd) {
    report_fd=fd;event=(struct event){.magic=UINT64_C(0x4757545950524f42),.mode=mode,.op=op,.pid=(uint64_t)getpid()};
    observed_tv=(struct timeval){.tv_sec=-1,.tv_usec=-1};observed_time=-1;
    observed_cpu=UINT32_MAX;observed_node=UINT32_MAX;
    struct rlimit cpu={2,2},core={0,0};
    if(setrlimit(RLIMIT_CPU,&cpu)||setrlimit(RLIMIT_CORE,&core))_exit(127);
    alarm(3);
    stack_t stack={.ss_sp=altstack,.ss_size=sizeof(altstack)};
    struct sigaction action={.sa_sigaction=caught,.sa_flags=SA_SIGINFO|SA_ONSTACK};
    sigfillset(&action.sa_mask);
    if(sigaltstack(&stack,0)||sigaction(SIGSYS,&action,0)||sigaction(SIGSEGV,&action,0)||sigaction(SIGILL,&action,0))_exit(127);
    sigset_t mask;sigemptyset(&mask);
    if(sigprocmask(SIG_SETMASK,&mask,0))_exit(127);
    long result;
    if(mode==SUD || mode==SUD_FILTER) {
        event.stage=1;
        result=li2_raw6(SYS_prctl,PR_SET_SYSCALL_USER_DISPATCH,PR_SYS_DISPATCH_ON,
                        (long)li2_gateway_start,li2_gateway_end-li2_gateway_start,0,0);
        if(result){event.kind=3;event.result=result;emit(126);}
    }
    if(mode==FILTER || mode==SUD_FILTER) {
        event.stage=2;result=install_filter();
        if(result){event.kind=3;event.result=result;emit(126);}
    }
    event.stage=3;
    if(op==VGETTIMEOFDAY) {
        result=((long (*)(struct timeval *,void *))(uintptr_t)VSBASE)(&observed_tv,0);
    } else if(op==VTIME) {
        result=((long (*)(time_t *))(uintptr_t)(VSBASE+0x400))(&observed_time);
    } else if(op==VGETCPU) {
        result=((long (*)(unsigned *,unsigned *,void *))(uintptr_t)(VSBASE+0x800))(&observed_cpu,&observed_node,0);
    } else if(op==TRUSTED_GETPID) result=li2_raw6(SYS_getpid,0,0,0,0,0,0);
    else if(op==OUTSIDE_GETPID) result=outside_getpid();
    else if(op==COMPAT_GETPID) result=compat_getpid();
    else result=li2_raw6(X32_BIT|SYS_getpid,0,0,0,0,0,0);
    event.kind=1;event.result=result;emit(0);
}
int main(void) {
    unsigned controls=header_controls();if(controls!=17 || mock_total!=8)return 4;
    printf("{\"gateway\":[%" PRIuPTR ",%" PRIuPTR "],\"trusted_ip\":%" PRIuPTR
           ",\"outside_ip\":%" PRIuPTR ",\"compat_ip\":%" PRIuPTR ",\"events\":[",
           (uintptr_t)li2_gateway_start,(uintptr_t)li2_gateway_end,(uintptr_t)li2_gateway_syscall_return,
           (uintptr_t)outside_syscall_return,(uintptr_t)compat_syscall_return);
    fflush(stdout);
    for(unsigned mode=0;mode<MODES;mode++)for(unsigned op=0;op<OPS;op++) {
        int fds[2];if(pipe(fds))return 2;
        pid_t pid=fork();if(pid<0)return 3;
        if(!pid){close(fds[0]);child(mode,op,fds[1]);}
        close(fds[1]);struct event e={0};size_t n=0;
        while(n<sizeof(e)) {
            ssize_t got=read(fds[0],(char *)&e+n,sizeof(e)-n);
            if(got<0 && errno==EINTR)continue;
            if(got<=0)break;
            n+=(size_t)got;
        }
        char extra;ssize_t tail=read(fds[0],&extra,1);close(fds[0]);
        int status=0;pid_t waited;
        do {waited=waitpid(pid,&status,0);}while(waited<0 && errno==EINTR);
        printf("%s{\"mode\":%u,\"op\":%u,\"child\":%ld,\"waited\":%ld,\"wait_status\":%d,\"bytes\":%zu,\"extra\":%zd,"
               "\"magic\":%" PRIu64 ",\"record_mode\":%" PRIu64 ",\"record_op\":%" PRIu64 ",\"pid\":%" PRIu64
               ",\"kind\":%" PRIu64 ",\"stage\":%" PRIu64 ",\"result\":%" PRId64
               ",\"signal\":%" PRIu64 ",\"code\":%" PRIu64 ",\"errno\":%" PRIu64
               ",\"arch\":%" PRIu64 ",\"syscall\":%" PRIu64 ",\"call_address\":%" PRIu64
               ",\"rip\":%" PRIu64 ",\"rax\":%" PRIu64 ",\"trap\":%" PRIu64 ",\"error_code\":%" PRIu64
               ",\"values\":[%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64 "]}",
               mode||op?",":"",mode,op,(long)pid,(long)waited,status,n,tail,e.magic,e.mode,e.op,e.pid,e.kind,e.stage,e.result,
               e.signal,e.code,e.error,e.arch,e.syscall,e.call_address,e.rip,e.rax,e.trap,e.error_code,
               e.values[0],e.values[1],e.values[2],e.values[3]);
        fflush(stdout);
    }
    printf("],\"record_bytes\":%zu,\"header_controls\":%u,\"supplied_raw_calls\":%u,\"layout\":[%zu,%zu,%zu,%zu,%zu,%zu]}\n",
           sizeof(struct event),controls,mock_total,sizeof(struct sock_filter),sizeof(struct sock_fprog),
           sizeof(struct seccomp_data),offsetof(struct seccomp_data,nr),offsetof(struct seccomp_data,arch),
           offsetof(struct seccomp_data,instruction_pointer));return 0;
}
