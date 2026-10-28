#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <sys/ucontext.h>
#include <asm/prctl.h>
#include <sys/syscall.h>
extern long li2_raw6(long,long,long,long,long,long,long) __attribute__((visibility("hidden")));
extern void li2_restorer(void) __attribute__((visibility("hidden")));
extern void _start(void) __attribute__((visibility("hidden")));
static uint64_t observation[16];
static void disabled_fault(int sig,siginfo_t *si,void *context) {
    const ucontext_t *u=context;uint64_t mask=0;
    const unsigned char *m=(const void *)&u->uc_sigmask;
    for(unsigned i=0;i<8;i++)mask|=(uint64_t)m[i]<<(8*i);
    observation[2]=(unsigned)sig;observation[3]=(unsigned)si->si_signo;
    observation[4]=(unsigned)si->si_code;observation[5]=(unsigned)si->si_errno;
    observation[6]=(uintptr_t)si->si_addr;observation[7]=(uint64_t)u->uc_mcontext.gregs[REG_RIP];
    observation[8]=(uint64_t)u->uc_mcontext.gregs[REG_TRAPNO];observation[9]=(uint64_t)u->uc_mcontext.gregs[REG_ERR];
    observation[10]=(uint64_t)u->uc_mcontext.gregs[REG_EFL];observation[11]=(uint64_t)u->uc_mcontext.gregs[REG_CSGSFS];
    observation[12]=mask;observation[13]=1;
    const volatile unsigned char *pc=(const void *)(uintptr_t)observation[7];
    observation[14]=(uint64_t)pc[0]|(uint64_t)pc[1]<<8;observation[15]=(uintptr_t)_start;
    long written=li2_raw6(SYS_write,3,(long)observation,sizeof observation,0,0,0);
    (void)li2_raw6(SYS_exit_group,written==(long)sizeof observation?125:97,0,0,0,0,0);
    __builtin_trap();
}
long nx_disable_setup(void) {
    struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} action;
    action.handler=disabled_fault;action.flags=SA_SIGINFO|0x04000000UL;action.restorer=li2_restorer;action.mask=0;
    observation[0]=UINT64_C(0x3147504449555043);
    if(li2_raw6(SYS_rt_sigaction,SIGSEGV,(long)&action,0,8,0,0))return 1;
    observation[1]=(uint64_t)li2_raw6(SYS_arch_prctl,ARCH_SET_CPUID,0,0,0,0,0);
    return observation[1]!=0;
}
