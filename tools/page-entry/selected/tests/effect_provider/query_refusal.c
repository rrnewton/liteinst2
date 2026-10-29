#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

extern const ptrdiff_t __rseq_offset __attribute__((weak));
extern const unsigned int __rseq_size __attribute__((weak));
extern const unsigned int __rseq_flags __attribute__((weak));
/* Real default-loader child. Each query would write the actual pinned rseq
   area if issued. The gate must terminate before the raw syscall; reaching
   the return below is a failed control. Do not execute this fixture natively. */
int main(int argc,char **argv) {
    if(argc!=2 || !argv[1][0] || argv[1][1] || !&__rseq_offset ||
       !&__rseq_size || !&__rseq_flags || __rseq_size<20 || __rseq_flags)return 98;
    uintptr_t address=(uintptr_t)__builtin_thread_pointer();ptrdiff_t offset=__rseq_offset;
    if(offset>=0) {
        if((uintptr_t)offset>UINTPTR_MAX-address)return 98;
        address+=(uintptr_t)offset;
    } else {
        uintptr_t magnitude=(uintptr_t)(-(offset+1))+1;
        if(magnitude>address)return 98;
        address-=magnitude;
    }
    if((address&31) || address>UINTPTR_MAX-32 || *(const volatile uint64_t *)(address+8))return 98;
    switch(argv[1][0]) {
    case '1':(void)syscall(SYS_arch_prctl,0x1021,address+8);break;
    case '2':(void)syscall(SYS_arch_prctl,0x1022,address+8);break;
    case '3':(void)syscall(SYS_rt_sigprocmask,0,0,address+8,8);break;
    case '4':(void)syscall(SYS_getcpu,address+8,0,0);break;
    case '5':(void)syscall(SYS_getcpu,0,address+8,0);break;
    default:return 98;
    }
    return 99;
}
