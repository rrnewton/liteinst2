#ifndef LI2_NATIVE_SECCOMP_H
#define LI2_NATIVE_SECCOMP_H

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#define LI2_NATIVE_SECCOMP_INSTRUCTIONS 13U
#define LI2_NATIVE_SECCOMP_MAX_GATEWAY 4096U
#define LI2_NATIVE_SECCOMP_X32_BIT UINT32_C(0x40000000)
enum li2_native_seccomp_reason {
    LI2_NATIVE_SECCOMP_ARCH=1, LI2_NATIVE_SECCOMP_X32=2,
    LI2_NATIVE_SECCOMP_IP=3
};
typedef long (*li2_native_seccomp_raw6)(long,long,long,long,long,long,long);

/* Pure construction only. The caller independently authenticates the exact
   private gateway and preserves its executable lifetime. This helper neither
   grants mapping ownership nor prevents application entry into that gateway.
   Linux's syscall instruction_pointer is checked as a full 64-bit value. The
   supplied range must include the saved post-SYSCALL PC (and sigreturn site).
   Invalid arguments leave the caller's output untouched. */
static inline int li2_native_seccomp_construct(struct sock_filter *out,size_t capacity,
                                               uintptr_t first,uintptr_t end) {
    if(!out || capacity!=LI2_NATIVE_SECCOMP_INSTRUCTIONS || !first || end<=first ||
       end-first>LI2_NATIVE_SECCOMP_MAX_GATEWAY || (first>>32)!=(end>>32) ||
       (end>>63))return -EINVAL;
    const struct sock_filter code[LI2_NATIVE_SECCOMP_INSTRUCTIONS]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRAP|LI2_NATIVE_SECCOMP_ARCH),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,LI2_NATIVE_SECCOMP_X32_BIT,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRAP|LI2_NATIVE_SECCOMP_X32),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)+4),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(first>>32),0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)),
        BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,(uint32_t)first,0,2),
        BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,(uint32_t)end,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRAP|LI2_NATIVE_SECCOMP_IP),
    };
    for(size_t i=0;i<LI2_NATIVE_SECCOMP_INSTRUCTIONS;i++)out[i]=code[i];
    return 0;
}

/* Install before any target instruction, under actual singleton ownership.
   All raw calls, including subsequent signal reporting/termination/restoration,
   must execute inside the authenticated range. Keep SUD independently enabled.
   A nonzero return is terminal for an enabling caller: NO_NEW_PRIVS may already
   be set, and no caller may continue target execution without the filter.
   A seccomp SIGSYS is a terminal confinement refusal, never an ordinary syscall
   dispatch request. In particular vsyscall emulation can place the saved RIP at
   its CALL continuation while si_call_addr still identifies the vsyscall.
   This API does not change the runtime's signal dispatcher or enable a profile. */
static inline long li2_native_seccomp_install(li2_native_seccomp_raw6 raw,
                                              uintptr_t first,uintptr_t end) {
    if(!raw)return -EINVAL;
    struct sock_filter code[LI2_NATIVE_SECCOMP_INSTRUCTIONS];
    int error=li2_native_seccomp_construct(code,LI2_NATIVE_SECCOMP_INSTRUCTIONS,first,end);
    if(error)return error;
    struct sock_fprog program={.len=LI2_NATIVE_SECCOMP_INSTRUCTIONS,.filter=code};
    long result=raw(SYS_prctl,PR_SET_NO_NEW_PRIVS,1,0,0,0,0);
    if(result)return result<0?result:-EPROTO;
    result=raw(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,(long)&program,0,0,0);
    return result<=0?result:-EPROTO;
}
#endif
