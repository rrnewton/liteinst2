#include "fixture.h"
.text
.global _start
.type _start,@function
_start:
    mov %rsp,%rdi
    and $-16,%rsp
    call fixture_main
    mov %eax,%edi
    mov $231,%eax
    syscall
    ud2
.size _start,.-_start
.global step_restorer
step_restorer:
    mov $15,%eax
    syscall
    ud2
.global fixture_vector_clobber
fixture_vector_clobber:
    pxor %xmm0,%xmm0
    pxor %xmm7,%xmm7
    pxor %xmm15,%xmm15
    ret
.macro capture_live out,fp
    movq $1,\out+LIVE_STARTED(%rip)
    mov %rax,\out+0(%rip)
    mov %rcx,\out+8(%rip)
    mov %rdx,\out+16(%rip)
    mov %rbx,\out+24(%rip)
    mov %rsp,\out+32(%rip)
    mov %rbp,\out+40(%rip)
    mov %rsi,\out+48(%rip)
    mov %rdi,\out+56(%rip)
    mov %r8,\out+64(%rip)
    mov %r9,\out+72(%rip)
    mov %r10,\out+80(%rip)
    mov %r11,\out+88(%rip)
    mov %r12,\out+96(%rip)
    mov %r13,\out+104(%rip)
    mov %r14,\out+112(%rip)
    mov %r15,\out+120(%rip)
    movw %cs,\out+LIVE_SELECTORS+0(%rip)
    movw %ss,\out+LIVE_SELECTORS+2(%rip)
    movw %ds,\out+LIVE_SELECTORS+4(%rip)
    movw %es,\out+LIVE_SELECTORS+6(%rip)
    movw %fs,\out+LIVE_SELECTORS+8(%rip)
    movw %gs,\out+LIVE_SELECTORS+10(%rip)
    /* Own scratch stack: observing flags never writes the target's stack. */
    lea fixture_observer_end(%rip),%rsp
    pushfq
    popq \out+LIVE_FLAGS(%rip)
    mov fixture_xcr0(%rip),%eax
    mov fixture_xcr0+4(%rip),%edx
    xsave64 \fp(%rip)
    mov \out+0(%rip),%rax
    mov \out+16(%rip),%rdx
    mov \out+32(%rip),%rsp
    movq $1,\out+LIVE_COMPLETE(%rip)
.endm
.global fixture_enter
.type fixture_enter,@function
fixture_enter:
    mov %rsp,fixture_caller(%rip)
    mov %rbx,fixture_caller+8(%rip)
    mov %rbp,fixture_caller+16(%rip)
    mov %r12,fixture_caller+24(%rip)
    mov %r13,fixture_caller+32(%rip)
    mov %r14,fixture_caller+40(%rip)
    mov %r15,fixture_caller+48(%rip)
    fninit
    fld1
    fldpi
    ldmxcsr fixture_mxcsr(%rip)
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    movdqa sse2_vectors+32*\reg(%rip),%xmm\reg
    .endr
    testq $4,fixture_xcr0(%rip)
    jz 1f
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    vmovdqa sse2_vectors+32*\reg(%rip),%ymm\reg
    .endr
1:
    lea fixture_observer_end(%rip),%rsp
    pushq fixture_input_flags(%rip)
    popfq
    pushfq
    popq fixture_flags(%rip)
    mov fixture_seed+0(%rip),%rax
    mov fixture_seed+8(%rip),%rcx
    mov fixture_seed+16(%rip),%rdx
    mov fixture_seed+24(%rip),%rbx
    mov fixture_seed+32(%rip),%rsp
    mov fixture_seed+40(%rip),%rbp
    mov fixture_seed+48(%rip),%rsi
    mov fixture_seed+56(%rip),%rdi
    mov fixture_seed+64(%rip),%r8
    mov fixture_seed+72(%rip),%r9
    mov fixture_seed+80(%rip),%r10
    mov fixture_seed+88(%rip),%r11
    mov fixture_seed+96(%rip),%r12
    mov fixture_seed+104(%rip),%r13
    mov fixture_seed+112(%rip),%r14
    mov fixture_seed+120(%rip),%r15
    capture_live fixture_live_before,fixture_fp_before
    jmp *fixture_target(%rip)
.size fixture_enter,.-fixture_enter
.global fixture_capture_return
.type fixture_capture_return,@function
fixture_capture_return:
    /* First actual post-sigreturn instructions preserve all subject values. */
    capture_live fixture_live_after,fixture_fp_after
    jmp fixture_return
.size fixture_capture_return,.-fixture_capture_return
.global fixture_return
.type fixture_return,@function
fixture_return:
    cld
    mov fixture_caller+8(%rip),%rbx
    mov fixture_caller+16(%rip),%rbp
    mov fixture_caller+24(%rip),%r12
    mov fixture_caller+32(%rip),%r13
    mov fixture_caller+40(%rip),%r14
    mov fixture_caller+48(%rip),%r15
    mov fixture_caller(%rip),%rsp
    ret
.size fixture_return,.-fixture_return
.section .rodata
.p2align 2
fixture_mxcsr: .long 0x1f80
.p2align 5
fixture_vectors:
.set seed,1
.rept 64
    .quad 0x3141592653589793+seed
    .set seed,seed+1
.endr
.bss
.p2align 4
fixture_caller: .zero 56
.p2align 4
fixture_observer: .zero 4096
fixture_observer_end:
.section .note.GNU-stack,"",@progbits
