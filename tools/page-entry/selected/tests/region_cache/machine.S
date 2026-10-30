#include "machine.h"
.text
.global region_restorer
region_restorer:
    mov $15,%eax
    syscall
    ud2
.macro capture dst,fp
    mov %rax,\dst+0(%rip)
    mov %rcx,\dst+8(%rip)
    mov %rdx,\dst+16(%rip)
    mov %rbx,\dst+24(%rip)
    mov %rsp,\dst+32(%rip)
    mov %rbp,\dst+40(%rip)
    mov %rsi,\dst+48(%rip)
    mov %rdi,\dst+56(%rip)
    mov %r8,\dst+64(%rip)
    mov %r9,\dst+72(%rip)
    mov %r10,\dst+80(%rip)
    mov %r11,\dst+88(%rip)
    mov %r12,\dst+96(%rip)
    mov %r13,\dst+104(%rip)
    mov %r14,\dst+112(%rip)
    mov %r15,\dst+120(%rip)
    movw %cs,\dst+136(%rip)
    movw %ss,\dst+138(%rip)
    movw %ds,\dst+140(%rip)
    movw %es,\dst+142(%rip)
    movw %fs,\dst+144(%rip)
    movw %gs,\dst+146(%rip)
    lea observer_end(%rip),%rsp
    pushfq
    popq \dst+128(%rip)
    mov region_xcr0(%rip),%eax
    mov region_xcr0+4(%rip),%edx
    xsave64 \fp(%rip)
    mov \dst+0(%rip),%rax
    mov \dst+16(%rip),%rdx
    mov \dst+32(%rip),%rsp
.endm
.global region_enter
.type region_enter,@function
region_enter:
    mov %rsp,caller(%rip)
    mov %rbx,caller+8(%rip)
    mov %rbp,caller+16(%rip)
    mov %r12,caller+24(%rip)
    mov %r13,caller+32(%rip)
    mov %r14,caller+40(%rip)
    mov %r15,caller+48(%rip)
    pushfq
    popq caller+56(%rip)
    mov region_xcr0(%rip),%eax
    mov region_xcr0+4(%rip),%edx
    xsave64 host_fp(%rip)
    fninit
    fld1
    fldpi
    ldmxcsr mxcsr(%rip)
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    vmovdqa64 vectors+64*\reg(%rip),%zmm\reg
    .endr
    .irp reg,0,1,2,3,4,5,6,7
    kmovq masks+8*\reg(%rip),%k\reg
    .endr
    lea observer_end(%rip),%rsp
    pushq region_input_flags(%rip)
    popfq
    mov region_seed+0(%rip),%rax
    mov region_seed+8(%rip),%rcx
    mov region_seed+16(%rip),%rdx
    mov region_seed+24(%rip),%rbx
    mov region_seed+32(%rip),%rsp
    mov region_seed+40(%rip),%rbp
    mov region_seed+48(%rip),%rsi
    mov region_seed+56(%rip),%rdi
    mov region_seed+64(%rip),%r8
    mov region_seed+72(%rip),%r9
    mov region_seed+80(%rip),%r10
    mov region_seed+88(%rip),%r11
    mov region_seed+96(%rip),%r12
    mov region_seed+104(%rip),%r13
    mov region_seed+112(%rip),%r14
    mov region_seed+120(%rip),%r15
    capture region_before,region_fp_before
    jmp *region_target(%rip)
.size region_enter,.-region_enter
.global region_capture
.type region_capture,@function
region_capture:
    capture region_after,region_fp_after
    lea observer_end(%rip),%rsp
    cld
    mov region_xcr0(%rip),%eax
    mov region_xcr0+4(%rip),%edx
    xrstor64 host_fp(%rip)
    pushq caller+56(%rip)
    popfq
    mov caller+8(%rip),%rbx
    mov caller+16(%rip),%rbp
    mov caller+24(%rip),%r12
    mov caller+32(%rip),%r13
    mov caller+40(%rip),%r14
    mov caller+48(%rip),%r15
    mov caller(%rip),%rsp
    ret
.size region_capture,.-region_capture
.section .rodata
.p2align 2
mxcsr: .long 0x1f80
.p2align 6
vectors:
.set v,1
.rept 256
.quad 0x3141592653589793+v
.set v,v+1
.endr
masks:
.quad 0x0123456789abcdef,0xfedcba9876543210,0xaaaaaaaa55555555,0x0f0ff0f0a5a55a5a
.quad 0x1111222233334444,0x8877665544332211,0xffff00000000ffff,0x5a5a5a5aa5a5a5a5
.bss
.p2align 6
host_fp: .zero REGION_FP
caller: .zero 64
observer: .zero 4096
observer_end:
.section .note.GNU-stack,"",@progbits
