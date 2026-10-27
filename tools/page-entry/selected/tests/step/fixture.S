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
    /* Deliberately exercise kernel FP-frame restoration; the owner must not
       depend on its handler helpers or the Rust decoder being integer-only. */
    pxor %xmm0,%xmm0
    pxor %xmm7,%xmm7
    pxor %xmm15,%xmm15
    ret
.global fixture_enter
.type fixture_enter,@function
.macro capture_live out
    /* MOV stores preserve every observed GPR and arithmetic flag. These are
       actual user-mode selectors, not the kernel's zero FS/GS frame slots. */
    movq $1,\out+LI2_LIVE_STARTED(%rip)
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
    movw %cs,\out+LI2_LIVE_SELECTORS+0(%rip)
    movw %ss,\out+LI2_LIVE_SELECTORS+2(%rip)
    movw %ds,\out+LI2_LIVE_SELECTORS+4(%rip)
    movw %es,\out+LI2_LIVE_SELECTORS+6(%rip)
    movw %fs,\out+LI2_LIVE_SELECTORS+8(%rip)
    movw %gs,\out+LI2_LIVE_SELECTORS+10(%rip)
    /* After the MOV prefix RF has naturally cleared. PUSHFQ observes these
       actual flags; it is not an observation of arbitrary original RF. */
    lea fixture_observer_end(%rip),%rsp
    pushfq
    popq \out+LI2_LIVE_FLAGS(%rip)
    mov \out+32(%rip),%rsp
    movq $1,\out+LI2_LIVE_COMPLETE(%rip)
.endm
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
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    movdqa fixture_vectors+32*\reg(%rip),%xmm\reg
    .endr
    testq $4,fixture_xcr0(%rip)
    jz 1f
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    vmovdqa fixture_vectors+32*\reg(%rip),%ymm\reg
    .endr
1:
    lea fixture_subject_end(%rip),%rsp
    .irp off,0,8,16,24,32,40,48,56,64,72,80,88,96,104,112,120
    movabs $0x31557799bbddeeff,%rax
    mov %rax,-128+\off(%rsp)
    .endr
    /* POPFQ selects only this fixture's controlled arithmetic/DF state.
       The succeeding ordinary instructions establish RF=0. The saved image
       is an independent known-input flags observation, not NX-frame masking. */
    pushq $0x647
    popfq
    pushfq
    popq fixture_flags(%rip)
    movabs $0x0123456789abcdef,%rax
    movabs $0x1122334455667788,%rcx
    movabs $0x2233445566778899,%rdx
    movabs $0x33445566778899aa,%rbx
    movabs $0x445566778899aabb,%rbp
    movabs $0x5566778899aabbcc,%rsi
    movabs $0x66778899aabbccdd,%rdi
    movabs $0x778899aabbccddee,%r8
    movabs $0x8899aabbccddeeff,%r9
    movabs $0x99aabbccddeeff10,%r10
    movabs $0xaabbccddeeff1021,%r11
    movabs $0xbbccddeeff102132,%r12
    movabs $0xccddeeff10213243,%r13
    movabs $0xddeeff1021324354,%r14
    movabs $0xeeff102132435465,%r15
    capture_live fixture_live_before
    jmp *fixture_target(%rip)
.size fixture_enter,.-fixture_enter
.global fixture_capture_return
.type fixture_capture_return,@function
fixture_capture_return:
    /* Diagnostic RX continuation entered only after the real native endpoint
       or mandatory stepped next-NX endpoint was retained and all fetch pages
       closed. rt_sigreturn, not handler-local state, supplies these values. */
    capture_live fixture_live_after
    jmp fixture_return
.size fixture_capture_return,.-fixture_capture_return
.global fixture_return
.type fixture_return,@function
fixture_return:
    /* Reached only after the independent signal endpoint has been copied.
       No returned subject state is inferred from this C-ABI restoration. */
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
.p2align 12
fixture_subject: .zero 65536
fixture_subject_end:
.p2align 4
fixture_observer: .zero 4096
fixture_observer_end:
.section .note.GNU-stack,"",@progbits
