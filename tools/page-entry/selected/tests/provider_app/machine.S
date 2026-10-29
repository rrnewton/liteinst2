/* Existing provider_launch native seed/capture pattern. The entire emitted
   helper page and both 14-byte halos must pass the unchanged native policy.
   These live registers are not a complete XSAVE record. */
#if PA_DSO
#define P(x) pa_dso_##x
#else
#define P(x) pa_main_##x
#endif
.section .text.pa_helper,"ax",@progbits
.balign 4096
.globl P(helper_page),P(helper_end),P(seed_x87)
.hidden P(helper_page),P(helper_end),P(seed_x87)
P(helper_page):
.macro save_gprs name
    mov %rax,\name+0(%rip)
    mov %rcx,\name+8(%rip)
    mov %rdx,\name+16(%rip)
    mov %rbx,\name+24(%rip)
    mov %rsp,\name+32(%rip)
    mov %rbp,\name+40(%rip)
    mov %rsi,\name+48(%rip)
    mov %rdi,\name+56(%rip)
    mov %r8,\name+64(%rip)
    mov %r9,\name+72(%rip)
    mov %r10,\name+80(%rip)
    mov %r11,\name+88(%rip)
    mov %r12,\name+96(%rip)
    mov %r13,\name+104(%rip)
    mov %r14,\name+112(%rip)
    mov %r15,\name+120(%rip)
.endm
.macro save_live name
.irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    vmovdqu64 %zmm\n,\name+64*\n(%rip)
.endr
.irp n,0,1,2,3,4,5,6,7
    kmovq %k\n,\name+2048+8*\n(%rip)
.endr
    fnstcw \name+2112(%rip)
    fnstsw \name+2114(%rip)
.endm
.macro load_gprs name
    mov \name+0(%rip),%rax
    mov \name+8(%rip),%rcx
    mov \name+16(%rip),%rdx
    mov \name+24(%rip),%rbx
    mov \name+40(%rip),%rbp
    mov \name+48(%rip),%rsi
    mov \name+56(%rip),%rdi
    mov \name+64(%rip),%r8
    mov \name+72(%rip),%r9
    mov \name+80(%rip),%r10
    mov \name+88(%rip),%r11
    mov \name+96(%rip),%r12
    mov \name+104(%rip),%r13
    mov \name+112(%rip),%r14
    mov \name+120(%rip),%r15
    mov \name+32(%rip),%rsp
.endm
.globl P(machine),P(capture_before),P(capture_after)
.hidden P(machine),P(capture_before),P(capture_after)
.type P(machine),@function
P(machine):
    mov %rsp,P(host)+0(%rip)
    mov %rbx,P(host)+8(%rip)
    mov %rbp,P(host)+16(%rip)
    mov %r12,P(host)+24(%rip)
    mov %r13,P(host)+32(%rip)
    mov %r14,P(host)+40(%rip)
    mov %r15,P(host)+48(%rip)
    pushfq
    popq P(host)+56(%rip)
    fnstcw P(host_fcw)(%rip)
    fninit
    fld1
P(seed_x87):
    fldpi
.irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    vmovdqu64 P(vectors)+64*\n(%rip),%zmm\n
.endr
.irp n,0,1,2,3,4,5,6,7
    kmovq P(masks)+8*\n(%rip),%k\n
.endr
    pushq P(input)+128(%rip)
    popfq
    load_gprs P(input)
P(capture_before):
    save_gprs P(before)
    mov P(host)(%rip),%rsp
    pushfq
    popq P(before)+128(%rip)
    save_live P(before_live)
    pushq P(before)+128(%rip)
    popfq
    load_gprs P(before)
    jmp *P(target)(%rip)
P(capture_after):
    save_gprs P(after)
    mov P(host)(%rip),%rsp
    pushfq
    popq P(after)+128(%rip)
    save_live P(after_live)
    /* SysV caller-saved vector/x87 data need no invented restore. The x87
       stack is empty on C return; restore its actual incoming control word. */
    fninit
    fldcw P(host_fcw)(%rip)
    mov P(host)+8(%rip),%rbx
    mov P(host)+16(%rip),%rbp
    mov P(host)+24(%rip),%r12
    mov P(host)+32(%rip),%r13
    mov P(host)+40(%rip),%r14
    mov P(host)+48(%rip),%r15
    pushq P(host)+56(%rip)
    popfq
    ret
.size P(machine),.-P(machine)
.org 4096,0xcc
P(helper_end):
.section .note.GNU-stack,"",@progbits
