/* Freestanding ET_DYN main, entered by the real system ld.so. No libc.
   Link with linker.ld, -nostdlib -pie and the actual --dynamic-linker path.
   Native and gated executions each check the original CALL return word and
   saved stack. Their deterministic 128-byte output must match exactly. */
.section .text.call,"ax",@progbits
.global _start,li2_boundary_call,li2_boundary_return,li2_native_callee
.global li2_straddler,li2_straddler_end,li2_boundary_output
.type _start,@function
_start:
    lea li2_boundary_output(%rip),%r14
    mov %rsp,%r15
    movabs $0x1122334455667788,%r10
    xor %eax,%eax
    std
    stc
    pushfq
    pop %rax
    mov %rax,0(%r14)
    jmp li2_boundary_call
    .org 4091,0x90
li2_boundary_call:
    call li2_native_callee
.size _start,.-_start

.section .text.return,"ax",@progbits
li2_boundary_return:
    /* This first instruction has not executed while CALL runs. The page is
       blocked by the explicit CPUID core below, outside the caller's halo. */
    jmp li2_observe_return
    .org 512,0x90
    .byte 0x0f,0xa2 /* deliberately unreachable all-start admission barrier */
    .org 4096,0x90

.section .text.callee,"ax",@progbits
li2_native_callee:
    mov (%rsp),%r11
    mov %r11,24(%r14)
    mov %rsp,32(%r14)
    pushfq
    pop %rax
    mov %rax,8(%r14)
    ret
    .org 256,0x90
li2_observe_return:
    pushfq
    pop %rax
    mov %rax,16(%r14)
    cmp %r15,%rsp
    jne li2_boundary_fail
    lea li2_boundary_return(%rip),%rax
    cmp %rax,24(%r14)
    jne li2_boundary_fail
    lea -8(%r15),%rax
    cmp %rax,32(%r14)
    jne li2_boundary_fail
    cmpq $0x647,0(%r14)
    jne li2_boundary_fail
    cmpq $0x647,8(%r14)
    jne li2_boundary_fail
    cmpq $0x647,16(%r14)
    jne li2_boundary_fail
    movabs $0x1122334455667788,%rax
    cmp %rax,%r10
    jne li2_boundary_fail
    mov %r10,40(%r14)
    /* Raw ASLR-dependent addresses have served their exact checks. Replace
       them with the checked zero deltas for deterministic public output. */
    lea li2_boundary_return(%rip),%rax
    sub %rax,24(%r14)
    lea -8(%r15),%rax
    sub %rax,32(%r14)
    cld
    jmp li2_straddle_entry
    .org 4096,0x90

.section .text.straddle,"ax",@progbits
li2_straddle_entry:
    jmp li2_straddler
    .org 4093,0x90
li2_straddler:
    /* MOVABS $0x1122334455667788,R12, split 3+7. The first page can
       execute natively; the second stays NX because of its later CPUID. */
    .byte 0x49,0xbc,0x88

.section .text.tail,"ax",@progbits
    .byte 0x77,0x66,0x55,0x44,0x33,0x22,0x11
li2_straddler_end:
    mov %r12,48(%r14)
    movabs $0x1122334455667788,%rax
    cmp %rax,%r12
    jne li2_boundary_fail
    cmp %r15,%rsp
    jne li2_boundary_fail
    jmp li2_boundary_cpuid
    .org 256,0x90
li2_boundary_cpuid:
    xor %eax,%eax
    xor %ecx,%ecx
    cpuid
    mov %eax,56(%r14)
    mov %ebx,60(%r14)
    mov %ecx,64(%r14)
    mov %edx,68(%r14)
    movabs $0x4e41544956455047,%rax
    mov %rax,72(%r14)
    mov $1,%eax
    mov $1,%edi
    mov %r14,%rsi
    mov $128,%edx
    syscall
    cmp $128,%rax
    jne li2_boundary_fail
    mov $231,%eax
    xor %edi,%edi
    syscall
    ud2
li2_boundary_fail:
    cld
    mov $231,%eax
    mov $99,%edi
    syscall
    ud2
    .org 4096,0x90

.section .data,"aw",@progbits
.balign 64
li2_boundary_output:
    .zero 128
.section .note.GNU-stack,"",@progbits
