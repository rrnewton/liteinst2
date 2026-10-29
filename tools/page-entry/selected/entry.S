.text
.hidden li2_boot
.hidden li2_fail
.hidden li2_saved
.hidden li2_xstate
.hidden li2_xmask
.hidden li2_xmode
.hidden li2_target
.global _start
.hidden _start
.type _start,@function
_start:
    mov %rax,li2_saved+0(%rip)
    mov %rbx,li2_saved+8(%rip)
    mov %rcx,li2_saved+16(%rip)
    mov %rdx,li2_saved+24(%rip)
    mov %rsi,li2_saved+32(%rip)
    mov %rdi,li2_saved+40(%rip)
    mov %rbp,li2_saved+48(%rip)
    mov %rsp,li2_saved+56(%rip)
    mov %r8,li2_saved+64(%rip)
    mov %r9,li2_saved+72(%rip)
    mov %r10,li2_saved+80(%rip)
    mov %r11,li2_saved+88(%rip)
    mov %r12,li2_saved+96(%rip)
    mov %r13,li2_saved+104(%rip)
    mov %r14,li2_saved+112(%rip)
    mov %r15,li2_saved+120(%rip)
    lea li2_private_stack_end(%rip),%rsp
    pushfq
    popq li2_saved+128(%rip)
    mov $1,%eax
    cpuid
    and $0x0c000000,%ecx
    cmp $0x0c000000,%ecx
    jne 1f
    xor %ecx,%ecx
    xgetbv
    mov %eax,li2_xmask(%rip)
    mov %edx,li2_xmask+4(%rip)
    mov $13,%eax
    xor %ecx,%ecx
    cpuid
    cmp $65536,%ebx
    ja 9f
    mov li2_xmask(%rip),%eax
    mov li2_xmask+4(%rip),%edx
    xsave64 li2_xstate(%rip)
    movq $1,li2_xmode(%rip)
    jmp 2f
1:  fxsave64 li2_xstate(%rip)
2:  lea li2_private_stack_end(%rip),%rsp
    and $-16,%rsp
    cld
    mov li2_saved+56(%rip),%rdi
    call li2_boot
    mov %rax,li2_target(%rip)
#ifdef LI2_ENTRY_TIMING
    .hidden li2_entry_time_start
    mov %rax,%rdi
    call li2_entry_time_start
#endif
    cmpq $0,li2_xmode(%rip)
    je 3f
    mov li2_xmask(%rip),%eax
    mov li2_xmask+4(%rip),%edx
    xrstor64 li2_xstate(%rip)
    jmp 4f
3:  fxrstor64 li2_xstate(%rip)
4:  pushq li2_saved+128(%rip)
    popfq
    mov li2_saved+0(%rip),%rax
    mov li2_saved+8(%rip),%rbx
    mov li2_saved+16(%rip),%rcx
    mov li2_saved+24(%rip),%rdx
    mov li2_saved+32(%rip),%rsi
    mov li2_saved+40(%rip),%rdi
    mov li2_saved+48(%rip),%rbp
    mov li2_saved+64(%rip),%r8
    mov li2_saved+72(%rip),%r9
    mov li2_saved+80(%rip),%r10
    mov li2_saved+88(%rip),%r11
    mov li2_saved+96(%rip),%r12
    mov li2_saved+104(%rip),%r13
    mov li2_saved+112(%rip),%r14
    mov li2_saved+120(%rip),%r15
    mov li2_saved+56(%rip),%rsp
    jmp *li2_target(%rip)
9:  mov $231,%eax
    mov $125,%edi
    syscall
    ud2
.size _start,.-_start

.p2align 4
.global li2_gateway_start
.hidden li2_gateway_start
li2_gateway_start:
.global li2_raw6
.hidden li2_raw6
.type li2_raw6,@function
li2_raw6:
    mov %rdi,%rax
    mov %rsi,%rdi
    mov %rdx,%rsi
    mov %rcx,%rdx
    mov %r8,%r10
    mov %r9,%r8
    mov 8(%rsp),%r9
    syscall
    ret
.size li2_raw6,.-li2_raw6
.global li2_restorer
.hidden li2_restorer
li2_restorer:
    mov $15,%eax
    syscall
    ud2
.global li2_gateway_end
.hidden li2_gateway_end
li2_gateway_end:

.bss
.p2align 6
.global li2_saved
li2_saved: .zero 136
.p2align 6
li2_xstate: .zero 65536
li2_xmask: .zero 8
li2_xmode: .zero 8
li2_target: .zero 8
.p2align 4
li2_private_stack: .zero 262144
li2_private_stack_end:
.section .note.GNU-stack,"",@progbits
