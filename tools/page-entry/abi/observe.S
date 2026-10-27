#include "record.h"
#include "capability.inc"
.text
.hidden abi_record
.hidden abi_collect
#if ABI_PRE
#define ENTRY _abi_kernel_entry
.hidden _start
#else
#define ENTRY _abi_interpreter_entry
#endif
.global ENTRY
.hidden ENTRY
.type ENTRY,@function
ENTRY:
#if ABI_NEGATIVE == 1
    /* Explicit test-only post-transfer corruption; positive has neither. */
    mov $1,%r12
#elif ABI_NEGATIVE == 2
    notb -8(%rsp)
#endif
.global _abi_capture
.hidden _abi_capture
_abi_capture:
    mov %rax,abi_record+32(%rip)
    mov %rbx,abi_record+40(%rip)
    mov %rcx,abi_record+48(%rip)
    mov %rdx,abi_record+56(%rip)
    mov %rsi,abi_record+64(%rip)
    mov %rdi,abi_record+72(%rip)
    mov %rbp,abi_record+80(%rip)
    mov %rsp,abi_record+88(%rip)
    mov %r8,abi_record+96(%rip)
    mov %r9,abi_record+104(%rip)
    mov %r10,abi_record+112(%rip)
    mov %r11,abi_record+120(%rip)
    mov %r12,abi_record+128(%rip)
    mov %r13,abi_record+136(%rip)
    mov %r14,abi_record+144(%rip)
    mov %r15,abi_record+152(%rip)
    lea abi_private_stack_end(%rip),%rsp
    pushfq
    popq abi_record+160(%rip)
    lea _abi_capture(%rip),%rax
    mov %rax,abi_record+168(%rip)
    xor %ecx,%ecx
    xgetbv
    mov %eax,abi_record+176(%rip)
    mov %edx,abi_record+180(%rip)
    mov $1,%ecx
    xgetbv
    mov %eax,abi_record+184(%rip)
    mov %edx,abi_record+188(%rip)
    mov abi_record+176(%rip),%rax
    movabs $CAP_XCR0,%rdx
    cmp %rdx,%rax
    jne 9f
    mov abi_record+176(%rip),%eax
    mov abi_record+180(%rip),%edx
    /* No CPUID, syscall or C code precedes this actual endpoint capture. */
    xsave64 abi_record+384(%rip)
    cld
    mov $ABI_PRE,%edi
    call abi_collect
#if ABI_PRE
    mov abi_record+176(%rip),%eax
    mov abi_record+180(%rip),%edx
    xrstor64 abi_record+384(%rip)
    pushq abi_record+160(%rip)
    popfq
    mov abi_record+32(%rip),%rax
    mov abi_record+40(%rip),%rbx
    mov abi_record+48(%rip),%rcx
    mov abi_record+56(%rip),%rdx
    mov abi_record+64(%rip),%rsi
    mov abi_record+72(%rip),%rdi
    mov abi_record+80(%rip),%rbp
    mov abi_record+96(%rip),%r8
    mov abi_record+104(%rip),%r9
    mov abi_record+112(%rip),%r10
    mov abi_record+120(%rip),%r11
    mov abi_record+128(%rip),%r12
    mov abi_record+136(%rip),%r13
    mov abi_record+144(%rip),%r14
    mov abi_record+152(%rip),%r15
    mov abi_record+88(%rip),%rsp
    jmp _start
#else
    mov $231,%eax
    mov $23,%edi
    syscall
    ud2
#endif
9:  mov $231,%eax
    mov $124,%edi
    syscall
    ud2
.size ENTRY,.-ENTRY
.bss
.p2align 4
abi_private_stack: .zero 131072
abi_private_stack_end:
.section .note.GNU-stack,"",@progbits
