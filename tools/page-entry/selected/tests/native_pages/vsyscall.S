/* Real-ld.so ET_DYN fixture. The selected write/exit sites are on separate
   pages from the candidate-free page containing the genuine legacy CALL.
   Baseline: 16-byte reached marker followed by a checked 32-byte result.
   Confined run: reached marker only, followed by terminal seccomp refusal. */
.section .text.start,"ax",@progbits
.global _start,li2_vsyscall_clean,li2_vsyscall_call,li2_vsyscall_return
.global li2_vsyscall_value,li2_vsyscall_result,li2_vsyscall_prefix
.type _start,@function
_start:
    mov $1,%eax
    mov $1,%edi
    lea li2_vsyscall_prefix(%rip),%rsi
    mov $16,%edx
    syscall
    cmp $16,%rax
    jne li2_vsyscall_fail
    jmp li2_vsyscall_clean
    .org 4096,0x90
.size _start,.-_start

.section .text.call,"ax",@progbits
li2_vsyscall_clean:
    mov %rsp,%r15
    lea li2_vsyscall_value(%rip),%rdi
    movabs $0xffffffffff600400,%rax
li2_vsyscall_call:
    call *%rax
li2_vsyscall_return:
    test %rax,%rax
    jle li2_vsyscall_fail
    cmp li2_vsyscall_value(%rip),%rax
    jne li2_vsyscall_fail
    mov %rax,li2_vsyscall_result(%rip)
    sub %rsp,%r15
    jne li2_vsyscall_fail
    mov %r15,li2_vsyscall_stack_delta(%rip)
    jmp li2_vsyscall_complete
    .org 4096,0x90

.section .text.tail,"ax",@progbits
li2_vsyscall_complete:
    mov $1,%eax
    mov $1,%edi
    lea li2_vsyscall_value(%rip),%rsi
    mov $32,%edx
    syscall
    cmp $32,%rax
    jne li2_vsyscall_fail
    mov $231,%eax
    xor %edi,%edi
    syscall
    ud2
li2_vsyscall_fail:
    mov $231,%eax
    mov $99,%edi
    syscall
    ud2
    .org 4096,0x90

.section .data,"aw",@progbits
.balign 64
li2_vsyscall_prefix:
    .quad 0x5653595343414c4c,1
li2_vsyscall_value:
    .quad -1
li2_vsyscall_result:
    .quad -1
li2_vsyscall_stack_delta:
    .quad -1
    .quad 0x434f4d504c455445
.section .note.GNU-stack,"",@progbits
