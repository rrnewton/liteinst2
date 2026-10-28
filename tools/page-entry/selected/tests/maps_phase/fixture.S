.text
.global _start
.type _start,@function
_start:
    mov %rsp,%rdi
    and $-16,%rsp
    call fixture_main
    ud2
.size _start,.-_start
.global kernel_raw
.type kernel_raw,@function
kernel_raw:
    mov %rdi,%rax
    mov %rsi,%rdi
    mov %rdx,%rsi
    mov %rcx,%rdx
    mov %r8,%r10
    mov %r9,%r8
    mov 8(%rsp),%r9
    syscall
    ret
.size kernel_raw,.-kernel_raw
.global fixture_restorer
.type fixture_restorer,@function
fixture_restorer:
    mov $15,%eax
    syscall
    ud2
.size fixture_restorer,.-fixture_restorer
.section .note.GNU-stack,"",@progbits
