.text
.p2align 4
.global li2_gateway_start,li2_gateway_end,li2_raw6,li2_gateway_syscall_return
.type li2_raw6,@function
li2_gateway_start:
li2_raw6:
    mov %rdi,%rax
    mov %rsi,%rdi
    mov %rdx,%rsi
    mov %rcx,%rdx
    mov %r8,%r10
    mov %r9,%r8
    mov 8(%rsp),%r9
    syscall
li2_gateway_syscall_return:
    ret
.size li2_raw6,.-li2_raw6
.global li2_restorer
.type li2_restorer,@function
li2_restorer:
    mov $15,%eax
    syscall
    ud2
.size li2_restorer,.-li2_restorer
li2_gateway_end:
.p2align 4
.global outside_getpid,outside_syscall_return
.type outside_getpid,@function
outside_getpid:
    mov $39,%eax
    syscall
outside_syscall_return:
    ret
.size outside_getpid,.-outside_getpid
.global compat_getpid,compat_syscall_return
.type compat_getpid,@function
compat_getpid:
    mov $20,%eax
    int $0x80
compat_syscall_return:
    ret
.size compat_getpid,.-compat_getpid
.section .note.GNU-stack,"",@progbits
