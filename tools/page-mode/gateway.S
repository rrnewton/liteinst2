.text
.p2align 4
.hidden li2_gateway_start
.global li2_gateway_start
li2_gateway_start:
.hidden li2_raw6
.global li2_raw6
.type li2_raw6,@function
li2_raw6:
    mov %rdi, %rax
    mov %rsi, %rdi
    mov %rdx, %rsi
    mov %rcx, %rdx
    mov %r8, %r10
    mov %r9, %r8
    mov 8(%rsp), %r9
    syscall
    ret
.size li2_raw6,.-li2_raw6
.p2align 4
.hidden li2_restorer
.global li2_restorer
.type li2_restorer,@function
li2_restorer:
    mov $15, %rax
    syscall
    ud2
.size li2_restorer,.-li2_restorer
.hidden li2_gateway_end
.global li2_gateway_end
li2_gateway_end:
.section .note.GNU-stack,"",@progbits
