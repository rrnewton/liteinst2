.text
.globl se_native_enter
.type se_native_enter,@function
se_native_enter:
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp,se_native_host_sp(%rip)
    int3
.globl se_native_start
se_native_start:
    ud2
.size se_native_enter,.-se_native_enter
.globl se_native_return
.type se_native_return,@function
se_native_return:
    cld
    movq se_native_host_sp(%rip),%rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    ret
.size se_native_return,.-se_native_return
.section .note.GNU-stack,"",@progbits
