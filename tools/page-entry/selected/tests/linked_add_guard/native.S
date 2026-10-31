.text
.globl ag_native_enter
.type ag_native_enter,@function
ag_native_enter:
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp,ag_native_host_sp(%rip)
    int3
.globl ag_native_start
ag_native_start:
    ud2
.size ag_native_enter,.-ag_native_enter
.globl ag_native_return
.type ag_native_return,@function
ag_native_return:
    cld
    movq ag_native_host_sp(%rip),%rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    ret
.size ag_native_return,.-ag_native_return
.section .note.GNU-stack,"",@progbits
