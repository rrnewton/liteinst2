/* Freestanding process entry and kernel signal restorer; no C runtime/TLS. */
.section .interp,"a",@progbits
.asciz LI2_DIRECT_FRONTIER_INTERPRETER
.section .rodata.direct_frontier_dynamic,"a",@progbits
.globl direct_frontier_dynstr
direct_frontier_dynstr:.byte 0
.section .data.direct_frontier_dynamic,"aw",@progbits
.p2align 3
.globl direct_frontier_dynamic
direct_frontier_dynamic:
.quad 5,direct_frontier_dynstr,10,1,0,0
.section .text.startup,"ax",@progbits
.globl _start
.type _start,@function
_start:
    xor %ebp,%ebp
    mov (%rsp),%rdi
    lea 8(%rsp),%rsi
    and $-16,%rsp
    call main
    mov %eax,%edi
    mov $231,%eax
    syscall
    ud2
.size _start,.-_start
.globl direct_frontier_restorer
.type direct_frontier_restorer,@function
direct_frontier_restorer:
    mov $15,%eax
    syscall
    ud2
.size direct_frontier_restorer,.-direct_frontier_restorer
.section .note.GNU-stack,"",@progbits
