/* Freestanding process entry and kernel signal restorer; no C runtime/TLS. */
.section .interp,"a",@progbits
.asciz LI2_CROSS_PAIR_INTERPRETER
.section .rodata.cross_pair_dynamic,"a",@progbits
.globl cross_pair_dynstr
cross_pair_dynstr:.byte 0
.section .data.cross_pair_dynamic,"aw",@progbits
.p2align 3
.globl cross_pair_dynamic
cross_pair_dynamic:
.quad 5,cross_pair_dynstr,10,1,0,0
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
.globl cross_pair_restorer
.type cross_pair_restorer,@function
cross_pair_restorer:
    mov $15,%eax
    syscall
    ud2
.size cross_pair_restorer,.-cross_pair_restorer
.section .note.GNU-stack,"",@progbits
