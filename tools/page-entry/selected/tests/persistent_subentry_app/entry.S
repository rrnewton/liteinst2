/* Freestanding process entry and kernel signal restorer; no C runtime/TLS. */
.section .interp,"a",@progbits
.asciz LI2_SUBENTRY_INTERPRETER
.section .rodata.subentry_dynamic,"a",@progbits
.globl subentry_dynstr
subentry_dynstr:.byte 0
.section .data.subentry_dynamic,"aw",@progbits
.p2align 3
.globl subentry_dynamic
subentry_dynamic:
.quad 5,subentry_dynstr,10,1,0,0
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
.globl subentry_restorer
.type subentry_restorer,@function
subentry_restorer:
    mov $15,%eax
    syscall
    ud2
.size subentry_restorer,.-subentry_restorer
.section .note.GNU-stack,"",@progbits
