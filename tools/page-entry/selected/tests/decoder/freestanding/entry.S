    .text
    .global _start
    .type _start,@function
_start:
    xor %ebp,%ebp
    and $-16,%rsp
    call harness_main
    mov %eax,%edi
    mov $231,%eax
    syscall
    ud2
    .size _start,.-_start
    .section .note.GNU-stack,"",@progbits
