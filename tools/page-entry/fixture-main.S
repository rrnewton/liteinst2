.text
.global _start
.type _start,@function
_start:
    rdtsc
    mov $39,%eax
    syscall
    test %rax,%rax
    jle 1f
    mov $1,%eax
    mov $1,%edi
    lea text(%rip),%rsi
    mov $15,%edx
    syscall
    cmp $15,%rax
    jne 1f
    mov $231,%eax
    mov $7,%edi
    syscall
1:  mov $231,%eax
    mov $99,%edi
    syscall
    ud2
.size _start,.-_start
.section .rodata
text: .ascii "FIRST_ENTRY_OK\n"
.section .note.GNU-stack,"",@progbits
