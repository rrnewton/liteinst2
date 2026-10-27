.text
.global _start
.type _start,@function
_start:
    cpuid
    mov (%rsp),%rcx
    lea 16(%rsp,%rcx,8),%rsi
1:  lodsq
    test %rax,%rax
    jne 1b
2:  lodsq
    mov %rax,%rcx
    lodsq
    cmp $9,%rcx
    je 3f
    test %rcx,%rcx
    jne 2b
    ud2
3:  jmp *%rax
.size _start,.-_start
.section .note.GNU-stack,"",@progbits
