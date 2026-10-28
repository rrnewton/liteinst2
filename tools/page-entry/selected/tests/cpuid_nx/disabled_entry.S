/* Ancillary same-process control, never a fresh-exec qualification lane. */
.text
.hidden nx_disabled_entry,nx_disable_setup
.global nx_disabled_entry
.type nx_disabled_entry,@function
nx_disabled_entry:
    pushfq
    push %rax
    push %rcx
    push %rdx
    push %rdi
    push %rsi
    push %r8
    push %r9
    push %r10
    push %r11
    call nx_disable_setup
    test %rax,%rax
    jne 1f
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rsi
    pop %rdi
    pop %rdx
    pop %rcx
    pop %rax
    popfq
    jmp _start
1:  mov $231,%eax
    mov $98,%edi
    syscall
    ud2
.size nx_disabled_entry,.-nx_disabled_entry
.section .note.GNU-stack,"",@progbits
