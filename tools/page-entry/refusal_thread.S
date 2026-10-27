.text
.globl actual_clone
.hidden actual_clone
.type actual_clone,@function
actual_clone:
    mov %rdi,%rsi
    mov $0x50f00,%edi /* VM | FS | FILES | SIGHAND | THREAD | SYSVSEM */
    xor %edx,%edx
    xor %r10d,%r10d
    xor %r8d,%r8d
    mov $56,%eax
    syscall
    test %rax,%rax
    jne 1f
    movl $1,thread_seen(%rip)
    xor %edi,%edi
    mov $60,%eax
    syscall
    ud2
1:  ret
.size actual_clone,.-actual_clone

.section .text.li2_probe_target,"ax",@progbits
.balign 4096
.globl protected_target
.hidden protected_target
.type protected_target,@function
protected_target:
    mov $7,%eax
    ret
.fill 4096-(.-protected_target),1,0x90
.size protected_target,.-protected_target
.section .note.GNU-stack,"",@progbits
