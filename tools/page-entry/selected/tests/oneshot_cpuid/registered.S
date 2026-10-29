/* Combined-profile variant only. mmap/rseq enter the real 66 0f 05 at page
   offset4093 and continue at PC+3; its opcode tail remains at offset4094.
   The four canonical registered windows and original two-page layout remain.
   The unchanged canonical setup fixture is still a separate mandatory cohort. */
.section .text.registered,"ax",@progbits
.balign 4096
.globl _start,li2_registered_tail,li2_registered_clock,li2_registered_getpid
.globl li2_registered_writev,li2_registered_exit
_start:
    xor %r12d,%r12d
    xor %edi,%edi
    mov $4096,%esi
    mov $3,%edx
    mov $0x22,%r10d
    mov $-1,%r8
    xor %r9d,%r9d
    mov $9,%eax
    jmp li2_registered_setup
.org 4093,0xcc
.globl li2_registered_setup
li2_registered_setup:
    .byte 0x66
li2_registered_tail:
    .byte 0x0f,0x05
    test %r12d,%r12d
    jnz .Lregistered
    cmp $-4095,%rax
    jae .Lfailed
    mov %rax,%r13
    mov %rax,%rdi
    mov $32,%esi
    xor %edx,%edx
    mov $0x53053053,%r10d
    mov $1,%r12d
    mov $334,%eax
    jmp li2_registered_setup
.Lregistered:
    test %rax,%rax
    jnz .Lfailed
    mov %rax,li2_registered_output+40(%rip)
li2_registered_clock:
    .byte 0x0f,0x31,0x90,0x90,0x90
    mov %rax,li2_registered_output+16(%rip)
    mov %rdx,li2_registered_output+24(%rip)
    mov $39,%eax
li2_registered_getpid:
    .byte 0x0f,0x05,0x90,0x90,0x90
    mov %rax,li2_registered_output+32(%rip)
    lea li2_registered_writev(%rip),%rax
    mov %rax,li2_registered_iov(%rip)
    lea li2_registered_output(%rip),%rax
    mov %rax,li2_registered_iov+16(%rip)
    lea li2_registered_iov(%rip),%rsi
    mov $1,%edi
    mov $2,%edx
    mov $20,%eax
li2_registered_writev:
    .byte 0x0f,0x05,0x90,0x90,0x90
    cmp $53,%rax
    jne .Lfailed
    xor %edi,%edi
    mov $231,%eax
li2_registered_exit:
    .byte 0x0f,0x05,0x90,0x90,0x90
    ud2
.Lfailed:
    mov $99,%edi
    mov $231,%eax
    syscall
    ud2
.org 8192,0xcc
.section .data.registered,"aw",@progbits
.balign 4096
.globl li2_registered_output,li2_registered_iov
li2_registered_output:
    .ascii "LI2-RSEQ-FBACK!\n"
    .zero 32
    .zero 16
li2_registered_iov:
    .quad 0,5,0,48
.org 4096,0
.section .note.GNU-stack,"",@progbits
