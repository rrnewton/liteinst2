/* Positive builtin program source. IMAGE_ROLE1 is the actual ET_DYN
   interpreter; IMAGE_ROLE2 is main. No setup precedes either entry clock. */
#ifndef PB_NEGATIVE
#define PB_NEGATIVE 0
#endif
#if PB_NEGATIVE < 0 || PB_NEGATIVE > 12
#error invalid finite negative selector
#endif
#ifndef ENTRY_KIND
#error actual interpreter entry kind is required
#endif
#ifndef IMAGE_ROLE
#error actual image role is required
#endif
.section .text.main,"ax",@progbits
.global _start
_start:
#if IMAGE_ROLE == 1 && ENTRY_KIND == 2
    .byte 0x0f,0x01,0xf9,0x90,0x90
#elif (IMAGE_ROLE == 1 && ENTRY_KIND == 1) || IMAGE_ROLE == 2
    .byte 0x0f,0x31,0x90,0x90,0x90
#else
#error unsupported image role/entry kind
#endif
    jmp pl_capture_entry

/* Six actual syscall arguments are seeded independently. Stores happen before
   the unchanged full-state seed body; they are not provider result adapters. */
.macro prepare name,next,number=0,write_kind=0
setup_\name:
    movabs $0x5162738495a6b7c8,%r10
    mov %r10,%r11
    mov %r11,%r12
    cmp %rax,%rax
    lea site_\name(%rip),%rax
    mov %rax,pl_target(%rip)
    lea \next(%rip),%rax
    mov %rax,pl_after(%rip)
    movabs $0xa501020304050607,%rax
.if \number
    mov $\number,%eax
.endif
    mov %rax,pl_rax(%rip)
    movabs $0xb608090a0b0c0d0e,%rax
    mov %rax,pl_rcx(%rip)
.irp r,rdx,rsi,rdi,r8,r9,r10
    movabs $0x31425364758697a8,%rax
    mov %rax,pl_\r(%rip)
.endr
.if \write_kind
    movq $1,pl_rdi(%rip)
    lea pl_output(%rip),%rax
    movq $16,pl_rdx(%rip)
.if \write_kind == 1
    lea site_\name(%rip),%rax
    movq $5,pl_rdx(%rip)
.elseif \write_kind == 2
    lea _start(%rip),%rax
    movq $5,pl_rdx(%rip)
.elseif \write_kind == 4
    movq $-1,pl_rdi(%rip)
.endif
    mov %rax,pl_rsi(%rip)
.endif
.if \number == 231
    movq $0,pl_rdi(%rip)
.endif
    jmp pl_seed
.global site_\name
site_\name:
.endm
.macro finish
    jmp pl_capture
.endm
#if IMAGE_ROLE == 1
    prepare i_rdtsc,setup_i_rdtscp
    .byte 0x0f,0x31,0x90,0x90,0x90
    finish
    prepare i_rdtscp,setup_i_getpid
    .byte 0x0f,0x01,0xf9
    finish
#if PB_NEGATIVE == 12
    prepare i_getpid,setup_i_gettid,157
#else
    prepare i_getpid,setup_i_gettid,39
#endif
    .byte 0x0f,0x05,0x90,0x90,0x90
    finish
    prepare i_gettid,setup_i_write,186
    .byte 0x0f,0x05,0x90,0x90,0x90
    finish
    prepare i_write,setup_i_ebadf,1,3
    .byte 0x0f,0x05,0x90,0x90,0x90
    finish
    prepare i_ebadf,interpreter_done,1,4
    .byte 0x0f,0x05,0x90,0x90,0x90
    finish
interpreter_done:
    movabs $0x200401000,%rax
    jmp *%rax
#else
    prepare m_rdtscp,setup_m_rdtsc
    .byte 0x0f,0x01,0xf9
    finish
    prepare m_rdtsc,setup_m_getpid
    .byte 0x0f,0x31,0x90,0x90,0x90
    finish
    prepare m_getpid,setup_m_gettid,39
    .byte 0x0f,0x05,0x90,0x90,0x90
    finish
    prepare m_gettid,setup_m_write_self,186
    .byte 0x0f,0x05,0x90,0x90,0x90
    finish
    prepare m_write_self,setup_m_write_clock,1,1
    .byte 0x0f,0x05,0x90,0x90,0x90
    finish
    prepare m_write_clock,setup_m_write_output,1,2
    .byte 0x0f,0x05,0x90,0x90,0x90
    finish
    prepare m_write_output,setup_m_exit,1,3
    .byte 0x0f,0x05,0x90,0x90,0x90
    finish
    prepare m_exit,unreturned_exit,231
.global pl_exit
.set pl_exit,site_m_exit
    .byte 0x0f,0x05,0x90,0x90,0x90
unreturned_exit:
    ud2
#endif
    .org 4096,0xcc

/* Whole actual emitted page and both halos must satisfy the unchanged native
   policy before execution. No exception is made for PUSHFQ/POPFQ or SIMD. */
.section .text.helper,"ax",@progbits
.global pl_seed,pl_capture
pl_seed:
    fninit
    fld1
    fldpi
.irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    vmovdqu64 pl_vectors+64*\n(%rip),%zmm\n
.endr
.irp n,0,1,2,3,4,5,6,7
    kmovq pl_masks+8*\n(%rip),%k\n
.endr
    lea pl_stack_top(%rip),%rsp
    pushq $0xed7
    popfq
    mov pl_rax(%rip),%rax
    mov pl_rcx(%rip),%rcx
    mov pl_rdx(%rip),%rdx
    movabs $0x1122334455667703,%rbx
    movabs $0x1122334455667705,%rbp
    mov pl_rsi(%rip),%rsi
    mov pl_rdi(%rip),%rdi
.irp n,8,9,10
    mov pl_r\n(%rip),%r\n
.endr
.irp n,11,12,13,14,15
    movabs $(0x1122334455667700+\n),%r\n
.endr
    jmp *pl_target(%rip)
pl_capture:
    /* No scratch GPR precedes the complete live capture. */
    mov %rax,pl_live_gpr+0(%rip)
    mov %rcx,pl_live_gpr+8(%rip)
    mov %rdx,pl_live_gpr+16(%rip)
    mov %rbx,pl_live_gpr+24(%rip)
    mov %rsp,pl_live_gpr+32(%rip)
    mov %rbp,pl_live_gpr+40(%rip)
    mov %rsi,pl_live_gpr+48(%rip)
    mov %rdi,pl_live_gpr+56(%rip)
.irp n,8,9,10,11,12,13,14,15
    mov %r\n,pl_live_gpr+8*\n(%rip)
.endr
    mov %cs,pl_live_selectors+0(%rip)
    mov %ss,pl_live_selectors+2(%rip)
    mov %ds,pl_live_selectors+4(%rip)
    mov %es,pl_live_selectors+6(%rip)
    mov %fs,pl_live_selectors+8(%rip)
    mov %gs,pl_live_selectors+10(%rip)
    pushfq
    popq pl_live_flags(%rip)
.irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    vmovdqu64 %zmm\n,pl_live_vectors+64*\n(%rip)
.endr
.irp n,0,1,2,3,4,5,6,7
    kmovq %k\n,pl_live_masks+8*\n(%rip)
.endr
    jmp *pl_after(%rip)
pl_capture_entry:
    /* No scratch GPR precedes the complete live capture. */
    mov %rax,pl_live_gpr+0(%rip)
    mov %rcx,pl_live_gpr+8(%rip)
    mov %rdx,pl_live_gpr+16(%rip)
    mov %rbx,pl_live_gpr+24(%rip)
    mov %rsp,pl_live_gpr+32(%rip)
    mov %rbp,pl_live_gpr+40(%rip)
    mov %rsi,pl_live_gpr+48(%rip)
    mov %rdi,pl_live_gpr+56(%rip)
.irp n,8,9,10,11,12,13,14,15
    mov %r\n,pl_live_gpr+8*\n(%rip)
.endr
    mov %cs,pl_live_selectors+0(%rip)
    mov %ss,pl_live_selectors+2(%rip)
    mov %ds,pl_live_selectors+4(%rip)
    mov %es,pl_live_selectors+6(%rip)
    mov %fs,pl_live_selectors+8(%rip)
    mov %gs,pl_live_selectors+10(%rip)
    pushfq
    popq pl_live_flags(%rip)
.irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    vmovdqu64 %zmm\n,pl_live_vectors+64*\n(%rip)
.endr
.irp n,0,1,2,3,4,5,6,7
    kmovq %k\n,pl_live_masks+8*\n(%rip)
.endr
#if IMAGE_ROLE == 1
    jmp setup_i_rdtsc
#else
    jmp setup_m_rdtscp
#endif
    .org 4096,0xcc

.section .data.fixture,"aw",@progbits
.global pl_data,pl_data_end,pl_output,pl_vectors,pl_masks,pl_live_vectors,pl_live_masks
.global pl_live_gpr,pl_live_flags,pl_live_selectors,pl_stack_top
pl_data:
    .quad 0x31504c5244565250,ENTRY_KIND
pl_target: .quad 0
pl_after: .quad 0
pl_rax: .quad 0
pl_rcx: .quad 0
pl_rdx: .quad 0
pl_rsi: .quad 0
pl_rdi: .quad 0
pl_r8: .quad 0
pl_r9: .quad 0
pl_r10: .quad 0
    .org 104,0
.global pb_negative
pb_negative: .quad PB_NEGATIVE
    .org 128,0
pl_output:
    .ascii "LI2-BUILTINS-OK!"
    .quad 0,0,0,0
    .org 512,0
pl_vectors:
.set zr,0
.rept 32
.set zb,0
.rept 64
    .byte 1+((zr*17+zb*13)%255)
.set zb,zb+1
.endr
.set zr,zr+1
.endr
pl_masks:
.set kr,0
.rept 8
    .quad 0x1020304050607080+kr*0x0101010101010101
.set kr,kr+1
.endr
    .org 4096,0
pl_live_vectors: .zero 2048
pl_live_masks: .zero 64
pl_live_gpr: .zero 128
pl_live_flags: .quad 0
pl_live_selectors: .zero 12
    .org 16320,0xa5
pl_stack_top:
    .org 16384,0xa5
pl_data_end:
.section .note.GNU-stack,"",@progbits
.section .dynstr.fixture,"a",@progbits
.asciz "li2-provider-builtins-entry.so"
