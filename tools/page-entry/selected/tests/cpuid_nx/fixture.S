/* Six finite CPUID route programs; genuine interpreter/main entries precede all seeds. */
#ifndef PROGRAM
#error PROGRAM is required
#endif
.section .text.main,"ax",@progbits
.global _start,nx_exit,nx_write,nx_control
_start:
    cpuid
    jmp setup0
.macro setup n,target,next,leaf=1
setup\n:
    movabs $0x5162738495a6b7c8,%r10
    mov %r10,%r11
    mov %r11,%r12
    cmp %rax,%rax
    lea \target(%rip),%rax
    mov %rax,pl_target(%rip)
    lea \next(%rip),%rax
    mov %rax,pl_after(%rip)
    movabs $(0xa501020300000000+\leaf),%rax
    mov %rax,pl_rax(%rip)
    movabs $0xb608090a00000000,%rax
    mov %rax,pl_rcx(%rip)
    movq $\n,nx_slot(%rip)
    lea nx_embedded_ret+2(%rip),%rax
    mov %rax,pl_stack_top(%rip)
    lea nx_embedded_indirect+2(%rip),%rax
    mov %rax,nx_indirect(%rip)
    jmp pl_seed
.endm
#if PROGRAM == 1
    setup 0,nx_plain0,setup1,1
    setup 1,nx_plain1,nx_finish,7
#elif PROGRAM == 2
    setup 0,nx_ending,setup1,1
    setup 1,nx_split,nx_finish,7
#elif PROGRAM == 3
    setup 0,nx_direct,setup1,1
    setup 1,nx_indirect_branch,setup2,7
    setup 2,nx_return,setup3,1
    setup 3,nx_enclosing,nx_finish,7
#elif PROGRAM == 4
    setup 0,nx_boundary_call,setup1,1
    setup 1,nx_straddler,nx_finish,7
#elif PROGRAM == 5
    setup 0,nx_trace0,setup1,1
    setup 1,nx_trace1,nx_finish,7
#elif PROGRAM == 6
    setup 0,nx_run0,setup1,1
    setup 1,nx_run1,nx_finish,7
#elif PROGRAM == 7 || PROGRAM == 8
    setup 0,nx_plain0,nx_control,1
#else
#error unknown PROGRAM
#endif
nx_control:
    mov $158,%eax
#if PROGRAM == 7
    mov $0x1011,%edi
#else
    mov $0x1012,%edi
#endif
    mov $1,%esi
    syscall
    /* A gated process must stop before this marker is stored or written. */
    movq $1,nx_output+16(%rip)
nx_finish:
    cld
    mov $1,%eax
    mov $1,%edi
    lea nx_output(%rip),%rsi
    mov $9728,%edx
nx_write:
    syscall
    cmp $9728,%rax
    jne nx_fail
    mov $231,%eax
    xor %edi,%edi
nx_exit:
    syscall
    ud2
nx_fail:
    mov $231,%eax
    mov $99,%edi
    syscall
    ud2
    .org 4096,0xcc
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
    movabs $0x1122334455667702,%rdx
    movabs $0x1122334455667703,%rbx
    movabs $0x1122334455667705,%rbp
    movabs $0x1122334455667706,%rsi
    movabs $0x1122334455667707,%rdi
.irp n,8,9,10,11,12,13,14,15
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
    mov nx_slot(%rip),%r8
    imul $2304,%r8,%r8
    lea nx_output+512(%rip),%r9
    add %r8,%r9
    lea pl_live_vectors(%rip),%r8
    mov $288,%ecx
1:  mov (%r8),%rax
    mov %rax,(%r9)
    add $8,%r8
    add $8,%r9
    dec %ecx
    jne 1b
    jmp *pl_after(%rip)

    .org 4096,0xcc
.section .text.routes,"ax",@progbits
.global nx_plain0,nx_plain1,nx_ending,nx_split,nx_direct,nx_indirect_branch,nx_return
.global nx_embedded_direct,nx_embedded_indirect,nx_embedded_ret,nx_enclosing
.global nx_boundary_call,nx_boundary_return,nx_boundary_target,nx_straddler,nx_straddler_end,nx_straddler_cpuid
.global nx_trace0,nx_trace1,nx_trace_cpuid0,nx_trace_cpuid1,nx_run0,nx_run1,nx_run_cpuid0,nx_run_cpuid1
    /* Keep the helper's complete right halo free of selected cores. */
    .org 32,0xcc
nx_plain0: cpuid
    jmp pl_capture
nx_plain1: cpuid
    jmp pl_capture
    .org 4094,0xcc
nx_ending: cpuid
    jmp pl_capture
    .org 8191,0xcc
nx_split: cpuid
    jmp pl_capture
    .org 12288,0xcc
nx_direct: jmp nx_embedded_direct+2
nx_indirect_branch: jmp *nx_indirect(%rip)
nx_return: ret
/* Each original MOVABS contains a real alternate CPUID/JMP instruction stream. */
.macro embedded name
\name:
    .byte 0x48,0xb8,0x0f,0xa2,0xe9
    .long pl_capture-(.+4)
    .byte 0x90
    jmp pl_capture
.endm
    embedded nx_embedded_direct
    embedded nx_embedded_indirect
    embedded nx_embedded_ret
nx_enclosing: jmp nx_embedded_direct
    .org 20475,0xcc
/* This CALL page contains no selected core, including its 14-byte halos. */
nx_boundary_call: call nx_boundary_target
nx_boundary_return: jmp pl_capture
    .org 24576,0xcc
nx_boundary_target: cpuid
    ret
    .org 32765,0xcc
nx_straddler:
    .byte 0x49,0xbc,0x88
    .byte 0x77,0x66,0x55,0x44,0x33,0x22,0x11
nx_straddler_end:
    /* Native admission scans fourteen bytes beyond the preceding page. */
    .rept 9
    nop
    .endr
nx_straddler_cpuid:
    cpuid
    jmp pl_capture
    .org 36864,0xcc
nx_trace0: add $1,%r10
nx_trace_cpuid0: cpuid
    jmp pl_capture
nx_trace1: add $1,%r10
nx_trace_cpuid1: cpuid
    jmp pl_capture
nx_run0: mov %r10,%r11
    mov %r11,%r12
nx_run_cpuid0: cpuid
    jmp pl_capture
nx_run1: mov %r10,%r11
    mov %r11,%r12
nx_run_cpuid1: cpuid
    jmp pl_capture
    .org 57344,0xcc
.section .data.fixture,"aw",@progbits
.global pl_data,pl_data_end,pl_output,pl_vectors,pl_masks,pl_live_vectors,pl_live_masks
.global pl_live_gpr,pl_live_flags,pl_live_selectors,pl_stack_top
pl_data:
    .quad 0x31584e4449555043,PROGRAM
pl_target: .quad 0
pl_after: .quad 0
pl_rax: .quad 0
pl_rcx: .quad 0
nx_slot: .quad 0
nx_indirect: .quad 0
    .org 128,0
pl_output:
    .ascii "LI2-PROVIDER-OK!"
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
    .org 7680,0
.global nx_output
nx_output: .quad 0x3154554f584e5043,PROGRAM
    .zero 496
    .zero 9216
    .org 32704,0xa5
pl_stack_top:
    .org 32768,0xa5
pl_data_end:
.section .note.GNU-stack,"",@progbits
