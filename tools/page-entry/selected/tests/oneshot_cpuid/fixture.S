/* Genuine first-entry CPUID and nine original-PC selected/CPUID windows.
 * GEOMETRY 0 is aligned; 1 puts the first two five-byte windows across pages.
 * Slots 0..7 publish once; slot8 must use the unchanged capacity fallback. */
#ifndef GEOMETRY
#error GEOMETRY is required
#endif
#if GEOMETRY < 0 || GEOMETRY > 1
#error unknown GEOMETRY
#endif
.section .text.main,"ax",@progbits
.global _start,oc_write,oc_exit
_start:
    cpuid
    jmp setup0
.macro setup n,next
setup\n:
    lea oc_site\n(%rip),%rax
    mov %rax,pl_target(%rip)
    lea \next(%rip),%rax
    mov %rax,pl_after(%rip)
    movq $\n,nx_slot(%rip)
    movabs $0xb608090a00000000,%rax
    mov %rax,pl_rcx(%rip)
.if (\n & 1)
    movq $1,pl_rax(%rip)
    movq $1,pl_rdi(%rip)
    lea oc_site\n(%rip),%rax
    mov %rax,pl_rsi(%rip)
    movq $5,pl_rdx(%rip)
.else
    movabs $0xa501020300000001,%rax
    mov %rax,pl_rax(%rip)
    movabs $0x1122334455667707,%rax
    mov %rax,pl_rdi(%rip)
    movabs $0x1122334455667706,%rax
    mov %rax,pl_rsi(%rip)
    movabs $0x1122334455667702,%rax
    mov %rax,pl_rdx(%rip)
.endif
    jmp pl_seed
.endm
    setup 0,setup1
    setup 1,setup2
    setup 2,setup3
    setup 3,setup4
    setup 4,setup5
    setup 5,setup6
    setup 6,setup7
    setup 7,setup8
    setup 8,oc_finish
oc_finish:
    cld
    mov $1,%eax
    mov $1,%edi
    lea nx_output(%rip),%rsi
    mov $21248,%edx
oc_write:
    syscall
    cmp $21248,%rax
    jne oc_fail
    mov $231,%eax
    xor %edi,%edi
oc_exit:
    syscall
    ud2
oc_fail:
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
    mov pl_rdx(%rip),%rdx
    movabs $0x1122334455667703,%rbx
    movabs $0x1122334455667705,%rbp
    mov pl_rsi(%rip),%rsi
    mov pl_rdi(%rip),%rdi
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
.macro site n
.global oc_site\n,oc_cpuid\n
oc_site\n:
.if (\n & 1)
    syscall
.else
    rdtsc
.endif
oc_cpuid\n:
    cpuid
    nop
    jmp pl_capture
.endm
#if GEOMETRY == 0
    .org 32,0xcc
    site 0
    .balign 32,0xcc
    site 1
#else
    .org 4093,0xcc
    site 0
    .org 12284,0xcc
    site 1
#endif
    .org 16384,0xcc
    site 2
    .balign 32,0xcc
    site 3
    .balign 32,0xcc
    site 4
    .balign 32,0xcc
    site 5
    .balign 32,0xcc
    site 6
    .balign 32,0xcc
    site 7
    .balign 32,0xcc
    site 8
    .balign 32,0xcc
    .org 57344,0xcc
.section .data.fixture,"aw",@progbits
.global pl_data,pl_data_end,pl_output,pl_vectors,pl_masks,pl_live_vectors,pl_live_masks
.global pl_live_gpr,pl_live_flags,pl_live_selectors,pl_stack_top
pl_data:
    .quad 0x31584e4449555043,GEOMETRY
pl_target: .quad 0
pl_after: .quad 0
pl_rax: .quad 0
pl_rcx: .quad 0
nx_slot: .quad 0
nx_indirect: .quad 0
pl_rdx: .quad 0
pl_rsi: .quad 0
pl_rdi: .quad 0
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
nx_output: .quad 0x3154554f584e5043,GEOMETRY
    .zero 496
    .zero 20736
    .org 32704,0xa5
pl_stack_top:
    .org 32768,0xa5
pl_data_end:
.section .note.GNU-stack,"",@progbits
