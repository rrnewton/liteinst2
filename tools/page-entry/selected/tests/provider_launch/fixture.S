/* Four real first-main entry variants. No earlier main instruction seeds the
   entry effect. Later source blocks enter the separately admitted helper page. */
#ifndef ENTRY_KIND
#error ENTRY_KIND must name the actual first instruction
#endif
.section .text.main,"ax",@progbits
.global _start,pl_time0,pl_time1,pl_write_self,pl_write_time,pl_write_output,pl_exit
_start:
#if ENTRY_KIND == 1
    .byte 0x0f,0xa2
#elif ENTRY_KIND == 2
    .byte 0x49,0x0f,0xc7,0xf7
#elif ENTRY_KIND == 3
    .byte 0x49,0x0f,0xc7,0xff
#elif ENTRY_KIND == 4
    .byte 0xf3,0x41,0x0f,0xc7,0xff
#else
#error unknown entry
#endif
    jmp setup_cpuid1

/* Setup intentionally runs on the NX source page. Two genuine register MOVs
   followed by a CMP force the existing register-run route before any seed. */
.macro prepare name,next,rax=0x1122334455667700,rcx=0x1122334455667701
setup_\name:
    movabs $0x5162738495a6b7c8,%r10
    mov %r10,%r11
    mov %r11,%r12
    cmp %rax,%rax
    lea site_\name(%rip),%rax
    mov %rax,pl_target(%rip)
    lea \next(%rip),%rax
    mov %rax,pl_after(%rip)
    movabs $\rax,%rax
    mov %rax,pl_rax(%rip)
    movabs $\rcx,%rax
    mov %rax,pl_rcx(%rip)
    jmp pl_seed
.global site_\name
site_\name:
.endm
.macro finish
    jmp pl_capture
.endm
    prepare cpuid1,setup_cpuid7,0xa501020300000001,0xb608090a00000000
    .byte 0x0f,0xa2
    finish
    prepare cpuid7,setup_rand16lo,0xa501020300000007,0xb608090a00000000
    .byte 0x0f,0xa2
    finish
    prepare rand16lo,setup_rand16hi
    .byte 0x66,0x0f,0xc7,0xf0
    finish
    prepare rand16hi,setup_rand32lo
    .byte 0x66,0x41,0x0f,0xc7,0xf7
    finish
    prepare rand32lo,setup_rand32hi
    .byte 0x0f,0xc7,0xf0
    finish
    prepare rand32hi,setup_rand64lo
    .byte 0x41,0x0f,0xc7,0xf7
    finish
    prepare rand64lo,setup_rand64hi
    .byte 0x48,0x0f,0xc7,0xf0
    finish
    prepare rand64hi,setup_seed16lo
    .byte 0x49,0x0f,0xc7,0xf7
    finish
    prepare seed16lo,setup_seed16hi
    .byte 0x66,0x0f,0xc7,0xf8
    finish
    prepare seed16hi,setup_seed32lo
    .byte 0x66,0x41,0x0f,0xc7,0xff
    finish
    prepare seed32lo,setup_seed32hi
    .byte 0x0f,0xc7,0xf8
    finish
    prepare seed32hi,setup_seed64lo
    .byte 0x41,0x0f,0xc7,0xff
    finish
    prepare seed64lo,setup_seed64hi
    .byte 0x48,0x0f,0xc7,0xf8
    finish
    prepare seed64hi,setup_pidlo
    .byte 0x49,0x0f,0xc7,0xff
    finish
    prepare pidlo,setup_pidhi
    .byte 0xf3,0x0f,0xc7,0xf8
    finish
    prepare pidhi,pl_times
    .byte 0xf3,0x41,0x0f,0xc7,0xff
    finish

pl_times:
pl_time0:
    .byte 0x0f,0x31,0x90,0x90,0x90
    mov %rax,pl_output+16(%rip)
    mov %rdx,pl_output+24(%rip)
pl_time1:
    .byte 0x0f,0x31,0x90,0x90,0x90
    mov %rax,pl_output+32(%rip)
    mov %rdx,pl_output+40(%rip)

.macro original site,opcode
    cmpl $\opcode,\site(%rip)
    jne pl_fail
    cmpb $0x90,\site+4(%rip)
    jne pl_fail
.endm
    original pl_time0,0x9090310f
    original pl_time1,0x9090310f
    mov $1,%eax
    mov $1,%edi
    lea pl_write_self(%rip),%rsi
    mov $5,%edx
pl_write_self:
    .byte 0x0f,0x05,0x90,0x90,0x90
    cmp $5,%rax
    jne pl_fail
    original pl_write_self,0x9090050f
    mov $1,%eax
    mov $1,%edi
    lea pl_time0(%rip),%rsi
    mov $5,%edx
pl_write_time:
    .byte 0x0f,0x05,0x90,0x90,0x90
    cmp $5,%rax
    jne pl_fail
    mov $1,%eax
    mov $1,%edi
    lea pl_output(%rip),%rsi
    mov $48,%edx
pl_write_output:
    .byte 0x0f,0x05,0x90,0x90,0x90
    cmp $48,%rax
    jne pl_fail
    original pl_write_self,0x9090050f
    original pl_write_time,0x9090050f
    original pl_write_output,0x9090050f
    original pl_time0,0x9090310f
    original pl_time1,0x9090310f
    mov $231,%eax
    xor %edi,%edi
pl_exit:
    .byte 0x0f,0x05,0x90,0x90,0x90
    ud2
pl_fail:
    mov $231,%eax
    mov $99,%edi
    syscall
    ud2
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
    jmp *pl_after(%rip)
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
    .org 16320,0xa5
pl_stack_top:
    .org 16384,0xa5
pl_data_end:
.section .note.GNU-stack,"",@progbits
