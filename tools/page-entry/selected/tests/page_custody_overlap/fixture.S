/* Fixed, real high-address subjects. Native reference mode is the literal
   argv[1] "native"; the gated lane never installs an application handler. */
#ifndef RN_CASE
#error fixed RN_CASE is required
#endif
#if RN_CASE != 5
#error unknown fixed case
#endif
.set RN_AREA,0x300001040
.set RN_WORD,0x300001048
.set RN_ARENA,0x300000000
.section .text.setup,"ax",@progbits
.global _start,rn_setup_syscall,rn_seed,rn_capture,rn_body,rn_tail,rn_guard
.global rn_finish,rn_guard_write
_start:
    mov (%rsp),%rax
    cmp $1,%rax
    je .Lgated
    cmp $2,%rax
    jne rn_fail
    mov 16(%rsp),%rax
    cmpl $0x6974616e,(%rax)
    jne rn_fail
    cmpw $0x6576,4(%rax)
    jne rn_fail
    cmpb $0,6(%rax)
    jne rn_fail
    movq $1,rn_mode(%rip)
.Lgated:
    and $-16,%rsp
    movabs $RN_ARENA,%rdi
    mov $12288,%esi
    xor %edx,%edx
    mov $0x100022,%r10d
    mov $-1,%r8
    xor %r9d,%r9d
    mov $9,%eax
    syscall
    movabs $RN_ARENA,%rdx
    cmp %rdx,%rax
    jne rn_fail
    movabs $(RN_ARENA+4096),%rdi
    mov $4096,%esi
    mov $3,%edx
    mov $10,%eax
    syscall
    test %rax,%rax
    jne rn_fail
    cmpq $0,rn_mode(%rip)
    je .Lnative_ready
    mov $RN_CASE,%edi
    call lso_native_setup
    test %rax,%rax
    jne rn_fail
.Lnative_ready:
    mov $0x1002,%edi
    lea rn_data+2048(%rip),%rsi
    mov $158,%eax
    syscall
    test %rax,%rax
    jne rn_fail
    mov $0x1001,%edi
    lea rn_data+2304(%rip),%rsi
    mov $158,%eax
    syscall
    test %rax,%rax
    jne rn_fail
    movabs $RN_AREA,%rdi
    mov $32,%esi
    xor %edx,%edx
    mov $0x53053053,%r10d
    mov $334,%eax
rn_setup_syscall:
    syscall
    test %rax,%rax
    jne rn_fail
    mov %rax,rn_registration_result(%rip)
    cld
    movabs $(RN_ARENA+4096),%rsi
    lea rn_rseq_initial(%rip),%rdi
    mov $512,%ecx
.Linitial_page:
    mov (%rsi),%rax
    mov %rax,(%rdi)
    add $8,%rsi
    add $8,%rdi
    dec %ecx
    jne .Linitial_page
    movq $1,rn_active(%rip)
    jmp rn_seed
rn_fail:
    mov $99,%edi
    mov $231,%eax
    syscall
    ud2
    .org 4096,0x90

/* The established full ZMM/K/GPR seed/capture sequence is retained here with
   renamed symbols and explicit scalar inputs. Actual full page+halos must
   pass the unchanged native policy; the fixture receives no opcode exemption. */
.section .text.helper,"ax",@progbits
rn_seed:
    fninit
    fld1
    fldpi
.irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    vmovdqu64 rn_vectors+64*\n(%rip),%zmm\n
.endr
.irp n,0,1,2,3,4,5,6,7
    kmovq rn_masks+8*\n(%rip),%k\n
.endr
    lea rn_stack_top(%rip),%rsp
    pushq $0xed7
    popfq
    lea rn_descriptor(%rip),%rax
    movabs $0x1122334455667701,%rcx
    movabs $0x1122334455667702,%rdx
    movabs $0x1122334455667703,%rbx
    movabs $0x1122334455667705,%rbp
    movabs $0x1122334455667706,%rsi
#if RN_CASE == 5
    movabs $RN_WORD,%rdi
#else
    lea rn_store(%rip),%rdi
#endif
.irp n,8,9,10,11,12,13,14,15
    movabs $(0x1122334455667700+\n),%r\n
.endr
    jmp rn_program
rn_capture:
    mov %rax,rn_live_gpr+0(%rip)
    mov %rcx,rn_live_gpr+8(%rip)
    mov %rdx,rn_live_gpr+16(%rip)
    mov %rbx,rn_live_gpr+24(%rip)
    mov %rsp,rn_live_gpr+32(%rip)
    mov %rbp,rn_live_gpr+40(%rip)
    mov %rsi,rn_live_gpr+48(%rip)
    mov %rdi,rn_live_gpr+56(%rip)
.irp n,8,9,10,11,12,13,14,15
    mov %r\n,rn_live_gpr+8*\n(%rip)
.endr
    mov %cs,rn_live_selectors+0(%rip)
    mov %ss,rn_live_selectors+2(%rip)
    mov %ds,rn_live_selectors+4(%rip)
    mov %es,rn_live_selectors+6(%rip)
    mov %fs,rn_live_selectors+8(%rip)
    mov %gs,rn_live_selectors+10(%rip)
    pushfq
    popq rn_live_flags(%rip)
.irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    vmovdqu64 %zmm\n,rn_live_vectors+64*\n(%rip)
.endr
.irp n,0,1,2,3,4,5,6,7
    kmovq %k\n,rn_live_masks+8*\n(%rip)
.endr
    jmp rn_finish
    .org 4096,0x90

/* Every exercised BODY/TAIL/GUARD is actually dirty under the unchanged
   whole-page scanner. The unreachable CPUID bytes are not a policy exemption. */
.section .text.body,"ax",@progbits
rn_body:
#if RN_CASE == 3 || RN_CASE == 4
    .org 256,0x90
    .byte 0x0f,0xa2
#if RN_CASE == 3
    .org 4089,0x90
#else
    .org 4091,0x90
#endif
.global rn_program
rn_program:
    .byte 0x48,0x01,0xd8
#if RN_CASE == 3
    .byte 0x48,0x83,0xc0,0x01
#else
    .byte 0x48,0x83
#endif
#else
    .org 32,0x90
.global rn_program
rn_program:
#if RN_CASE == 2
    .byte 0x29,0xc0,0x29,0xc9,0x0f,0xa2
    .byte 0x49,0x83,0xc0,0x01,0x49,0x83,0xc1,0x01
#elif RN_CASE == 5
    .byte 0x48,0x01,0xd8,0x48,0x83,0xc0,0x01,0x48,0x89,0x07
#else
    .byte 0x48,0x01,0xd8,0x48,0x83,0xc0,0x01
#if RN_CASE == 1
    .byte 0xe9
    .long rn_branch_target - . - 4
    .org 64,0x90
rn_branch_target:
    .byte 0x49,0x83,0xc0,0x01,0x49,0x83,0xc1,0x01
#else
    .byte 0x66,0x0f,0xef,0xc7,0x48,0x89,0x07
#endif
#endif
    .byte 0x90
#if RN_CASE != 1 && RN_CASE != 2 && RN_CASE != 5
    .byte 0x49,0x83,0xc0,0x01
#endif
    jmp rn_guard
    .org 256,0x90
    .byte 0x0f,0xa2
    .org 4096,0x90
#endif
.section .text.tail,"ax",@progbits
rn_tail:
#if RN_CASE == 4
    .byte 0xc0,0x01
#endif
#if RN_CASE == 3 || RN_CASE == 4
    .byte 0x49,0x83,0xc0,0x01,0x90
    jmp rn_guard
#endif
    .org 256,0x90
    .byte 0x0f,0xa2
    .org 4096,0x90
.section .text.guard,"ax",@progbits
rn_guard:
    .byte 0x90 /* old STEP_CANDIDATE forces the genuine endpoint NX */
rn_guard_write:
    jmp rn_capture
    .balign 32,0x90
rn_finish:
    cld
    incq rn_rounds(%rip)
    mov $0x1003,%edi
    lea rn_final_fs(%rip),%rsi
    mov $158,%eax
    syscall
    test %rax,%rax
    jne rn_fail
    mov $0x1004,%edi
    lea rn_final_gs(%rip),%rsi
    mov $158,%eax
    syscall
    test %rax,%rax
    jne rn_fail
    mov $1,%edi
    lea rn_data(%rip),%rsi
    mov $16384,%edx
    mov $1,%eax
    syscall
    cmp $16384,%rax
    jne rn_fail
    mov $1,%edi
    movabs $(RN_ARENA+4096),%rsi
    mov $4096,%edx
    mov $1,%eax
    syscall
    cmp $4096,%rax
    jne rn_fail
    cmpq $0,rn_mode(%rip)
    je .Lexit
    call lso_native_finish
.Lexit:
    xor %edi,%edi
    mov $231,%eax
    syscall
    ud2
    .org 4096,0x90

.section .data.fixture,"aw",@progbits
.global rn_data,rn_data_end,rn_case,rn_mode,rn_active,rn_registration_result,rn_rounds
.global rn_commit,rn_abort_seen,rn_store,rn_descriptor,rn_final_fs,rn_final_gs
.global rn_vectors,rn_masks,rn_live_vectors,rn_live_masks,rn_live_gpr
.global rn_live_flags,rn_live_selectors,rn_rseq_initial,rn_stack_top
rn_data:
    .quad 0x31464954414e5352
rn_case: .quad RN_CASE
rn_mode: .quad 0
rn_active: .quad 0
rn_registration_result: .quad -1
rn_rounds: .quad 0
rn_commit: .quad 0
rn_abort_seen: .quad 0
rn_final_fs: .quad 0
rn_final_gs: .quad 0
.global rn_call_return,rn_call_rsp
rn_call_return: .quad 0
rn_call_rsp: .quad 0
    .org 128,0
rn_store: .quad 0
    .org 256,0
rn_descriptor:
    .long 0,0
    .quad 0,0,0 /* never published; overlap case must refuse before the store */
    .org 512,0
rn_vectors:
.set zr,0
.rept 32
.set zb,0
.rept 64
    .byte 1+((zr*17+zb*13)%255)
.set zb,zb+1
.endr
.set zr,zr+1
.endr
rn_masks:
.set kr,0
.rept 8
    .quad 0x1020304050607080+kr*0x0101010101010101
.set kr,kr+1
.endr
    .org 4096,0
rn_live_vectors: .zero 2048
rn_live_masks: .zero 64
rn_live_gpr: .zero 128
rn_live_flags: .quad 0
rn_live_selectors: .zero 12
    .org 8192,0
rn_rseq_initial: .zero 4096
    .org 16320,0xa5
rn_stack_top:
    .org 16384,0xa5
rn_data_end:
.section .note.GNU-stack,"",@progbits
