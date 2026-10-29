/* Fixed, real high-address subjects. Native reference mode is the literal
   argv[1] "native"; the gated lane never installs an application handler. */
#ifndef RN_CASE
#error fixed RN_CASE is required
#endif
#if RN_CASE < 0 || RN_CASE > 20
#error unknown fixed case
#endif
#ifndef NP_CONTROL
#define NP_CONTROL 0
#endif
#if NP_CONTROL < 0 || NP_CONTROL > 1 || (RN_CASE != 16 && NP_CONTROL != 0)
#error unknown fixed control
#endif
#if RN_CASE == 3 || RN_CASE == 19
#define NP_ITERATIONS 1
#else
#define NP_ITERATIONS 32
#endif
.set RN_AREA,0x300001040
.set RN_WORD,0x300001048
.set RN_ARENA,0x300000000
.section .text.setup,"ax",@progbits
.global _start,rn_setup_syscall,rn_seed,rn_capture,rn_body,rn_tail,rn_guard
.global rn_finish,rn_cs_start,rn_cs_end,rn_abort,rn_fault,rn_guard_write
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
    call npf_native_setup
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
#if RN_CASE >= 2
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
#else
rn_setup_syscall:
    nop /* fixed unregistered profile: no fabricated registration result */
#endif
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
    call npf_native_finish
.Lexit:
    xor %edi,%edi
    mov $231,%eax
    syscall
    ud2

rn_fail:
    mov $99,%edi
    mov $231,%eax
    syscall
    ud2
    .org 3072,0x90
.global npf_start_gate,npf_close_gate
npf_start_gate:
    nop /* real dirty-page NX closes the helper epoch, preserving the seed */
    jmp rn_body
    .org 3104,0x90
npf_close_gate:
    nop /* real dirty-page NX closes the actual focal occupied slots */
    jmp rn_capture
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
    movabs $0x1122334455667700,%rax
    mov $NP_ITERATIONS,%ecx
    movabs $0x1122334455667702,%rdx
    movabs $0x1122334455667703,%rbx
    movabs $0x1122334455667705,%rbp
    movabs $0x1122334455667706,%rsi
    movabs $RN_AREA,%rdi
.irp n,8,9,10,11,12,13,14,15
    movabs $(0x1122334455667700+\n),%r\n
.endr
    lea npf_ledger(%rip),%r8
#if RN_CASE == 10
    movabs $RN_ARENA,%r15
#endif
    jmp npf_start_gate
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

.macro NPF_LEAF
    rolq $1,%rax
    xor %r14,%rax
    add %rbx,%rax
    xor $0x5a5a,%rbx
    mov %rax,(%r8)
    add $8,%r8
    ret
.endm
.section .text.body,"ax",@progbits
rn_body:
    nop /* genuine OLD_STEP/SLOW endpoint on incoming TRACE; not in loop backedge */
.Lpair_loop:
    call rn_b
.global rn_after_call
rn_after_call:
    dec %ecx
    jne .Lpair_loop
#if RN_CASE == 4 || RN_CASE == 5 || RN_CASE == 6
#if RN_CASE == 5 || RN_CASE == 6
    mov $0,%ecx
#if RN_CASE == 5
    mov $0,%eax
#else
    mov $39,%eax
#endif
#endif
    jmp npf_c
#elif RN_CASE == 7
    lea rn_descriptor(%rip),%rax
    jmp rn_cs_start
#elif RN_CASE == 8 || RN_CASE == 9
    jmp rn_fault
#elif RN_CASE == 10
    jmp rn_data_fault
#else
    jmp npf_close_gate
#endif
#if RN_CASE == 0
    .org 128,0x90
.global rn_b
rn_b:
    NPF_LEAF
#endif
#if RN_CASE == 7
    .org 4078,0x90
    .long 0x53053053
rn_abort:
    jmp npf_close_gate
    .org 4090,0x90
rn_cs_start:
    mov %rax,8(%rdi)
#elif RN_CASE == 8 || RN_CASE == 9
    .org 252,0x90
    .long 0x53053053
rn_abort:
    jmp npf_close_gate
    .org 4094,0x90
rn_cs_start:
#else
    .org 252,0x90
    .long 0x53053053
rn_abort:
    jmp npf_close_gate
rn_cs_start:
rn_cs_end:
#endif
#if RN_CASE == 7 || RN_CASE == 8 || RN_CASE == 9
rn_fault:
#if RN_CASE == 9
    .byte 0xe8,0xfd /* rel32 0xffd: GUARD-(TAIL+3), split 2+3 */
#else
    .byte 0x48,0x89 /* complete MOV RBX,RAX across actual page boundary */
#endif
#else
rn_fault:
    .org 4096,0x90
#endif

.section .text.tail,"ax",@progbits
rn_tail:
#if RN_CASE == 9
    .byte 0x0f,0x00,0x00
#elif RN_CASE == 7 || RN_CASE == 8
    .byte 0xc3
#endif
#if RN_CASE == 7 || RN_CASE == 8 || RN_CASE == 9
rn_cs_end:
#endif
.global rn_return,npf_c
#if RN_CASE == 4 || RN_CASE == 5 || RN_CASE == 6
    .org 32,0x90 /* keep C's selected core outside A's mandatory 14-byte halo */
#endif
npf_c:
rn_return:
#if RN_CASE == 3
.global rn_b
rn_b:
    NPF_LEAF
#elif RN_CASE == 4
    xor $0x10203040,%edx
    jmp npf_close_gate
#elif RN_CASE == 5
    cpuid
    jmp npf_close_gate
#elif RN_CASE == 6
    syscall
    jmp npf_close_gate
#else
#if RN_CASE != 8 && RN_CASE != 9
    nop
#endif
    jmp npf_close_gate
#endif
#if RN_CASE == 7 || RN_CASE == 8 || RN_CASE == 9
    .org 256,0x90
    .byte 0x0f,0xa2 /* actual old-owner boundary; not executed */
#endif
#if RN_CASE == 19
    .org 4095,0x90
    .byte 0x0f /* CPUID core continues in the actual next page's halo */
#else
    .org 4096,0x90
#endif

.section .text.guard,"ax",@progbits
rn_guard:
#if RN_CASE == 19
    .byte 0xa2 /* unreachable suffix; rn_b is the next byte */
#endif
#if RN_CASE != 0 && RN_CASE != 3
.global rn_b
rn_b:
#if RN_CASE == 9
    nop /* split CALL reaches a genuine OLD_STEP/SLOW endpoint before B */
#endif
    NPF_LEAF
#endif
    .org 128,0x90
.global rn_data_fault
rn_data_fault:
#if RN_CASE == 10
    mov (%r15),%rdx
    jmp npf_close_gate
#else
    jmp npf_close_gate
#endif
rn_guard_write:
    .org 4096,0x90

.section .data.fixture,"aw",@progbits
.global rn_data,rn_data_end,rn_case,rn_mode,rn_active,rn_registration_result,rn_rounds
.global rn_commit,rn_abort_seen,rn_store,rn_descriptor,rn_final_fs,rn_final_gs
.global rn_vectors,rn_masks,rn_live_vectors,rn_live_masks,rn_live_gpr
.global rn_live_flags,rn_live_selectors,rn_rseq_initial,rn_stack_top
rn_data:
    .quad 0x31524941504e534c
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
.global npf_control
npf_control: .quad NP_CONTROL
    .org 128,0
rn_store: .quad 0
    .org 256,0
rn_descriptor:
    .long 0,0
    .quad rn_cs_start
#if RN_CASE == 7
    .quad 7
#elif RN_CASE == 8
    .quad 3
#elif RN_CASE == 9
    .quad 5
#else
    .quad 0
#endif
    .quad rn_abort
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
    .org 12288,0
.global npf_ledger
npf_ledger: .zero 264 /* 32 calls, plus split-CALL's independently modeled call */
    .org 16320,0xa5
rn_stack_top:
    .org 16384,0xa5
rn_data_end:
.section .note.GNU-stack,"",@progbits

.section .text.reference.prefix,"ax",@progbits
    .fill 32,1,0x90 /* full B trailing halo is literal NOP */
