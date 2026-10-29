/* Fixed actual syscall subjects. Native observers never edit a frame.
   The FD1 construction mode belongs to the trusted parent launcher. */
#ifndef RN_CASE
#error fixed RN_CASE required
#endif
#if RN_CASE < 0 || RN_CASE > 19
#error unknown fixed case
#endif
#ifndef RTC_WINSZ
#define RTC_WINSZ 0
#endif
#if RTC_WINSZ != 0 && RTC_WINSZ != 1
#error fixed request profile required
#endif
#ifndef RTC_INJECT
#define RTC_INJECT 0
#endif
#if RTC_INJECT < 0 || RTC_INJECT > 16 || (RTC_INJECT && RN_CASE != 0)
#error fixed injected controls use only original case0
#endif
.set RN_AREA,0x300001040
.set RN_WORD,0x300001048
.set RN_ARENA,0x300000000
.section .text.setup,"ax",@progbits
.global _start,rn_setup_syscall,rn_seed,rn_body,rn_tail,rn_guard,rn_finish,rn_fault
_start:
    mov %rsp,rn_startup(%rip)
    mov (%rsp),%rcx
    cmp $1,%rcx
    je .Lgated
    cmp $2,%rcx
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
#if RN_CASE == 4
    lea 16(%rsp,%rcx,8),%rsi
    mov $256,%ecx
.Lenv:
    dec %ecx
    jz rn_fail
    cmpq $0,(%rsi)
    lea 8(%rsi),%rsi
    jne .Lenv
    mov $128,%ecx
.Laux:
    dec %ecx
    jz rn_fail
    mov (%rsi),%rax
    test %rax,%rax
    jz rn_fail
    cmp $33,%rax
    je .Lvdso
    add $16,%rsi
    jmp .Laux
.Lvdso:
    mov 8(%rsi),%rax
    test %rax,%rax
    jz rn_fail
    test $4095,%rax
    jnz rn_fail
    mov %rax,rn_vdso(%rip)
#endif
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
#if RN_CASE == 2
    movabs $RN_ARENA,%rdi
    mov $4096,%esi
    mov $11,%eax
    syscall
    test %rax,%rax
    jne rn_fail
    movq $1,rn_unmapped(%rip)
#endif
    cmpq $0,rn_mode(%rip)
    je .Lnative_ready
    mov $RN_CASE,%edi
    call rtc_native_setup
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
#if RN_CASE == 8
    mov $1,%edi
    mov $0,%esi
    mov $16,%edx
    mov $72,%eax
    syscall
    cmp $16,%rax
    jl rn_fail
    mov %rax,%r13
#endif
#if RN_CASE == 7 || RN_CASE == 8
    mov $1,%edi
    mov $3,%eax
    syscall
    test %rax,%rax
    jne rn_fail
    movq $1,rn_closed(%rip)
#endif
#if RN_CASE == 8
    mov %r13,%rdi
    mov $0,%esi
    mov $1,%edx
    mov $72,%eax
    syscall
    cmp $1,%rax
    jne rn_fail
    mov %r13,%rdi
    mov $3,%eax
    syscall
    test %rax,%rax
    jne rn_fail
    movq $1,rn_restored(%rip)
#endif
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
    mov $16,%eax
    movabs $0x1122334455667701,%rcx
#if RN_CASE == 1
    mov $0,%edx
#elif RN_CASE == 2
    movabs $RN_ARENA,%rdx
#elif RN_CASE == 3 || RN_CASE == 15
    movabs $RN_WORD,%rdx
#elif RN_CASE == 4
    mov rn_vdso(%rip),%rdx
#else
    lea rn_store(%rip),%rdx
#endif
    movabs $0x1122334455667703,%rbx
    movabs $0x1122334455667705,%rbp
#if RTC_WINSZ
#if RN_CASE == 9
    mov $0x5412,%esi
#elif RN_CASE == 10
    mov $0x5414,%esi
#elif RN_CASE == 11
    movabs $0x100005413,%rsi
#elif RN_CASE == 15
    mov $0x541b,%esi
#else
    mov $0x5413,%esi
#endif
#else
#if RN_CASE == 9
    mov $0x5400,%esi
#elif RN_CASE == 10
    mov $0x5402,%esi
#elif RN_CASE == 11
    movabs $0x100005401,%rsi
#elif RN_CASE == 15
    mov $0x541b,%esi
#else
    mov $0x5401,%esi
#endif
#endif
#if RN_CASE == 12
    mov $3,%edi
#elif RN_CASE == 13
    mov $-1,%rdi
#elif RN_CASE == 14
    movabs $0x100000001,%rdi
#else
    mov $1,%edi
#endif
.irp n,8,9,10,11,12,13,14,15
    movabs $(0x1122334455667700+\n),%r\n
.endr
    jmp rn_fault
    .org 4096,0x90

.section .text.body,"ax",@progbits
rn_body:
    .org 4094,0x90
rn_fault:
    .byte 0x0f,0x05
.section .text.tail,"ax",@progbits
rn_tail:
    nop
    jmp rn_finish
    .org 256,0x90
    .byte 0x0f,0xa2
    .org 4096,0x90
.section .text.guard,"ax",@progbits
rn_guard:
rn_finish:
    cld
    cmpq $0,rn_mode(%rip)
    je .Lexit
    call rtc_native_finish
.Lexit:
    xor %edi,%edi
    mov $231,%eax
    syscall
    ud2
    .org 4096,0x90
.section .data.fixture,"aw",@progbits
.global rn_data,rn_data_end,rn_case,rn_mode,rn_active,rn_registration_result,rn_rounds
.global rn_commit,rn_abort_seen,rn_store,rn_descriptor,rn_final_fs,rn_final_gs
.global rn_vdso,rn_unmapped,rn_closed,rn_restored,rn_startup,rn_injected
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
rn_vdso: .quad 0
rn_unmapped: .quad 0
rn_closed: .quad 0
rn_restored: .quad 0
rn_startup: .quad 0
rn_injected: .quad RTC_INJECT
    .org 128,0
rn_store: .fill 32,1,0x5a
#if RTC_WINSZ
.global rn_request_profile
rn_request_profile: .quad 1
#endif
    .org 256,0
rn_descriptor: .zero 32
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
