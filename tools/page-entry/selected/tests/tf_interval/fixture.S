/* Fixed parent-clock fixture. Modes and descriptor arguments are validated
   before setup; normal samples never select a protocol-failure control. */
#ifndef TFI_N
#error fixed TFI_N is required
#endif
#if TFI_N != 1 && TFI_N != 256
#error unknown fixed operation count
#endif
.set RN_AREA,0x300001040
.set RN_WORD,0x300001048
.set RN_ARENA,0x300000000
.section .text.setup,"ax",@progbits
.global _start,rn_setup_syscall,rn_seed,rn_capture,rn_body,rn_tail,rn_guard
.global rn_finish,rn_guard_write
_start:
    mov %rsp,%rbx
    mov (%rbx),%rdi
    lea 8(%rbx),%rsi
    and $-16,%rsp
    call tfi_configure
    test %rax,%rax
    jne rn_fail
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
    mov $TFI_N,%edi
    call tfi_native_setup
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
    lea rn_store(%rip),%rdi
.irp n,8,9,10,11,12,13,14,15
    movabs $(0x1122334455667700+\n),%r\n
.endr
    jmp tfi_wait
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

/* READY precedes the final old-step NOP and two-byte read. No instruction
   between the actual read return and the first ADD. */
.section .text.body,"ax",@progbits
rn_body:
tfi_wait:
    mov tfi_notify_fd(%rip),%rdi
    lea tfi_ready(%rip),%rsi
    cmpq $1,tfi_control(%rip)
    jne .Lready
    lea tfi_bad_ready(%rip),%rsi
.Lready:
    mov $8,%edx
    mov $1,%eax
    syscall
    cmp $8,%rax
    jne rn_fail
    mov tfi_go_fd(%rip),%rdi
    lea tfi_go_byte(%rip),%rsi
    mov $1,%edx
    mov $0,%eax
    jmp tfi_wait_tail
    .org 4093,0x90
.global tfi_wait_tail,tfi_read
tfi_wait_tail:
    .byte 0x90
tfi_read:
    .byte 0x0f,0x05
.section .text.tail,"ax",@progbits
rn_tail:
.global rn_program
rn_program:
    .rept TFI_N
    .byte 0x49,0x83,0xc0,0x01
    .endr
.global tfi_body_end
tfi_body_end:
    .byte 0x90
    jmp rn_guard
    .org 3072,0x90
    .byte 0x0f,0xa2
    .org 4096,0x90
.section .text.guard,"ax",@progbits
rn_guard:
    .byte 0x90
rn_guard_write:
    jmp rn_capture
    .balign 32,0x90
rn_finish:
    cld
    cmpq $0,rn_rounds(%rip)
    jne rn_fail
    incq rn_rounds(%rip)
    cmpq $1,rn_live_gpr(%rip)
    jne rn_fail
    cmpq $0x47,tfi_go_byte(%rip)
    jne rn_fail
    movabs $(0x1122334455667708+TFI_N),%rax
    cmp %rax,rn_live_gpr+64(%rip)
    jne rn_fail
#if TFI_N == 1
    cmpq $0x606,rn_live_flags(%rip)
#else
    cmpq $0x602,rn_live_flags(%rip)
#endif
    jne rn_fail
    cmpq $3,tfi_control(%rip)
    je .Lafter_done
    mov tfi_notify_fd(%rip),%rdi
    lea tfi_done(%rip),%rsi
    mov $8,%edx
    cmpq $2,tfi_control(%rip)
    jne .Ldone
    mov $16,%edx
.Ldone:
    mov $1,%eax
    syscall
    cmp %rdx,%rax
    jne rn_fail
.Lafter_done:
    /* All bulky output and full raw observation follow the DONE endpoint. */
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
    cmpq $1,rn_mode(%rip)
    jne .Lexit
    call tfi_native_finish
.Lexit:
    xor %edi,%edi
    mov $231,%eax
    syscall
    ud2
    .balign 8,0x90
tfi_ready: .ascii "TFI-RDY\n"
tfi_bad_ready: .ascii "TFI-BAD\n"
tfi_done: .ascii "TFI-DON\nTFI-DON\n"
    .org 3072,0x90
    .byte 0x0f,0xa2
    .org 4096,0x90

.section .data.fixture,"aw",@progbits
.global rn_data,rn_data_end,rn_case,rn_mode,rn_active,rn_registration_result,rn_rounds
.global tfi_control,tfi_go_byte,rn_store,rn_descriptor,rn_final_fs,rn_final_gs
.global rn_vectors,rn_masks,rn_live_vectors,rn_live_masks,rn_live_gpr
.global rn_live_flags,rn_live_selectors,rn_rseq_initial,rn_stack_top
rn_data:
    .quad 0x31464954414e5352
rn_case: .quad TFI_N
rn_mode: .quad 0
rn_active: .quad 0
rn_registration_result: .quad -1
rn_rounds: .quad 0
tfi_control: .quad 0
tfi_go_byte: .quad 0
rn_final_fs: .quad 0
rn_final_gs: .quad 0
.global tfi_go_fd,tfi_notify_fd
tfi_go_fd: .quad 0
tfi_notify_fd: .quad 0
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
