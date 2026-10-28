.text
.global _start
_start:
    and $-16,%rsp
    call footprint_main
    mov %eax,%edi
    mov $231,%eax
    syscall
    ud2
.macro save_gprs target
    mov %rax,\target+0(%rip)
    mov %rcx,\target+8(%rip)
    mov %rdx,\target+16(%rip)
    mov %rbx,\target+24(%rip)
    mov %rsp,\target+32(%rip)
    mov %rbp,\target+40(%rip)
    mov %rsi,\target+48(%rip)
    mov %rdi,\target+56(%rip)
    mov %r8,\target+64(%rip)
    mov %r9,\target+72(%rip)
    mov %r10,\target+80(%rip)
    mov %r11,\target+88(%rip)
    mov %r12,\target+96(%rip)
    mov %r13,\target+104(%rip)
    mov %r14,\target+112(%rip)
    mov %r15,\target+120(%rip)
.endm
.global footprint_enter
footprint_enter:
    save_gprs footprint_caller
    movdqu footprint_vector(%rip),%xmm0
    mov footprint_seed+0(%rip),%rax
    mov footprint_seed+8(%rip),%rcx
    mov footprint_seed+16(%rip),%rdx
    mov footprint_seed+24(%rip),%rbx
    mov footprint_seed+32(%rip),%rsp
    mov footprint_seed+40(%rip),%rbp
    mov footprint_seed+48(%rip),%rsi
    mov footprint_seed+56(%rip),%rdi
    mov footprint_seed+64(%rip),%r8
    mov footprint_seed+72(%rip),%r9
    mov footprint_seed+80(%rip),%r10
    mov footprint_seed+88(%rip),%r11
    mov footprint_seed+96(%rip),%r12
    mov footprint_seed+104(%rip),%r13
    mov footprint_seed+112(%rip),%r14
    mov footprint_seed+120(%rip),%r15
    save_gprs footprint_before
    jmp *footprint_target(%rip)
.global footprint_capture
footprint_capture:
    save_gprs footprint_after
    mov footprint_caller+24(%rip),%rbx
    mov footprint_caller+40(%rip),%rbp
    mov footprint_caller+96(%rip),%r12
    mov footprint_caller+104(%rip),%r13
    mov footprint_caller+112(%rip),%r14
    mov footprint_caller+120(%rip),%r15
    mov footprint_caller+32(%rip),%rsp
    ret
.macro instruction name, bytes:vararg
.global \name,\name\()_end
\name:
    .byte \bytes
\name\()_end:
    jmp footprint_capture
.endm
instruction fp_mov8,0x88,0x07
instruction fp_mov16,0x66,0x89,0x07
instruction fp_mov32,0x89,0x07
instruction fp_mov64,0x48,0x89,0x07
instruction fp_mov128,0x0f,0x11,0x07
instruction fp_load64,0x48,0x8b,0x07
instruction fp_reg,0x48,0x89,0xc3
instruction fp_nop,0x90
instruction fp_endbr,0xf3,0x0f,0x1e,0xfa
instruction fp_add32,0x83,0x07,0x01
instruction fp_xchg64,0x48,0x87,0x07
instruction fp_cmpxchg32,0x0f,0xb1,0x0f
instruction fp_shift0,0xc1,0x27,0x00
.global fp_rip,fp_rip_end
fp_rip:
    .byte 0x48,0x89,0x05
    .long footprint_memory+1024-(.+4)
fp_rip_end:
    jmp footprint_capture
instruction fp_sib,0x48,0x89,0x44,0x8d,0xf0
instruction fp_addr32,0x67,0x48,0x89,0x07
instruction fp_wrap32,0x67,0x89,0x44,0x8d,0x10
instruction fp_fs,0x64,0x48,0x89,0x07
instruction fp_gs,0x65,0x48,0x89,0x47,0xf8
instruction fp_push,0x50
instruction fp_pushmem,0xff,0x37
instruction fp_pushimm,0x6a,0x7f
.global fp_call,fp_call_end
fp_call:
    .byte 0xe8
    .long footprint_call_target-(.+4)
fp_call_end:
    jmp footprint_capture
instruction fp_callreg,0xff,0xd0
.global footprint_call_target
footprint_call_target:
    jmp footprint_capture
instruction fp_pop,0x58
/* The following are supplied query controls, never executed. */
instruction fp_popmem,0x8f,0x07
instruction fp_btsmem,0x48,0x0f,0xab,0x07
instruction fp_btrmem,0x48,0x0f,0xb3,0x07
instruction fp_btcimm,0x48,0x0f,0xba,0x3f,0x01
instruction fp_rep,0xf3,0x48,0xab
instruction fp_unknown,0x0f,0x0b
.section .note.GNU-stack,"",@progbits
