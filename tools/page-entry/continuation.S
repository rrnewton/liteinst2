#include "continuation.h"
#ifndef CONTINUATION_NEGATIVE
#define CONTINUATION_NEGATIVE 0
#endif
.text
.hidden continuation_record
.hidden continuation_fork
/* The capture instruction sequence uses no CALL, CPUID or syscall before all
   GPR/flags/redzone/XSTATE bytes at that endpoint have been saved. */
.macro capture offset, pc
    mov %rax,continuation_record+\offset+0(%rip)
    mov %rbx,continuation_record+\offset+8(%rip)
    mov %rcx,continuation_record+\offset+16(%rip)
    mov %rdx,continuation_record+\offset+24(%rip)
    mov %rsi,continuation_record+\offset+32(%rip)
    mov %rdi,continuation_record+\offset+40(%rip)
    mov %rbp,continuation_record+\offset+48(%rip)
    mov %rsp,continuation_record+\offset+56(%rip)
    mov %r8,continuation_record+\offset+64(%rip)
    mov %r9,continuation_record+\offset+72(%rip)
    mov %r10,continuation_record+\offset+80(%rip)
    mov %r11,continuation_record+\offset+88(%rip)
    mov %r12,continuation_record+\offset+96(%rip)
    mov %r13,continuation_record+\offset+104(%rip)
    mov %r14,continuation_record+\offset+112(%rip)
    mov %r15,continuation_record+\offset+120(%rip)
    lea observer_stack_end(%rip),%rsp
    pushfq
    popq continuation_record+\offset+OBS_FLAGS(%rip)
    lea \pc(%rip),%rax
    mov %rax,continuation_record+\offset+OBS_PC(%rip)
    mov continuation_record+\offset+56(%rip),%rsi
    lea continuation_record+\offset+OBS_REDZONE(%rip),%rdi
    /* DF may be set in the subject; explicit MOVs never change it. */
    .irp off,0,8,16,24,32,40,48,56,64,72,80,88,96,104,112,120
    mov -128+\off(%rsi),%rax
    mov %rax,\off(%rdi)
    .endr
    mov $0,%ecx
    xgetbv
    mov %eax,continuation_record+\offset+OBS_XCR0(%rip)
    mov %edx,continuation_record+\offset+OBS_XCR0+4(%rip)
    mov $1,%ecx
    xgetbv
    mov %eax,continuation_record+\offset+OBS_XINUSE(%rip)
    mov %edx,continuation_record+\offset+OBS_XINUSE+4(%rip)
    mov continuation_record+\offset+OBS_XCR0(%rip),%eax
    mov continuation_record+\offset+OBS_XCR0+4(%rip),%edx
    xsave64 continuation_record+\offset+OBS_XSAVE(%rip)
    cld
    /* The actual base queries follow the complete endpoint capture. */
    mov $158,%eax
    mov $0x1003,%edi
    lea continuation_record+\offset+OBS_FS(%rip),%rsi
    syscall
    test %rax,%rax
    jne observer_failure
    mov $158,%eax
    mov $0x1004,%edi
    lea continuation_record+\offset+OBS_GS(%rip),%rsi
    syscall
    test %rax,%rax
    jne observer_failure
    xor %eax,%eax
    mov %cs,%ax
    mov %rax,continuation_record+\offset+OBS_SELECTORS(%rip)
    mov %ss,%ax
    mov %rax,continuation_record+\offset+OBS_SELECTORS+8(%rip)
    mov %ds,%ax
    mov %rax,continuation_record+\offset+OBS_SELECTORS+16(%rip)
    mov %es,%ax
    mov %rax,continuation_record+\offset+OBS_SELECTORS+24(%rip)
    mov %fs,%ax
    mov %rax,continuation_record+\offset+OBS_SELECTORS+32(%rip)
    mov %gs,%ax
    mov %rax,continuation_record+\offset+OBS_SELECTORS+40(%rip)
.endm
.p2align 12
.global continuation_fork
.type continuation_fork,@function
continuation_fork:
    mov %rsp,continuation_record+56(%rip)
    mov %rbx,caller_saved(%rip)
    mov %rbp,caller_saved+8(%rip)
    mov %r12,caller_saved+16(%rip)
    mov %r13,caller_saved+24(%rip)
    mov %r14,caller_saved+32(%rip)
    mov %r15,caller_saved+40(%rip)
    mov continuation_record+64(%rip),%eax
    mov continuation_record+68(%rip),%edx
    xsave64 caller_xsave(%rip)
    /* A nonzero x87/SSE/AVX subject makes preservation nonvacuous. Other
       enabled components retain their actual incoming state. */
    fninit
    fld1
    fldpi
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    movdqa vector_seed+32*\reg(%rip),%xmm\reg
    .endr
    testq $4,continuation_record+64(%rip)
    jz 1f
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    vmovdqa vector_seed+32*\reg(%rip),%ymm\reg
    .endr
1:
    movabs $0x8badf00d13579bdf,%rax
    mov %rax,-128(%rsp)
    movabs $0x8badf00d13579be0,%rax
    mov %rax,-120(%rsp)
    movabs $0x8badf00d13579be1,%rax
    mov %rax,-112(%rsp)
    movabs $0x8badf00d13579be2,%rax
    mov %rax,-104(%rsp)
    movabs $0x8badf00d13579be3,%rax
    mov %rax,-96(%rsp)
    movabs $0x8badf00d13579be4,%rax
    mov %rax,-88(%rsp)
    movabs $0x8badf00d13579be5,%rax
    mov %rax,-80(%rsp)
    movabs $0x8badf00d13579be6,%rax
    mov %rax,-72(%rsp)
    movabs $0x8badf00d13579be7,%rax
    mov %rax,-64(%rsp)
    movabs $0x8badf00d13579be8,%rax
    mov %rax,-56(%rsp)
    movabs $0x8badf00d13579be9,%rax
    mov %rax,-48(%rsp)
    movabs $0x8badf00d13579bea,%rax
    mov %rax,-40(%rsp)
    movabs $0x8badf00d13579beb,%rax
    mov %rax,-32(%rsp)
    movabs $0x8badf00d13579bec,%rax
    mov %rax,-24(%rsp)
    movabs $0x8badf00d13579bed,%rax
    mov %rax,-16(%rsp)
    movabs $0x8badf00d13579bee,%rax
    mov %rax,-8(%rsp)
    lea observer_stack_end(%rip),%rsp
    pushq $0x647
    popfq
    mov $57,%eax
    movabs $0x1122334455667788,%rbx
    movabs $0x2233445566778899,%rcx
    movabs $0x33445566778899aa,%rdx
    movabs $0x445566778899aabb,%rsi
    movabs $0x5566778899aabbcc,%rdi
    movabs $0x66778899aabbccdd,%rbp
    movabs $0x778899aabbccddee,%r8
    movabs $0x8899aabbccddeeff,%r9
    movabs $0x99aabbccddeeff10,%r10
    movabs $0xaabbccddeeff1021,%r11
    movabs $0xbbccddeeff102132,%r12
    movabs $0xccddeeff10213243,%r13
    movabs $0xddeeff1021324354,%r14
    movabs $0xeeff102132435465,%r15
    mov continuation_record+56(%rip),%rsp
    capture RECORD_BEFORE, continuation_syscall
    /* Restore the independently saved subject after diagnostic base queries. */
    mov continuation_record+RECORD_BEFORE+OBS_XCR0(%rip),%eax
    mov continuation_record+RECORD_BEFORE+OBS_XCR0+4(%rip),%edx
    xrstor64 continuation_record+RECORD_BEFORE+OBS_XSAVE(%rip)
    pushq continuation_record+RECORD_BEFORE+OBS_FLAGS(%rip)
    popfq
    mov continuation_record+RECORD_BEFORE+0(%rip),%rax
    mov continuation_record+RECORD_BEFORE+8(%rip),%rbx
    mov continuation_record+RECORD_BEFORE+16(%rip),%rcx
    mov continuation_record+RECORD_BEFORE+24(%rip),%rdx
    mov continuation_record+RECORD_BEFORE+32(%rip),%rsi
    mov continuation_record+RECORD_BEFORE+40(%rip),%rdi
    mov continuation_record+RECORD_BEFORE+48(%rip),%rbp
    mov continuation_record+RECORD_BEFORE+64(%rip),%r8
    mov continuation_record+RECORD_BEFORE+72(%rip),%r9
    mov continuation_record+RECORD_BEFORE+80(%rip),%r10
    mov continuation_record+RECORD_BEFORE+88(%rip),%r11
    mov continuation_record+RECORD_BEFORE+96(%rip),%r12
    mov continuation_record+RECORD_BEFORE+104(%rip),%r13
    mov continuation_record+RECORD_BEFORE+112(%rip),%r14
    mov continuation_record+RECORD_BEFORE+120(%rip),%r15
    mov continuation_record+RECORD_BEFORE+56(%rip),%rsp
.global continuation_syscall
.hidden continuation_syscall
continuation_syscall:
    syscall
.global continuation_resume
.hidden continuation_resume
continuation_resume:
#if CONTINUATION_NEGATIVE == 1
    /* Actual post-return corruption control: does not change flags. */
    lea 1(%r12),%r12
#elif CONTINUATION_NEGATIVE == 2
    /* The original seed at RSP-8 has low byte 0xee, so this differs. */
    movb $0,-8(%rsp)
#elif CONTINUATION_NEGATIVE != 0
#error unknown continuation control
#endif
.global continuation_capture
.hidden continuation_capture
continuation_capture:
    capture RECORD_AFTER, continuation_capture
    /* Restore the C caller only after the actual parent/child endpoint. */
    mov continuation_record+64(%rip),%eax
    mov continuation_record+68(%rip),%edx
    xrstor64 caller_xsave(%rip)
    cld
    mov caller_saved(%rip),%rbx
    mov caller_saved+8(%rip),%rbp
    mov caller_saved+16(%rip),%r12
    mov caller_saved+24(%rip),%r13
    mov caller_saved+32(%rip),%r14
    mov caller_saved+40(%rip),%r15
    mov continuation_record+RECORD_AFTER(%rip),%rax
    mov continuation_record+56(%rip),%rsp
    ret
.size continuation_fork,.-continuation_fork
observer_failure:
    mov $231,%eax
    mov $92,%edi
    syscall
    ud2
    /* The first instruction admits this page. No new executable-page fault
       can occur midway through either endpoint capture. Oversize is a hard
       assembler error (backward .org), not a geometry waiver. */
    .org continuation_fork+4096,0x90
.section .rodata
.p2align 5
vector_seed:
    .quad 0x123456789abcdef,0xe0d0c0b0a0908070,0x8877665544332211,0x1020304050607080
    .quad 0x22446688aaccef0,0xe1d1c1b1a1918171,0x8978675645342312,0x1121314151617181
    .quad 0x32547698badcff1,0xe2d2c2b2a2928272,0x8a79685746352413,0x1222324252627282
    .quad 0x426486a8caed0f2,0xe3d3c3b3a3938373,0x8b7a695847362514,0x1323334353637383
    .quad 0x527496b8dafd1f3,0xe4d4c4b4a4948474,0x8c7b6a5948372615,0x1424344454647484
    .quad 0x6284a6c8eb0d2f4,0xe5d5c5b5a5958575,0x8d7c6b5a49382716,0x1525354555657585
    .quad 0x7294b6d8fb1d3f5,0xe6d6c6b6a6968676,0x8e7d6c5b4a392817,0x1626364656667686
    .quad 0x82a4c6e90b2d4f6,0xe7d7c7b7a7978777,0x8f7e6d5c4b3a2918,0x1727374757677787
    .quad 0x92b4d6f91b3d5f7,0xe8d8c8b8a8988878,0x907f6e5d4c3b2a19,0x1828384858687888
    .quad 0xa2c4e7092b4d6f8,0xe9d9c9b9a9998979,0x91806f5e4d3c2b1a,0x1929394959697989
    .quad 0xb2d4f7193b5d7f9,0xeadacabaaa9a8a7a,0x9281705f4e3d2c1b,0x1a2a3a4a5a6a7a8a
    .quad 0xc2e507294b6d8fa,0xebdbcbbbab9b8b7b,0x938271604f3e2d1c,0x1b2b3b4b5b6b7b8b
    .quad 0xd2f517395b7d9fb,0xecdcccbcac9c8c7c,0x94837261503f2e1d,0x1c2c3c4c5c6c7c8c
    .quad 0xe30527496b8dafc,0xedddcdbdad9d8d7d,0x9584736251402f1e,0x1d2d3d4d5d6d7d8d
    .quad 0xf31537597b9dbfd,0xeedecebeae9e8e7e,0x968574635241301f,0x1e2e3e4e5e6e7e8e
    .quad 0x1032547698badcfe,0xefdfcfbfaf9f8f7f,0x9786756453423120,0x1f2f3f4f5f6f7f8f

.bss
.p2align 6
caller_xsave: .zero 65536
caller_saved: .zero 48
.p2align 4
observer_stack: .zero 131072
observer_stack_end:
.section .note.GNU-stack,"",@progbits
