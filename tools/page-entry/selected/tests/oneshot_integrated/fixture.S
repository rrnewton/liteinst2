/* Freestanding ET_DYN main entered by the actual system interpreter. No libc
   startup. The very first main instruction is a selected RDTSC on a complete
   RX file page, after the separate R ELF/PHDR page. */
.section .text.oneshot,"ax",@progbits
.global _start,li2_oneshot_entry,li2_oneshot_seeded
.global li2_oneshot_write_self,li2_oneshot_write_entry,li2_oneshot_write_record
.global li2_oneshot_exit,li2_oneshot_record,li2_oneshot_record_end
.type _start,@function
_start:
li2_oneshot_entry:
    .byte 0x0f,0x31,0x90,0x90,0x90
    mov %rax,li2_entry_rax(%rip)
    mov %rdx,li2_entry_rdx(%rip)

    jmp li2_helper_seed
    .org 256,0xcc
li2_oneshot_seeded:
    .byte 0x0f,0x31,0x90,0x90,0x90
    jmp li2_helper_capture
    .org 512,0xcc
li2_io:
.macro original site,opcode
    cmpl $\opcode,\site(%rip)
    jne li2_fail
    cmpb $0x90,\site+4(%rip)
    jne li2_fail
.endm
    original li2_oneshot_entry,0x9090310f
    original li2_oneshot_seeded,0x9090310f

    /* The real write reads its OWN five original source bytes. In the gated
       lane this kernel copy can match only after restoration precedes effect. */
    mov $1,%eax
    mov $1,%edi
    lea li2_oneshot_write_self(%rip),%rsi
    mov $5,%edx
li2_oneshot_write_self:
    .byte 0x0f,0x05,0x90,0x90,0x90
    cmp $5,%rax
    jne li2_fail
    original li2_oneshot_write_self,0x9090050f

    mov $1,%eax
    mov $1,%edi
    lea li2_oneshot_entry(%rip),%rsi
    mov $5,%edx
li2_oneshot_write_entry:
    .byte 0x0f,0x05,0x90,0x90,0x90
    cmp $5,%rax
    jne li2_fail
    original li2_oneshot_write_entry,0x9090050f

    mov $1,%eax
    mov $1,%edi
    lea li2_oneshot_record(%rip),%rsi
    mov $328,%edx
li2_oneshot_write_record:
    .byte 0x0f,0x05,0x90,0x90,0x90
    cmp $328,%rax
    jne li2_fail
    original li2_oneshot_write_record,0x9090050f
    original li2_oneshot_write_self,0x9090050f
    original li2_oneshot_write_entry,0x9090050f
    original li2_oneshot_entry,0x9090310f
    original li2_oneshot_seeded,0x9090310f
    mov $231,%eax
    xor %edi,%edi
li2_oneshot_exit:
    .byte 0x0f,0x05,0x90,0x90,0x90
    ud2
li2_fail:
    cld
    mov $231,%eax
    mov $99,%edi
    syscall
    ud2
    .org 4096,0xcc
.size _start,.-_start

/* Candidate-free page: actual native-page admission is mandatory before
   these PUSHFQ/POPFQ captures. The ELF reader checks the emitted whole-page
   policy and both halo sides before any run; no TF exception is added. */
.section .text.capture,"ax",@progbits
.global li2_helper_seed,li2_helper_capture
li2_helper_seed:
    /* Independent seeds; none of these MOVs changes flags. RSP is the actual
       initial process stack and is compared before any normalization. */
    movabs $0xa501020304050607,%rax
    movabs $0x1122334455667701,%rcx
    movabs $0xb608090a0b0c0d0e,%rdx
    movabs $0x1122334455667703,%rbx
    movabs $0x1122334455667705,%rbp
    movabs $0x1122334455667706,%rsi
    movabs $0x1122334455667707,%rdi
    movabs $0x1122334455667708,%r8
    movabs $0x1122334455667709,%r9
    movabs $0x112233445566770a,%r10
    movabs $0x112233445566770b,%r11
    movabs $0x112233445566770c,%r12
    movabs $0x112233445566770d,%r13
    movabs $0x112233445566770e,%r14
    movabs $0x112233445566770f,%r15
    pushq $0xed7
    popfq

.macro snapshot base,flags,selectors
    mov %rax,\base+0(%rip)
    mov %rcx,\base+8(%rip)
    mov %rdx,\base+16(%rip)
    mov %rbx,\base+24(%rip)
    mov %rsp,\base+32(%rip)
    mov %rbp,\base+40(%rip)
    mov %rsi,\base+48(%rip)
    mov %rdi,\base+56(%rip)
    mov %r8,\base+64(%rip)
    mov %r9,\base+72(%rip)
    mov %r10,\base+80(%rip)
    mov %r11,\base+88(%rip)
    mov %r12,\base+96(%rip)
    mov %r13,\base+104(%rip)
    mov %r14,\base+112(%rip)
    mov %r15,\base+120(%rip)
    mov %cs,\selectors+0(%rip)
    mov %ss,\selectors+2(%rip)
    mov %ds,\selectors+4(%rip)
    mov %es,\selectors+6(%rip)
    mov %fs,\selectors+8(%rip)
    mov %gs,\selectors+10(%rip)
    pushfq
    popq \flags(%rip)
.endm
    snapshot li2_before,li2_before_flags,li2_before_selectors
    jmp li2_oneshot_seeded
li2_helper_capture:
    snapshot li2_after,li2_after_flags,li2_after_selectors
    cld

    /* All fourteen non-destinations, including actual RSP, must be identical.
       Only after this equality is proven are the two equal RSP observations
       replaced by zero; no ASLR-dependent stack address reaches stdout. */
.irp i,1,3,4,5,6,7,8,9,10,11,12,13,14,15
    mov li2_before+8*\i(%rip),%rax
    cmp %rax,li2_after+8*\i(%rip)
    jne li2_fail
.endr
    cmpq $0xed7,li2_before_flags(%rip)
    jne li2_fail
    cmpq $0xed7,li2_after_flags(%rip)
    jne li2_fail
.irp i,0,1,2,3,4,5
    movzwl li2_before_selectors+2*\i(%rip),%eax
    cmp %ax,li2_after_selectors+2*\i(%rip)
    jne li2_fail
.endr
    movq $0,li2_before+32(%rip)
    movq $0,li2_after+32(%rip)

    /* Both destination writes must really zero-extend. The actual 64-bit TSC
       values must be nonzero; they are observations, never exact native/gated
       equality or a latency benchmark. */
.irp field,li2_entry_rax,li2_entry_rdx,li2_after,li2_after+16
    mov \field(%rip),%rax
    shr $32,%rax
    jne li2_fail
.endr
    mov li2_entry_rax(%rip),%rax
    or li2_entry_rdx(%rip),%rax
    je li2_fail
    mov li2_after(%rip),%rax
    or li2_after+16(%rip),%rax
    je li2_fail

    jmp li2_io
    .org 4096,0xcc

.section .data,"aw",@progbits
.balign 64
li2_oneshot_record:
    .ascii "ONESHOT-READY!!\n"
li2_entry_rax: .quad 0
li2_entry_rdx: .quad 0
li2_before: .zero 128
li2_after: .zero 128
li2_before_flags: .quad 0
li2_after_flags: .quad 0
li2_before_selectors: .zero 12
li2_after_selectors: .zero 12
li2_oneshot_record_end:
.section .note.GNU-stack,"",@progbits
