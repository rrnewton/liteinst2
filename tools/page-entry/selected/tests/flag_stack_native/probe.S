.text
.global probe_enter
.type probe_enter,@function
probe_enter:
    mov %rsp,probe_caller(%rip)
    mov %rbx,probe_caller+8(%rip)
    mov %rbp,probe_caller+16(%rip)
    mov %r12,probe_caller+24(%rip)
    mov %r13,probe_caller+32(%rip)
    mov %r14,probe_caller+40(%rip)
    mov %r15,probe_caller+48(%rip)
    fninit
    fld1
    fldpi
    ldmxcsr probe_mxcsr(%rip)
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    movdqa probe_vectors+16*\reg(%rip),%xmm\reg
    .endr
.global probe_reload
probe_reload:
    lea probe_scratch_end(%rip),%rsp
    pushq probe_flags(%rip)
    popfq
    mov probe_seed+0(%rip),%rax
    mov probe_seed+8(%rip),%rcx
    mov probe_seed+16(%rip),%rdx
    mov probe_seed+24(%rip),%rbx
    mov probe_seed+32(%rip),%rsp
    mov probe_seed+40(%rip),%rbp
    mov probe_seed+48(%rip),%rsi
    mov probe_seed+56(%rip),%rdi
    mov probe_seed+64(%rip),%r8
    mov probe_seed+72(%rip),%r9
    mov probe_seed+80(%rip),%r10
    mov probe_seed+88(%rip),%r11
    mov probe_seed+96(%rip),%r12
    mov probe_seed+104(%rip),%r13
    mov probe_seed+112(%rip),%r14
    mov probe_seed+120(%rip),%r15
    jmp *probe_pc(%rip)
.size probe_enter,.-probe_enter
.global probe_return
.type probe_return,@function
probe_return:
    cld
    mov probe_caller+8(%rip),%rbx
    mov probe_caller+16(%rip),%rbp
    mov probe_caller+24(%rip),%r12
    mov probe_caller+32(%rip),%r13
    mov probe_caller+40(%rip),%r14
    mov probe_caller+48(%rip),%r15
    mov probe_caller(%rip),%rsp
    ret
.size probe_return,.-probe_return
.global probe_handler_entry
.type probe_handler_entry,@function
probe_handler_entry:
    /* Signal entry RSP is eight-byte aligned. Every operand until AC clears
       is aligned; the kernel ucontext is untouched. Retain actual live flags. */
    pushfq
    popq probe_handler_flags(%rip)
    pushfq
    andq $-279809,(%rsp) /* clear live AC,NT,DF,TF only */
    popfq
    jmp probe_handler
.size probe_handler_entry,.-probe_handler_entry
.section .rodata
.p2align 2
probe_mxcsr: .long 0x1f80
.p2align 4
probe_vectors:
.set seed,1
.rept 32
    .quad 0x3141592653589793+seed
    .set seed,seed+1
.endr
.bss
.p2align 4
probe_caller: .zero 56
.p2align 4
probe_scratch: .zero 4096
.global probe_scratch_end
probe_scratch_end:
.section .note.GNU-stack,"",@progbits
