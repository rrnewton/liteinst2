// Authored original frames. All labels describe actual instructions/CFI points.
.macro exported label
.global \label
.hidden \label
\label:
.endm
.macro initial_callee
.cfi_same_value %rbx
.cfi_same_value %rbp
.cfi_same_value %r12
.cfi_same_value %r13
.cfi_same_value %r14
.cfi_same_value %r15
.endm

.section .text.uw_frameless,"ax",@progbits
.balign 4096,0xcc
.type uw_frameless,@function
exported uw_frameless
.cfi_startproc
initial_callee
    pushq %rbx
.cfi_def_cfa_offset 16
.cfi_offset %rbx,-16
    subq $32,%rsp
.cfi_def_cfa_offset 48
    movabsq $0x5a637c91e2d4b608,%rbx
exported uw_frameless_selected
    .byte 0x0f,0x1f,0x44,0x00,0x00
exported uw_frameless_call
    call uw_collect_original
exported uw_frameless_after_call
    movq %rbx,%rax
    addq $32,%rsp
.cfi_def_cfa_offset 16
    popq %rbx
.cfi_def_cfa_offset 8
.cfi_same_value %rbx
    ret
.cfi_endproc
exported uw_frameless_end
.size uw_frameless,.-uw_frameless
.fill 4096-(.-uw_frameless),1,0xcc

.section .text.uw_frame_pointer,"ax",@progbits
.balign 4096,0xcc
.type uw_frame_pointer,@function
exported uw_frame_pointer
.cfi_startproc
initial_callee
    pushq %rbp
.cfi_def_cfa_offset 16
.cfi_offset %rbp,-16
    movq %rsp,%rbp
.cfi_def_cfa_register %rbp
    pushq %rbx
.cfi_offset %rbx,-24
    subq $24,%rsp
    movabsq $0x5a637c91e2d4b608,%rbx
exported uw_frame_pointer_selected
    .byte 0x0f,0x1f,0x44,0x00,0x00
exported uw_frame_pointer_call
    call uw_collect_original
exported uw_frame_pointer_after_call
    movq %rbx,%rax
    addq $24,%rsp
    popq %rbx
.cfi_same_value %rbx
    popq %rbp
.cfi_def_cfa %rsp,8
.cfi_same_value %rbp
    ret
.cfi_endproc
exported uw_frame_pointer_end
.size uw_frame_pointer,.-uw_frame_pointer
.fill 4096-(.-uw_frame_pointer),1,0xcc

.section .text.uw_outer,"ax",@progbits
.balign 16,0xcc
.type uw_outer,@function
exported uw_outer
exported uw_outer_begin
.cfi_startproc
initial_callee
    pushq %rbx
.cfi_def_cfa_offset 16
.cfi_offset %rbx,-16
    pushq %rbp
.cfi_def_cfa_offset 24
.cfi_offset %rbp,-24
    pushq %r12
.cfi_def_cfa_offset 32
.cfi_offset %r12,-32
    pushq %r13
.cfi_def_cfa_offset 40
.cfi_offset %r13,-40
    pushq %r14
.cfi_def_cfa_offset 48
.cfi_offset %r14,-48
    pushq %r15
.cfi_def_cfa_offset 56
.cfi_offset %r15,-56
    subq $24,%rsp
.cfi_def_cfa_offset 80
    movq %rdi,0(%rsp)
    movq %rsi,8(%rsp)
    movq %rsp,0(%rsi)
    leaq uw_outer_return(%rip),%rax
    movq %rax,8(%rsi)
    movq 0(%rdi),%rbx
    movq 8(%rdi),%rbp
    movq 16(%rdi),%r12
    movq 24(%rdi),%r13
    movq 32(%rdi),%r14
    movq 40(%rdi),%r15
    movq 48(%rdi),%rax
exported uw_outer_call
    call *%rax
exported uw_outer_return
    movq 8(%rsp),%rsi
    movq %rax,16(%rsi)
    movq %rbx,24(%rsi)
    movq %rbp,32(%rsi)
    movq %r12,40(%rsi)
    movq %r13,48(%rsi)
    movq %r14,56(%rsi)
    movq %r15,64(%rsi)
    addq $24,%rsp
.cfi_def_cfa_offset 56
    popq %r15
.cfi_def_cfa_offset 48
.cfi_same_value %r15
    popq %r14
.cfi_def_cfa_offset 40
.cfi_same_value %r14
    popq %r13
.cfi_def_cfa_offset 32
.cfi_same_value %r13
    popq %r12
.cfi_def_cfa_offset 24
.cfi_same_value %r12
    popq %rbp
.cfi_def_cfa_offset 16
.cfi_same_value %rbp
    popq %rbx
.cfi_def_cfa_offset 8
.cfi_same_value %rbx
    ret
.cfi_endproc
exported uw_outer_end
.size uw_outer,.-uw_outer
.hidden uw_collect_original
.section .note.GNU-stack,"",@progbits
