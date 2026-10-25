// Authored x86-64 System V/Itanium EH fixture. No generated-code unwind claim.
.section .text.liteinst_exception,"ax",@progbits
.balign 4096,0xcc
.global liteinst_exception_function
.hidden liteinst_exception_function
.type liteinst_exception_function,@function
liteinst_exception_function:
.cfi_startproc
.cfi_personality 0x9b,liteinst_exception_personality_ref
.cfi_lsda 0x1b,liteinst_exception_lsda
    pushq %rbp
.cfi_def_cfa_offset 16
.cfi_offset %rbp,-16
    movq %rsp,%rbp
.cfi_def_cfa_register %rbp
    pushq %rbx
.cfi_offset %rbx,-24
    subq $8,%rsp
.global liteinst_exception_call_begin
.hidden liteinst_exception_call_begin
liteinst_exception_call_begin:
    call liteinst_exception_throw
.global liteinst_exception_call_end
.hidden liteinst_exception_call_end
liteinst_exception_call_end:
    // The throw helper is noreturn. Returning is a failed positive, not a catch.
    ud2
.global liteinst_exception_landing
.hidden liteinst_exception_landing
liteinst_exception_landing:
    // One complete five-byte NOP preserves the personality's RAX/RDX values.
    .byte 0x0f,0x1f,0x44,0x00,0x00
.global liteinst_exception_prefix_end
.hidden liteinst_exception_prefix_end
liteinst_exception_prefix_end:
    movq %rax,liteinst_exception_pad_rax(%rip)
    movq %rdx,liteinst_exception_pad_rdx(%rip)
    addq $1,liteinst_exception_pad_visits(%rip)
    cmpq $1,%rdx
    jne .Lresume
.global liteinst_exception_block_end
.hidden liteinst_exception_block_end
liteinst_exception_block_end:
    movq %rax,%rdi
    call __cxa_begin_catch
    movl (%rax),%ebx
    call __cxa_end_catch
    movl %ebx,%eax
    jmp .Ldone
.Lresume:
    movq %rax,%rdi
    call _Unwind_Resume
    ud2
.Ldone:
    addq $8,%rsp
    popq %rbx
.cfi_restore %rbx
    popq %rbp
.cfi_def_cfa %rsp,8
.cfi_restore %rbp
    ret
.cfi_endproc
.global liteinst_exception_function_end
.hidden liteinst_exception_function_end
liteinst_exception_function_end:
.size liteinst_exception_function,.-liteinst_exception_function
// Own the complete page: temporary RW permissions cannot remove execute access
// from a publisher, callback, throw helper, personality or caller instruction.
.fill 4096-(.-liteinst_exception_function),1,0xcc
.global liteinst_exception_page_end
.hidden liteinst_exception_page_end
liteinst_exception_page_end:

.section .gcc_except_table,"a",@progbits
.balign 4
.global liteinst_exception_lsda
.hidden liteinst_exception_lsda
liteinst_exception_lsda:
    .byte 0xff                       // omitted LPStart: function base
    .byte 0x9b                       // indirect PC-relative signed four-byte type
    .uleb128 liteinst_exception_type_base-.Ltype_offset_end
.Ltype_offset_end:
    .byte 0x01                       // unsigned LEB128 call-site fields
    .uleb128 liteinst_exception_callsites_end-liteinst_exception_callsites
.global liteinst_exception_callsites
.hidden liteinst_exception_callsites
liteinst_exception_callsites:
    .uleb128 liteinst_exception_call_begin-liteinst_exception_function
    .uleb128 liteinst_exception_call_end-liteinst_exception_call_begin
    .uleb128 liteinst_exception_landing-liteinst_exception_function
    .uleb128 1                       // first action, stored offset plus one
.global liteinst_exception_callsites_end
.hidden liteinst_exception_callsites_end
liteinst_exception_callsites_end:
    .sleb128 1                       // catch type entry one (_ZTIi)
    .sleb128 0                       // no subsequent action
    .balign 4
.global liteinst_exception_type_entry
.hidden liteinst_exception_type_entry
liteinst_exception_type_entry:
    .long liteinst_exception_type_ref-.
.global liteinst_exception_type_base
.hidden liteinst_exception_type_base
liteinst_exception_type_base:
.global liteinst_exception_lsda_end
.hidden liteinst_exception_lsda_end
liteinst_exception_lsda_end:

.section .data.rel.ro.local,"aw",@progbits
.balign 8
.global liteinst_exception_personality_ref
.hidden liteinst_exception_personality_ref
liteinst_exception_personality_ref:
    .quad liteinst_exception_personality
.global liteinst_exception_type_ref
.hidden liteinst_exception_type_ref
liteinst_exception_type_ref:
    .quad _ZTIi

.hidden liteinst_exception_throw
.hidden liteinst_exception_personality
.hidden liteinst_exception_pad_visits
.hidden liteinst_exception_pad_rax
.hidden liteinst_exception_pad_rdx
.section .note.GNU-stack,"",@progbits
