.section .text,"ax",@progbits
.p2align 12
.fill 16,1,0xcc
.global branch_leaf
.type branch_leaf,@function
branch_leaf:
    .byte 0x48,0x8d,0x44,0x7f,0x07
    .byte 0x4c,0x8b,0x15
    .long branch_bias_pointer - . - 4
    .byte 0x49,0x03,0x02
    # Fully defined compare flags; this authored function tests zero/nonzero.
    .byte 0x48,0x83,0xff,0x00
    .byte 0x75,0x07
    # The zero return block owns a complete seven-byte relocation window.
    .byte 0x48,0x8d,0x00,0x48,0x89,0x06,0xc3
    # The nonzero return block owns a separate eight-byte window.
    .byte 0x48,0x83,0xc0,0x01,0x48,0x89,0x06,0xc3
.size branch_leaf,.-branch_leaf
.p2align 4,0xcc
.global branch_invoke
.type branch_invoke,@function
branch_invoke:
    .byte 0xe8
    .long branch_leaf - . - 4
.size branch_invoke,.-branch_invoke
.global branch_terminal
.type branch_terminal,@function
branch_terminal:
    .byte 0xcc
.size branch_terminal,.-branch_terminal
.section .rodata,"a",@progbits
.p2align 3
.global branch_bias
.hidden branch_bias
.type branch_bias,@object
branch_bias:
    .quad 11
.size branch_bias,8
.section .data.rel.ro,"aw",@progbits
.p2align 3
.global branch_bias_pointer
.hidden branch_bias_pointer
.type branch_bias_pointer,@object
branch_bias_pointer:
    .quad branch_bias
.size branch_bias_pointer,8
.section .note.GNU-stack,"",@progbits
