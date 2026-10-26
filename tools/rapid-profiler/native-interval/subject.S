.section .text,"ax",@progbits
.p2align 12
.fill 16,1,0xcc
.global interval_leaf
.type interval_leaf,@function
interval_leaf:
    .byte 0x48,0x8d,0x44,0x7f,0x07
    .byte 0x4c,0x8b,0x15
    .long interval_bias_pointer - . - 4
    .byte 0x49,0x03,0x02,0x48,0x89,0x06,0xc3
.size interval_leaf,.-interval_leaf
.p2align 4,0xcc
.global interval_invoke
.type interval_invoke,@function
interval_invoke:
    .byte 0xe8
    .long interval_leaf - . - 4
.size interval_invoke,.-interval_invoke
.global interval_terminal
.type interval_terminal,@function
interval_terminal:
    .byte 0xcc
.size interval_terminal,.-interval_terminal
.section .rodata,"a",@progbits
.p2align 3
.global interval_bias
.hidden interval_bias
.type interval_bias,@object
interval_bias:
    .quad 11
.size interval_bias,8
.section .data.rel.ro,"aw",@progbits
.p2align 3
.global interval_bias_pointer
.hidden interval_bias_pointer
.type interval_bias_pointer,@object
interval_bias_pointer:
    .quad interval_bias
.size interval_bias_pointer,8
.section .note.GNU-stack,"",@progbits
