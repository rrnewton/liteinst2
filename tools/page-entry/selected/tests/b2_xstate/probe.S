.text
.globl b2_probe_enter
.type b2_probe_enter,@function
b2_probe_enter:
    mov %rdi,%rax
    fninit
    fld1
    pcmpeqd %xmm1,%xmm1
    movdqa %xmm1,%xmm2
    jmp *%rax
.size b2_probe_enter,.-b2_probe_enter
.section .note.GNU-stack,"",@progbits
