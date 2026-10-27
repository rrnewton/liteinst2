.intel_syntax noprefix
.text
.global fixture_enter
.type fixture_enter,@function
fixture_enter:
    mov [rip+fixture_host+0], rsp
    mov [rip+fixture_host+8], rbx
    mov [rip+fixture_host+16], rbp
    mov [rip+fixture_host+24], r12
    mov [rip+fixture_host+32], r13
    mov [rip+fixture_host+40], r14
    mov [rip+fixture_host+48], r15
    pushfq
    pop qword ptr [rip+fixture_host+56]
    mov eax, [rip+fixture_mask]
    mov edx, [rip+fixture_mask+4]
    xsave64 [rip+fixture_host_fp]
    fninit
    fld1
    fldpi
    ldmxcsr [rip+seed_mxcsr]
    test qword ptr [rip+fixture_mask], 4
    jz 1f
    vmovdqu ymm0, [rip+seed_vectors+0]
    vmovdqu ymm1, [rip+seed_vectors+32]
    vmovdqu ymm2, [rip+seed_vectors+64]
    vmovdqu ymm3, [rip+seed_vectors+96]
    vmovdqu ymm4, [rip+seed_vectors+128]
    vmovdqu ymm5, [rip+seed_vectors+160]
    vmovdqu ymm6, [rip+seed_vectors+192]
    vmovdqu ymm7, [rip+seed_vectors+224]
    vmovdqu ymm8, [rip+seed_vectors+256]
    vmovdqu ymm9, [rip+seed_vectors+288]
    vmovdqu ymm10, [rip+seed_vectors+320]
    vmovdqu ymm11, [rip+seed_vectors+352]
    vmovdqu ymm12, [rip+seed_vectors+384]
    vmovdqu ymm13, [rip+seed_vectors+416]
    vmovdqu ymm14, [rip+seed_vectors+448]
    vmovdqu ymm15, [rip+seed_vectors+480]
    jmp 2f
1:
    movdqu xmm0, [rip+seed_vectors+0]
    movdqu xmm1, [rip+seed_vectors+32]
    movdqu xmm2, [rip+seed_vectors+64]
    movdqu xmm3, [rip+seed_vectors+96]
    movdqu xmm4, [rip+seed_vectors+128]
    movdqu xmm5, [rip+seed_vectors+160]
    movdqu xmm6, [rip+seed_vectors+192]
    movdqu xmm7, [rip+seed_vectors+224]
    movdqu xmm8, [rip+seed_vectors+256]
    movdqu xmm9, [rip+seed_vectors+288]
    movdqu xmm10, [rip+seed_vectors+320]
    movdqu xmm11, [rip+seed_vectors+352]
    movdqu xmm12, [rip+seed_vectors+384]
    movdqu xmm13, [rip+seed_vectors+416]
    movdqu xmm14, [rip+seed_vectors+448]
    movdqu xmm15, [rip+seed_vectors+480]
2:
    push qword ptr [rip+fixture_input+128]
    popfq
    mov rax, [rip+fixture_input+0]
    mov rcx, [rip+fixture_input+8]
    mov rdx, [rip+fixture_input+16]
    mov rbx, [rip+fixture_input+24]
    mov rbp, [rip+fixture_input+40]
    mov rsi, [rip+fixture_input+48]
    mov rdi, [rip+fixture_input+56]
    mov r8, [rip+fixture_input+64]
    mov r9, [rip+fixture_input+72]
    mov r10, [rip+fixture_input+80]
    mov r11, [rip+fixture_input+88]
    mov r12, [rip+fixture_input+96]
    mov r13, [rip+fixture_input+104]
    mov r14, [rip+fixture_input+112]
    mov r15, [rip+fixture_input+120]
    mov rsp, [rip+fixture_input+32]
.global fixture_pre_entry
fixture_pre_entry:
    mov [rip+fixture_pre+0], rax
    mov [rip+fixture_pre+8], rcx
    mov [rip+fixture_pre+16], rdx
    mov [rip+fixture_pre+24], rbx
    mov [rip+fixture_pre+32], rsp
    mov [rip+fixture_pre+40], rbp
    mov [rip+fixture_pre+48], rsi
    mov [rip+fixture_pre+56], rdi
    mov [rip+fixture_pre+64], r8
    mov [rip+fixture_pre+72], r9
    mov [rip+fixture_pre+80], r10
    mov [rip+fixture_pre+88], r11
    mov [rip+fixture_pre+96], r12
    mov [rip+fixture_pre+104], r13
    mov [rip+fixture_pre+112], r14
    mov [rip+fixture_pre+120], r15
    mov rsp, [rip+fixture_host]
    pushfq
    pop qword ptr [rip+fixture_pre+128]
    mov eax, [rip+fixture_mask]
    mov edx, [rip+fixture_mask+4]
    xsave64 [rip+fixture_pre_fp]
    mov ecx, 1
    xgetbv
    mov [rip+fixture_pre+136], eax
    mov [rip+fixture_pre+140], edx
    lea rsi, [rip+fixture_pre+144]
    mov edi, 0x1003
    mov eax, 158
    syscall
    mov [rip+fixture_pre+160], rax
    lea rsi, [rip+fixture_pre+152]
    mov edi, 0x1004
    mov eax, 158
    syscall
    mov [rip+fixture_pre+168], rax
    mov ax, cs
    mov [rip+fixture_pre+176], ax
    mov ax, ss
    mov [rip+fixture_pre+178], ax
    mov ax, ds
    mov [rip+fixture_pre+180], ax
    mov ax, es
    mov [rip+fixture_pre+182], ax
    mov ax, fs
    mov [rip+fixture_pre+184], ax
    mov ax, gs
    mov [rip+fixture_pre+186], ax
    push qword ptr [rip+fixture_pre+128]
    popfq
    mov rax, [rip+fixture_pre+0]
    mov rcx, [rip+fixture_pre+8]
    mov rdx, [rip+fixture_pre+16]
    mov rbx, [rip+fixture_pre+24]
    mov rbp, [rip+fixture_pre+40]
    mov rsi, [rip+fixture_pre+48]
    mov rdi, [rip+fixture_pre+56]
    mov r8, [rip+fixture_pre+64]
    mov r9, [rip+fixture_pre+72]
    mov r10, [rip+fixture_pre+80]
    mov r11, [rip+fixture_pre+88]
    mov r12, [rip+fixture_pre+96]
    mov r13, [rip+fixture_pre+104]
    mov r14, [rip+fixture_pre+112]
    mov r15, [rip+fixture_pre+120]
    mov rsp, [rip+fixture_pre+32]
    jmp qword ptr [rip+fixture_target]
.size fixture_enter,.-fixture_enter
.global fixture_post_entry
.type fixture_post_entry,@function
fixture_post_entry:
    mov [rip+fixture_post+0], rax
    mov [rip+fixture_post+8], rcx
    mov [rip+fixture_post+16], rdx
    mov [rip+fixture_post+24], rbx
    mov [rip+fixture_post+32], rsp
    mov [rip+fixture_post+40], rbp
    mov [rip+fixture_post+48], rsi
    mov [rip+fixture_post+56], rdi
    mov [rip+fixture_post+64], r8
    mov [rip+fixture_post+72], r9
    mov [rip+fixture_post+80], r10
    mov [rip+fixture_post+88], r11
    mov [rip+fixture_post+96], r12
    mov [rip+fixture_post+104], r13
    mov [rip+fixture_post+112], r14
    mov [rip+fixture_post+120], r15
    mov rsp, [rip+fixture_host]
    pushfq
    pop qword ptr [rip+fixture_post+128]
    mov eax, [rip+fixture_mask]
    mov edx, [rip+fixture_mask+4]
    xsave64 [rip+fixture_post_fp]
    mov ecx, 1
    xgetbv
    mov [rip+fixture_post+136], eax
    mov [rip+fixture_post+140], edx
    lea rsi, [rip+fixture_post+144]
    mov edi, 0x1003
    mov eax, 158
    syscall
    mov [rip+fixture_post+160], rax
    lea rsi, [rip+fixture_post+152]
    mov edi, 0x1004
    mov eax, 158
    syscall
    mov [rip+fixture_post+168], rax
    mov ax, cs
    mov [rip+fixture_post+176], ax
    mov ax, ss
    mov [rip+fixture_post+178], ax
    mov ax, ds
    mov [rip+fixture_post+180], ax
    mov ax, es
    mov [rip+fixture_post+182], ax
    mov ax, fs
    mov [rip+fixture_post+184], ax
    mov ax, gs
    mov [rip+fixture_post+186], ax
    mov eax, [rip+fixture_mask]
    mov edx, [rip+fixture_mask+4]
    xrstor64 [rip+fixture_host_fp]
    mov rsp, [rip+fixture_host+0]
    mov rbx, [rip+fixture_host+8]
    mov rbp, [rip+fixture_host+16]
    mov r12, [rip+fixture_host+24]
    mov r13, [rip+fixture_host+32]
    mov r14, [rip+fixture_host+40]
    mov r15, [rip+fixture_host+48]
    push qword ptr [rip+fixture_host+56]
    popfq
    ret
.size fixture_post_entry,.-fixture_post_entry
.global fixture_vector_clobber
.type fixture_vector_clobber,@function
fixture_vector_clobber:
    test qword ptr [rip+fixture_mask], 4
    jz 3f
    vzeroall
    ret
3:
    pxor xmm0, xmm0
    pxor xmm1, xmm1
    pxor xmm2, xmm2
    pxor xmm3, xmm3
    pxor xmm4, xmm4
    pxor xmm5, xmm5
    pxor xmm6, xmm6
    pxor xmm7, xmm7
    pxor xmm8, xmm8
    pxor xmm9, xmm9
    pxor xmm10, xmm10
    pxor xmm11, xmm11
    pxor xmm12, xmm12
    pxor xmm13, xmm13
    pxor xmm14, xmm14
    pxor xmm15, xmm15
    ret
.size fixture_vector_clobber,.-fixture_vector_clobber
.section .rodata
.balign 64
seed_mxcsr: .long 0x1f80
.balign 64
seed_vectors:
    .byte 1,12,23,34,45,56,67,78,89,100,111,122,133,144,155,166,177,188,199,210,221,232,243,254,9,20,31,42,53,64,75,86
    .byte 38,49,60,71,82,93,104,115,126,137,148,159,170,181,192,203,214,225,236,247,2,13,24,35,46,57,68,79,90,101,112,123
    .byte 75,86,97,108,119,130,141,152,163,174,185,196,207,218,229,240,251,6,17,28,39,50,61,72,83,94,105,116,127,138,149,160
    .byte 112,123,134,145,156,167,178,189,200,211,222,233,244,255,10,21,32,43,54,65,76,87,98,109,120,131,142,153,164,175,186,197
    .byte 149,160,171,182,193,204,215,226,237,248,3,14,25,36,47,58,69,80,91,102,113,124,135,146,157,168,179,190,201,212,223,234
    .byte 186,197,208,219,230,241,252,7,18,29,40,51,62,73,84,95,106,117,128,139,150,161,172,183,194,205,216,227,238,249,4,15
    .byte 223,234,245,0,11,22,33,44,55,66,77,88,99,110,121,132,143,154,165,176,187,198,209,220,231,242,253,8,19,30,41,52
    .byte 4,15,26,37,48,59,70,81,92,103,114,125,136,147,158,169,180,191,202,213,224,235,246,1,12,23,34,45,56,67,78,89
    .byte 41,52,63,74,85,96,107,118,129,140,151,162,173,184,195,206,217,228,239,250,5,16,27,38,49,60,71,82,93,104,115,126
    .byte 78,89,100,111,122,133,144,155,166,177,188,199,210,221,232,243,254,9,20,31,42,53,64,75,86,97,108,119,130,141,152,163
    .byte 115,126,137,148,159,170,181,192,203,214,225,236,247,2,13,24,35,46,57,68,79,90,101,112,123,134,145,156,167,178,189,200
    .byte 152,163,174,185,196,207,218,229,240,251,6,17,28,39,50,61,72,83,94,105,116,127,138,149,160,171,182,193,204,215,226,237
    .byte 189,200,211,222,233,244,255,10,21,32,43,54,65,76,87,98,109,120,131,142,153,164,175,186,197,208,219,230,241,252,7,18
    .byte 226,237,248,3,14,25,36,47,58,69,80,91,102,113,124,135,146,157,168,179,190,201,212,223,234,245,0,11,22,33,44,55
    .byte 7,18,29,40,51,62,73,84,95,106,117,128,139,150,161,172,183,194,205,216,227,238,249,4,15,26,37,48,59,70,81,92
    .byte 44,55,66,77,88,99,110,121,132,143,154,165,176,187,198,209,220,231,242,253,8,19,30,41,52,63,74,85,96,107,118,129
.section .note.GNU-stack,"",@progbits

.text
.global fixture_restorer
.type fixture_restorer,@function
fixture_restorer:
    mov eax, 15
    syscall
    ud2
.size fixture_restorer,.-fixture_restorer
