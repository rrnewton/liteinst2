.text
.global li2_probe_invoke
.type li2_probe_invoke,@function
li2_probe_invoke:
    mov [rip + LI2_HOST + 0], rsp
    mov [rip + LI2_HOST + 8], rbx
    mov [rip + LI2_HOST + 16], rbp
    mov [rip + LI2_HOST + 24], r12
    mov [rip + LI2_HOST + 32], r13
    mov [rip + LI2_HOST + 40], r14
    mov [rip + LI2_HOST + 48], r15
    pushfq
    pop qword ptr [rip + LI2_HOST + 56]
    mov eax, [rip + LI2_MASK]
    mov edx, [rip + LI2_MASK + 4]
    xsave64 [rip + LI2_HOST_XSTATE]
    xrstor64 [rip + LI2_SEED_XSTATE]
    push qword ptr [rip + LI2_INPUT + 128]
    popfq
    mov rax, [rip + LI2_INPUT + 0]
    mov rbx, [rip + LI2_INPUT + 8]
    mov rcx, [rip + LI2_INPUT + 16]
    mov rdx, [rip + LI2_INPUT + 24]
    mov rsi, [rip + LI2_INPUT + 32]
    mov rdi, [rip + LI2_INPUT + 40]
    mov rbp, [rip + LI2_INPUT + 48]
    mov r8, [rip + LI2_INPUT + 64]
    mov r9, [rip + LI2_INPUT + 72]
    mov r10, [rip + LI2_INPUT + 80]
    mov r11, [rip + LI2_INPUT + 88]
    mov r12, [rip + LI2_INPUT + 96]
    mov r13, [rip + LI2_INPUT + 104]
    mov r14, [rip + LI2_INPUT + 112]
    mov r15, [rip + LI2_INPUT + 120]
    mov rsp, [rip + LI2_INPUT + 56]
    jmp qword ptr [rip + LI2_TARGET]
.size li2_probe_invoke,.-li2_probe_invoke

// The owned application stack contains this real RET destination. Every
// application GPR and RSP is copied before any register is used as scratch.
// No push, call or write touches the application red zone during capture.
.global li2_probe_return
.type li2_probe_return,@function
li2_probe_return:
    mov [rip + LI2_OUTPUT + 0], rax
    mov [rip + LI2_OUTPUT + 8], rbx
    mov [rip + LI2_OUTPUT + 16], rcx
    mov [rip + LI2_OUTPUT + 24], rdx
    mov [rip + LI2_OUTPUT + 32], rsi
    mov [rip + LI2_OUTPUT + 40], rdi
    mov [rip + LI2_OUTPUT + 48], rbp
    mov [rip + LI2_OUTPUT + 56], rsp
    mov [rip + LI2_OUTPUT + 64], r8
    mov [rip + LI2_OUTPUT + 72], r9
    mov [rip + LI2_OUTPUT + 80], r10
    mov [rip + LI2_OUTPUT + 88], r11
    mov [rip + LI2_OUTPUT + 96], r12
    mov [rip + LI2_OUTPUT + 104], r13
    mov [rip + LI2_OUTPUT + 112], r14
    mov [rip + LI2_OUTPUT + 120], r15
    mov rsp, [rip + LI2_HOST]
    pushfq
    pop qword ptr [rip + LI2_OUTPUT + 128]
    mov eax, [rip + LI2_MASK]
    mov edx, [rip + LI2_MASK + 4]
    xsave64 [rip + LI2_OUTPUT_XSTATE]
    mov ecx, 1
    xgetbv
    mov [rip + LI2_OUTPUT_XINUSE], eax
    mov [rip + LI2_OUTPUT_XINUSE + 4], edx
    mov eax, [rip + LI2_MASK]
    mov edx, [rip + LI2_MASK + 4]
    xrstor64 [rip + LI2_HOST_XSTATE]
    mov rbx, [rip + LI2_HOST + 8]
    mov rbp, [rip + LI2_HOST + 16]
    mov r12, [rip + LI2_HOST + 24]
    mov r13, [rip + LI2_HOST + 32]
    mov r14, [rip + LI2_HOST + 40]
    mov r15, [rip + LI2_HOST + 48]
    push qword ptr [rip + LI2_HOST + 56]
    popfq
    ret
.size li2_probe_return,.-li2_probe_return

// Timing is deliberately separate from state capture: the same wrapper and
// register setup run in native and gated lanes, without XSAVE per iteration.
.global li2_probe_repeat
.type li2_probe_repeat,@function
li2_probe_repeat:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    test r13, r13
    jz 2f
1:
    mov rax, [rip + LI2_INPUT + 0]
    mov rcx, [rip + LI2_INPUT + 16]
    mov rdx, [rip + LI2_INPUT + 24]
    mov rsi, [rip + LI2_INPUT + 32]
    mov rdi, [rip + LI2_INPUT + 40]
    mov r8, [rip + LI2_INPUT + 64]
    mov r9, [rip + LI2_INPUT + 72]
    mov r10, [rip + LI2_INPUT + 80]
    call r12
    dec r13
    jnz 1b
2:
    pop r13
    pop r12
    pop rbx
    ret
.size li2_probe_repeat,.-li2_probe_repeat
// Enter the boundary E8 with RSP%16==0, holding an actual return address.
// Its helper therefore receives the System V RSP%16==8. The page1 RET
// returns here, and the second RET returns to the original Rust caller.
.global li2_boundary_invoke
.type li2_boundary_invoke,@function
li2_boundary_invoke:
    sub rsp, 8
    lea rax, [rip + 3f]
    mov [rsp], rax
    jmp rdi
3:
    ret
.size li2_boundary_invoke,.-li2_boundary_invoke

.global li2_boundary_repeat
.type li2_boundary_repeat,@function
li2_boundary_repeat:
    push r12
    push r13
    sub rsp, 8
    mov r12, rdi
    mov r13, rsi
4:
    mov rdi, r12
    call li2_boundary_invoke
    dec r13
    jnz 4b
    add rsp, 8
    pop r13
    pop r12
    ret
.size li2_boundary_repeat,.-li2_boundary_repeat
.section .note.GNU-stack,"",@progbits
