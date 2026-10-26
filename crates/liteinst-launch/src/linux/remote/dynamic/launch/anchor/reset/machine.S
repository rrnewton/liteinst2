.text
.global liteinst_anchor_reset_spawn
.type liteinst_anchor_reset_spawn,@function
liteinst_anchor_reset_spawn:
    push r12
    mov r12, rdi
    mov rdx, rsi
    mov rsi, qword ptr [r12 + {stack}]
    mov edi, 0x5100
    xor r10d, r10d
    xor r8d, r8d
    mov eax, 56
    syscall
    test rax, rax
    jz .Lanchor_reset_s
    pop r12
    ret
.Lanchor_reset_s:
.if {test_enabled}
    cmp dword ptr [r12 + {fault}], 1
    je .Lanchor_reset_kill_s
.endif
    mov edi, 0x9000
    xor esi, esi
    lea rdx, [r12 + {descriptor}]
    xor r10d, r10d
    xor r8d, r8d
    mov eax, 56
    syscall
    test rax, rax
    js .Lanchor_reset_fail
    jz .Lanchor_reset_r
.if {test_enabled}
    cmp dword ptr [r12 + {fault}], 4
    je .Lanchor_reset_kill_s
.endif
    mov dword ptr [r12 + {packet_pid}], eax
.if {test_enabled}
    cmp dword ptr [r12 + {fault}], 2
    je .Lanchor_reset_kill_s
.endif
    mov eax, dword ptr [r12 + {descriptor}]
    mov dword ptr [r12 + {control_fd}], eax
    mov edi, dword ptr [r12 + {channel}]
.if {test_enabled}
    cmp dword ptr [r12 + {fault}], 3
    jne .Lanchor_reset_send
    mov edi, -1
.Lanchor_reset_send:
.endif
    lea rsi, [r12 + {message}]
    mov edx, 0x4040
    mov eax, 46
    syscall
    mov qword ptr [r12 + {send_result}], rax
    mov qword ptr [r12 + {send_observed}], 1
    cmp rax, 64
    jne .Lanchor_reset_fail
    xor edi, edi
    jmp .Lanchor_reset_exit
.Lanchor_reset_fail:
    mov edi, 125
.Lanchor_reset_exit:
    mov eax, 60
    syscall
    jmp .Lanchor_reset_exit
.if {test_enabled}
.Lanchor_reset_kill_s:
    mov eax, 39
    syscall
    mov rdi, rax
    mov esi, 9
    mov eax, 62
    syscall
    jmp .Lanchor_reset_fail
.endif
.Lanchor_reset_r:
    mov rdi, r12
    and rsp, -16
    call {reaper}
    ud2
.size liteinst_anchor_reset_spawn,.-liteinst_anchor_reset_spawn
