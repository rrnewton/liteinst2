/* Fixture-private ordinary-ABI reference enclosure. Source-derived literal bytes.
 * Arguments: RDI=target, RSI=&Request[2], RDX=&u64 results[2], RCX=&ReferenceCell[2].
 * New fixture only. No TLS, SDK invoke, return substitution or clock correction.
 * Five saves: R13 target, R12 results, RBP requests, RBX first result, R14 cells.
 * Entry RSP=S (8 mod16); before CALL S-40; target entry S-48; protect from S-176.
 * Reader cells are separate from all application/code/journal/stack storage.
 * See reference_bytes.rs and the CLOSED authority note before any execution.
 */
.section .text.normal_reference_caller,"ax",@progbits
.p2align 12
.global normal_reference_caller
.type normal_reference_caller, @function
normal_reference_caller:
    .byte 0x41,0x55 /* +000 push r13 */
    .byte 0x49,0x89,0xfd /* +002 mov r13,rdi */
    .byte 0x41,0x54 /* +005 push r12 */
    .byte 0x49,0x89,0xd4 /* +007 mov r12,rdx */
    .byte 0x55 /* +010 push rbp */
    .byte 0x48,0x89,0xf5 /* +011 mov rbp,rsi */
    .byte 0x53 /* +014 push rbx */
    .byte 0x41,0x56 /* +015 push r14 */
    .byte 0x49,0x89,0xce /* +017 mov r14,rcx */
    .byte 0x48,0x8b,0x7d,0x00 /* +020 mov rdi,[rbp] */
    .byte 0x48,0x8b,0x75,0x08 /* +024 mov rsi,[rbp+8] */
    .byte 0x49,0x89,0x66,0x18 /* +028 mov [r14+24],rsp */
.global normal_reference_c0_start_before
.hidden normal_reference_c0_start_before
normal_reference_c0_start_before:
    .byte 0x49,0x89,0x46,0x58 /* +032 mov [r14+88],rax */
    .byte 0x49,0x89,0x4e,0x60 /* +036 mov [r14+96],rcx */
    .byte 0x49,0x89,0x56,0x68 /* +040 mov [r14+104],rdx */
    .byte 0x0f,0xae,0xe8 /* +044 lfence */
.global normal_reference_c0_start_rdtscp
.hidden normal_reference_c0_start_rdtscp
normal_reference_c0_start_rdtscp:
    .byte 0x0f,0x01,0xf9 /* +047 rdtscp */
    .byte 0x0f,0xae,0xe8 /* +050 lfence */
.global normal_reference_c0_start_lo
.hidden normal_reference_c0_start_lo
normal_reference_c0_start_lo:
    .byte 0x41,0x89,0x46,0x28 /* +053 mov [r14+40],eax */
.global normal_reference_c0_start_hi
.hidden normal_reference_c0_start_hi
normal_reference_c0_start_hi:
    .byte 0x41,0x89,0x56,0x30 /* +057 mov [r14+48],edx */
.global normal_reference_c0_start_aux
.hidden normal_reference_c0_start_aux
normal_reference_c0_start_aux:
    .byte 0x41,0x89,0x4e,0x38 /* +061 mov [r14+56],ecx */
    .byte 0x49,0x8b,0x46,0x58 /* +065 mov rax,[r14+88] */
    .byte 0x49,0x8b,0x4e,0x60 /* +069 mov rcx,[r14+96] */
    .byte 0x49,0x8b,0x56,0x68 /* +073 mov rdx,[r14+104] */
.global normal_reference_c0_start_after
.hidden normal_reference_c0_start_after
normal_reference_c0_start_after:
.global normal_reference_call0
.hidden normal_reference_call0
normal_reference_call0:
    .byte 0x41,0xff,0xd5 /* +077 call r13 */
.global normal_reference_continuation0
.hidden normal_reference_continuation0
normal_reference_continuation0:
    .byte 0x49,0x89,0x66,0x20 /* +080 mov [r14+32],rsp */
.global normal_reference_c0_end_before
.hidden normal_reference_c0_end_before
normal_reference_c0_end_before:
    .byte 0x49,0x89,0x46,0x70 /* +084 mov [r14+112],rax */
    .byte 0x49,0x89,0x4e,0x78 /* +088 mov [r14+120],rcx */
    .byte 0x49,0x89,0x96,0x80,0x00,0x00,0x00 /* +092 mov [r14+128],rdx */
    .byte 0x0f,0xae,0xe8 /* +099 lfence */
.global normal_reference_c0_end_rdtscp
.hidden normal_reference_c0_end_rdtscp
normal_reference_c0_end_rdtscp:
    .byte 0x0f,0x01,0xf9 /* +102 rdtscp */
    .byte 0x0f,0xae,0xe8 /* +105 lfence */
.global normal_reference_c0_end_lo
.hidden normal_reference_c0_end_lo
normal_reference_c0_end_lo:
    .byte 0x41,0x89,0x46,0x40 /* +108 mov [r14+64],eax */
.global normal_reference_c0_end_hi
.hidden normal_reference_c0_end_hi
normal_reference_c0_end_hi:
    .byte 0x41,0x89,0x56,0x48 /* +112 mov [r14+72],edx */
.global normal_reference_c0_end_aux
.hidden normal_reference_c0_end_aux
normal_reference_c0_end_aux:
    .byte 0x41,0x89,0x4e,0x50 /* +116 mov [r14+80],ecx */
    .byte 0x49,0x8b,0x46,0x70 /* +120 mov rax,[r14+112] */
    .byte 0x49,0x8b,0x4e,0x78 /* +124 mov rcx,[r14+120] */
    .byte 0x49,0x8b,0x96,0x80,0x00,0x00,0x00 /* +128 mov rdx,[r14+128] */
.global normal_reference_c0_end_phase
.hidden normal_reference_c0_end_phase
normal_reference_c0_end_phase:
    .byte 0x49,0xc7,0x06,0x02,0x00,0x00,0x00 /* +135 mov qword ptr [r14],2 */
.global normal_reference_c0_end_after
.hidden normal_reference_c0_end_after
normal_reference_c0_end_after:
    .byte 0x49,0x89,0x04,0x24 /* +142 mov [r12],rax */
    .byte 0x48,0x89,0xc3 /* +146 mov rbx,rax */
    .byte 0x4d,0x8d,0xb6,0x90,0x00,0x00,0x00 /* +149 lea r14,[r14+144] */
    .byte 0x48,0x8b,0x7d,0x10 /* +156 mov rdi,[rbp+16] */
    .byte 0x48,0x8b,0x75,0x18 /* +160 mov rsi,[rbp+24] */
    .byte 0x49,0x89,0x66,0x18 /* +164 mov [r14+24],rsp */
.global normal_reference_c1_start_before
.hidden normal_reference_c1_start_before
normal_reference_c1_start_before:
    .byte 0x49,0x89,0x46,0x58 /* +168 mov [r14+88],rax */
    .byte 0x49,0x89,0x4e,0x60 /* +172 mov [r14+96],rcx */
    .byte 0x49,0x89,0x56,0x68 /* +176 mov [r14+104],rdx */
    .byte 0x0f,0xae,0xe8 /* +180 lfence */
.global normal_reference_c1_start_rdtscp
.hidden normal_reference_c1_start_rdtscp
normal_reference_c1_start_rdtscp:
    .byte 0x0f,0x01,0xf9 /* +183 rdtscp */
    .byte 0x0f,0xae,0xe8 /* +186 lfence */
.global normal_reference_c1_start_lo
.hidden normal_reference_c1_start_lo
normal_reference_c1_start_lo:
    .byte 0x41,0x89,0x46,0x28 /* +189 mov [r14+40],eax */
.global normal_reference_c1_start_hi
.hidden normal_reference_c1_start_hi
normal_reference_c1_start_hi:
    .byte 0x41,0x89,0x56,0x30 /* +193 mov [r14+48],edx */
.global normal_reference_c1_start_aux
.hidden normal_reference_c1_start_aux
normal_reference_c1_start_aux:
    .byte 0x41,0x89,0x4e,0x38 /* +197 mov [r14+56],ecx */
    .byte 0x49,0x8b,0x46,0x58 /* +201 mov rax,[r14+88] */
    .byte 0x49,0x8b,0x4e,0x60 /* +205 mov rcx,[r14+96] */
    .byte 0x49,0x8b,0x56,0x68 /* +209 mov rdx,[r14+104] */
.global normal_reference_c1_start_after
.hidden normal_reference_c1_start_after
normal_reference_c1_start_after:
.global normal_reference_call1
.hidden normal_reference_call1
normal_reference_call1:
    .byte 0x41,0xff,0xd5 /* +213 call r13 */
.global normal_reference_continuation1
.hidden normal_reference_continuation1
normal_reference_continuation1:
    .byte 0x49,0x89,0x66,0x20 /* +216 mov [r14+32],rsp */
.global normal_reference_c1_end_before
.hidden normal_reference_c1_end_before
normal_reference_c1_end_before:
    .byte 0x49,0x89,0x46,0x70 /* +220 mov [r14+112],rax */
    .byte 0x49,0x89,0x4e,0x78 /* +224 mov [r14+120],rcx */
    .byte 0x49,0x89,0x96,0x80,0x00,0x00,0x00 /* +228 mov [r14+128],rdx */
    .byte 0x0f,0xae,0xe8 /* +235 lfence */
.global normal_reference_c1_end_rdtscp
.hidden normal_reference_c1_end_rdtscp
normal_reference_c1_end_rdtscp:
    .byte 0x0f,0x01,0xf9 /* +238 rdtscp */
    .byte 0x0f,0xae,0xe8 /* +241 lfence */
.global normal_reference_c1_end_lo
.hidden normal_reference_c1_end_lo
normal_reference_c1_end_lo:
    .byte 0x41,0x89,0x46,0x40 /* +244 mov [r14+64],eax */
.global normal_reference_c1_end_hi
.hidden normal_reference_c1_end_hi
normal_reference_c1_end_hi:
    .byte 0x41,0x89,0x56,0x48 /* +248 mov [r14+72],edx */
.global normal_reference_c1_end_aux
.hidden normal_reference_c1_end_aux
normal_reference_c1_end_aux:
    .byte 0x41,0x89,0x4e,0x50 /* +252 mov [r14+80],ecx */
    .byte 0x49,0x8b,0x46,0x70 /* +256 mov rax,[r14+112] */
    .byte 0x49,0x8b,0x4e,0x78 /* +260 mov rcx,[r14+120] */
    .byte 0x49,0x8b,0x96,0x80,0x00,0x00,0x00 /* +264 mov rdx,[r14+128] */
.global normal_reference_c1_end_phase
.hidden normal_reference_c1_end_phase
normal_reference_c1_end_phase:
    .byte 0x49,0xc7,0x06,0x02,0x00,0x00,0x00 /* +271 mov qword ptr [r14],2 */
.global normal_reference_c1_end_after
.hidden normal_reference_c1_end_after
normal_reference_c1_end_after:
    .byte 0x49,0x89,0x44,0x24,0x08 /* +278 mov [r12+8],rax */
    .byte 0x48,0x01,0xd8 /* +283 add rax,rbx */
    .byte 0x41,0x5e /* +286 pop r14 */
    .byte 0x5b /* +288 pop rbx */
    .byte 0x5d /* +289 pop rbp */
    .byte 0x41,0x5c /* +290 pop r12 */
    .byte 0x41,0x5d /* +292 pop r13 */
.global normal_reference_outer_ret
.hidden normal_reference_outer_ret
normal_reference_outer_ret:
    .byte 0xc3 /* +294 ret */
.global normal_reference_end
.hidden normal_reference_end
normal_reference_end:
.size normal_reference_caller, normal_reference_end-normal_reference_caller
.if (normal_reference_end-normal_reference_caller) != 295
.error "normal reference extent"
.endif
.if (normal_reference_c0_start_before-normal_reference_caller) != 32
.error "normal reference label c0_start_before"
.endif
.if (normal_reference_c0_start_rdtscp-normal_reference_caller) != 47
.error "normal reference label c0_start_rdtscp"
.endif
.if (normal_reference_c0_start_lo-normal_reference_caller) != 53
.error "normal reference label c0_start_lo"
.endif
.if (normal_reference_c0_start_hi-normal_reference_caller) != 57
.error "normal reference label c0_start_hi"
.endif
.if (normal_reference_c0_start_aux-normal_reference_caller) != 61
.error "normal reference label c0_start_aux"
.endif
.if (normal_reference_c0_start_after-normal_reference_caller) != 77
.error "normal reference label c0_start_after"
.endif
.if (normal_reference_call0-normal_reference_caller) != 77
.error "normal reference label call0"
.endif
.if (normal_reference_continuation0-normal_reference_caller) != 80
.error "normal reference label continuation0"
.endif
.if (normal_reference_c0_end_before-normal_reference_caller) != 84
.error "normal reference label c0_end_before"
.endif
.if (normal_reference_c0_end_rdtscp-normal_reference_caller) != 102
.error "normal reference label c0_end_rdtscp"
.endif
.if (normal_reference_c0_end_lo-normal_reference_caller) != 108
.error "normal reference label c0_end_lo"
.endif
.if (normal_reference_c0_end_hi-normal_reference_caller) != 112
.error "normal reference label c0_end_hi"
.endif
.if (normal_reference_c0_end_aux-normal_reference_caller) != 116
.error "normal reference label c0_end_aux"
.endif
.if (normal_reference_c0_end_phase-normal_reference_caller) != 135
.error "normal reference label c0_end_phase"
.endif
.if (normal_reference_c0_end_after-normal_reference_caller) != 142
.error "normal reference label c0_end_after"
.endif
.if (normal_reference_c1_start_before-normal_reference_caller) != 168
.error "normal reference label c1_start_before"
.endif
.if (normal_reference_c1_start_rdtscp-normal_reference_caller) != 183
.error "normal reference label c1_start_rdtscp"
.endif
.if (normal_reference_c1_start_lo-normal_reference_caller) != 189
.error "normal reference label c1_start_lo"
.endif
.if (normal_reference_c1_start_hi-normal_reference_caller) != 193
.error "normal reference label c1_start_hi"
.endif
.if (normal_reference_c1_start_aux-normal_reference_caller) != 197
.error "normal reference label c1_start_aux"
.endif
.if (normal_reference_c1_start_after-normal_reference_caller) != 213
.error "normal reference label c1_start_after"
.endif
.if (normal_reference_call1-normal_reference_caller) != 213
.error "normal reference label call1"
.endif
.if (normal_reference_continuation1-normal_reference_caller) != 216
.error "normal reference label continuation1"
.endif
.if (normal_reference_c1_end_before-normal_reference_caller) != 220
.error "normal reference label c1_end_before"
.endif
.if (normal_reference_c1_end_rdtscp-normal_reference_caller) != 238
.error "normal reference label c1_end_rdtscp"
.endif
.if (normal_reference_c1_end_lo-normal_reference_caller) != 244
.error "normal reference label c1_end_lo"
.endif
.if (normal_reference_c1_end_hi-normal_reference_caller) != 248
.error "normal reference label c1_end_hi"
.endif
.if (normal_reference_c1_end_aux-normal_reference_caller) != 252
.error "normal reference label c1_end_aux"
.endif
.if (normal_reference_c1_end_phase-normal_reference_caller) != 271
.error "normal reference label c1_end_phase"
.endif
.if (normal_reference_c1_end_after-normal_reference_caller) != 278
.error "normal reference label c1_end_after"
.endif
.if (normal_reference_outer_ret-normal_reference_caller) != 294
.error "normal reference label outer_ret"
.endif
.if (normal_reference_end-normal_reference_caller) != 295
.error "normal reference label end"
.endif
.section .note.GNU-stack,"",@progbits
