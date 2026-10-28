/* Fixed SysV leaf: uint64_t cache_work_linked(const uint8_t *p, size_t bytes).
 * Unsafe caller contract: bytes == 1024, p is 64-byte aligned and the complete
 * [p,p+1024) is immutable/readable without wrap. Sixteen 64-byte nodes contain
 * a u64 byte-offset link at +0 and u64 payload at +8. Every link is a multiple
 * of 64 in 0..960; node0+16 contains u64 count 16 or 64. Ordinary RET/no active CET,
 * no foreign entry/signal/nonlocal exit/concurrent source writer. RSI is the
 * actual full slice extent; the loop count comes from the input, not RSI.
 * Literal bytes: no NOPs, stores, calls, stack or callee-saved modifications.
 */
.section .text
.globl cache_work_linked
.type cache_work_linked, @function
cache_work_linked:
    .byte 0x48,0x8b,0x4f,0x10             /* +00 mov rcx,[rdi+16] */
    .byte 0x31,0xc0                       /* +04 xor eax,eax */
    .byte 0x31,0xd2                       /* +06 xor edx,edx */
    .byte 0x4c,0x8b,0x44,0x17,0x08        /* +08 mov r8,[rdi+rdx+8] */
    .byte 0x4c,0x01,0xc0                  /* +13 add rax,r8 */
    .byte 0x48,0x8b,0x14,0x17             /* +16 mov rdx,[rdi+rdx] */
    .byte 0x48,0xff,0xc9                  /* +20 dec rcx */
    .byte 0x75,0xef                       /* +23 jnz +08 (-17 from +25) */
    .byte 0x48,0xba,0x15,0x7c,0x4a,0x7f,0xb9,0x79,0x37,0x9e
                                          /* +25 movabs rdx,KEY */
    .byte 0x48,0x31,0xd0                  /* +35 xor rax,rdx */
    .byte 0xc3                            /* +38 ret */
.size cache_work_linked, .-cache_work_linked
.section .note.GNU-stack,"",@progbits
