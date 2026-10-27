/* Fixed SysV leaf: uint64_t exact_work_nonempty(const uint8_t *p, size_t n).
 * Unsafe caller contract: 1 <= n <= 64, immutable readable [p,p+n), no pointer
 * wrap, ordinary RET/no active CET, no foreign entry or concurrent code writer.
 * Literal encodings prevent assembler branch relaxation or inserted padding.
 * There are no NOPs, stores, calls, stack adjustments or callee-saved writes.
 */
.section .text
.globl exact_work_nonempty
.type exact_work_nonempty, @function
exact_work_nonempty:
    .byte 0x31,0xc0                         /* +00 xor eax,eax */
    .byte 0x4c,0x8d,0x04,0x37              /* +02 lea r8,[rdi+rsi] */
    .byte 0x0f,0xb6,0x0f                   /* +06 movzx ecx,byte ptr [rdi] */
    .byte 0x83,0xf1,0x5a                   /* +09 xor ecx,0x5a */
    .byte 0x48,0x01,0xc8                   /* +12 add rax,rcx */
    .byte 0x48,0xff,0xc7                   /* +15 inc rdi */
    .byte 0x4c,0x39,0xc7                   /* +18 cmp rdi,r8 */
    .byte 0x72,0xef                        /* +21 jb +06 (-17 from +23) */
    .byte 0x48,0xba,0x15,0x7c,0x4a,0x7f,0xb9,0x79,0x37,0x9e
                                             /* +23 movabs rdx,0x9e3779b97f4a7c15 */
    .byte 0x48,0x31,0xd0                   /* +33 xor rax,rdx */
    .byte 0xc3                             /* +36 ret */
.size exact_work_nonempty, .-exact_work_nonempty
.section .note.GNU-stack,"",@progbits
