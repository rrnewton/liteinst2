/* One fixed SysV caller and the existing linked-memory child. The caller's
 * original direct CALL and saved root+14 continuation must never relocate.
 * Input: immutable 1024-byte, 64-byte-aligned cache-work fixture, count=64.
 * Ordinary RET only; no active CET, signals, foreign entry or nonlocal exit.
 */
.section .text
.balign 4096
.globl call_tree_root
.protected call_tree_root
.type call_tree_root, @function
call_tree_root:
    .byte 0x48,0x83,0xec,0x08             /* +00 sub rsp,8 */
    .byte 0xb8,0x00,0x00,0x00,0x00        /* +04 mov eax,0 */
    .byte 0xe8,0x12,0x00,0x00,0x00        /* +09 call root+32, saves root+14 */
    .byte 0x48,0x83,0xc0,0x01             /* +14 add rax,1 */
    .byte 0x48,0x83,0xc4,0x08             /* +18 add rsp,8 */
    .byte 0xc3                            /* +22 ret */
.size call_tree_root, .-call_tree_root
.fill 9,1,0xcc
.globl call_tree_child
.protected call_tree_child
.type call_tree_child, @function
call_tree_child:
    .byte 0x48,0x8b,0x4f,0x10
    .byte 0x31,0xc0
    .byte 0x31,0xd2
    .byte 0x4c,0x8b,0x44,0x17,0x08
    .byte 0x4c,0x01,0xc0
    .byte 0x48,0x8b,0x14,0x17
    .byte 0x48,0xff,0xc9
    .byte 0x75,0xef
    .byte 0x48,0xba,0x15,0x7c,0x4a,0x7f,0xb9,0x79,0x37,0x9e
    .byte 0x48,0x31,0xd0
    .byte 0xc3
.size call_tree_child, .-call_tree_child
.section .note.GNU-stack,"",@progbits
