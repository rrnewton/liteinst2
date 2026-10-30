#include "app.h"
.section .li2_ua_machine,"ax",@progbits
.balign 4096
.globl unrolled_app_helper,unrolled_app_helper_end
unrolled_app_helper:
.macro gprs name
    mov %rax,\name+0(%rip)
    mov %rcx,\name+8(%rip)
    mov %rdx,\name+16(%rip)
    mov %rbx,\name+24(%rip)
    mov %rsp,\name+32(%rip)
    mov %rbp,\name+40(%rip)
    mov %rsi,\name+48(%rip)
    mov %rdi,\name+56(%rip)
    mov %r8,\name+64(%rip)
    mov %r9,\name+72(%rip)
    mov %r10,\name+80(%rip)
    mov %r11,\name+88(%rip)
    mov %r12,\name+96(%rip)
    mov %r13,\name+104(%rip)
    mov %r14,\name+112(%rip)
    mov %r15,\name+120(%rip)
    movw %cs,\name+136(%rip)
    movw %ss,\name+138(%rip)
    movw %ds,\name+140(%rip)
    movw %es,\name+142(%rip)
    movw %fs,\name+144(%rip)
    movw %gs,\name+146(%rip)
.endm
.macro live name
.irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    vmovdqu64 %zmm\n,\name+64*\n(%rip)
.endr
.irp n,0,1,2,3,4,5,6,7
    kmovq %k\n,\name+2048+8*\n(%rip)
.endr
    fnstcw \name+2112(%rip)
    fnstsw \name+2114(%rip)
.endm
.macro load name
    mov \name+0(%rip),%rax
    mov \name+8(%rip),%rcx
    mov \name+16(%rip),%rdx
    mov \name+24(%rip),%rbx
    mov \name+40(%rip),%rbp
    mov \name+48(%rip),%rsi
    mov \name+56(%rip),%rdi
    mov \name+64(%rip),%r8
    mov \name+72(%rip),%r9
    mov \name+80(%rip),%r10
    mov \name+88(%rip),%r11
    mov \name+96(%rip),%r12
    mov \name+104(%rip),%r13
    mov \name+112(%rip),%r14
    mov \name+120(%rip),%r15
    mov \name+32(%rip),%rsp
.endm
.globl unrolled_app_enter,unrolled_app_capture_high,unrolled_app_seed_x87,unrolled_app_entry_jump
.type unrolled_app_enter,@function
unrolled_app_enter:
    mov %rsp,ua_host(%rip)
    mov %rbx,ua_host+8(%rip)
    mov %rbp,ua_host+16(%rip)
    mov %r12,ua_host+24(%rip)
    mov %r13,ua_host+32(%rip)
    mov %r14,ua_host+40(%rip)
    mov %r15,ua_host+48(%rip)
    pushfq
    popq ua_host+56(%rip)
    fnstcw ua_host_fcw(%rip)
    fninit
    fld1
unrolled_app_seed_x87:
    fldpi
.irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    vmovdqu64 ua_vectors+64*\n(%rip),%zmm\n
.endr
.irp n,0,1,2,3,4,5,6,7
    kmovq ua_masks+8*\n(%rip),%k\n
.endr
    pushq ua_input+128(%rip)
    popfq
    load ua_input
    gprs ua_before
    mov ua_host(%rip),%rsp
    pushfq
    popq ua_before+128(%rip)
    live ua_before_live
    pushq ua_before+128(%rip)
    popfq
    load ua_before
unrolled_app_entry_jump:
    jmp *unrolled_app_head_pointer(%rip)
.size unrolled_app_enter,.-unrolled_app_enter
.type unrolled_app_capture_high,@function
unrolled_app_capture_high:
    gprs ua_after
    mov ua_host(%rip),%rsp
    pushfq
    popq ua_after+128(%rip)
    live ua_after_live
    fninit
    fldcw ua_host_fcw(%rip)
    mov ua_host+8(%rip),%rbx
    mov ua_host+16(%rip),%rbp
    mov ua_host+24(%rip),%r12
    mov ua_host+32(%rip),%r13
    mov ua_host+40(%rip),%r14
    mov ua_host+48(%rip),%r15
    pushq ua_host+56(%rip)
    popfq
    ret
.size unrolled_app_capture_high,.-unrolled_app_capture_high
#ifdef LI2_CURRENT_TF_APP
/* PAUSE is native-policy eligible but outside the generic TF inventory.
   Existing fallback closes TF before genuine native entry; no state changes. */
.globl unrolled_current_return_high
.type unrolled_current_return_high,@function
unrolled_current_return_high:
    .byte 0xf3,0x90,0xff,0x25,0,0,0,0
    .quad unrolled_app_head
.size unrolled_current_return_high,8
#endif
.org 4096,0xcc
unrolled_app_helper_end:
.section .text.ua_hash,"ax",@progbits
.balign 4096
.globl unrolled_app_head,unrolled_app_stop,unrolled_app_source_end
.type unrolled_app_head,@function
unrolled_app_head:
    .byte 0x48,0x89,0xd8,0x48,0x83,0xc1,0x01,0x48,0xc1,0xe0,0x05,0x48,0x01,0xc3,0x48,0x01,0xd3,0x0f,0xb6,0x11,0x84,0xd2,0x75,0xe8
unrolled_app_stop:
    .byte 0x89,0xdb
    jmp unrolled_app_capture
.size unrolled_app_head,.-unrolled_app_head
.org 4096,0xcc
unrolled_app_source_end:
/* A low, unchanged-state return boundary: the focal guard still uses rel32.
   This original-PC indirect jump reads only its complete immutable literal. */
.section .text.ua_return,"ax",@progbits
.balign 4096
.globl unrolled_app_capture,unrolled_app_return_end
.type unrolled_app_capture,@function
unrolled_app_capture:
    .byte 0xff,0x25,0,0,0,0
    .quad unrolled_app_capture_high
.size unrolled_app_capture,6
.org 4096,0xcc
unrolled_app_return_end:
.section .li2_ua_rodata,"a",@progbits
.p2align 6
.globl ua_vectors,ua_masks,unrolled_app_head_pointer
ua_vectors:
.set v,1
.rept 256
.quad 0x3141592653589793+v
.set v,v+1
.endr
ua_masks:
.quad 0x0123456789abcdef,0xfedcba9876543210,0xaaaaaaaa55555555,0x0f0ff0f0a5a55a5a
.quad 0x1111222233334444,0x8877665544332211,0xffff00000000ffff,0x5a5a5a5aa5a5a5a5
.p2align 3
#ifdef LI2_CURRENT_TF_APP
unrolled_app_head_pointer:.quad unrolled_current_head
#else
unrolled_app_head_pointer:.quad unrolled_app_head
#endif
.section .li2_ua_state,"aw",@nobits
.p2align 3
.globl ua_host,ua_host_fcw
.type ua_host,@object
ua_host:.zero 64
.size ua_host,64
.type ua_host_fcw,@object
ua_host_fcw:.zero 2
.size ua_host_fcw,2
#ifdef LI2_CURRENT_TF_APP
.section .text.ua_current,"ax",@progbits
.balign 4096
.globl unrolled_current_head,unrolled_current_end
.type unrolled_current_head,@function
unrolled_current_head:
    .byte 0x66,0x90,0x66,0x90,0x66,0x90,0xff,0x25,0,0,0,0
    .quad unrolled_current_return_high
.size unrolled_current_head,12
.org 4096,0xcc
unrolled_current_end:
#endif
.section .note.GNU-stack,"",@progbits
