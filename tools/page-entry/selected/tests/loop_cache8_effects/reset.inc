/* Actual original application instructions. No injected context or owner. */
#include "effects.h"
#if LI2_LOOP_CACHE8_EFFECT == 2
    mov %rax,lc8e_state+0(%rip)
    mov %rcx,lc8e_state+8(%rip)
    mov %rdx,lc8e_state+16(%rip)
    mov %rsi,lc8e_state+24(%rip)
    mov %rdi,lc8e_state+32(%rip)
    mov %r11,lc8e_state+40(%rip)
    movl $1,lc8e_state+64(%rip)
    mov $0x412000,%edi
    mov $4096,%esi
    mov $1,%edx
    mov $10,%eax
.globl region_app_effect_syscall0,region_app_effect_syscall1
region_app_effect_syscall0:
    syscall
    mov %rax,lc8e_state+48(%rip)
    movl $1,lc8e_state+72(%rip)
    movl $1,lc8e_state+80(%rip)
    mov $5,%edx
    mov $10,%eax
region_app_effect_syscall1:
    syscall
    mov %rax,lc8e_state+56(%rip)
    movl $1,lc8e_state+88(%rip)
    mov lc8e_state+8(%rip),%rcx
    mov lc8e_state+16(%rip),%rdx
    mov lc8e_state+24(%rip),%rsi
    mov lc8e_state+32(%rip),%rdi
    mov lc8e_state+40(%rip),%r11
    mov lc8e_state+0(%rip),%rax
    .byte 0x48,0xc7,0xc1,8,0,0,0
region_app_reset_jump:
    .byte 0xe9
    .long region_app_head-(.+4)
#elif LI2_LOOP_CACHE8_EFFECT == 3
.globl region_app_effect_write
region_app_effect_write:
    .byte 0xc6,0x04,0x25,0x00,0x24,0x41,0x00,0x5a
region_app_reset_jump:
    .byte 0x0f,0x0b /* A successful write cannot silently continue. */
#else
.globl region_app_effect_load,region_app_effect_jump
region_app_effect_load:
    mov lc8e_state+96(%rip),%rax
region_app_effect_jump:
region_app_reset_jump:
    .byte 0xff,0xe0
#endif
.globl region_app_effect_end
region_app_effect_end:
