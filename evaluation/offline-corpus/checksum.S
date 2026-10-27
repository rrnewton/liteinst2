.section .text.start,"ax",@progbits
.globl _start
.type _start,@function
_start:
  cmpq $2,(%rsp)
  jne fail
  mov 16(%rsp),%rdi
  mov $0x20000,%esi
  xor %edx,%edx
  mov $2,%eax
  syscall
  test %rax,%rax
  js fail
  mov %rax,%r12
  xor %r13d,%r13d
read_more:
  mov %r12,%rdi
  lea input(%rip),%rsi
  add %r13,%rsi
  mov $65537,%edx
  sub %r13,%rdx
  xor %eax,%eax
  syscall
  cmp $-4,%rax
  je read_more
  test %rax,%rax
  js fail
  je input_done
  add %rax,%r13
  cmp $65536,%r13
  jbe read_more
  jmp fail
input_done:
  mov %r12,%rdi
  mov $3,%eax
  syscall
  test %eax,%eax
  jne fail
  lea stack_end-256(%rip),%rsp
  lea input(%rip),%rdi
  mov %r13,%rsi
  lea output(%rip),%rdx
  call kernel
  test %rax,%rax
  js fail
  mov %rax,%r14
  lea output(%rip),%r15
write_more:
  test %r14,%r14
  je success
  mov $1,%edi
  mov %r15,%rsi
  mov %r14,%rdx
  mov $1,%eax
  syscall
  cmp $-4,%rax
  je write_more
  test %rax,%rax
  jle fail
  add %rax,%r15
  sub %rax,%r14
  jmp write_more
success:
  xor %edi,%edi
  jmp exit
fail:
  mov $9,%edi
exit:
  mov $60,%eax
  syscall
  ud2
.size _start,.-_start
.section .text.kernel,"ax",@progbits
.globl kernel,kernel_end
.type kernel,@function
kernel:
head_entry:
  .byte 0x31,0xc0
head_hash:
  .byte 0x49,0xb8,0x25,0x23,0x22,0x84,0xe4,0x9c,0xf2,0xcb
head_prime:
  .byte 0x49,0xba,0xb3,0x1,0x0,0x0,0x0,0x1,0x0,0x0
head_index:
  .byte 0x31,0xc9
head_empty:
  .byte 0x48,0x85,0xf6
head_empty_branch:
  .byte 0xf,0x84,0x1b,0x0,0x0,0x0
head_loop:
  .byte 0x44,0xf,0xb6,0xc,0xf
head_sum:
  .byte 0x4c,0x1,0xc8
head_xor:
  .byte 0x4d,0x31,0xc8
head_multiply:
  .byte 0x4d,0xf,0xaf,0xc2
head_increment:
  .byte 0x48,0xff,0xc1
head_compare:
  .byte 0x48,0x39,0xf1
head_loop_branch:
  .byte 0xf,0x82,0xe5,0xff,0xff,0xff
head_done:
  .byte 0x48,0x89,0x2
head_save_hash:
  .byte 0x4c,0x89,0x42,0x8
head_save_length:
  .byte 0x48,0x89,0x72,0x10
head_length:
  .byte 0xb8,0x18,0x0,0x0,0x0
head_return:
  .byte 0xc3
kernel_end:
.size kernel,.-kernel
.section .text.hook,"ax",@progbits
.globl null_hook
.type null_hook,@function
null_hook: ret
.size null_hook,.-null_hook
.section .data.buffers,"aw",@progbits
.balign 4096
input: .fill 69632,1,0
output: .fill 200704,1,0
.balign 4096
stack: .fill 65536,1,0x5a
stack_end:
.section .note.fixture,"a",@note
.balign 4
.long 4,4,1
.asciz "LI2"
.long 1
.section .note.GNU-stack,"",@progbits
