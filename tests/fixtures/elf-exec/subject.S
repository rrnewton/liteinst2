.section .text.fixture,"ax",@progbits
.globl _start
.type _start,@function
_start:
  cmpq $1,(%rsp)
  je start_mov
  cmpq $2,(%rsp)
  jne failed
  mov 16(%rsp),%rdi
  cmpb $0,1(%rdi)
  jne failed
  cmpb $109,(%rdi)
  je start_mov
  cmpb $114,(%rdi)
  jne failed
  lea fixture_stack_end-256(%rip),%rsp
  lea fixture_data+512(%rip),%rsi
  mov $17,%eax
  jmp invoke_ret
start_mov:
  lea fixture_stack_end-256(%rip),%rsp
  lea fixture_data+512(%rip),%rsi
  jmp invoke_mov
.org 0x80,0xcc
.globl invoke_mov,after_mov
invoke_mov:
  call subject_value
after_mov:
  jmp check_mov
.org 0x90,0xcc
.globl invoke_ret,after_ret
invoke_ret:
  call subject_value+5
after_ret:
  jmp check_ret
.org 0x100,0xcc
.globl subject_value
.type subject_value,@function
subject_value:
  mov $5,%eax
  ret
.size subject_value,.-subject_value
.org 0x140,0xcc
check_mov:
  cmp $5,%eax
  jne failed
  mov $17,%eax
  jmp invoke_ret
.org 0x160,0xcc
check_ret:
  cmp $17,%eax
  jne failed
  mov $1,%eax
  mov $1,%edi
  lea message(%rip),%rsi
  mov $12,%edx
  syscall
  cmp $12,%rax
  jne failed
  xor %edi,%edi
  mov $60,%eax
  syscall
failed:
  mov $9,%edi
  mov $60,%eax
  syscall
.size _start,.-_start
.org 0x200,0xcc
.globl fixture_null_hook
.hidden fixture_null_hook
.type fixture_null_hook,@function
fixture_null_hook:
  ret
.size fixture_null_hook,.-fixture_null_hook
.org 0x220,0xcc
.globl fixture_journal_hook
.hidden fixture_journal_hook
.type fixture_journal_hook,@function
fixture_journal_hook:
  mov (%rdi),%rax
  mov %rax,fixture_journal+8(%rip)
  addq $1,fixture_journal(%rip)
  ret
.size fixture_journal_hook,.-fixture_journal_hook
.org 0x300,0xcc
message:
  .ascii "elf exec ok\n"
  .byte 0

.section .data.fixture,"aw",@progbits
.globl fixture_data
fixture_data:
  .set byte_index,0
  .rept 4096
  .byte (byte_index*37+11)&255
  .set byte_index,byte_index+1
  .endr
.section .journal.fixture,"aw",@progbits
.globl fixture_journal
fixture_journal:
  .fill 4096,1,0
.section .stack.fixture,"aw",@progbits
.globl fixture_stack,fixture_stack_end
fixture_stack:
  .fill 65536,1,0x5a
fixture_stack_end:
.section .note.GNU-stack,"",@progbits
