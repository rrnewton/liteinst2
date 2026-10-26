/* Additive normal-exec fixture. Assemble with --defsym TACTIC=2|3|4|5.
 * Values select B2, T1, T2, T3 respectively; there is no default family.
 * Fixed encodings make the startup/CALL contract independently inspectable.
 */
.ifndef TACTIC
  .error "TACTIC is required (2=B2, 3=T1, 4=T2, 5=T3)"
.endif
.if TACTIC < 2 || TACTIC > 5
  .error "invalid TACTIC"
.endif
.set SENTINEL,0x1122334400000011
.set H0,0
.if TACTIC == 2
  .set HEAD_COUNT,3
  .set H1,3
  .set H2,8
.elseif TACTIC == 3
  .set HEAD_COUNT,3
  .set H1,2
  .set H2,7
.elseif TACTIC == 4
  .set HEAD_COUNT,6
  .set H1,3
  .set H2,11
  .set H3,16
  .set H4,64
  .set H5,74
.else
  .set HEAD_COUNT,5
  .set H1,2
  .set H2,3
  .set H3,64
  .set H4,74
.endif
.if HEAD_COUNT < 4
  .set H3,0
  .set H4,0
.endif
.if HEAD_COUNT < 6
  .set H5,0
.endif

.macro JCC code, destination
  .byte 0x0f,\code
  .long \destination - . - 4
.endm
.macro JMP destination
  .byte 0xe9
  .long \destination - . - 4
.endm

.section .text.fixture,"ax",@progbits
.globl _start
.type _start,@function
_start:
  .byte 0x48,0x83,0x3c,0x24,0x01 /* cmpq $1,(%rsp) */
  JCC 0x84,start_ordinary
  .byte 0x48,0x83,0x3c,0x24,0x02 /* cmpq $2,(%rsp) */
  JCC 0x85,failed
  .byte 0x48,0x8b,0x7c,0x24,0x10 /* mov 16(%rsp),%rdi */
  .byte 0x80,0x7f,0x01,0x00      /* cmpb $0,1(%rdi) */
  JCC 0x85,failed
  .byte 0x44,0x0f,0xb6,0x27      /* movzbl (%rdi),%r12d */
  .byte 0x41,0x83,0xec,0x30      /* sub $'0',%r12d */
  .byte 0x41,0x83,0xfc,HEAD_COUNT /* cmp $HEAD_COUNT,%r12d */
  JCC 0x83,failed               /* jae failed */
  .byte 0x41,0xbe,0x01,0x00,0x00,0x00 /* mov $1,%r14d: one-head mode */
  .byte 0x45,0x31,0xed           /* xor %r13d,%r13d: ZF round zero */
  JMP prepare_call
.size _start,.-_start
.org 0x50,0xcc
.globl start_ordinary
.type start_ordinary,@function
start_ordinary:
  .byte 0x45,0x31,0xf6           /* xor %r14d,%r14d: all-head mode */
  .byte 0x45,0x31,0xe4           /* xor %r12d,%r12d: head index zero */
  .byte 0x45,0x31,0xed           /* xor %r13d,%r13d: ZF round zero */
  JMP prepare_call
.size start_ordinary,.-start_ordinary
.org 0x80,0xcc
.globl prepare_call
.type prepare_call,@function
prepare_call:
  .byte 0x48,0x8d,0x25          /* lea fixture_stack_end-256(%rip),%rsp */
  .long fixture_stack_end - 256 - . - 4
  .byte 0x48,0x8d,0x35          /* lea fixture_data+512(%rip),%rsi */
  .long fixture_data + 512 - . - 4
  .byte 0x48,0xb8              /* movabs $SENTINEL,%rax */
  .quad SENTINEL
  .byte 0x4c,0x8d,0x3d          /* lea call_table(%rip),%r15 */
  .long call_table - . - 4
  .byte 0x4f,0x8b,0x3c,0xe7    /* mov (%r15,%r12,8),%r15 */
  .byte 0x49,0x83,0xfd,0x01    /* cmpq $1,%r13: round0 ZF=0, round1 ZF=1 */
  .byte 0x41,0xff,0xe7          /* jmp *%r15; flags unchanged */
.size prepare_call,.-prepare_call

.org 0x200,0xcc
.globl fixture_null_hook
.hidden fixture_null_hook
.type fixture_null_hook,@function
fixture_null_hook:
  .byte 0xc3
.size fixture_null_hook,.-fixture_null_hook
.org 0x220,0xcc
.globl fixture_journal_hook
.hidden fixture_journal_hook
.type fixture_journal_hook,@function
fixture_journal_hook:
  .byte 0x48,0x8b,0x07          /* mov (%rdi),%rax: logical PC */
  .byte 0x48,0x89,0x05          /* mov %rax,fixture_journal+8(%rip) */
  .long fixture_journal + 8 - . - 4
  .byte 0x48,0x83,0x05          /* addq $1,fixture_journal(%rip) */
  .long fixture_journal - . - 5
  .byte 0x01,0xc3
.size fixture_journal_hook,.-fixture_journal_hook
.org 0x300,0xcc
message:
  .ascii "elf tactics ok\n"
  .byte 0
.org 0x340,0xcc
fixture_descriptor:
  .ascii "LI2TACT1"
  .quad TACTIC,HEAD_COUNT
  .quad H0,H1,H2,H3,H4,H5

/* Six physical table slots; unused slots are zero and never reachable. */
.org 0x390,0xcc
call_table:
  .quad invoke_head0,invoke_head1,invoke_head2
.if HEAD_COUNT > 3
  .quad invoke_head3
.else
  .quad 0
.endif
.if HEAD_COUNT > 4
  .quad invoke_head4
.else
  .quad 0
.endif
.if HEAD_COUNT > 5
  .quad invoke_head5
.else
  .quad 0
.endif
.org 0x3c0,0xcc
expected_table:
.if TACTIC == 2 || TACTIC == 3
  .quad 42,42,SENTINEL,0,0,0
.elseif TACTIC == 4
  .quad 42,42,42,SENTINEL,42,SENTINEL
.else
  .quad SENTINEL,SENTINEL,SENTINEL,42,SENTINEL,0
.endif

.macro CALL_SLOT index, head
  .org 0x400 + 16*\index,0xcc
  .if \index < HEAD_COUNT
    .globl invoke_head\index,after_head\index
    .type invoke_head\index,@function
    invoke_head\index:
      .byte 0xe8
      .long subject_value + \head - . - 4
    after_head\index:
      JMP after_return
    .size invoke_head\index,.-invoke_head\index
  .endif
.endm
CALL_SLOT 0,H0
CALL_SLOT 1,H1
CALL_SLOT 2,H2
CALL_SLOT 3,H3
CALL_SLOT 4,H4
CALL_SLOT 5,H5
.org 0x500,0xcc
.globl after_return
.type after_return,@function
after_return:
  .byte 0x4c,0x8d,0x3d          /* lea expected_table(%rip),%r15 */
  .long expected_table - . - 4
  .byte 0x4b,0x3b,0x04,0xe7    /* cmp (%r15,%r12,8),%rax */
  JCC 0x85,failed
  .byte 0x45,0x85,0xf6          /* test %r14d,%r14d */
  JCC 0x85,success
  .byte 0x41,0xff,0xc4          /* inc %r12d */
  .byte 0x41,0x83,0xfc,HEAD_COUNT
  JCC 0x82,prepare_call         /* jb prepare_call */
  .byte 0x45,0x31,0xe4          /* xor %r12d,%r12d */
  .byte 0x41,0xff,0xc5          /* inc %r13d */
  .byte 0x41,0x83,0xfd,0x02
  JCC 0x82,prepare_call
  JMP success
.size after_return,.-after_return
.org 0x580,0xcc
.globl success
.type success,@function
success:
  .byte 0xb8,1,0,0,0           /* mov $1,%eax */
  .byte 0xbf,1,0,0,0           /* mov $1,%edi */
  .byte 0x48,0x8d,0x35          /* lea message(%rip),%rsi */
  .long message - . - 4
  .byte 0xba,15,0,0,0          /* mov $15,%edx */
  .byte 0x0f,0x05
  .byte 0x48,0x83,0xf8,15
  JCC 0x85,failed
  .byte 0x31,0xff              /* xor %edi,%edi */
  .byte 0xb8,60,0,0,0
  .byte 0x0f,0x05,0x0f,0x0b
.size success,.-success
.org 0x5d0,0xcc
.globl failed
.type failed,@function
failed:
  .byte 0xbf,9,0,0,0
  .byte 0xb8,60,0,0,0
  .byte 0x0f,0x05,0x0f,0x0b
.size failed,.-failed
.org 0x1000,0xcc

.section .text.subject,"ax",@progbits
.org 0xf0,0xcc
  .fill 16,1,0x90
.globl subject_value
.type subject_value,@function
subject_value:
.if TACTIC == 2
  .byte 0x0f,0x1f,0x00,0xb8,42,0,0,0,0xc3
.elseif TACTIC == 3
  .byte 0x89,0xc0,0xb8,42,0,0,0,0xc3
.elseif TACTIC == 4
  .byte 0x0f,0x1f,0x00,0x0f,0x1f,0x84,0x00,0,0,0,0,0xb8,42,0,0,0,0xc3
  .fill 64-(.-subject_value),1,0x90
  .byte 0x48,0xb8
  .quad 42
  .byte 0xc3
.else
  .byte 0x75,0x01,0x90,0xc3
  .fill 64-(.-subject_value),1,0x90
  .byte 0x48,0xb8
  .quad 42
  .byte 0xc3
.endif
.size subject_value,.-subject_value
.org 0x1000,0xcc

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
