#!/usr/bin/env python3
"""Finite authored whole programs; no execution, inference, or host discovery."""
import hashlib
import struct

BASE = 0x402000
HOOK = 0x403000
MAX_INPUT = 65536
# Every tuple is one complete instruction. Branch displacements are resolved
# from this closed table, never from an incomplete disassembler/CFG guess.
# (label, exact bytes or near-branch opcode, branch target or None)
CHECKSUM = [
    ('entry', '31c0', None),                 # xor eax,eax: byte sum
    ('hash', '49b825232284e49cf2cb', None),   # FNV-1a offset basis
    ('prime', '49ba b301000000010000', None),
    ('index', '31c9', None),
    ('empty', '4885f6', None),
    ('empty_branch', '0f84', 'done'),
    ('loop', '440fb60c0f', None),            # movzx r9d,[rdi+rcx]
    ('sum', '4c01c8', None),
    ('xor', '4d31c8', None),
    ('multiply', '4d0fafc2', None),
    ('increment', '48ffc1', None),
    ('compare', '4839f1', None),
    ('loop_branch', '0f82', 'loop'),
    ('done', '488902', None),
    ('save_hash', '4c894208', None),
    ('save_length', '48897210', None),
    ('length', 'b818000000', None),
    ('return', 'c3', None),
]
RLE = [
    ('entry', '4531c0', None),               # r8 = encoded length
    ('input_index', '4531c9', None),
    ('empty', '4885f6', None),
    ('empty_branch', '0f84', 'encoded'),
    ('encode', '460fb6140f', None),          # r10b = input[r9]
    ('count', '41bb01000000', None),
    ('advance', '49ffc1', None),
    ('scan', '4939f1', None),
    ('at_end', '0f83', 'emit'),
    ('count_limit', '4181fbff000000', None),
    ('full_run', '0f84', 'emit'),
    ('same_byte', '463a140f', None),
    ('different', '0f85', 'emit'),
    ('more_count', '41ffc3', None),
    ('more_input', '49ffc1', None),
    ('scan_again', 'e9', 'scan'),
    ('emit', '46885c0208', None),            # count at output[8+r8]
    ('emit_byte', '4688540209', None),
    ('encoded_advance', '4983c002', None),
    ('encode_compare', '4939f1', None),
    ('encode_again', '0f82', 'encode'),
    ('encoded', '4c8902', None),
    ('decoded_base', '4a8d5c0208', None),    # rbx = output+8+encoded length
    ('pair_index', '4531c9', None),
    ('decoded_index', '31c9', None),
    ('decode', '4d39c1', None),
    ('decoded_all', '0f83', 'done'),
    ('read_count', '460fb6540a08', None),
    ('read_value', '460fb65c0a09', None),
    ('run', '4839f1', None),
    ('overflow', '0f83', 'bad'),
    ('check_byte', '443a1c0f', None),
    ('mismatch', '0f85', 'bad'),
    ('decode_store', '44881c0b', None),
    ('decode_increment', '48ffc1', None),
    ('run_decrement', '41ffca', None),
    ('run_again', '0f85', 'run'),
    ('next_pair', '4983c102', None),
    ('decode_again', 'e9', 'decode'),
    ('done', '4839f1', None),
    ('short_decode', '0f85', 'bad'),
    ('length', '498d440808', None),          # rax = 8+r8+rcx
    ('return', 'c3', None),
    ('bad', '48c7c0ffffffff', None),
    ('bad_return', 'c3', None),
]
PROGRAMS = {'checksum': CHECKSUM, 'rle-roundtrip': RLE}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def instructions(name):
    source = PROGRAMS[name]
    offsets = {}; cursor = BASE
    for label, op, target in source:
        assert label not in offsets
        offsets[label] = cursor
        cursor += len(bytes.fromhex(op)) + (4 if target is not None else 0)
    rows = []
    for label, op, target in source:
        pc = offsets[label]; code = bytes.fromhex(op)
        if target is not None:
            assert code == b'\xe9' or len(code) == 2 and code[0] == 0x0f and 0x80 <= code[1] <= 0x8f
            code += struct.pack('<i', offsets[target] - pc - len(code) - 4)
        rows.append(dict(label=label, pc=pc, code=code, target=None if target is None else offsets[target]))
    assert cursor - BASE < 4096
    return rows

START = r'''.section .text.start,"ax",@progbits
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
'''

END = r'''.section .text.hook,"ax",@progbits
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
'''

LINKER = r'''ENTRY(_start)
PHDRS {
 headers PT_PHDR PHDRS FLAGS(4);
 ro PT_LOAD FILEHDR PHDRS FLAGS(4);
 text PT_LOAD FLAGS(5);
 data PT_LOAD FLAGS(6);
 note PT_NOTE FLAGS(4);
 stack PT_GNU_STACK FLAGS(6);
}
SECTIONS {
 . = 0x400000 + SIZEOF_HEADERS;
 .note.fixture : { *(.note.fixture) } :ro :note
 .header_pad : { BYTE(0); . = ALIGN(4096); } :ro
 . = 0x401000;
 .text : { *(.text.start) . = 0x1000; *(.text.kernel) . = 0x2000; *(.text.hook) . = ALIGN(4096); } :text
 . = 0x404000;
 .data : { *(.data.buffers) } :data
 /DISCARD/ : { *(.comment) *(.note.GNU-stack) *(.eh_frame*) }
}
'''

def assembly(name):
    rows = instructions(name)
    body = ['.section .text.kernel,"ax",@progbits', '.globl kernel,kernel_end', '.type kernel,@function', 'kernel:']
    for row in rows:
        body += [f'head_{row["label"]}:', '  .byte ' + ','.join(hex(v) for v in row['code'])]
    body += ['kernel_end:', '.size kernel,.-kernel']
    return (START + '\n'.join(body) + '\n' + END).encode()

def datasets():
    # Every case is mandatory. 255/256 exercise RLE count saturation; the long
    # alternating case realizes maximum output expansion, not a compressible subset.
    return {
        'empty': b'', 'single-zero': b'\0', 'single-ff': b'\xff',
        'all-bytes': bytes(range(256)), 'run-255': b'Q' * 255,
        'run-256': b'Q' * 256, 'runs-boundary': b'A' * 257 + b'B' * 254 + b'A',
        'mixed-4096': bytes((i * 37 + i // 17 + 11) & 255 for i in range(4096)),
        'long-run': b'Z' * MAX_INPUT,
        'long-alternating': bytes([0, 255]) * (MAX_INPUT // 2),
    }

def expected(name, data):
    assert len(data) <= MAX_INPUT
    if name == 'checksum':
        value = 0xcbf29ce484222325
        for byte in data:
            value = ((value ^ byte) * 0x100000001b3) & ((1 << 64) - 1)
        return struct.pack('<QQQ', sum(data), value, len(data))
    assert name == 'rle-roundtrip'
    pairs = bytearray(); at = 0
    while at < len(data):
        end = at + 1
        while end < len(data) and data[end] == data[at] and end - at < 255:
            end += 1
        pairs.extend((end - at, data[at])); at = end
    decoded = b''.join(bytes([pairs[i+1]]) * pairs[i] for i in range(0, len(pairs), 2))
    assert decoded == data
    return struct.pack('<Q', len(pairs)) + pairs + decoded
