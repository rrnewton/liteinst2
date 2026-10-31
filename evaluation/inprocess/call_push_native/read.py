#!/usr/bin/env python3
"""Read all seven bounded raw chunks; report observations, never equivalence."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

PAGE, FP, STACK, FRAME, RECORD = 4096, 65536, 16384, 67072, 175544
MAGIC, REC_MAGIC, END = 0x315242504332494C, 0x314345525032494C, 0x31444E455032494C
REG = (13, 14, 12, 11, 15, 10, 9, 8, 0, 1, 2, 3, 4, 5, 6, 7)
GREG_NAMES = ('r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
              'rdi', 'rsi', 'rbp', 'rbx', 'rdx', 'rax', 'rcx', 'rsp',
              'rip', 'eflags', 'csgsfs', 'err', 'trapno', 'oldmask', 'cr2')
MASK64 = (1 << 64)-1


def need(value, message):
    if not value:
        raise ValueError(message)


def words(raw, count, offset=0):
    return struct.unpack_from('<'+'Q'*count, raw, offset)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def flags(value):
    return 0x202 | sum(1 << bit for i, bit in enumerate((0, 2, 4, 6, 7, 11)) if value & (1 << i))


def configuration(identity, header):
    stack, target = header[22], header[23]
    reg, group, item, sp, destination, status = 0, 0, identity, stack+2*PAGE+512, target+64, 0x202
    permissions = [0, 3, 3, 0]
    if identity < 16:
        reg, status = identity, flags(identity) | (0x400 if identity & 1 else 0)
    elif identity < 144:
        group, item = 1, identity-16
        status = flags(item & 63) | (0x400 if item & 64 else 0)
    elif identity < 160:
        group, item = 2, identity-144
        sp += item
    elif identity < 195:
        group, item = 3, identity-160
        sp = stack+2*PAGE+item % 7+1
        permissions[1:3] = ((3, 3), (3, 0), (0, 3), (3, 1), (1, 3))[item//7]
    elif identity < 211:
        group, item = 4, identity-195
        destination = (target+64, target+PAGE, 0x0100000000000000, 0x8000000000000000)[item//4]
        kind = item % 4
        if kind in (1, 2):
            permissions[2] = 0
        if kind == 2:
            sp = stack+2*PAGE+4
        if kind == 3:
            sp = 0x0100000000001000
    else:
        group, item, reg = 5, identity-211, 4
        if item in (1, 2, 3):
            sp = stack+2*PAGE+4
        if item == 2:
            permissions[2] = 0
        if item == 3:
            permissions[1] = 0
        if item == 4:
            sp = 0x0100000000001000
        if item == 5:
            sp = 0x8000000000001000
    if reg == 4:
        destination = sp
    return reg, group, item, sp, destination, status, permissions


def frame(raw, header, phase):
    need(len(raw) == FRAME, 'whole frame')
    h, greg = words(raw, 16), words(raw, 23, 128)
    mask, info, context, fp = raw[312:440], raw[440:568], raw[568:1536], raw[1536:]
    need(h[11] == header[16] and h[12] == phase, 'actual CPU and event order')
    need(header[24] <= h[10] < header[24]+header[25] and
         header[24] <= h[6] <= header[24]+header[25]-h[7], 'actual alternate-stack geometry')
    need(512 <= h[7] <= FP and not any(fp[h[7]:]), 'whole FP extent and zero unused tail')
    magic = struct.unpack_from('<I', fp, 464)[0]
    if magic == 0x46505853:
        need(struct.unpack_from('<I', fp, 468)[0] == h[7] and h[7] >= 576 and
             struct.unpack_from('<I', fp, h[7]-4)[0] == 0x46505845 and
             struct.unpack_from('<I', fp, 480)[0] <= h[7]-4, 'actual xstate framing')
    else:
        need(h[7] == 512, 'legacy FP framing')
    need(words(context, 23, 40) == greg and words(context, 1, 224)[0] == h[6] and
         context[296:424] == mask and words(context, 2) == h[4:6], 'whole ucontext joins')
    sig, error, code = struct.unpack_from('<iii', info)
    need((sig, error & MASK64, code & MASK64) == (h[0], h[2], h[1]) and
         words(info, 1, 16)[0] == h[3], 'whole siginfo joins')
    need((greg[20], greg[19], greg[22]) == h[13:16], 'raw trap/error/CR2 joins')
    return h, greg, fp


def ranges(before, after):
    result, i = [], 0
    while i < len(before):
        if before[i] == after[i]:
            i += 1
            continue
        start = i
        while i < len(before) and before[i] != after[i]:
            i += 1
        result.append({'offset': start, 'bytes': i-start,
                       'before_sha256': digest(before[start:i]),
                       'after_sha256': digest(after[start:i])})
    return result


def lane(raw, header, identity, which):
    need(len(raw) == RECORD, 'whole lane record')
    h, bootstrap = words(raw, 32), words(raw, 23, 256)
    reg, group, item, sp, target, status, permissions = configuration(identity, header)
    pc, call_bytes = header[21]+0x100, 3 if reg >= 8 else 2
    need(h[:13] == (REC_MAGIC, RECORD, identity, which, reg, group, item, pc,
                   pc+call_bytes, target, sp, status, call_bytes), 'complete exact matrix identity')
    need(h[13:19] == (1, 0, 2, 2, 6 if which else call_bytes, 15) and
         h[19] == 0 and h[20:24] == tuple(permissions) and not any(h[24:]),
         'completed observation, two events, seals and original permissions')
    before = frame(raw[440:440+FRAME], header, 0)
    after = frame(raw[440+FRAME:440+2*FRAME], header, 1)
    seed = [(0x13579BDF00110000+0x100010001*i+identity) & MASK64 for i in range(16)]
    seed[reg], seed[4] = target, sp
    need(tuple(before[1][r] for r in REG) == tuple(seed) and before[1][16] == pc and
         before[1][17] & ~0x10000 == status, 'actual NX-before complete seeded GPR/flags')
    need(before[0][0:2] == (11, 2) and before[0][3] == pc and
         before[1][20] == 14 and before[1][19] & 16, 'real NX instruction-fetch before event')
    expected_bootstrap = list(before[1])
    expected_bootstrap[16], expected_bootstrap[15] = header[28:30]
    expected_bootstrap[17] &= ~(0x10000 | 0x100)
    need(bootstrap == tuple(expected_bootstrap), 'exact safe-stack reload bootstrap')
    logical_before = list(before[1])
    logical_before[17] = status
    need(after[0][0] in (4, 5, 7, 11), 'actual synchronous stop')
    start = 440+2*FRAME
    initial, final = raw[start:start+STACK], raw[start+STACK:start+2*STACK]
    need(initial == bytes((0x5A+37*i+identity) & 255 for i in range(STACK)), 'whole initial stack')
    source = raw[start+2*STACK:]
    expected = bytearray(b'\xcc'*PAGE)
    if which:
        instruction = b'\xff\x35'+struct.pack('<i', PAGE-0x106)
    else:
        instruction = (b'\x41' if reg >= 8 else b'')+bytes((0xFF, 0xD0+(reg & 7)))
    expected[0x100:0x100+len(instruction)] = instruction
    need(source == expected+struct.pack('<Q', pc+call_bytes)+bytes(PAGE-8),
         'whole actual source and sealed original-next-PC page')
    changes = {name: {'before': logical_before[i], 'after': after[1][i]}
               for i, name in enumerate(GREG_NAMES) if logical_before[i] != after[1][i]}
    return {'id': identity, 'lane': 'push_literal' if which else 'call_register',
            'register': GREG_NAMES[REG[reg]], 'group': group, 'group_case': item,
            'initial_rsp': sp, 'initial_target': target, 'input_rflags': status,
            'signal': after[0][0], 'si_code': after[0][1], 'signal_address': after[0][3],
            'greg_changes': changes, 'after_greg': list(after[1]),
            'fp_storage_unchanged': before[2] == after[2],
            'fs_gs_unchanged': before[0][8:10] == after[0][8:10],
            'stack_changed_bytes': sum(a != b for a, b in zip(initial, final)),
            'stack_changes': ranges(initial, final),
            'raw_record_sha256': digest(raw)}


def read_chunks(paths, cpu):
    need(len(paths) == 7 and len(set(map(str, paths))) == 7, 'all seven distinct chunks required')
    observations, sources = [], []
    for chunk, path in enumerate(paths):
        raw = path.read_bytes()
        need(256+64 <= len(raw) < 16 << 20, 'original strict raw output bound')
        h = words(raw, 32)
        count = min(32, 217-32*chunk)
        need(h[:15] == (MAGIC, 1, 256, RECORD, FRAME, 968, 128, FP, STACK, 8192,
                        217, chunk, 32*chunk, count, 2*count), 'exact chunk/ABI framing')
        need(h[15] > 0 and h[16] == cpu and h[19] & 3 == 3 and 512 <= h[20] <= FP and
             h[25:28] == (262144, 15, 32) and h[28] and h[29] and not any(h[30:]),
             'CPU/FP/bounded bootstrap header')
        need((h[17] == 0 and h[18] == 0) or h[17] in ((-22) & MASK64, (-38) & MASK64),
             'unchanged actual production CET-disabled prerequisite')
        need(all(h[i] and h[i] % PAGE == 0 for i in (21, 22, 23, 24)), 'actual page bases')
        # Do not infer memory ownership from these numbers; only validate the
        # fixture's distinct complete allocation geometry in the raw record.
        spans = sorted(((h[21], h[21]+8192), (h[22], h[22]+STACK),
                        (h[23], h[23]+8192), (h[24]-PAGE, h[24]+h[25]+PAGE)))
        need(all(a < b for a, b in spans) and all(spans[i][1] <= spans[i+1][0] for i in range(3)),
             'distinct source, target, subject and alternate allocations')
        need(len(raw) == 256+2*count*RECORD+64 and
             words(raw, 8, len(raw)-64) == (END, 1, 2*count, len(raw), 0, 0, 0, 0),
             'whole completed output and footer')
        for n in range(2*count):
            start = 256+n*RECORD
            observations.append(lane(memoryview(raw)[start:start+RECORD], h, 32*chunk+n//2, n % 2))
        sources.append({'chunk': chunk, 'bytes': len(raw), 'sha256': digest(raw), 'pid': h[15]})
    need(len(observations) == 434, 'all original diagnostic cases, no subset')
    pairs = []
    for identity in range(217):
        call, push = observations[2*identity:2*identity+2]
        pairs.append({'id': identity, 'call': call, 'push': push,
                      'after_greg_differences': [name for i, name in enumerate(GREG_NAMES)
                                                 if call['after_greg'][i] != push['after_greg'][i]]})
    return {'schema': 1, 'status': 'observed_unqualified', 'matrix_pairs': 217,
            'native_lanes': 434, 'cpu': cpu, 'sources': sources, 'pairs': pairs,
            'call_push_equivalence': None, 'production_admission_credit': False,
            'owner_credit': False, 'qualification_credit': False, 'performance_credit': False,
            'scope': 'Actual INT3 endpoint or synchronous fault after individual unstepped native instructions. Differences are retained; no CALL/PUSH equivalence assertion.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-cpu', type=int, required=True)
    parser.add_argument('chunks', nargs=7, type=Path)
    args = parser.parse_args()
    need(args.expect_cpu >= 0, 'actual reserved CPU')
    print(json.dumps(read_chunks(args.chunks, args.expect_cpu), sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
