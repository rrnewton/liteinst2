#!/usr/bin/env python3
"""Read one complete native RET chunk; retain observed commitment, never rewrite authority."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

PAGE, FP, STACK, FRAME, RECORD = 4096, 65536, 16384, 67072, 183736
MAGIC, REC_MAGIC, END = 0x3154455232494C, 0x3152455232494C, 0x3145455232494C
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
    need(mask == bytes(mask[:8])+bytes(info[:120]) and context[304:432] == info,
         'whole captured mask128 is kernel mask8 plus event siginfo120; whole embedded siginfo128')
    sig, error, code = struct.unpack_from('<iii', info)
    need((sig, error & MASK64, code & MASK64) == (h[0], h[2], h[1]) and
         words(info, 1, 16)[0] == h[3], 'whole siginfo joins')
    need((greg[20], greg[19], greg[22]) == h[13:16], 'raw trap/error/CR2 joins')
    return h, greg, fp


def configuration(identity, header):
    stack, target = header[22], header[23]
    group, item, sp = 0, identity, stack+2*PAGE+512
    targets = (target+64, target+PAGE+64, 0x0100000000000000, 0x8000000000000000)
    destination = targets[0]
    permissions = [0, 3, 3, 0]
    status = flags((identity*7) & 63) | (0x400 if identity & 1 else 0)
    if identity < 20:
        destination = targets[identity % 4]
        position = identity//4
        if position == 1:
            sp += 1
        elif position >= 2:
            sp = stack+2*PAGE-(1, 4, 7)[position-2]
    elif identity < 24:
        group, item = 1, identity-20
        destination = targets[item]
        permissions[1:3] = [1, 1]
    elif identity < 30:
        group, item = 2, identity-24
        if item == 0:
            permissions[2] = 0
        elif item <= 3:
            sp = stack+2*PAGE-(1, 4, 7)[item-1]
            permissions[2] = 0
        else:
            sp = stack+2*PAGE-(1 if item == 4 else 4)
            permissions[1] = 0
    else:
        group, item = 3, identity-30
        sp = (0x0100000000001000, 0x8000000000001000)[item]
    return group, item, sp, destination, status, permissions


def lane(raw, header, identity):
    need(len(raw) == RECORD, 'whole RET record')
    h, bootstrap = words(raw, 32), words(raw, 23, 256)
    group, item, sp, target, status, permissions = configuration(identity, header)
    pc = header[21]+0x100
    need(h[:13] == (REC_MAGIC, RECORD, identity, 0, 4, group, item, pc,
                   pc+1, target, sp, status, 1), 'complete exact RET matrix identity')
    need(h[13:20] == (1, 0, 2, 2, 1, 0, 0) and h[20:24] == tuple(permissions) and
         h[24:26] == (5, 1) and not any(h[26:]), 'complete two-event observation and actual requested permissions')
    before = frame(raw[440:440+FRAME], header, 0)
    after = frame(raw[440+FRAME:440+2*FRAME], header, 1)
    seed = [(0x13579BDF00110000+0x100010001*i+identity) & MASK64 for i in range(16)]
    seed[4] = sp
    need(tuple(before[1][r] for r in REG) == tuple(seed) and before[1][16] == pc and
         before[1][17] & ~0x10000 == status, 'complete original NX-before GPRs and flags')
    need(before[0][0:2] == (11, 2) and before[0][3] == pc and
         before[1][20] == 14 and before[1][19] & 16, 'actual initial NX instruction-fetch event')
    expected_bootstrap = list(before[1])
    expected_bootstrap[16], expected_bootstrap[15] = header[28:30]
    expected_bootstrap[17] &= ~(0x10000 | 0x100)
    need(bootstrap == tuple(expected_bootstrap), 'unchanged real safe-stack reload bootstrap')
    need(after[0][0] in (4, 5, 7, 11), 'actual second synchronous stop')
    need(all(after[1][REG[i]] == seed[i] for i in range(16) if i != 4) and
         after[1][17] & ~0x10000 == status, 'all non-RSP GPRs and original condition flags unchanged')
    need(before[2] == after[2] and before[0][8:10] == after[0][8:10] and
         before[0][4:6] == after[0][4:6] and before[1][18] == after[1][18] and
         before[1][21] == after[1][21] and raw[440+312:440+320] == raw[440+FRAME+312:440+FRAME+320],
         'complete FP storage, actual TLS, uc flags/link, segment state and signal mask unchanged')
    start = 440+2*FRAME
    initial, final = raw[start:start+STACK], raw[start+STACK:start+2*STACK]
    expected = bytearray((0x5A+37*i+identity) & 255 for i in range(STACK))
    operand_present = header[22] <= sp <= header[22]+STACK-8
    if operand_present:
        expected[sp-header[22]:sp-header[22]+8] = struct.pack('<Q', target)
    need(initial == expected and final == initial, 'whole declared stack operand and complete unchanged stack bytes')
    source = raw[start+2*STACK:]
    code = bytearray(b'\xcc'*(2*PAGE))
    code[0x100] = 0xC3
    need(source == code+b'\xcc'*(2*PAGE), 'complete exact C3 source and both RX/NX target pages')
    actual_rsp, actual_rip = after[1][15:17]
    delta = (actual_rsp-sp) & MASK64
    commitment = 'unchanged' if delta == 0 else 'plus8' if delta == 8 else 'other'
    logical_before = list(before[1])
    logical_before[17] = status
    changes = {name: {'before': logical_before[i], 'after': after[1][i]}
               for i, name in enumerate(GREG_NAMES) if logical_before[i] != after[1][i]}
    return {'id': identity, 'group': group, 'group_case': item,
            'initial_rsp': sp, 'initial_target': target, 'stack_operand_present': operand_present,
            'input_rflags': status, 'actual_rsp': actual_rsp, 'actual_rip': actual_rip,
            'rsp_delta_mod64': delta, 'observed_rsp_commitment': commitment,
            'signal': after[0][0], 'si_code': after[0][1], 'signal_address': after[0][3],
            'trapno': after[1][20], 'error_code': after[1][19], 'cr2': after[1][22],
            'before_greg': list(before[1]), 'after_greg': list(after[1]), 'greg_changes': changes,
            'fp_storage_unchanged': True, 'fp_sha256': digest(before[2]),
            'fs_gs_unchanged': True, 'stack_bytes_unchanged': True, 'stack_sha256': digest(initial),
            'source_sha256': digest(source), 'raw_record_sha256': digest(raw)}


def read_file(path, cpu, pid):
    raw = path.read_bytes()
    need(256+64 <= len(raw) < 16 << 20, 'unchanged strict raw output bound')
    h = words(raw, 32)
    need(h[:15] == (MAGIC, 1, 256, RECORD, FRAME, 968, 128, FP, STACK, 16384,
                    32, 0, 0, 32, 32), 'complete single-chunk RET ABI and population')
    need(h[15] == pid and pid > 0 and h[16] == cpu and h[19] & 3 == 3 and 512 <= h[20] <= FP and
         h[25:28] == (262144, 0, 32) and h[28] and h[29] and not any(h[30:]),
         'actual process-owned PID/CPU, FP and bounded bootstrap')
    need((h[17] == 0 and h[18] == 0) or h[17] in ((-22) & MASK64, (-38) & MASK64),
         'unchanged actual production CET prerequisite; never disable CET')
    need(all(h[i] and h[i] % PAGE == 0 for i in (21, 22, 23, 24)), 'actual page bases')
    spans = sorted(((h[21], h[21]+8192), (h[22], h[22]+STACK),
                    (h[23], h[23]+8192), (h[24]-PAGE, h[24]+h[25]+PAGE)))
    need(all(a < b for a, b in spans) and all(spans[i][1] <= spans[i+1][0] for i in range(3)),
         'distinct source, target, subject and alternate allocations')
    need(len(raw) == 256+32*RECORD+64 and
         words(raw, 8, len(raw)-64) == (END, 1, 32, len(raw), 0, 0, 0, 0),
         'whole completed RET output and footer')
    observations = [lane(memoryview(raw)[256+i*RECORD:256+(i+1)*RECORD], h, i) for i in range(32)]
    need([sum(o['group'] == g for o in observations) for g in range(4)] == [20, 4, 6, 2],
         'all declared cases, no optional category or subset')
    return {'schema': 1, 'status': 'observed_unqualified', 'native_cases': 32, 'native_lanes': 32,
            'cpu': cpu, 'source': {'bytes': len(raw), 'sha256': digest(raw), 'pid': pid},
            'observations': observations, 'ret_continuation_safe': None,
            'production_admission_credit': False, 'owner_credit': False,
            'qualification_credit': False, 'performance_credit': False,
            'scope': 'Actual unstepped C3 endpoint/fault and stack-pointer commitment observations; no RET rewrite authority.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-cpu', type=int, required=True)
    parser.add_argument('--expect-pid', type=int, required=True)
    parser.add_argument('capture', type=Path)
    args = parser.parse_args()
    need(args.expect_cpu >= 0 and args.expect_pid > 0, 'actual reserved CPU and owned child PID')
    print(json.dumps(read_file(args.capture, args.expect_cpu, args.expect_pid), sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
