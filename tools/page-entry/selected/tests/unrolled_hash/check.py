"""Strict finite two-lane record reader. No execution, timing, or owner credit."""
import json
import struct

BODY = bytes.fromhex('4889d84883c10148c1e0054801c34801d30fb61184d275e8')
SOURCE = BODY + bytes.fromhex('89db488305eee4020001b8ffffffff')
OFFSETS = (0, 3, 7, 11, 14, 17, 20, 22)
LENGTHS = (3, 4, 4, 3, 3, 3, 2, 2)
CODES = (282, 249, 381, 8, 8, 2090, 271, 176)
COMPLETED = (1, 2, 63, 64, 64, 2, 64, 0, 63)
NUL = (1, 2, 63, 64, 65, 2, 64, 0, 0)
REGS = (13, 14, 12, 11, 15, 10, 9, 8, 0, 1, 2, 3, 4, 5, 6, 7)
FP = 65536
TF, RF = 0x100, 0x10000
MASK64 = (1 << 64) - 1
WIRE_BYTES = 556032
OBS_BYTES = 271696


def need(condition, message):
    if not condition:
        raise ValueError(message)


def q(data, at=0, n=1):
    return struct.unpack_from('<' + 'Q' * n, data, at)


def u(data, at=0, n=1):
    return struct.unpack_from('<' + 'I' * n, data, at)


def json_row(data):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            need(key not in out, 'duplicate_key')
            out[key] = value
        return out
    need(type(data) is bytes and len(data) <= 2048, 'stdout_bound')
    row = json.loads(data, object_pairs_hook=unique)
    need(type(row) is dict and all(type(x) is int for x in row.values()), 'integer_row')
    need(json.dumps(row, separators=(',', ':')).encode() + b'\n' == data, 'canonical_row')
    return row


def live(data):
    need(len(data) == 152 and data[148:] == b'\0' * 4, 'live_extent')
    return q(data, 0, 16), q(data, 128)[0], data[136:148]


def frame(data, h):
    need(len(data) == 65792, 'frame_extent')
    g = q(data, 0, 23)
    mask, address, count, initialized = q(data, 184, 4)
    need(mask == h[13] and initialized == count and 580 <= count <= FP, 'frame_header')
    need(address % 16 == 0 and h[12] + 4096 <= address <= h[12] + 4096 + 524288 - count, 'frame_storage')
    need(data[216:256] == b'\0' * 40, 'frame_padding')
    fp = data[256:]
    need(fp[count:] == b'\0' * (FP - count), 'frame_unused')
    if count != 512:
        need(count >= 580 and u(fp, 464)[0] == 0x46505853 and u(fp, 468)[0] == count and u(fp, 480)[0] == count - 4 and u(fp, count - 4)[0] == 0x46505845 and q(fp, 520)[0] == 0, 'kernel_standard_fp')
    return g, fp, count, mask


def seed_fp(fp, layout, xsave_bytes):
    need(len(fp) == FP and struct.unpack_from('<HH', fp) == (0x37f, 0x3000) and fp[4] == 0xc0 and u(fp, 24)[0] == 0x1f80, 'seed_x87_mxcsr')
    bv, comp = q(fp, 512, 2)
    need(bv & 0xe7 == 0xe7 and comp == 0, 'seed_xstate')
    for reg in range(32):
        for word in range(8):
            if reg >= 16:
                feature, off = 7, (reg - 16) * 64 + word * 8
            elif word >= 4:
                feature, off = 6, reg * 32 + (word - 4) * 8
            elif word >= 2:
                feature, off = 2, reg * 16 + (word - 2) * 8
            else:
                feature, off = 0, 160 + reg * 16 + word * 8
            if feature:
                present, base, size = layout[feature]
                need(present == 1 and off + 8 <= size, 'seed_component')
                off += base
            need(off + 8 <= xsave_bytes and q(fp, off)[0] == 0x3141592653589793 + reg * 8 + word + 1, 'seed_vector')
    masks = (0x0123456789abcdef, 0xfedcba9876543210, 0xaaaaaaaa55555555, 0x0f0ff0f0a5a55a5a, 0x1111222233334444, 0x8877665544332211, 0xffff00000000ffff, 0x5a5a5a5aa5a5a5a5)
    need(layout[5][0] == 1 and layout[5][2] >= 64 and q(fp, layout[5][1], 8) == masks, 'seed_opmask')


def observation(data, h, seed, layout, which):
    need(len(data) == OBS_BYTES, 'observation_extent')
    before, after = live(data[:152]), live(data[152:304])
    xbefore, xafter = data[304:65840], data[65840:131376]
    entry = frame(data[131376:197168], h)
    ending = frame(data[197168:262960], h)
    entry_si, exit_si = data[262960:263088], data[263088:263216]
    stack, memory = data[263216:263376], data[263376:271568]
    m = q(data, 271568, 16)
    mode, copies = h[3], COMPLETED[h[3]]
    fault = mode >= 7
    kind = 3 if fault else 1 if mode == 4 else 2
    trace = 0 if which else copies * 8 + (5 if fault else 0)
    raw_pc = h[9] + copies * 28 + 17 if which and fault else h[8] + (17 if fault else 0 if mode == 4 else 24)
    logical_pc = h[8] + (17 if fault else 0 if mode == 4 else 24)
    need(m[:7] == (which, 2 if which and not fault else 1, trace, copies, kind, raw_pc, logical_pc), 'event_prefix')
    need(m[9:] == (1, 1, copies if fault else copies - 1, 17 if fault else 22, h[11] + 8192 if fault else 0, 0, 0), 'event_suffix')
    need(before[0] == seed and before[1] == h[23] and before[2] == after[2], 'before_seed_selectors')
    need(xbefore == xafter and entry[1:] == ending[1:], 'full_fp_conservation')
    seed_fp(xbefore, layout, h[7]); seed_fp(xafter, layout, h[7]); seed_fp(entry[1], layout, h[7]); seed_fp(ending[1], layout, h[7])
    need(tuple(entry[0][r] for r in REGS) == seed and entry[0][16] == h[8] and entry[0][17] == h[23] | RF and entry[0][19:21] == (21, 14), 'actual_nx_entry')
    need(u(entry_si, 0, 3) == (11, 0, 2) and q(entry_si, 16)[0] == h[8], 'entry_siginfo')
    need(tuple(ending[0][r] for r in REGS) == after[0] and ending[0][16] == raw_pc, 'actual_exit_gprs')
    expected_flags = after[1] | (RF if which or fault else TF) | (TF if not which and fault else 0)
    need(ending[0][17] == expected_flags and not (after[1] & (TF | RF)), 'complete_flags_no_af_mask')
    if fault:
        need(ending[0][19:21] == (4, 14) and ending[0][22] == h[11] + 8192 and u(exit_si, 0, 3) == (11, 0, 2) and q(exit_si, 16)[0] == h[11] + 8192, 'actual_read_fault')
    elif which:
        need(ending[0][19:21] == (21, 14) and u(exit_si, 0, 3) == (11, 0, 2) and q(exit_si, 16)[0] == raw_pc, 'actual_nx_exit')
    else:
        need(ending[0][19:21] == (0, 1) and u(exit_si, 0, 3) == (5, 0, 2), 'actual_reference_trace')
    want_data = bytearray(1 + (i * 17) % 255 for i in range(8192))
    first = 8192 - 64 if mode == 6 else 8192 if mode == 7 else 8192 - 63 if mode == 8 else 128
    if NUL[mode]:
        want_data[first + NUL[mode] - 1] = 0
    need(memory == want_data and stack == bytes((i * 29 + 7) & 255 for i in range(160)), 'all_memory_and_stack')
    want = list(seed)
    for i in range(copies + int(fault)):
        want[0] = (want[3] << 5) & MASK64
        want[1] += 1
        want[3] = (want[3] + want[0] + want[2]) & MASK64
        if fault and i == copies:
            break
        need(h[11] <= want[1] < h[11] + 8192, 'model_read_bound')
        want[2] = want_data[want[1] - h[11]]
    need(after[0] == tuple(want), 'independent_defined_gpr_recurrence')
    return before, after, xbefore, xafter, entry, ending, m, stack, memory


def check(record, stdout, stderr, exit_status, mode):
    need(type(mode) is int and 0 <= mode < 9 and type(exit_status) is int and exit_status == (125 if mode >= 7 else 0), 'actual_exit')
    need(type(record) is bytes and len(record) == WIRE_BYTES and stderr == b'', 'complete_capture')
    h = q(record, 0, 32)
    need(h[:6] == (0x3148524c4e55494c, 1, 32, mode, 0, 1) and h[14:20] == (2528, 65792, 65536, 8192, 160, 2) and h[27] > 0 and h[29] > 0 and h[27] != h[29] and h[28] == h[30] and h[31] == 15, 'header')
    need(h[6] & 0xe7 == 0xe7 and 576 <= h[7] <= FP and h[8] + 4096 == h[9] and all(x > 0 and x % 4096 == 0 for x in h[8:13]), 'actual_layout')
    need(h[13] == MASK64 & ~sum(1 << (sig - 1) for sig in (11, 5, 31, 9, 19)), 'exact_application_mask')
    need(h[20:23] == ((70, 513, 1284) if mode == 0 else (0, 0, 0)) and h[23:27] == (0xad7 if mode == 5 else 0x202, COMPLETED[mode], NUL[mode], int(mode >= 7)), 'fixed_cases_controls')
    seed = q(record, 256, 16)
    want_seed = [0x3141592600000000 + i * 0x102030405 for i in range(16)]
    first = 8128 if mode == 6 else 8192 if mode == 7 else 8129 if mode == 8 else 128
    want_seed[1], want_seed[2], want_seed[3], want_seed[4] = h[11] + first - 1, 0xfedcba9876543280 if mode == 5 else 0x41, MASK64 - 3 if mode == 5 else 0x123456789abcdef0, h[10] + 4096 + 131072 - 504
    need(seed == tuple(want_seed) and seed[4] % 16 == 8, 'exact_seed')
    layout = tuple(q(record, 384 + i * 24, 3) for i in range(64))
    for feature, (present, offset, size) in enumerate(layout):
        if feature < 2 or not (h[6] >> feature & 1):
            need((present, offset, size) == (0, 0, 0), 'unused_cpuid_row')
        else:
            need(present == 1 and offset >= 576 and size > 0 and offset + size <= h[7], 'cpuid_component')
    source, image = record[1920:6016], record[6016:10112]
    need(source == SOURCE + b'\xcc' * (4096 - 39), 'whole_original_page')
    generated = bytearray()
    for copy in range(64):
        generated += BODY[:22] + b'\x0f\x84' + struct.pack('<i', h[8] + 24 - (h[9] + (copy + 1) * 28))
    generated += b'\xe9' + struct.pack('<i', h[8] - (h[9] + 1797))
    need(image == generated + b'\xcc' * (4096 - 1797), 'whole_generated_page')
    p = record[10112:12640]
    need(u(p, 0, 4) == (1, 1, 9, 0) and q(p, 16, 3) == (h[8], h[8] + 24, h[9]) and p[40:79] == SOURCE and p[79:1876] == generated and p[1876:1880] == b'\0' * 4, 'complete_plan')
    for i, offset in enumerate(OFFSETS + (24,)):
        d = p[1880 + 72 * i:1952 + 72 * i]
        length, code = (LENGTHS[i], CODES[i]) if i < 8 else (2, 281)
        need(q(d, 0, 2) == (h[8] + offset, h[8] + offset + length) and u(d, 16, 10) == (1, 0, code, 0, 16, 0, 1 if i in (0, 8) else 0, 15, length, 0) and d[56:] == SOURCE[offset:offset + 15] + b'\0', 'actual_decoder_rows')
    n = observation(record[12640:284336], h, seed, layout, 0)
    g = observation(record[284336:], h, seed, layout, 1)
    need(n[:4] == g[:4] and n[5][1:] == g[5][1:] and n[6][7:9] == g[6][7:9] and n[7:] == g[7:], 'full_hardware_lane_comparison')
    if mode >= 7:
        normalized = list(n[5][0]); normalized[16] = h[9] + COMPLETED[mode] * 28 + 17; normalized[17] &= ~TF
        need(tuple(normalized) == g[5][0], 'full_fault_frame_association')
    expected = dict(schema=1, mode=mode, qualified_comparison=1, completed_chunk=int(mode < 7), completed_loop=int(mode < 7 and mode != 4), required_read_failure=int(mode >= 7), cleanup=1, reference_trace=COMPLETED[mode] * 8 + (5 if mode >= 7 else 0), generated_trace=0, exit_kind=3 if mode >= 7 else 1 if mode == 4 else 2, negative_controls=h[20], head_checks=h[21], interior_misses=h[22])
    need(json_row(stdout) == expected, 'exact_numeric_output')
    return expected


if __name__ == '__main__':
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path); parser.add_argument('stdout', type=Path); parser.add_argument('stderr', type=Path)
    parser.add_argument('exit_status', type=int); parser.add_argument('mode', type=int)
    args = parser.parse_args()
    print(json.dumps(check(args.record.read_bytes(), args.stdout.read_bytes(), args.stderr.read_bytes(), args.exit_status, args.mode), separators=(',', ':')))
