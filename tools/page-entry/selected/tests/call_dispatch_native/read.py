#!/usr/bin/env python3
"""Read every additive native CALL-emitter pair; no owner or qualification credit."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

PAGE, FP, STACK, FRAME, RECORD = 4096, 65536, 16384, 67072, 295792
MAGIC, REC_MAGIC, END = 0x314E434432494C, 0x3152434432494C, 0x3145434432494C
REG = (13, 14, 12, 11, 15, 10, 9, 8, 0, 1, 2, 3, 4, 5, 6, 7)
MASK64 = (1 << 64)-1
STATUS, TF, RF = 0x8D5, 0x100, 0x10000


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
    # Linux x86-64 delivers an eight-byte kernel sigset. The remaining
    # 120 bytes copied through glibc's larger uc_sigmask alias the adjacent
    # event siginfo; retain and authenticate every byte of that raw span.
    need(mask == bytes(mask[:8])+bytes(info[:120]) and context[304:432] == info,
         'whole raw mask span and complete embedded siginfo match their independent captures')
    sig, error, code = struct.unpack_from('<iii', info)
    need((sig, error & MASK64, code & MASK64) == (h[0], h[2], h[1]) and
         words(info, 1, 16)[0] == h[3], 'whole siginfo joins')
    need((greg[20], greg[19], greg[22]) == h[13:16], 'raw trap/error/CR2 joins')
    return h, greg, fp


def configuration(identity, h):
    sp, target = h[22]+2*PAGE+512, h[23]+64
    reg, group, item, kind, status, count = 0, 0, identity, 0, 0x202, 1
    permissions = [0, 3, 3, 0]
    if identity < 32:
        reg, status = identity % 16, flags(identity) | (0x400 if identity >= 16 else 0)
    elif identity < 96:
        group, item = 1, identity-32
        status = flags(item)
    elif identity < 112:
        group, item, kind = 2, identity-96, 1
    elif identity < 120:
        group, item, kind = 3, identity-112, 2
        if item < 2:
            permissions[2] = 1 if item == 0 else 0
        else:
            sp = h[22]+2*PAGE+1+3*((item-2) % 3)
            permissions[2 if (item-2)//3 == 0 else 1] = 0
    else:
        group, item, kind = 4, identity-120, 3
        reg, status = item, flags(item) | (0x400 if item & 1 else 0)
    first = h[22]+2*PAGE+(0 if kind == 2 and item >= 2 else 512)-256
    end, row_pc = first+512, target
    if kind == 1:
        if item == 0:
            target += 128
        elif item == 1:
            target += 1
        elif item in (2, 7):
            row_pc += 8
        elif item in (3, 4):
            target = (0x0100000000000000, 0x8000000000000000)[item-3]
        elif item in (5, 6):
            count = (0, 257)[item-5]
        else:
            need(8 <= item < 16, 'fixed sixteen refusal cases')
            sp = (first, first+7, end+1, end+8, 0, 0x800000000000,
                  0x0100000000000000, MASK64)[item-8]
    if reg == 4:
        target, row_pc, permissions[2] = sp, sp, 7
    return reg, group, item, kind, sp, target, status, permissions, first, end, count, row_pc


def plan_model(h, reg):
    """Literal x86 instruction/row material, independent of the C helper calls."""
    pc, generated, spill, directory, window = h[21]+0x100, h[30], h[35], h[33], h[34]
    scratch = [0]+[r for r in range(1, 16) if r not in (4, 12, reg)][:3]
    a, e, t = scratch[1:]
    image, rows = bytearray(), []
    state = [0, 0, 0, 0]
    patches = []
    def emit(raw):
        at = len(image)
        rows.append((at, len(raw), *state))
        image.extend(raw)
        return at
    def displacement(at, length, target):
        return struct.pack('<i', target-(generated+at+length))
    def slot(i, load=False):
        r = scratch[i]
        at = len(image)
        emit(bytes((0x48 | ((r >> 3) << 2), 0x8B if load else 0x89,
                    5 | ((r & 7) << 3)))+displacement(at, 7, spill+8*i))
        if load:
            state[1] &= ~(1 << i)
        else:
            state[0] |= 1 << i
    def rr(op, r, m):
        emit(bytes((0x48 | ((r >> 3) << 2) | (m >> 3), op,
                    0xC0 | ((r & 7) << 3) | (m & 7))))
    def imm(r, op, value):
        emit(bytes((0x48 | (r >> 3), 0x81, 0xC0 | (op << 3) | (r & 7)))+struct.pack('<I', value))
    def absolute(r, value):
        emit(bytes((0x48 | (r >> 3), 0xB8+(r & 7)))+struct.pack('<Q', value))
    def load(r, base, offset):
        emit(bytes((0x48 | ((r >> 3) << 2) | (base >> 3), 0x8B,
                    0x40 | ((r & 7) << 3) | (base & 7), offset)))
    def branch(cc, label):
        at = emit(bytes((0x0F, 0x80+cc))+bytes(4))
        patches.append((at, label))
        return at
    def restore():
        emit(b'\x04\x7f'); state[2] = 1
        emit(b'\x9e'); state[2] = 0
        for i in (1, 2, 3, 0):
            slot(i, True)
    for i in range(4):
        slot(i)
    rr(0x89, reg, t); state[1] |= 8
    emit(b'\x9f'); state[1] |= 1; state[2] = 1
    emit(b'\x0f\x90\xc0'); state[2] = 2
    absolute(a, window); state[1] |= 2
    load(e, a, 24); state[1] |= 4
    imm(e, 0, 8); rr(0x3B, 4, e); branch(2, 'reject')
    load(e, a, 32); rr(0x3B, 4, e); branch(7, 'reject')
    absolute(a, directory); load(e, a, 8)
    imm(e, 7, 1); branch(2, 'reject')
    imm(e, 7, 256); branch(7, 'reject')
    imm(a, 0, 32)
    emit(bytes((0x48 | (e >> 3), 0xC1, 0xE0 | (e & 7), 5)))
    rr(0x03, e, a)
    loop = len(image)
    emit(bytes((0x48 | ((t >> 3) << 2) | (a >> 3), 0x3B,
                0x40 | ((t & 7) << 3) | (a & 7), 0)))
    found = branch(4, 'hit')
    imm(a, 0, 32); rr(0x3B, a, e); branch(2, 'loop')
    reject = len(image); restore()
    miss = len(image)
    emit(b'\xe9'+displacement(miss, 5, pc))
    hit = len(image); state[:] = [15, 15, 2, 0]
    load(a, a, 8)
    at = len(image)
    emit(bytes((0x48 | ((a >> 3) << 2), 0x89, 5 | ((a & 7) << 3)))+displacement(at, 7, spill+32))
    state[3] = 1; restore(); state[3] = 2
    push = len(image); emit(b'\xff\x35'+displacement(push, 6, generated+504))
    state[3] = 3
    transfer = len(image); emit(b'\xff\x25'+displacement(transfer, 6, spill+32))
    for at, label in patches:
        image[at+2:at+6] = displacement(at, 6, generated+{'reject': reject, 'hit': hit, 'loop': loop}[label])
    need((len(image), len(rows), miss, push, transfer) == (248, 46, 189, 236, 242),
         'exact fixed emitted scalar geometry')
    length = 3 if reg >= 8 else 2
    instruction = (b'\x41' if reg >= 8 else b'')+bytes((0xFF, 0xD0+(reg & 7)))
    source15 = instruction+b'\xcc'*(15-length)
    image += bytes(504-len(image))+struct.pack('<Q', pc+length)
    record = struct.pack('<16I', 1, 1, 0, 248, 46, 236, 242, 189, 504, 0, 0, 0, *scratch)
    record += b''.join(struct.pack('<6I', *row) for row in rows)+bytes(24*(64-len(rows)))
    decoded = struct.pack('<QQ10I', pc, pc+length, 1, 0, 759, 0, 16, 0, 0, 15, length, 0)+source15+b'\0'
    tf = struct.pack('<QQ6I', pc, pc+length, 1, 1, 759, length, 2, 4)
    descriptor = decoded+tf+struct.pack('<8I', 1, 1, 0, 15, reg, 0, 0, 0)
    binding = struct.pack('<QQQIIQQ', h[32], h[30], h[31], 1, 0, h[33], h[34])
    complete = record+descriptor+struct.pack('<QQ', generated, spill)+binding+image
    need(len(complete) == 2320, 'whole typed plan ABI')
    trace_path = [row[0]+row[1] for row in rows if row[0] < found]+[hit]
    trace_path += [row[0]+row[1] for row in rows if hit <= row[0] <= push]
    return complete, bytes(image), rows, scratch, trace_path


def recover(raw, pc, status, spills, h, reg, rows, scratch):
    selected = [r for r in rows if h[30]+r[0] == pc]
    need(len(selected) == 1, 'exact actual generated recovery boundary')
    _, _, valid, dirty, mode, phase = selected[0]
    need(dirty & ~valid == 0, 'initialized-only spill recovery')
    registers, recovered_flags = list(raw), status
    if mode:
        overflow = (raw[0] & 1) << 11 if mode == 2 else status & 0x800
        need(mode != 2 or raw[0] & 255 in (0, 1), 'exact saved OF value')
        recovered_flags = (status & ~STATUS) | ((raw[0] >> 8) & 0xD5) | overflow
    for i in range(4):
        if dirty & (1 << i):
            registers[scratch[i]] = spills[i]
    original_sp = registers[4]+(8 if phase == 3 else 0)
    original_pc = (original_sp if reg == 4 else registers[reg]) if phase == 3 else h[21]+0x100
    logical_phase = 0 if phase == 1 else phase
    return struct.pack('<20QII', *registers, recovered_flags, original_pc, original_sp,
                       h[21]+0x100+(3 if reg >= 8 else 2), logical_phase, 1)


def protection(h, lane, kind, permissions):
    rows = [(h[21], PAGE, 3, 0, 0), (h[30], 32768, 3, 0, 0), (h[31], 32768, 3, 0, 0),
            (h[32], PAGE, 3, 0, 0), (h[33], 12288, 3, 0, 0), (h[34], PAGE, 3, 0, 0),
            (h[35], PAGE, 3, 0, 0), (h[23], PAGE, 3, 0, 0), (h[22], STACK, 3, 0, 0)]
    rows += [(h[22]+i*PAGE, PAGE, p, 0, 0) for i, p in enumerate(permissions)]
    rows += [(h[21], PAGE, 1, 0, 0), (h[30], 32768, 1, 0, 0), (h[31], 32768, 5, 0, 0),
             (h[32], PAGE, 1, 0, 0), (h[33], 12288, 1, 0, 0), (h[34], PAGE, 1, 0, 0),
             (h[23], PAGE, 5, 0, 0)]
    if lane:
        rows += [(h[30], 32768, 5, 1, 0)]
    elif kind != 1:
        rows += [(h[21], PAGE, 5, 1, 0)]
    rows += [(h[22], STACK, 3, 2, 0), (h[21], PAGE, 1, 2, 0),
             (h[30], 32768, 1, 2, 0), (h[31], 32768, 1, 2, 0)]
    need(len(rows) <= 32, 'complete protection transition capacity')
    return len(rows), b''.join(struct.pack('<5Q', *row) for row in rows)+bytes((32-len(rows))*40)
def lane(raw, h, identity, which):
    need(len(raw) == RECORD, 'whole lane record')
    r, bootstrap = words(raw, 64), words(raw, 23, 512)
    reg, group, item, kind, sp, target, status, permissions, first, end, count, row_pc = configuration(identity, h)
    pc, length, entry = h[21]+0x100, 3 if reg >= 8 else 2, h[30] if which else h[21]+0x100
    cached = h[30+(identity & 1)]+512
    need(r[:13] == (REC_MAGIC, RECORD, identity, which, reg, group, item, pc,
                    pc+length, target, sp, status, length), 'literal complete136-case identity')
    expected_plan, emitted, rows, scratch, trace_path = plan_model(h, reg)
    expected_trace = trace_path if kind == 3 and which else []
    protect_count, protections = protection(h, which, kind, permissions)
    need(r[13:20] == (1, 0, 2, 1+len(expected_trace) if expected_trace else 2,
                       entry, cached, len(expected_trace)) and r[20:24] == tuple(permissions) and
         r[24:33] == (kind, item, first, end, count, row_pc, 1,
                      1 if which and kind in (2, 3) else 0, protect_count) and not any(r[33:]),
         'completed exact phase/events/recovery/permissions with zero unused header')
    before_raw, after_raw = raw[696:67768], raw[67768:134840]
    before, after = frame(before_raw, h, 0), frame(after_raw, h, 1)
    saved_recovery, actual_plan = raw[134840:135008], raw[135008:137328]
    need(actual_plan == expected_plan, 'complete actual descriptor/row/image/relocation material')
    need(raw[159344:160624] == protections, 'every actual mprotect call/result/order; no skipped transition')
    initial, final = raw[160624:177008], raw[177008:193392]
    source, images, row_bytes = raw[193392:197488], raw[197488:263024], raw[263024:267120]
    directory, window, target_page = raw[267120:279408], raw[279408:283504], raw[283504:287600]
    spill_initial, spill_final = raw[287600:291696], raw[291696:295792]
    stack_model = bytearray((0x5A+37*i+identity) & 255 for i in range(STACK))
    if reg == 4:
        stack_model[sp-h[22]] = 0xCC
    need(initial == stack_model, 'whole seeded guest stack including explicit CALL-RSP endpoint')
    source_model = bytearray(b'\xcc'*PAGE)
    instruction = (b'\x41' if reg >= 8 else b'')+bytes((0xFF, 0xD0+(reg & 7)))
    source_model[0x100:0x100+length] = instruction
    need(source == source_model and images == emitted+b'\xcc'*(65536-512) and
         not any(row_bytes) and target_page == b'\xcc'*PAGE, 'whole original and generated source/target/row bytes')
    directory_model = bytearray(12288)
    struct.pack_into('<4Q', directory_model, 0, 1, count, 73, 0)
    struct.pack_into('<3Q2I', directory_model, 32, row_pc, cached, 91, identity & 1, 1)
    if kind == 1 and item == 7:
        struct.pack_into('<3Q2I', directory_model, 64, target, cached, 92, 1, 1)
    need(directory == directory_model and window == struct.pack('<8Q', 1, h[32], 73, first, end, 0, 0, 0)+bytes(PAGE-64),
         'whole fixed numeric directory/window with complete zero tail; no owner-custody claim')
    poisoned = bytes((0xA7+19*i+identity) & 255 for i in range(PAGE))
    need(spill_initial == poisoned, 'whole poisoned scratch and uninitialized target cell')
    seed = [(0x13579BDF00110000+0x100010001*i+identity) & MASK64 for i in range(16)]
    seed[reg], seed[4] = target, sp
    expected_spill = bytearray(poisoned)
    if which:
        for i, register in enumerate(scratch):
            struct.pack_into('<Q', expected_spill, i*8, seed[register])
        if kind != 1:
            struct.pack_into('<Q', expected_spill, 32, cached)
    need(spill_final == expected_spill, 'only four initialized spills and one hit target cell may change')
    need(tuple(before[1][i] for i in REG) == tuple(seed) and before[1][16] == entry and
         before[1][17] == status | RF and before[0][0:4] == (11, 2, 0, entry) and
         before[1][20] == 14 and before[1][19] == 21 and before[1][22] == entry,
         'real first NX event, all16 seeded registers, flags, page-fault class and exact CR2')
    expected_bootstrap = list(before[1])
    if kind == 3:
        expected_bootstrap[17] = status | TF
    else:
        expected_bootstrap[16], expected_bootstrap[15] = h[28:30]
        expected_bootstrap[17] &= ~(RF | TF)
    need(bootstrap == tuple(expected_bootstrap), 'actual signal-return bootstrap; TF only from valid frame')
    need(before[2] == after[2] and before[0][8:10] == after[0][8:10] and
         before_raw[312:320] == after_raw[312:320], 'whole65536 FP storage, FS/GS and complete kernel signal mask unchanged')
    expected_gpr = list(seed)
    if kind in (0, 3):
        expected_gpr[4] -= 8
        expected_stack = bytearray(initial)
        struct.pack_into('<Q', expected_stack, sp-8-h[22], pc+length)
        need(final == expected_stack, 'exact one committed eight-byte return word and complete other-stack equality')
    elif kind == 1:
        need(final == initial, 'lookup/window refusal has no guest-stack effect')
    # Injected store-fault cases retain and compare their complete actual stack,
    # including any partial write. They are never a valid owner window permit.
    need(tuple(after[1][i] for i in REG) == tuple(expected_gpr), 'all16 exact original/generated effect registers')
    if kind == 0:
        stop = (cached if which else target)+1
        need(after[0][0:4] == (5, 128, 0, 0) and after[1][16] == stop and
             after[1][17] == status and after[1][19:21] == (0, 3) and after[1][22] == entry,
             'actual known-hit INT3 endpoint, unchanged flags and retained initial CR2')
    elif kind == 1:
        stop = pc
        need(after[0][0:4] == (11, 2, 0, pc) and after[1][16] == pc and
             after[1][17] == status | RF and after[1][19:21] == (21, 14) and after[1][22] == pc,
             'actual original NX miss before CALL effect')
    elif kind == 2:
        stop = h[30]+236 if which else pc
        need(after[0][0:3] == (11, 2, 0) and after[1][16] == stop and
             after[1][17] == status | RF and after[1][20] == 14 and
             after[1][19] in (6, 7) and after[1][22] == after[0][3] and
             sp-8 <= after[0][3] < sp, 'actual injected PUSH/CALL stack-write fault and unchanged RSP')
    else:
        stop = h[30]+242 if which else target
        need(after[0][0:4] == (5, 2, 0, stop) and after[1][16] == stop and
             after[1][17] == status | TF and after[1][19:21] == (0, 1) and after[1][22] == entry,
             'actual post-CALL or post-PUSH TRACE before cached transfer')
    if which and kind in (2, 3):
        independent = recover([after[1][i] for i in REG], stop, after[1][17],
                              words(spill_final, 4), h, reg, rows, scratch)
        need(saved_recovery == independent, 'actual helper recovery equals independent raw-frame reconstruction')
        expected_recovery = struct.pack('<20QII', *expected_gpr, after[1][17],
                                        target if kind == 3 else pc, sp, pc+length,
                                        3 if kind == 3 else 2, 1)
        need(saved_recovery == expected_recovery, 'exact committed versus before-PUSH typed state; never replay')
    else:
        need(not any(saved_recovery), 'no fabricated recovery at original or out-of-plan endpoint')
    for index, offset in enumerate(expected_trace):
        at = 137328+344*index
        t = raw[at:at+344]
        tpc, tflags = words(t, 2)
        registers, spills = words(t, 16, 16), words(t, 4, 144)
        need(tpc == h[30]+offset and tflags & TF and not tflags & RF,
             'exact all actual TRACE boundary sequence; no missed/extra retirement')
        expected = recover(registers, tpc, tflags, spills, h, reg, rows, scratch)
        need(t[176:] == expected, 'every actual native raw TRACE recovery independently reconstructed')
        logical = words(expected, 20)
        expected_registers = list(seed)
        committed = offset == 242
        if committed:
            expected_registers[4] -= 8
        need(logical[:16] == tuple(expected_registers) and logical[16:] ==
             (status | TF, target if committed else pc, sp, pc+length),
             'each actual intermediate recovery has exact original GPR/flags/effect state')
        row = next(row for row in rows if row[0] == offset)
        expected_spills = [seed[scratch[i]] if row[2] & (1 << i) else words(poisoned, 4)[i] for i in range(4)]
        need(spills == tuple(expected_spills), 'actual initialized spill subset, poisoned unused words retained')
    need(not any(raw[137328+344*len(expected_trace):159344]), 'whole unused trace storage zero')
    return {'header': r, 'before': before, 'after': after, 'before_raw': before_raw, 'after_raw': after_raw,
            'initial': initial, 'final': final, 'immutable': raw[193392:287600],
            'record_sha256': digest(raw), 'kind': kind, 'target': target, 'pc': pc, 'entry': entry,
            'trace_count': len(expected_trace), 'committed': kind in (0, 3)}


def normalized_context(raw, greg, info):
    context = bytearray(raw[568:1536])
    context[40:224] = struct.pack('<23Q', *greg)
    context[224:232] = bytes(8)  # actual FP pointer is independently joined to its full captured storage
    # frame() first authenticates all128 embedded bytes against this separate
    # siginfo capture; pair() changes only its exact architectural endpoint.
    context[304:432] = info
    return bytes(context)


def pair(a, b):
    need(a['header'][2] == b['header'][2] and a['kind'] == b['kind'] and
         a['initial'] == b['initial'] and a['final'] == b['final'] and a['immutable'] == b['immutable'],
         'complete matched source/target/window/directory and before/after guest stack')
    for phase in ('before', 'after'):
        x, y = a[phase], b[phase]
        gx, gy = list(x[1]), list(y[1])
        xr, yr = a[phase+'_raw'], b[phase+'_raw']
        # Only literal architectural source/cached endpoint addresses differ.
        # Every raw register was already checked against its exact lane value.
        if phase == 'before':
            gx[16] = gy[16] = a['pc']
            gx[22] = gy[22] = a['pc']
        else:
            gx[16] = gy[16] = a['target']+(1 if a['kind'] == 0 else 0) if a['kind'] in (0, 3) else a['pc']
            if a['kind'] in (0, 3):
                gx[22] = gy[22] = a['pc']
        need(gx == gy and x[2] == y[2] and x[0][4:6] == y[0][4:6] and
             x[0][7:10] == y[0][7:10] and xr[312:320] == yr[312:320],
             'all23 GREGs, full FP, FS/GS, uc fields and complete kernel mask with literal endpoint join')
        xi, yi = bytearray(xr[440:568]), bytearray(yr[440:568])
        if phase == 'before' or a['kind'] == 3:
            xi[16:24] = yi[16:24] = struct.pack('<Q', a['pc'] if phase == 'before' else a['target'])
        need(xi == yi and bytes(xr[312:320])+bytes(xi[:120]) == bytes(yr[312:320])+bytes(yi[:120]) and
             normalized_context(xr, gx, xi) == normalized_context(yr, gy, yi),
             'complete raw siginfo/ucontext after only authenticated pointer/endpoint substitution')
    return {'id': a['header'][2], 'group': a['header'][5], 'register': a['header'][4],
            'committed_once': a['committed'], 'no_effect_miss': a['kind'] == 1,
            'injected_stack_fault': a['kind'] == 2, 'post_push_trace': a['kind'] == 3,
            'actual_generated_trace_boundaries': b['trace_count'],
            'original_record_sha256': a['record_sha256'], 'generated_record_sha256': b['record_sha256']}


def read_chunks(paths, cpu, pids):
    need(len(paths) == len(pids) == 6 and len(set(map(str, paths))) == 6 and
         len(set(pids)) == 6 and all(pid > 0 for pid in pids), 'all six actual process-owned chunks')
    pairs, sources = [], []
    for chunk, path in enumerate(paths):
        raw = path.read_bytes()
        need(576 <= len(raw) < 16 << 20, 'unchanged strict16MiB whole capture bound')
        h = words(raw, 64)
        count = min(24, 136-24*chunk)
        need(h[:15] == (MAGIC, 1, 512, RECORD, FRAME, 968, 128, FP, STACK, PAGE,
                        136, chunk, 24*chunk, count, 2*count), 'exact new fixed framing and complete population')
        need(h[15] == pids[chunk] and h[16] == cpu and h[19] & 3 == 3 and 512 <= h[20] <= FP and
             h[25:28] == (262144, 0, 24) and h[28] and h[29] and
             h[36:42] == (2320, 168, 344, 64, 40, 32) and not any(h[42:]),
             'actual PID/CPU/FP/bootstrap/type header joins')
        need((h[17] == 0 and h[18] == 0) or h[17] in ((-22) & MASK64, (-38) & MASK64),
             'original production CET prerequisite, never disabled')
        spans = [(h[21], PAGE), (h[22], STACK), (h[23], PAGE), (h[24]-PAGE, h[25]+2*PAGE),
                 (h[30], 32768), (h[31], 32768), (h[32], PAGE), (h[33], 12288), (h[34], PAGE), (h[35], PAGE)]
        need(all(a >= PAGE and a % PAGE == 0 and a+n < 1 << 47 for a, n in spans), 'exact lower47 complete mapping geometry')
        spans.sort()
        need(all(spans[i][0]+spans[i][1] <= spans[i+1][0] for i in range(len(spans)-1)),
             'all actual numeric buffer extents disjoint; no owner permit inferred')
        need(len(raw) == 512+2*count*RECORD+64 and
             words(raw, 8, len(raw)-64) == (END, 1, 2*count, len(raw), 0, 0, 0, 0),
             'exact complete stream with no tail or partial case')
        for local in range(count):
            at = 512+2*local*RECORD
            original = lane(memoryview(raw)[at:at+RECORD], h, 24*chunk+local, 0)
            generated = lane(memoryview(raw)[at+RECORD:at+2*RECORD], h, 24*chunk+local, 1)
            pairs.append(pair(original, generated))
        sources.append({'chunk': chunk, 'bytes': len(raw), 'sha256': digest(raw), 'pid': h[15]})
    need(len(pairs) == 136 and [sum(p['group'] == g for p in pairs) for g in range(5)] == [32, 64, 16, 8, 16],
         'all136 declared pairs, no skipped case or optional category')
    return {'schema': 1, 'status': 'finite_native_comparisons_passed', 'native_pairs': 136, 'native_lanes': 272,
            'cpu': cpu, 'sources': sources, 'pairs': pairs, 'old217_cases_replaced': False,
            'owner_credit': False, 'production_admission_credit': False, 'qualification_credit': False,
            'performance_credit': False, 'scope': 'Standalone actual emitted CALL, numeric supplied bindings, complete matched frames/memory. Old217 and whole owner gates remain separate.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-cpu', type=int, required=True)
    parser.add_argument('--expect-pids', nargs=6, type=int, required=True)
    parser.add_argument('chunks', nargs=6, type=Path)
    args = parser.parse_args()
    need(args.expect_cpu >= 0, 'actual reserved CPU')
    print(json.dumps(read_chunks(args.chunks, args.expect_cpu, args.expect_pids), sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
