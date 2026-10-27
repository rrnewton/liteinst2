"""Independent complete fork endpoint reader; no runtime or fixture imports."""
import struct

OBS = 65920
BEFORE = 4096
AFTER = BEFORE + OBS
SIZE = AFTER + OBS
KNOWN = 0x2e7
SEEDS = (57, 0x1122334455667788, 0x2233445566778899, 0x33445566778899aa,
         0x445566778899aabb, 0x5566778899aabbcc, 0x66778899aabbccdd, None,
         0x778899aabbccddee, 0x8899aabbccddeeff, 0x99aabbccddeeff10,
         0xaabbccddeeff1021, 0xbbccddeeff102132, 0xccddeeff10213243,
         0xddeeff1021324354, 0xeeff102132435465)


def need(ok, message):
    if not ok:
        raise ValueError(message)


def q(data, at):
    need(0 <= at <= len(data)-8, "word extent")
    return struct.unpack_from('<Q', data, at)[0]


def symbols(image):
    need(image[:7] == b'\x7fELF\x02\x01\x01', 'ELF class')
    h = struct.unpack_from('<16sHHIQQQIHHHHHH', image)
    need(h[2] == 62 and h[11] == 64 and h[6]+h[12]*64 <= len(image), 'ELF sections')
    sections = [struct.unpack_from('<IIQQQQIIQQ', image, h[6]+i*64) for i in range(h[12])]
    found = {}
    for row in sections:
        if row[1] != 2:
            continue
        need(row[9] == 24 and row[6] < len(sections) and row[4]+row[5] <= len(image), 'symtab')
        text = sections[row[6]]
        need(text[4]+text[5] <= len(image), 'strtab')
        strings = image[text[4]:text[4]+text[5]]
        for at in range(row[4], row[4]+row[5], 24):
            name, _, _, section, value, _ = struct.unpack_from('<IBBHQQ', image, at)
            need(name < len(strings), 'symbol string')
            end = strings.find(b'\0', name)
            need(end >= 0, 'symbol terminator')
            name = strings[name:end]
            if section and name in (b'continuation_fork', b'continuation_syscall', b'continuation_resume', b'continuation_capture'):
                need(name not in found, 'duplicate continuation symbol')
                found[name] = value
    need(set(found) == {b'continuation_fork', b'continuation_syscall', b'continuation_resume', b'continuation_capture'}, 'continuation symbols')
    need(found[b'continuation_fork']%4096 == 0 and found[b'continuation_fork'] < found[b'continuation_syscall'] < found[b'continuation_resume'] <= found[b'continuation_capture'] < found[b'continuation_fork']+4096, 'one already admitted observer code page')
    need(found[b'continuation_resume'] == found[b'continuation_syscall']+2, 'literal SYSCALL length')
    need(h[9] == 56 and h[5]+h[10]*56 <= len(image), 'PHDR bounds')
    rows = [struct.unpack_from('<IIQQQQQQ', image, h[5]+56*i) for i in range(h[10])]
    offsets = [r[2]+found[b'continuation_syscall']-r[3] for r in rows
               if r[0] == 1 and r[1]&1 and r[3] <= found[b'continuation_syscall']
               and found[b'continuation_capture'] <= r[3]+r[5] and r[2]+r[5] <= len(image)]
    need(len(offsets) == 1 and image[offsets[0]:offsets[0]+2] == b'\x0f\x05', 'actual syscall bytes')
    prefix_bytes = found[b'continuation_capture']-found[b'continuation_resume']
    prefix = image[offsets[0]+2:offsets[0]+2+prefix_bytes]
    variants = {b'': 'positive', b'\x4d\x8d\x64\x24\x01': 'gpr', b'\xc6\x44\x24\xf8\x00': 'redzone'}
    need(prefix in variants, 'exact assembly control prefix')
    found['variant'] = variants[prefix]
    return found


def capabilities(data):
    mask, supported, size, xgetbv1, count = struct.unpack_from('<5Q', data, 64)
    need(mask&3 == 3 and not mask&~supported and 576 <= size <= 65536 and xgetbv1 == 1,
         'actual XSAVE qualification')
    need(count <= 62 and data[104:128] == bytes(24), 'capability header')
    rows = [struct.unpack_from('<4Q', data, 128+i*32) for i in range(count)]
    bits, spans = set(), []
    for bit, offset, size_component, flags in rows:
        need(2 <= bit < 64 and bit not in bits and size_component > 0 and offset >= 576
             and offset+size_component <= size and not flags&1, 'component bound')
        need(all(offset+size_component <= a or offset >= b for a, b in spans), 'component overlap')
        bits.add(bit); spans.append((offset, offset+size_component))
    need(sum(1 << b for b in bits) == mask&~3, 'complete enabled component layout')
    need(data[128+count*32:4096] == bytes(4096-128-count*32), 'unused capability storage')
    return mask, size, rows


def state(data, cap):
    mask, _, rows = cap
    need(len(data) == OBS and data[352:384] == bytes(32), 'observation geometry')
    need(q(data, 144) == mask and not q(data, 152)&~mask, 'XCR0/XINUSE distinction')
    x = data[384:]
    bv = q(x, 512)
    need(not bv&~mask and not (bv|q(data, 152))&~KNOWN, 'unknown active XSTATE')
    need(q(x, 520) == 0 and x[528:576] == bytes(48), 'standard XSAVE header')
    # Init components are decoded as architecture-defined init state, never
    # assumed to have overwritten their pre-zeroed XSAVE output bytes.
    x87 = x[:24] if bv&1 else b'\x7f\x03'+bytes(22)
    parts = [('x87', x87[:5]+x87[6:]+b''.join(x[32+16*i:42+16*i] if bv&1 else bytes(10) for i in range(8))),
             ('mxcsr', x[24:28]), ('sse', x[160:416] if bv&2 else bytes(256))]
    for bit, offset, width, _ in rows:
        if KNOWN&(1 << bit):
            parts.append((bit, x[offset:offset+width] if bv&(1 << bit) else bytes(width)))
    return parts


def record(data, image):
    need(len(data) == SIZE, 'complete record length')
    magic, version, extent, role, pid, parent, result, caller_sp = struct.unpack_from('<8Q', data)
    need(magic == 0x314b524f4632494c and version == 1 and extent == SIZE and role in (0, 1), 'record identity')
    need(pid > 0 and parent > 0 and (result == 0 if role else result > 0), 'actual fork result')
    cap = capabilities(data)
    before, after = data[BEFORE:AFTER], data[AFTER:]
    pre, post = struct.unpack_from('<16Q', before), struct.unpack_from('<16Q', after)
    need(pre[7] == post[7] == caller_sp and caller_sp%16 == 8, 'original call stack restored')
    need(all(v is None or pre[i] == v for i, v in enumerate(SEEDS)), 'nonvacuous register input')
    need(q(before, 128) == 0x647 and q(after, 128) == q(before, 128), 'full RFLAGS incl DF')
    syms = symbols(image)
    bias = q(before, 136)-syms[b'continuation_syscall']
    need(bias >= 0 and bias%4096 == 0 and q(after, 136) == bias+syms[b'continuation_capture'], 'actual capture-PC association')
    expected = list(pre)
    expected[0], expected[2], expected[11] = result, bias+syms[b'continuation_resume'], q(before, 128)
    need(post == tuple(expected), 'full GPR syscall return contract')
    need(before[160:224] == after[160:224], 'actual FS/GS/selectors')
    need(before[224:352] == after[224:352] == b''.join(struct.pack('<Q', 0x8badf00d13579bdf+i) for i in range(16)), 'full original redzone')
    need(state(before, cap) == state(after, cap), 'full qualified architectural XSTATE')
    # Each XMM/YMM input has a distinct architectural value. No equal-value
    # register swap can satisfy this seed check accidentally.
    vectors = [struct.pack('<4Q', *(value+i*0x0101010101010101 for value in
                (0x0123456789abcdef, 0xe0d0c0b0a0908070, 0x8877665544332211, 0x1020304050607080)))
               for i in range(16)]
    need(q(before, 384+512)&3 == 3 and before[384+160:384+416] == b''.join(v[:16] for v in vectors),
         'nonvacuous x87/SSE input')
    if cap[0]&4:
        avx = [row for row in cap[2] if row[0] == 2]
        need(len(avx) == 1 and avx[0][2] == 256 and q(before, 384+512)&4
             and before[384+avx[0][1]:384+avx[0][1]+256] == b''.join(v[16:] for v in vectors),
             'nonvacuous AVX input')
    return {'role': role, 'pid': pid, 'parent': parent, 'result': result, 'before': before,
            'after': after, 'capability': data[64:4096]}


def family(parent, child, image):
    p, c = record(parent, image), record(child, image)
    need(p['role'] == 0 and c['role'] == 1 and p['pid'] == p['parent'] == c['parent']
         and p['result'] == c['pid'] and p['pid'] != c['pid'], 'real parent/child identity')
    need(p['before'] == c['before'] and p['capability'] == c['capability'], 'complete COW before-record equality')
    need(p['after'][160:224] == c['after'][160:224], 'parent/child inherited bases/selectors')
    return p, c


def summary(n, g):
    return {'families': 2, 'endpoints': 4, 'gprs': 16, 'redzone_bytes': 128,
            'xsave_capacity': 65536,
            'native_pids': [n[0]['pid'], n[1]['pid']],
            'gated_pids': [g[0]['pid'], g[1]['pid']], 'gated_fork_result': g[0]['result'],
            'xstate_bitmaps': [{'lane': lane, 'role': role,
                               'before_xinuse': q(row['before'], 152), 'after_xinuse': q(row['after'], 152),
                               'before_bv': q(row['before'], 384+512), 'after_bv': q(row['after'], 384+512)}
                              for lane, family_rows in (('native', n), ('gated', g))
                              for role, row in enumerate(family_rows)]}


def pair(native, gated, image):
    need(symbols(image)['variant'] == 'positive', 'positive has no control prefix')
    n, g = family(*native, image), family(*gated, image)
    # ASLR and real process IDs are independent. No literal address equality
    # is invented across processes: each image-relative PC and complete
    # unchanged field was proved against its own actual before capture.
    need(n[0]['capability'] == g[0]['capability'], 'same observed host XSTATE profile')
    return dict(summary(n, g), complete=True)


def negative(native, gated, image, kind):
    need(kind in ('gpr', 'redzone') and symbols(image)['variant'] == kind, 'actual negative binary identity')
    message = 'full GPR syscall return contract' if kind == 'gpr' else 'full original redzone'
    rejections, checked_families = [], []
    for lane, records in (('native', native), ('gated', gated)):
        restored = []
        for role, data in enumerate(records):
            need(len(data) == SIZE, 'negative record extent')
            try:
                record(data, image)
            except ValueError as error:
                need(str(error) == message, 'negative rejected for a different reason')
                rejections.append({'lane': lane, 'role': role, 'reason': str(error)})
            else:
                raise ValueError('actual assembly corruption was accepted')
            # Diagnostic-only local copy verifies that the precise observed
            # instruction effect is the sole mismatch. The original record
            # is retained unchanged and is NEVER a passing state observation.
            fixed = bytearray(data)
            if kind == 'gpr':
                need(q(data, AFTER+96) == q(data, BEFORE+96)+1, 'actual LEA R12 effect')
                struct.pack_into('<Q', fixed, AFTER+96, q(data, BEFORE+96))
            else:
                at = AFTER+224+120
                need(data[at] == 0 and data[BEFORE+224+120] == 0xee, 'actual MOV redzone effect')
                fixed[at] = data[BEFORE+224+120]
            restored.append(bytes(fixed))
        checked_families.append(family(*restored, image))
    n, g = checked_families
    need(n[0]['capability'] == g[0]['capability'], 'negative same host XSTATE profile')
    return dict(summary(n, g), complete=False, expected_rejections=rejections,
                original_records_rejected=True, kind=kind)


def corruption_controls(native, image):
    family(*native, image)
    count = 0
    for role in (0, 1):
        # Every compared family plus both explicit architectural syscall outputs.
        for offset in (AFTER, AFTER+8, AFTER+16, AFTER+56, AFTER+88, AFTER+128,
                       AFTER+136, AFTER+144, AFTER+152, AFTER+160, AFTER+168,
                       AFTER+176, AFTER+224, AFTER+384+160, AFTER+384+512):
            corrupted = [bytearray(x) for x in native]
            corrupted[role][offset] ^= 0x10 if offset == AFTER+152 else 1
            try:
                family(bytes(corrupted[0]), bytes(corrupted[1]), image)
            except ValueError:
                count += 1
            else:
                raise ValueError('vacuous endpoint corruption control')
    return count
