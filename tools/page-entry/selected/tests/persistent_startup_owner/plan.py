"""Independent complete MOV-loop graph and generated-byte/recovery model.

The pinned interpreter pair is retained whole.  The model includes all 27
heads, all four real frontiers, the three alternate-path RIP-relative LEAs,
and all five guarded stores.  It imports no decoder, emitter, or native code.
"""
import hashlib
import struct

U64 = (1 << 64) - 1
PAIR_SHA256 = 'd581910c998f52887ed76623d2280e52d178a4d25d46001d64586bd2c8ddf7ab'
OFFSETS = (0x2c8, 0x2cc, 0x2d1, 0x2d4, 0x2d8, 0x2e4, 0x2da,
           0x2e9, 0x2de, 0x2ed, 0x1d60, 0x2f0, 0x1d67, 0x2f3,
           0x1d6c, 0x2f6, 0x1d73, 0x2f8, 0x2ff, 0x302, 0xc06,
           0x308, 0xc11, 0x30c, 0xc18, 0xc1e, 0xc25)
SUCCESSORS = ((1,), (2,), (3,), (4,), (5, 6), (7,), (8,), (9,),
              (10, 5), (11,), (12,), (13,), (14,), (15,), (16,),
              (0, 17), (128,), (18,), (19,), (20, 21), (22,),
              (23,), (24,), (129,), (130, 25), (26,), (131,))
FRONTIERS = ((0x1d7a, 'e881b50000', 693, 1),
             (0x313, '41f6871e03000020', 711, 1),
             (0xa0, '48838548ffffff20', 249, 5),
             (0xc2c, '0f1f4000', 1057, 1))
# Complete original bytes and descriptor facts, not a path-pruned program.
RAW = ('498b1424', '418b442408', '4c01d2', '4883f826', '740a',
       '498b442410', '4883f808', '4983c418', '0f857c1a0000', '4c01d0',
       '488d0dc9cd0100', '488902', 'ba24020000', '4c39e3',
       '488d35a5e30100', '77d0', '488d3dbee30100', '4d8b9fd0010000',
       '4d85db', '0f84fe080000', '48c78540ffffff00000000', '498b4308',
       '48399d68ffffff', '48898560ffffff', '0f8682f4ffff',
       '4c899d58ffffff', '4c899578ffffff')
CODES = (286, 285, 8, 270, 173, 286, 270, 249, 1871, 8, 292, 282,
         357, 110, 292, 182, 292, 286, 274, 1868, 405, 286, 110,
         282, 1874, 282, 282)
STORE_INDICES = (11, 20, 23, 25, 26)


def need(ok, why):
    if not ok:
        raise ValueError(why)


def table(ranges, address):
    merged = []
    for first, end in sorted(ranges):
        need(0 <= first < end <= 1 << 47, 'bounded complete exclusion')
        if merged and first <= merged[-1][1]:
            merged[-1][1] = max(end, merged[-1][1])
        else:
            merged.append([first, end])
    need(0 < len(merged) <= 131, 'complete bounded exclusion set')
    nodes = [[a, b, 0, 0] for a, b in merged]
    height = 0

    def tree(lo, hi, depth):
        nonlocal height
        if lo == hi:
            return 0
        m = (lo + hi) // 2
        height = max(height, depth)
        nodes[m][2] = tree(lo, m, depth + 1)
        nodes[m][3] = tree(m + 1, hi, depth + 1)
        return address + 32 + 32 * m

    root = tree(0, len(nodes), 1)
    return (struct.pack('<4I2Q', 1, 1, len(nodes), height, address, root) +
            b''.join(struct.pack('<4Q', *n) for n in nodes) +
            bytes(32 * (131 - len(nodes))))


def reg(r, width, access):
    return (0, 1, r, width, access, 0, 0)


def imm(value, width, encoding):
    return (value & U64, 3, 0, width, 1, encoding, 0)


def mem(width):
    return (0, 2, 0, width, 1, 0, 0)


def address(base, displacement=0, width=8):
    # iced's exact default segment is SS for RBP/RSP, DS for R12/R13.
    return (displacement & U64, base, 16, 1, width, 64,
            2 if base in (4, 5) else 1, 1, 0)


def ins(raw, code, ops=(), flags=(0, 0, 0, 0, 0), address=None,
        reloc=0, step=0, flow=0, target=0, condition=16):
    return dict(raw=bytes.fromhex(raw) if isinstance(raw, str) else raw,
                code=code, ops=ops, flags=flags, address=address, reloc=reloc,
                step=step, flow=flow, target=target, condition=condition)


def descriptor(row, pc, source, offset, refusal=0):
    """Whole 336-byte span description, including the independent 72-byte decode."""
    raw = row['raw']
    need(source[offset:offset + len(raw)] == raw and offset + 15 <= len(source),
         'complete exact original instruction and fifteen-byte decoder window')
    d = bytearray(336)
    struct.pack_into('<QQ10I', d, 0, pc, pc + len(raw), 1, 0, row['code'],
                     0, 16, 0, row['step'], 15, len(raw), 0)
    d[56:72] = source[offset:offset + 15] + b'\0'
    struct.pack_into('<I', d, 256, 1)
    if refusal:
        struct.pack_into('<I', d, 264, refusal)
        return bytes(d)
    struct.pack_into('<Q', d, 72, row['target'])
    regs = []
    for i, operand in enumerate(row['ops']):
        struct.pack_into('<Q6I', d, 80 + 32 * i, *operand)
        _, kind, r, width, access, _, _ = operand
        if kind == 1 and access:
            if width == 32 and access == 3:
                regs += [(r, 32, 1, 0), (r, 64, 2, 0)]
            else:
                regs.append((r, 64 if width == 32 and access == 2 else width, access, 0))
        elif kind in (2, 5):
            for r in row['address'][1:3]:
                if r != 16:
                    regs.append((r, row['ops'][0][3] if kind == 5 else 64, 1, 0))
    need(len(regs) <= 4, 'complete bounded span register effects')
    for i, value in enumerate(regs):
        struct.pack_into('<4I', d, 144 + 16 * i, *value)
    a = row['address']
    if a:
        struct.pack_into('<Q8I', d, 208, *a)
    if row['reloc']:
        struct.pack_into('<Q', d, 248, a[0])
        struct.pack_into('<3I', d, 320, 1, row['reloc'], 4)
    struct.pack_into('<9I', d, 256, 1, 1, 0, row['flow'], row['condition'],
                     len(row['ops']), len(regs), int(a is not None and a[7] == 1), int(a is not None))
    struct.pack_into('<5I', d, 292, *row['flags'])
    read = write = 0
    for r, _, access, _ in regs:
        if access & 1:
            read |= 1 << r
        if access & 2:
            write |= 1 << r
    struct.pack_into('<2I', d, 312, read, write)
    return bytes(d)


def descriptions(source, page):
    arithmetic = (0, 0x8d5, 0, 0, 0)
    rows = [ins(raw, code) for raw, code in zip(RAW, CODES, strict=True)]
    operands = {
        0: ((reg(2, 64, 2), mem(64)), address(12)),
        1: ((reg(0, 32, 2), mem(32)), address(12, 8, 4)),
        2: ((reg(2, 64, 3), reg(10, 64, 1)), None),
        3: ((reg(0, 64, 1), imm(38, 64, 8)), None),
        5: ((reg(0, 64, 2), mem(64)), address(12, 16)),
        6: ((reg(0, 64, 1), imm(8, 64, 8)), None),
        7: ((reg(12, 64, 3), imm(24, 64, 8)), None),
        9: ((reg(0, 64, 3), reg(10, 64, 1)), None),
        12: ((reg(2, 32, 2), imm(0x224, 32, 32)), None),
        13: ((reg(3, 64, 1), reg(12, 64, 1)), None),
        17: ((reg(11, 64, 2), mem(64)), address(15, 0x1d0)),
        18: ((reg(11, 64, 1), reg(11, 64, 1)), None),
        21: ((reg(0, 64, 2), mem(64)), address(11, 8)),
        22: ((mem(64), reg(3, 64, 1)), address(5, -0x98)),
    }
    for i, (ops, a) in operands.items():
        rows[i].update(ops=ops, address=a)
    for i in (2, 3, 6, 7, 9, 13, 22):
        rows[i]['flags'] = arithmetic
    rows[12]['step'] = 1
    rows[18]['flags'] = (0, 0xc4, 0, 0x801, 0x10)
    for i, destination, target in ((10, 1, page + 0x1eb30),
                                   (14, 6, page + 0x20118),
                                   (16, 7, page + 0x20138)):
        rows[i].update(ops=(reg(destination, 64, 2), (0, 5, 0, 64, 7, 0, 0)),
                       address=(target, 16, 16, 1, 0, 64, 0, 7, 0), reloc=3)
    for i, target, condition in ((4, 0x2e4, 4), (8, 0x1d60, 5),
                                 (15, 0x2c8, 7), (19, 0xc06, 4), (24, 0xa0, 6)):
        width = 8 if len(rows[i]['raw']) == 2 else 32
        rows[i].update(ops=((page + target, 4, 0, 64, 1, width, 0),),
                       flags=(0x41 if condition in (6, 7) else 0x40, 0, 0, 0, 0),
                       flow=1, target=page + target, condition=condition)
    return tuple(rows)


def store_description(source, page, index):
    """The five actual canonical qword stores; no other form is accepted."""
    facts = {11: (2, 0, 1, 0), 20: (5, -0xc0, 2, 16),
             23: (5, -0xa0, 1, 0), 25: (5, -0xa8, 1, 11),
             26: (5, -0x88, 1, 10)}
    need(index in facts, 'one of five literal MOV store heads')
    base, displacement, kind, source_reg = facts[index]
    off = OFFSETS[index]
    raw = bytes.fromhex(RAW[index])
    need(source[off:off + len(raw)] == raw, 'exact original guarded store')
    pc = page + off
    return (struct.pack('<QQ6I', pc, pc + len(raw), 1, 1, CODES[index], len(raw), 1, 1) +
            source[off:off + 15] + b'\0' + struct.pack('<3Q', displacement & U64, 0, 0) +
            struct.pack('<16I', 1, 1, 0, 15, 8, kind, source_reg, base,
                        16, 1, 0, 3 if displacement else 0, 4 if displacement else 0, 2, 1, 0))


def guard(source, page, index, generated, spill, successor, table_bytes):
    """Fixed 37-instruction guard templates and literal pre-instruction states.

    Only the two scratch palettes and five EA/store forms of this real graph
    are modeled.  A recovery record is derived from the explicit states, not
    copied from an observed emitter record or generated by the production API.
    """
    need(index in STORE_INDICES, 'fixed interpreter MOV guard index')
    scratch = (0, 1, 3, 5) if index == 11 else (0, 1, 2, 3)
    a, e, t = scratch[1:]
    raw = bytes.fromhex(RAW[index])
    ea = bytes.fromhex('488d0a') if index == 11 else b'\x48\x8d\x8d' + raw[3:7]
    root = struct.unpack_from('<Q', table_bytes, 24)[0]
    # Placeholder displacements have fixed widths; all targets are filled
    # from the independently listed CFG below, after exact instruction sizes.
    save = lambda r: bytes((0x48, 0x89, 5 | (r << 3))) + bytes(4)
    load = lambda r: bytes((0x48, 0x8b, 5 | (r << 3))) + bytes(4)
    rr = lambda op, left, right: bytes((0x48, op, 0xc0 | (left << 3) | right))
    memory = lambda op, r, b, disp: bytes((0x48, op, 0x40 | (r << 3) | b, disp))
    branch = lambda cc: b'\xe9' + bytes(4) if cc == 16 else bytes((15, 128 + cc)) + bytes(4)
    restore = [b'\x04\x7f', b'\x9e', load(a), load(e), load(t), load(0)]
    pieces = ([save(r) for r in scratch] +
              [ea, b'\x9f', b'\x0f\x90\xc0', bytes((0x48, 0xb8 + t)) + struct.pack('<Q', root),
               memory(0x8d, e, a, 8), rr(0x3b, e, a), branch(6), rr(0x85, t, t), branch(4),
               memory(0x3b, e, t, 0), branch(6), memory(0x3b, a, t, 8), branch(3), branch(16),
               memory(0x8b, t, t, 16), branch(16), memory(0x8b, t, t, 24), branch(16)] +
              restore + [raw, branch(16)] + restore + [b'\x0f\x0b'])
    states = ((0, 0, 0, 0), (1, 0, 0, 0), (3, 0, 0, 0), (7, 0, 0, 0),
              (15, 0, 0, 0), (15, 2, 0, 0), (15, 3, 1, 0), (15, 3, 2, 0),
              (15, 11, 2, 0)) + ((15, 15, 2, 0),) * 14 + (
              (15, 15, 1, 0), (15, 15, 0, 0), (15, 13, 0, 0), (15, 9, 0, 0), (15, 1, 0, 0),
              (15, 0, 0, 1), (15, 0, 0, 2), (15, 15, 2, 0), (15, 15, 1, 0),
              (15, 15, 0, 0), (15, 13, 0, 0), (15, 9, 0, 0), (15, 1, 0, 0), (15, 0, 0, 3))
    need(len(pieces) == len(states) == 37, 'all thirty-seven actual guard boundaries')
    offsets = []
    at = 0
    for p in pieces:
        offsets.append(at)
        at += len(p)
    code = bytearray(b''.join(pieces))

    def relative(i, target):
        end = offsets[i] + len(pieces[i])
        code[end - 4:end] = struct.pack('<i', target - generated - end)

    for i in range(4):
        relative(i, spill + 8 * i)
    for first in (24, 32):
        for j, slot in enumerate((1, 2, 3, 0)):
            relative(first + j, spill + 8 * slot)
    for i, target in ((10, 30), (12, 22), (14, 18), (16, 20),
                      (17, 30), (19, 11), (21, 11)):
        relative(i, generated + offsets[target])
    relative(29, successor)
    rows = tuple((off, len(p), *state) for off, p, state in zip(offsets, pieces, states, strict=True))
    boundary = b''.join(struct.pack('<6I', *r) for r in rows) + bytes(27 * 24)
    expected_bytes = 182 if index == 11 else 194 if index == 20 else 190
    need(len(code) == expected_bytes and rows[28][5] == 1 and rows[29][5] == 2 and rows[36][5] == 3,
         'exact store/follow/reject states and complete fixed guard extent')
    header = struct.pack('<8I', 1, 1, 0, len(code), 37, offsets[28], offsets[36], 0)
    record = header + struct.pack('<4I', *scratch) + boundary
    description = store_description(source, page, index)
    whole = (header + struct.pack('<3Q', generated, spill, successor) + struct.pack('<4I', *scratch) +
             description + table_bytes + boundary + code + bytes(512 - len(code)))
    need(len(description) == 144 and len(record) == 1584 and len(whole) == 6488,
         'whole MOV description, compact recovery record and typed materialization')
    return dict(image=bytes(code), description=description, record=record, whole=bytes(whole),
                rows=rows, scratch_regs=scratch, store_offset=offsets[28], reject_offset=offsets[36])


def graph(source, page, entry, layout, table):
    need(type(source) is bytes and len(source) == 8192 and
         hashlib.sha256(source).hexdigest() == PAIR_SHA256,
         'whole exact interpreter pair including every alternate branch')
    need(page >= 4096 and page % 4096 == 0 and entry == page + 0x2c8 and
         len(layout) == 6 and all(4096 <= v < 1 << 47 and v % 4096 == 0 for v in layout),
         'one exact MOV root and actual complete active-domain layout')
    need(type(table) is bytes and len(table) == 4224 and struct.unpack_from('<2I', table) == (1, 1),
         'complete independently reconstructed exclusion table')
    a, _, _, _, spill, _ = layout
    rows = descriptions(source, page)
    original_rows = tuple(descriptor(row, page + off, source, off, 5 if i in STORE_INDICES else 0)
                          for i, (off, row) in enumerate(zip(OFFSETS, rows, strict=True)))
    frontier_rows = tuple(descriptor(ins(raw, code), page + off, source, off, refusal)
                          for off, raw, code, refusal in FRONTIERS)
    exits = tuple(page + x[0] for x in FRONTIERS)
    images = bytearray(b'\xcc' * 65536)
    instructions = bytearray(128 * 144)
    guards = bytearray(128 * 1584)
    heads = []
    guard_models = {}

    def target(token):
        return a + 512 * token if token < 128 else exits[token - 128]

    def jump(at, destination):
        return b'\xe9' + struct.pack('<i', destination - at - 5)

    for i, (off, row, successors) in enumerate(zip(OFFSETS, rows, SUCCESSORS, strict=True)):
        generated = a + 512 * i
        kind = 2 if i in STORE_INDICES else 1
        if kind == 2:
            g = guard(source, page, i, generated, spill, target(successors[0]), table)
            guard_models[i] = g
            body = g['image']
            instructions[i * 144:(i + 1) * 144] = g['description']
            guards[i * 1584:(i + 1) * 1584] = g['record']
        elif row['flow'] == 1:
            body = (bytes((15, 128 + row['condition'])) +
                    struct.pack('<i', target(successors[0]) - generated - 6) +
                    jump(generated + 6, target(successors[1])))
        else:
            body = bytearray(row['raw'])
            if row['reloc']:
                body[3:7] = struct.pack('<i', row['address'][0] - generated - len(body))
            body += jump(generated + len(body), target(successors[0]))
        need(0 < len(body) <= 512, 'complete one-slot emitted body')
        images[512 * i:512 * i + len(body)] = body
        heads.append((kind, off // 4096, off % 4096, len(row['raw']), len(successors),
                      successors[0], successors[1] if len(successors) == 2 else 0, len(body)))
    need(len(heads) == 27 and len(guard_models) == 5 and sum(h[3] for h in heads) == 139,
         'complete unchanged twenty-seven-head/five-store graph')
    gpr_written = flags_written = 0
    for i, d in enumerate(original_rows):
        if i not in STORE_INDICES:
            gpr_written |= struct.unpack_from('<I', d, 316)[0]
            for value in struct.unpack_from('<4I', d, 296):
                flags_written |= value
    need((gpr_written, flags_written) == (0x18c7, 0x8d5), 'whole NONE graph effect union')
    predecessor = descriptor(ins('0f1f8000000000', 1057), page + 0x2c1, source, 0x2c1, 1)
    return dict(head=b''.join(struct.pack('<8I', *h) for h in heads) + bytes((128 - 27) * 32),
                original=b''.join(original_rows) + bytes((128 - 27) * 336),
                frontier=b''.join(frontier_rows) + bytes(4 * 336),
                instruction=bytes(instructions), guard=bytes(guards), image=bytes(images),
                stub_image=b'\xcc' * 4096, edge=bytes(8 * 48),
                exit_pc=struct.pack('<8Q', *exits, 0, 0, 0, 0),
                initial_slots=bytes(4096), terminal_slots=bytes(4096),
                heads=27, stores=5, exits=4, links=0, source_bytes=139, source_mask=3,
                member_heads=(27, 0), offsets=OFFSETS, head_rows=tuple(heads),
                original_rows=original_rows, frontier_rows=frontier_rows, guard_models=guard_models,
                gpr_written=gpr_written, flags_written=flags_written,
                last_none_index=24, last_none_decoded=original_rows[24][:72],
                focal_frontier_index=2, last_store_index=20,
                last_store_scratch=guard_models[20]['scratch_regs'],
                predecessor=predecessor, predecessor_decoded=predecessor[:72],
                terminal_decoded=frontier_rows[2][:72])
