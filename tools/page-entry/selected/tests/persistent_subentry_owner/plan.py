"""Independent complete 66-head subentry graph and guarded-store bytes.

The whole original pair is reconstructed from literal instructions and the
independently authenticated readonly trampoline pointer.  Both generated
members, the cross-member stub/slot and all unused bytes are modeled.  No
production decoder/emitter or captured recovery record is imported.
"""
import struct

U64 = (1 << 64) - 1
OFFSETS = tuple(range(0x200, 0x2fc, 4)) + (0x2fc, 0x1100, 0x1103)
SUCCESSORS = tuple((i + 1,) for i in range(65)) + ((128,),)
STORE_INDICES = (64,)


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


def source_image(page, subentry_pointer):
    need(page >= 4096 and page % 4096 == 0 and
         4096 <= subentry_pointer < page and subentry_pointer % 8 == 0,
         'actual source and preceding readonly ELF pointer geometry')
    out = bytearray(b'\xcc' * 8192)
    out[0x1fe:0x200] = bytes.fromhex('6690')
    out[0x200:0x2fc] = bytes.fromhex('4883c001') * 63
    out[0x2fc:0x301] = b'\xe9' + struct.pack('<i', 0x1100 - 0x301)
    out[0x1100:0x110a] = bytes.fromhex('4889074883c20141ff23')
    out[0x1120:0x1128] = bytes.fromhex('49924c87c74d87e3')
    out[0x1128:0x112e] = b'\xff\x25' + struct.pack('<i', subentry_pointer - page - 0x112e)
    return bytes(out)


def descriptions(source, page):
    arithmetic = (0, 0x8d5, 0, 0, 0)
    rows = [ins('4883c001', 249, (reg(0, 64, 3), imm(1, 64, 8)), arithmetic)
            for _ in range(63)]
    target = page + 0x1100
    rows.append(ins(b'\xe9' + struct.pack('<i', 0x1100 - 0x301), 696,
                    ((target, 4, 0, 64, 1, 32, 0),), flow=2, target=target))
    rows.append(ins('488907', 282))
    rows.append(ins('4883c201', 249, (reg(2, 64, 3), imm(1, 64, 8)), arithmetic))
    need(len(rows) == len(OFFSETS) == 66, 'all original graph heads')
    return tuple(rows)


def store_description(source, page, index):
    need(index == 64 and source[0x1100:0x1103] == bytes.fromhex('488907'),
         'exact canonical qword MOV [RDI],RAX')
    pc = page + 0x1100
    return (struct.pack('<QQ6I', pc, pc + 3, 1, 1, 282, 3, 1, 1) +
            source[0x1100:0x110f] + b'\0' + struct.pack('<3Q', 0, 0, 0) +
            struct.pack('<16I', 1, 1, 0, 15, 8, 1, 0, 7, 16, 1, 0, 0, 0, 2, 1, 0))


def guard(source, page, index, generated, spill, successor, table_bytes):
    """Independent MOV [RDI],RAX guard and all 37 pre-instruction states."""
    need(index == 64, 'only actual guarded MOV head64')
    scratch = (0, 1, 2, 3)
    a, e, t = scratch[1:]
    raw = bytes.fromhex('488907')
    ea = bytes.fromhex('488d0f')
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
    expected_bytes = 182
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



def graph(source, page, entry, layout, table_bytes, *, subentry_pointer):
    need(type(source) is bytes and source == source_image(page, subentry_pointer),
         'whole exact original pair including unsupported trampoline and all padding')
    need(entry == page + 0x200 and len(layout) == 6 and
         all(4096 <= v < 1 << 47 and v % 4096 == 0 for v in layout),
         'immutable compiled root and complete actual layout')
    need(type(table_bytes) is bytes and len(table_bytes) == 4224 and
         struct.unpack_from('<2I', table_bytes) == (1, 1),
         'complete independently reconstructed exclusion table')
    a, b, stubs, slots, spill, _ = layout
    rows = descriptions(source, page)
    originals = tuple(descriptor(row, page + off, source, off, 5 if i == 64 else 0)
                      for i, (off, row) in enumerate(zip(OFFSETS, rows, strict=True)))
    frontier = descriptor(ins('41ff23', 765), page + 0x1107, source, 0x1107, 1)
    images = [bytearray(b'\xcc' * 32768), bytearray(b'\xcc' * 32768)]
    instructions = bytearray(128 * 144)
    guards = bytearray(128 * 1584)
    heads = []
    guard_models = {}

    def jump(at, destination):
        return b'\xe9' + struct.pack('<i', destination - at - 5)

    for i, (off, row, successors) in enumerate(zip(OFFSETS, rows, SUCCESSORS, strict=True)):
        generated = (a if i < 64 else b) + 512 * (i % 64)
        kind = 2 if i == 64 else 1
        if i == 64:
            g = guard(source, page, i, generated, spill, b + 512, table_bytes)
            body = g['image']
            guard_models[i] = g
            instructions[i * 144:(i + 1) * 144] = g['description']
            guards[i * 1584:(i + 1) * 1584] = g['record']
        elif i == 63:
            body = jump(generated, stubs)
        else:
            destination = page + 0x1107 if i == 65 else a + 512 * (i + 1)
            body = row['raw'] + jump(generated + len(row['raw']), destination)
        images[i // 64][512 * (i % 64):512 * (i % 64) + len(body)] = body
        heads.append((kind, off // 4096, off % 4096, len(row['raw']), 1,
                      successors[0], 0, len(body)))
    need(sum(h[3] for h in heads) == 264 and len(heads) == 66,
         'whole 66-head/264-byte graph')
    edge = struct.pack('<4I4Q', 1, 63, 0, 64, page + 0x1100, b, stubs, slots) + bytes(7 * 48)
    stub = b'\xff\x25' + struct.pack('<i', slots - stubs - 6) + b'\xcc' * (4096 - 6)
    gpr_written = flags_written = 0
    for i, d in enumerate(originals):
        if i != 64:
            gpr_written |= struct.unpack_from('<I', d, 316)[0]
            for value in struct.unpack_from('<4I', d, 296):
                flags_written |= value
    need((gpr_written, flags_written) == (5, 0x8d5), 'whole NONE graph effect union')
    predecessor = descriptor(ins('6690', 299, step=1), page + 0x1fe, source, 0x1fe, 1)
    return dict(head=b''.join(struct.pack('<8I', *h) for h in heads) + bytes(62 * 32),
                original=b''.join(originals) + bytes(62 * 336),
                frontier=frontier + bytes(7 * 336), instruction=bytes(instructions), guard=bytes(guards),
                image=bytes(images[0] + images[1]), stub_image=stub, edge=edge,
                exit_pc=struct.pack('<8Q', page + 0x1107, 0, 0, 0, 0, 0, 0, 0),
                initial_slots=struct.pack('<Q', b) + bytes(4088),
                terminal_slots=struct.pack('<Q', page + 0x1100) + bytes(4088),
                heads=66, stores=1, exits=1, links=1, source_bytes=264, source_mask=3,
                member_heads=(64, 2), offsets=OFFSETS, head_rows=tuple(heads), original_rows=originals,
                frontier_rows=(frontier,), guard_models=guard_models, source=source,
                gpr_written=gpr_written, flags_written=flags_written,
                last_none_index=65, last_none_decoded=originals[65][:72],
                focal_frontier_index=0, last_store_index=64,
                last_store_scratch=guard_models[64]['scratch_regs'],
                predecessor=predecessor, predecessor_decoded=predecessor[:72],
                terminal_decoded=frontier[:72])
