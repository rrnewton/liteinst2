"""Independent complete S2/T5 graph, guarded-store bytes and recovery rows.
No production decoder/emitter import; every alternative frontier and unused byte is checked.
"""
import struct
U64=(1<<64)-1
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
    available=min(15,len(source)-offset)
    need(0<available<=15 and len(raw)<=available and source[offset:offset + len(raw)] == raw,
         'complete exact original instruction and bounded source-owned decoder window')
    d = bytearray(336)
    struct.pack_into('<QQ10I', d, 0, pc, pc + len(raw), 1, 0, row['code'],
                     0, 16, 0, row['step'], available, len(raw), 0)
    d[56:72] = source[offset:offset + available] + bytes(16-available)
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


def store_description(source, page, entry):
    need(entry-page in(0,7),'one exact target store')
    offset=entry-page
    displaced=offset==7
    raw = bytes.fromhex('48894708' if displaced else '488907')
    need(source[offset:offset + len(raw)] == raw, 'exact canonical qword store and displacement')
    pc = page + offset
    return (struct.pack('<QQ6I', pc, pc + len(raw), 1, 1, 282, len(raw), 1, 1) +
            source[offset:offset + 15] + b'\0' + struct.pack('<3Q', 8 if displaced else 0, 0, 0) +
            struct.pack('<16I', 1, 1, 0, 15, 8, 1, 0, 7, 16, 1, 0,
                        3 if displaced else 0, 1 if displaced else 0, 2, 1, 0))


def guard(source, page, entry, generated, spill, successor, table_bytes):
    """Both exact qword store forms and all37 pre-instruction recovery states."""
    need(entry-page in(0,7),'one actual target guarded store')
    displaced=entry-page==7
    scratch = (0, 1, 2, 3)
    a, e, t = scratch[1:]
    raw = bytes.fromhex('48894708' if displaced else '488907')
    ea = bytes.fromhex('488d4f08' if displaced else '488d0f')
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
    expected_bytes = 184 if displaced else 182
    need(len(code) == expected_bytes and rows[28][5] == 1 and rows[29][5] == 2 and rows[36][5] == 3,
         'exact store/follow/reject states and complete fixed guard extent')
    header = struct.pack('<8I', 1, 1, 0, len(code), 37, offsets[28], offsets[36], 0)
    record = header + struct.pack('<4I', *scratch) + boundary
    description = store_description(source, page, entry)
    whole = (header + struct.pack('<3Q', generated, spill, successor) + struct.pack('<4I', *scratch) +
             description + table_bytes + boundary + code + bytes(512 - len(code)))
    need(len(description) == 144 and len(record) == 1584 and len(whole) == 6488,
         'whole MOV description, compact recovery record and typed materialization')
    return dict(image=bytes(code), description=description, record=record, whole=bytes(whole),
                rows=rows, scratch_regs=scratch, store_offset=offsets[28], reject_offset=offsets[36])


def source_image():
    out=bytearray(b'\xcc'*8192)
    out[:21]=bytes.fromhex('4889074883c007488947084883e9017502ff23ff26')
    out[0xfe:0x107]=bytes.fromhex('669089c0e90cffffff')
    return bytes(out)


def descriptions(page,entry):
    arithmetic=(0,0x8d5,0,0,0)
    def branch(raw,code,target,condition,encoding):
        return ins(raw,code,((target,4,0,64,1,encoding,0),),
            (0x40 if condition<16 else 0,0,0,0,0),flow=1 if condition<16 else 2,
            target=target,condition=condition)
    if entry==page+0x100:
        return (0x100,0x102),(ins('89c0',281,(reg(0,32,2),reg(0,32,1)),step=1),branch('e90cffffff',696,page+0x13,16,32)),((1,),(128,)),(0x13,)
    need(entry==page,'one exact target root')
    return (0,3,7,11,15),(ins('488907',282),
        ins('4883c007',249,(reg(0,64,3),imm(7,64,8)),arithmetic),ins('48894708',282),
        ins('4883e901',264,(reg(1,64,3),imm(1,64,8)),arithmetic),
        branch('7502',176,page+0x13,5,8)),((1,),(2,),(3,),(4,),(128,129)),(0x13,0x11)


def graph(source,page,entry,layout,table_bytes):
    need(type(source)is bytes and len(source)==8192 and page>=4096 and page%4096==0 and
         entry-page in(0,0x100)and source==source_image(),
         'whole exact cold-admission source pair including every padding byte')
    need(len(layout)==6 and all(type(v)is int and 4096<=v<1<<47 and v%4096==0 for v in layout),
         'complete actual image/spill/directory geometry')
    need(type(table_bytes)is bytes and len(table_bytes)==4224 and struct.unpack_from('<2I',table_bytes)==(1,1),
         'complete independently modeled guard table')
    count=struct.unpack_from('<I',table_bytes,8)[0];table_address=struct.unpack_from('<Q',table_bytes,16)[0]
    need(0<count<=131 and table_address>=146632+4096 and table_address%8==0,
         'actual immutable table and full original-row binding')
    ranges=tuple(struct.unpack_from('<2Q',table_bytes,32+32*i)for i in range(count))
    need(table(ranges,table_address)==table_bytes,'entire canonical exclusion tree including unused nodes')
    a,b,stubs,slots,spill,directory=layout
    offsets,rows,successors,exit_offsets=descriptions(page,entry);n=len(offsets);stores=()if n==2 else(0,2)
    originals=tuple(descriptor(row,page+off,source,off,5 if i in stores else 0)
        for i,(off,row)in enumerate(zip(offsets,rows,strict=True)))
    fronts=tuple(descriptor(ins('ff26'if off==0x13 else'ff23',765),page+off,source,off,1)for off in exit_offsets)
    images=[bytearray(b'\xcc'*32768),bytearray(b'\xcc'*32768)]
    instructions=bytearray(128*144);guards=bytearray(128*1584);heads=[];guard_models={}
    def destination(token):return a+512*token if token<128 else page+exit_offsets[token-128]
    def jump(at,target):return b'\xe9'+struct.pack('<i',target-at-5)
    for i,(off,row,succ)in enumerate(zip(offsets,rows,successors,strict=True)):
        generated=a+512*i;kind=2 if i in stores else 1
        if kind==2:
            model=guard(source,page,page+off,generated,spill,destination(succ[0]),table_bytes)
            body=model['image'];instructions[i*144:(i+1)*144]=model['description']
            guards[i*1584:(i+1)*1584]=model['record'];guard_models[i]=model
        elif row['flow']==1:
            body=bytes((15,128+row['condition']))+struct.pack('<i',destination(succ[0])-generated-6)
            body+=jump(generated+6,destination(succ[1]))
        elif row['flow']==2:body=jump(generated,destination(succ[0]))
        else:body=row['raw']+jump(generated+len(row['raw']),destination(succ[0]))
        images[0][512*i:512*i+len(body)]=body
        heads.append((kind,off//4096,off%4096,len(row['raw']),len(succ),succ[0],succ[1]if len(succ)==2 else 0,len(body)))
    source_bytes=sum(h[3]for h in heads);gpr_written=flags_written=0
    for i,d in enumerate(originals):
        if heads[i][0]==1:
            gpr_written|=struct.unpack_from('<I',d,316)[0]
            for value in struct.unpack_from('<4I',d,296):flags_written|=value
    need((n,source_bytes,len(stores),gpr_written,flags_written)==((2,7,0,1,0)if entry-page==0x100 else(5,17,2,3,0x8d5)),
         'exact seed/target graph and complete ordinary effects')
    exit_pcs=tuple(page+x for x in exit_offsets);last=n-1
    return dict(head=b''.join(struct.pack('<8I',*h)for h in heads)+bytes((128-n)*32),
        original=b''.join(originals)+bytes((128-n)*336),frontier=b''.join(fronts)+bytes((8-len(fronts))*336),
        instruction=bytes(instructions),guard=bytes(guards),image=bytes(images[0]+images[1]),stub_image=b'\xcc'*4096,edge=bytes(8*48),
        exit_pc=exit_pcs[0],exit_pc_bytes=struct.pack('<8Q',*exit_pcs,*([0]*(8-len(exit_pcs)))),
        initial_slots=bytes(4096),terminal_slots=bytes(4096),source=source,source_bytes=source_bytes,
        heads=n,stores=len(stores),exits=len(fronts),links=0,source_mask=1,member_heads=(n,0),
        offsets=offsets,head_rows=tuple(heads),original_rows=originals,frontier_rows=fronts,
        guard_models=guard_models,dispatch_models={},direct_models={},
        boundary_rows=tuple(dict(index=i,head=None,arm=None,kind='ordinary',token=128+i,target=pc)for i,pc in enumerate(exit_pcs)),
        gpr_written=gpr_written,flags_written=flags_written,last_none_index=last,last_none_decoded=originals[last][:72],
        last_proved_index=last,last_proved_decoded=originals[last][:72],last_store_index=2 if stores else None,
        last_store_scratch=guard_models[2]['scratch_regs']if stores else(),terminal_decoded=fronts[0][:72])
