"""Independent full A7/B9 typed direct-frontier graph and byte reconstruction.

No production decoder/emitter is imported. Both original8192-byte pairs,
all alternative edges, both distinct Jcc exit tokens and every private
instruction boundary/unused byte are modeled from the finite fixture.
"""
import struct
U64=(1<<64)-1
A_OFFSETS=(0x200,0x204,0x207,0x20b,0x215,0x20d,0x210)
B_OFFSETS=(0x400,0x404,0x408,0x40c,0x410,0x41b,0x412,0x416,0x1ffa)

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
    need(entry - page in (0x200, 0x400), 'one exact guarded A/B store')
    offset = entry - page + 4
    displaced = entry - page == 0x400
    raw = bytes.fromhex('48894708' if displaced else '488907')
    need(source[offset:offset + len(raw)] == raw, 'exact canonical qword store and displacement')
    pc = page + offset
    return (struct.pack('<QQ6I', pc, pc + len(raw), 1, 1, 282, len(raw), 1, 1) +
            source[offset:offset + 15] + b'\0' + struct.pack('<3Q', 8 if displaced else 0, 0, 0) +
            struct.pack('<16I', 1, 1, 0, 15, 8, 1, 0, 7, 16, 1, 0,
                        3 if displaced else 0, 1 if displaced else 0, 2, 1, 0))

def guard(source, page, entry, generated, spill, successor, table_bytes):
    """Both exact qword store forms and all37 pre-instruction recovery states."""
    need(entry - page in (0x200, 0x400), 'one actual A/B guarded store')
    displaced = entry - page == 0x400
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

def dispatch(pc,source,offset,generated,spill,directory,target):
    """Two literal fixture forms; all generated boundaries independently listed.
    Directory membership, never a guessed register target, determines a hit."""
    need(target in(2,3),'fixture dispatch uses only actual RDX/RBX forms')
    E=3 if target==2 else 2
    def rel(prefix,next_,dest):return bytes.fromhex(prefix)+struct.pack('<i',dest-generated-next_)
    def restore(at):
        return b'\x04\x7f\x9e'+rel('488b0d',at+10,spill+8)+rel('488b1d'if E==3 else'488b15',at+17,spill+16)+rel('488b2d',at+24,spill+24)+rel('488b05',at+31,spill)
    image=(rel('488905',7,spill)+rel('48890d',14,spill+8)+rel('48891d'if E==3 else'488915',21,spill+16)+rel('48892d',28,spill+24)+
        bytes.fromhex('4889d5'if target==2 else'4889dd')+bytes.fromhex('9f0f90c0')+b'\x48\xb9'+struct.pack('<Q',directory)+
        bytes.fromhex('488b5908'if E==3 else'488b5108')+bytes.fromhex('4881fb01000000'if E==3 else'4881fa01000000')+rel('0f82',62,generated+115)+
        bytes.fromhex('4881fb00010000'if E==3 else'4881fa00010000')+rel('0f87',75,generated+115)+bytes.fromhex('4881c120000000')+
        bytes.fromhex('48c1e3054803d9'if E==3 else'48c1e2054803d1')+bytes.fromhex('483b6900')+rel('0f84',99,generated+151)+
        bytes.fromhex('4881c120000000')+bytes.fromhex('483bcb'if E==3 else'483bca')+rel('0f82',115,generated+89)+restore(115)+rel('e9',151,pc)+
        bytes.fromhex('488b4908')+rel('48890d',162,spill+32)+restore(162)+rel('ff25',199,spill+32))
    boundary=(
        (0,7,0,0,0,0),(7,7,1,0,0,0),(14,7,3,0,0,0),(21,7,7,0,0,0),
        (28,3,15,0,0,0),(31,1,15,8,0,0),(32,3,15,9,1,0),(35,10,15,9,2,0),
        (45,4,15,11,2,0),(49,7,15,15,2,0),(56,6,15,15,2,0),(62,7,15,15,2,0),
        (69,6,15,15,2,0),(75,7,15,15,2,0),(82,4,15,15,2,0),(86,3,15,15,2,0),
        (89,4,15,15,2,0),(93,6,15,15,2,0),(99,7,15,15,2,0),(106,3,15,15,2,0),(109,6,15,15,2,0),
        (115,2,15,15,2,0),(117,1,15,15,1,0),(118,7,15,15,0,0),(125,7,15,13,0,0),(132,7,15,9,0,0),(139,7,15,1,0,0),(146,5,15,0,0,0),
        (151,4,15,15,2,0),(155,7,15,15,2,0),(162,2,15,15,2,1),(164,1,15,15,1,1),(165,7,15,15,0,1),(172,7,15,13,0,1),(179,7,15,9,0,1),(186,7,15,1,0,1),(193,6,15,0,0,1))
    need(len(image)==199 and len(boundary)==37 and all(a+n==b for(a,n,*_), (b,*_)in zip(boundary,boundary[1:])),'whole fixed domain dispatch encoding/boundaries')
    raw=bytes((0xff,0xe0+target));original=descriptor(ins(raw,765),pc,source,offset,refusal=1)
    description=original[:72]+struct.pack('<QQ6I',pc,pc+2,1,1,765,2,2,3)+struct.pack('<8I',2,1,0,15,target,0,0,0)
    record=struct.pack('<12I',2,1,0,199,37,193,146,0,0,1,E,5)+b''.join(struct.pack('<6I',*r)for r in boundary)+bytes(27*24)
    need(len(description)==144 and len(record)==1584,'whole typed domain descriptor and recovery record')
    return image,description,record

def source_image(entry_offset):
    need(entry_offset in(0x200,0x400),'one exact direct-frontier graph root')
    out=bytearray(b'\xcc'*8192)
    if entry_offset==0x200:
        out[0x1fe:0x200]=bytes.fromhex('6690')
        out[0x200:0x217]=bytes.fromhex('4883c0014889074983e80175084d89c8e9eb210000ffe2')
    else:
        out[0x400:0x41d]=bytes.fromhex('4883c002488947084883e9014983ea0174094883e900e9df1b0000ffe3')
        out[0x1ffa:0x2000]=bytes.fromhex('0f8500c2ffff')
    return bytes(out)


def descriptions(page,entry):
    arithmetic=(0,0x8d5,0,0,0)
    def branch(raw,code,target,condition,encoding):
        return ins(raw,code,((target,4,0,64,1,encoding,0),),
            (0x40 if condition<16 else 0,0,0,0,0),flow=1 if condition<16 else 2,
            target=target,condition=condition)
    if entry==page+0x200:
        rows=(ins('4883c001',249,(reg(0,64,3),imm(1,64,8)),arithmetic),
            ins('488907',282),
            ins('4983e801',264,(reg(8,64,3),imm(1,64,8)),arithmetic),
            branch('7508',176,page+0x215,5,8),
            ins('ffe2',765),
            ins('4d89c8',282,(reg(8,64,2),reg(9,64,1)),step=1),
            branch('e9eb210000',696,page+0x2400,16,32))
        return A_OFFSETS,rows,((1,),(2,),(3,),(4,5),(),(6,),(129,))
    need(entry==page+0x400,'one exact direct-frontier B root')
    rows=(ins('4883c002',249,(reg(0,64,3),imm(2,64,8)),arithmetic),
        ins('48894708',282),
        ins('4883e901',264,(reg(1,64,3),imm(1,64,8)),arithmetic),
        ins('4983ea01',264,(reg(10,64,3),imm(1,64,8)),arithmetic),
        branch('7409',173,page+0x41b,4,8),
        ins('ffe3',765),
        ins('4883e900',264,(reg(1,64,3),imm(0,64,8)),arithmetic),
        branch('e9df1b0000',696,page+0x1ffa,16,32),
        branch('0f8500c2ffff',1871,page-0x1e00,5,32))
    return B_OFFSETS,rows,((1,),(2,),(3,),(4,),(5,6),(),(7,),(8,),(129,130))


def direct(original,generated,spill,binding,conditional):
    """Literal JMP-external/JNZ-two-external adapters; all37/40 rows.

    The two Jcc target MOVs are selected while original flags remain physical.
    The common directory scan begins only after that selection. Every row
    recovers the original branch-before; CELL_READY is private state only.
    """
    pc,next_pc=struct.unpack_from('<2Q',original)
    target=struct.unpack_from('<Q',original,72)[0]
    available=struct.unpack_from('<I',original,44)[0]
    rows_address,a,b,heads,head,directory=struct.unpack('<3Q2IQ',binding)
    need(conditional in(False,True)and heads in(7,9)and head==(8 if conditional else 6)and
         generated==a+head*512 and rows_address>=4096 and b!=a,
         'exact fixture direct adapter binding')
    desc=original[:72]+struct.pack('<2Q8I',target,next_pc if conditional else 0,
        1,1,0,available,1 if conditional else 2,5 if conditional else 16,3 if conditional else 1,0)
    save=lambda r:bytes((0x48,0x89,5|(r<<3)))+bytes(4)
    load=lambda r:bytes((0x48,0x8b,5|(r<<3)))+bytes(4)
    branch=lambda c:b'\xe9'+bytes(4)if c==16 else bytes((15,128+c))+bytes(4)
    absolute=lambda reg,value:bytes((0x48,0xb8+reg))+struct.pack('<Q',value)
    restore=(b'\x04\x7f',b'\x9e',load(1),load(2),load(3),load(0))
    pieces=[save(r)for r in range(4)]
    states=[(0,0,0,0),(1,0,0,0),(3,0,0,0),(7,0,0,0)]
    if conditional:
        pieces += [branch(5),absolute(3,next_pc),branch(16),absolute(3,target)]
        states += [(15,0,0,0),(15,0,0,0),(15,8,0,0),(15,0,0,0)]
    else:
        pieces += [absolute(3,target)];states += [(15,0,0,0)]
    start=len(pieces)
    pieces += [b'\x9f',b'\x0f\x90\xc0',absolute(1,directory),bytes.fromhex('488b5108'),
        bytes.fromhex('4881fa01000000'),branch(2),bytes.fromhex('4881fa00010000'),branch(7),
        bytes.fromhex('4881c120000000'),bytes.fromhex('48c1e205'),bytes.fromhex('4803d1'),
        bytes.fromhex('483b5900'),branch(4),bytes.fromhex('4881c120000000'),bytes.fromhex('483bca'),branch(2)]
    states += [(15,8,0,0),(15,9,1,0),(15,9,2,0),(15,11,2,0)]+[(15,15,2,0)]*12
    rejected=len(pieces)
    pieces += list(restore)+[branch(16)]
    states += [(15,15,2,0),(15,15,1,0),(15,15,0,0),(15,13,0,0),(15,9,0,0),(15,1,0,0),(15,0,0,0)]
    hit=len(pieces)
    pieces += [bytes.fromhex('488b4908'),bytes.fromhex('48890d')+bytes(4)]+list(restore)+[bytes.fromhex('ff25')+bytes(4)]
    states += [(15,15,2,0),(15,15,2,0),(15,15,2,1),(15,15,1,1),(15,15,0,1),
        (15,13,0,1),(15,9,0,1),(15,1,0,1),(15,0,0,1)]
    offsets=[];at=0
    for value in pieces:offsets.append(at);at+=len(value)
    code=bytearray(b''.join(pieces))
    def rel(index,dest):
        end=offsets[index]+len(pieces[index]);code[end-4:end]=struct.pack('<i',dest-generated-end)
    for i in range(4):rel(i,spill+8*i)
    if conditional:
        rel(4,generated+offsets[7]);rel(6,generated+offsets[start])
    for index,dest in((start+5,rejected),(start+7,rejected),(start+12,hit),(start+15,start+11)):
        rel(index,generated+offsets[dest])
    for begin in(rejected+2,hit+4):
        for i,slot in enumerate((1,2,3,0)):rel(begin+i,spill+8*slot)
    rel(rejected+6,pc);rel(hit+1,spill+32);rel(hit+8,spill+32)
    boundary=tuple((off,len(piece),*state)for off,piece,state in zip(offsets,pieces,states,strict=True))
    miss_offset=offsets[rejected+6];hit_offset=offsets[hit+8]
    need((len(code),len(boundary),miss_offset,hit_offset)==((227,40,174,221)if conditional else(206,37,153,200)),
        'literal full direct byte and recovery-boundary extents')
    record=struct.pack('<12I',1,1,0,len(code),len(boundary),hit_offset,miss_offset,0,0,1,2,3)
    record+=b''.join(struct.pack('<6I',*row)for row in boundary)+bytes((64-len(boundary))*24)
    whole=record+desc+struct.pack('<2Q',generated,spill)+binding+bytes(16)+code+bytes(512-len(code))
    need(len(desc)==120 and len(record)==1584 and len(whole)==2288,'exact typed direct descriptor/record/adapter')
    return dict(image=bytes(code),description=desc,record=record,whole=bytes(whole)+bytes(6488-len(whole)),
        rows=boundary,scratch_regs=(0,1,2,3),hit_offset=hit_offset,miss_offset=miss_offset,
        external_mask=3 if conditional else 1,targets=(target,next_pc if conditional else 0),internal=(0,0))
def graph(source,page,entry,layout,table_bytes):
    need(type(source)is bytes and len(source)==8192 and page>=4096 and page%4096==0 and
         entry-page in(0x200,0x400)and source==source_image(entry-page),
         'whole exact direct-frontier original pair including every padding byte')
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
    offsets,rows,successors=descriptions(page,entry);n=len(offsets)
    dispatch_index=4 if n==7 else 5;direct_index=n-1
    originals=tuple(descriptor(row,page+off,source,off,5 if i==1 else 1 if i==dispatch_index else 0)
        for i,(off,row)in enumerate(zip(offsets,rows,strict=True)))
    images=[bytearray(b'\xcc'*32768),bytearray(b'\xcc'*32768)]
    instructions=bytearray(128*144);guards=bytearray(128*1584)
    heads=[];guard_models={};dispatch_models={};direct_models={}
    def jump(at,target):return b'\xe9'+struct.pack('<i',target-at-5)
    for i,(off,row,succ)in enumerate(zip(offsets,rows,successors,strict=True)):
        generated=a+512*i
        kind=2 if i==1 else 3 if i==dispatch_index else 5 if i==direct_index else 1
        if kind==2:
            model=guard(source,page,entry,generated,spill,a+512*succ[0],table_bytes)
            body=model['image'];instructions[i*144:(i+1)*144]=model['description']
            guards[i*1584:(i+1)*1584]=model['record'];guard_models[i]=model
        elif kind==3:
            target=2 if n==7 else 3
            body,description,record=dispatch(page+off,source,off,generated,spill,directory,target)
            instructions[i*144:(i+1)*144]=description;guards[i*1584:(i+1)*1584]=record
            binding=struct.pack('<3Q2IQ',table_address-64576,a,b,n,i,directory)
            whole=record+description+struct.pack('<2Q',generated,spill)+binding+body+bytes(512-len(body))
            need(len(whole)==2296,'complete actual register dispatch materialization')
            boundary=tuple(struct.unpack_from('<6I',record,48+24*j)for j in range(37))
            dispatch_models[i]=dict(image=body,description=description,record=record,whole=whole+bytes(6488-len(whole)),
                rows=boundary,scratch_regs=struct.unpack_from('<4I',record,32),hit_offset=193,miss_offset=146)
        elif kind==5:
            binding=struct.pack('<3Q2IQ',table_address-64576,a,b,n,i,directory)
            model=direct(originals[i],generated,spill,binding,n==9);body=model['image']
            instructions[i*144:(i+1)*144]=model['description']+bytes(24)
            guards[i*1584:(i+1)*1584]=model['record'];direct_models[i]=model
        elif row['flow']==1:
            body=bytes((15,128+row['condition']))+struct.pack('<i',a+512*succ[0]-generated-6)
            body+=jump(generated+6,a+512*succ[1])
        elif row['flow']==2:
            body=jump(generated,a+512*succ[0])
        else:
            body=row['raw']+jump(generated+len(row['raw']),a+512*succ[0])
        images[0][512*i:512*i+len(body)]=body
        heads.append((kind,off//4096,off%4096,len(row['raw']),len(succ),
            succ[0]if succ else 0,succ[1]if len(succ)==2 else 0,len(body)))
    source_bytes=sum(h[3]for h in heads)
    need((n,source_bytes)==((7,23)if entry-page==0x200 else(9,35)),
         'whole exact seven/nine-head graphs and23/35 original bytes')
    gpr_written=flags_written=0
    for i,d in enumerate(originals):
        if heads[i][0]==1:
            gpr_written|=struct.unpack_from('<I',d,316)[0]
            for value in struct.unpack_from('<4I',d,296):flags_written|=value
    need((gpr_written,flags_written)==(0x101 if n==7 else 0x403,0x8d5),
         'complete ordinary-instruction effects including both alternative arms')
    # The register-JMP exit is discovered before its direct alternative in BFS.
    # Both B direct arms remain separate tokens even though they share one PC.
    exit_heads=(dispatch_index,direct_index)if n==7 else(dispatch_index,direct_index,direct_index)
    frontiers=tuple(originals[i]for i in exit_heads);exit_pcs=tuple(page+offsets[i]for i in exit_heads)
    boundaries=tuple(dict(index=j,head=i,arm=None if j==0 else j-1,
        kind='register'if j==0 else'direct',token=128+j,
        target=None if j==0 else direct_models[direct_index]['targets'][j-1])for j,i in enumerate(exit_heads))
    last_none=5 if n==7 else 7;last_proved=direct_index
    return dict(head=b''.join(struct.pack('<8I',*h)for h in heads)+bytes((128-n)*32),
        original=b''.join(originals)+bytes((128-n)*336),
        frontier=b''.join(frontiers)+bytes((8-len(frontiers))*336),instruction=bytes(instructions),guard=bytes(guards),
        image=bytes(images[0]+images[1]),stub_image=b'\xcc'*4096,edge=bytes(8*48),
        exit_pc=exit_pcs[0],exit_pc_bytes=struct.pack('<8Q',*exit_pcs,*([0]*(8-len(exit_pcs)))),
        initial_slots=bytes(4096),terminal_slots=bytes(4096),source=source,source_bytes=source_bytes,
        heads=n,stores=1,exits=len(frontiers),links=0,source_mask=1 if n==7 else 3,member_heads=(n,0),
        offsets=offsets,head_rows=tuple(heads),original_rows=originals,frontier_rows=frontiers,
        guard_models=guard_models,dispatch_models=dispatch_models,direct_models=direct_models,
        boundary_rows=boundaries,gpr_written=gpr_written,flags_written=flags_written,
        last_none_index=last_none,last_none_decoded=originals[last_none][:72],
        last_proved_index=last_proved,last_proved_decoded=originals[last_proved][:72],
        last_store_index=1,last_store_scratch=guard_models[1]['scratch_regs'],
        dispatch_index=dispatch_index,dispatch_scratch=dispatch_models[dispatch_index]['scratch_regs'],
        terminal_decoded=originals[dispatch_index][:72],direct_index=direct_index,
        direct_terminal_decoded=originals[direct_index][:72],
        direct_terminal_exit_index=1 if n==7 else 2,direct_terminal_arm=0 if n==7 else 1)
