"""Exact bounded-journal-v1 pair contracts; no execution or admission authority."""
import hashlib
import struct

PROFILE = 'bounded-journal-v1'
FLAG = '--recording-profile=' + PROFILE
CORE_HOOK = 0x401970
CORE_HOOK_BYTES = 211
JOURNAL_BYTES = 131144
CAPACITY = 16384
TRACE_RESERVE = 176 * (20000 * 128 + 16384)
TRACE_LIVE = 2 * (20000 * 128 + 16384)
CELLS = ('journal-heap-write-unstripped', 'journal-heap-write-stripped',
         'journal-jump-site-unstripped', 'journal-jump-site-stripped')
LANES = ('core', 'stock-algorithm', 'bootstrap-patched-reference')
ALL_CELLS = tuple(cell + '-' + lane for cell in CELLS for lane in LANES)
BEFORE = bytes.fromhex('488da42400c0ffff415341525041514150515256570f90c09f50')
AFTER = bytes.fromhex('58047f9e5f5e5a594158415958415a415b488da42400400000')


def initial_journal():
    b = bytearray(JOURNAL_BYTES)
    for at, value in ((0, 0x6c69326a6f75726e), (8, 1), (16, CAPACITY),
                      (JOURNAL_BYTES - 8, 0x7265636f72647321)):
        struct.pack_into('<Q', b, at, value)
    return bytes(b)


def journal_seed(base, lo, rw_start, rw_end):
    """Identify the complete initial object, then set precisely active=1."""
    template = initial_journal()
    hits = [i for i in range(0, len(base)-len(template)+1, 8)
            if base[i:i+len(template)] == template]
    assert len(hits) == 1
    at = hits[0]
    assert rw_start <= lo+at and lo+at+len(template) <= rw_end
    b = bytearray(base); struct.pack_into('<Q', b, at+24, 1)
    return bytes(b), at


def journal_after(seed, at, logical):
    template = bytearray(initial_journal()); struct.pack_into('<Q', template, 24, 1)
    assert type(at) is int and at >= 0 and at+JOURNAL_BYTES <= len(seed)
    assert seed[at:at+JOURNAL_BYTES] == template
    b = bytearray(seed)
    if logical is not None:
        assert type(logical) is int and 0 < logical < 1 << 64
        struct.pack_into('<Q', b, at+32, 1); struct.pack_into('<Q', b, at+64, logical)
    return bytes(b)


def ordinary_journal(read, json_read, observation, row, run, variant, style):
    """Rejoin the complete admitted ordered stream, including repeated PCs."""
    assert style in ('heap-write','jump-site') and variant in ('unstripped','stripped')
    name='observe-'+variant+'-'+row['dataset']; stem='heap' if style=='heap-write' else 'jump'
    case=observation['cases'][name]
    from pathlib import Path
    captures=Path(case['capture_directory'])
    assert captures==Path(observation['directory'])/name/'captures'
    pcs=read(captures/(stem+'-pcs.bin'))
    digest=hashlib.sha256(pcs).hexdigest()
    assert digest==case[stem+'_pcs_sha256'] and len(pcs)%8==0 and len(pcs)//8<=CAPACITY
    expected=(struct.pack('<8Q',0x6c69326a6f75726e,1,CAPACITY,0,len(pcs)//8,0,0,0)+pcs+
              bytes(131072-len(pcs))+struct.pack('<Q',0x7265636f72647321))
    assert read(run/'journal.bin')==expected
    assert row['journal_bytes']==len(expected) and row['journal_sha256']==hashlib.sha256(expected).hexdigest()
    assert row['expected_record_count']==row['original_pc_stream_count']==len(pcs)//8
    assert row['expected_pc_stream_sha256']==row['original_pc_stream_sha256']==digest


def clean_prefix(entry, logical, hook):
    def relative(op, at, target):
        delta = target-(at+len(op)+4)
        assert -(1 << 31) <= delta < 1 << 31
        return op+struct.pack('<i', delta)
    b = BEFORE+relative(b'\x48\x8d\x3d', entry+len(BEFORE), logical)
    b += relative(b'\xe8', entry+len(b), hook)
    b += AFTER
    assert len(b) == 63
    return b


def clean_instructions(entry, logical, hook):
    """Literal clean-template instruction boundaries, not a disassembler guess."""
    b = clean_prefix(entry, logical, hook)
    lengths = (8,2,2,1,2,2,1,1,1,1,3,1,1,7,5,1,2,1,1,1,1,1,2,2,1,2,2,8)
    assert sum(lengths) == len(b)
    out = []; at = 0
    for n in lengths:
        raw = b[at:at+n]; pc = entry+at
        dest = hook if raw[0] == 0xe8 else pc+n
        out.append((pc,dest,raw)); at += n
    assert sum(raw[0] == 0xe8 for _,_,raw in out) == 1
    return out


def clean_stack(before, stack_start, application_start, registers, return_pc):
    assert len(before) == 65536
    b = bytearray(before); sp = registers['rsp']-0x4000
    values = [registers[k] for k in ('r11','r10','rax','r9','r8','rcx','rdx','rsi','rdi')]
    flags = registers['eflags']
    values += [(registers['rax'] & ~0xffff) | (((flags & 0xd5) | 2) << 8) | ((flags >> 11) & 1), return_pc]
    for value in values:
        sp -= 8
        assert stack_start <= sp and sp+8 <= application_start
        struct.pack_into('<Q', b, sp-stack_start, value)
    assert sp == registers['rsp']-0x4058
    return bytes(b)


def hook_elf(data, hook):
    """Independent bounded ELF/dynsym/LOAD derivation for the exact hook role."""
    assert type(hook) is dict and hook['symbol'] == 'li2_e9_record'
    assert data[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<HHI',data,16) == (3,62,1)
    assert struct.unpack_from('<HH',data,52) == (64,56)
    off = struct.unpack_from('<Q',data,32)[0]; count = struct.unpack_from('<H',data,56)[0]
    assert 1 <= count <= 128 and off+56*count <= len(data)
    headers = [struct.unpack_from('<IIQQQQQQ',data,off+56*i) for i in range(count)]
    base = hook['base']; assert type(base) is int and base >= 0 and base % 4096 == 0
    loads = [p for p in headers if p[0] == 1]; assert loads
    for p in loads:
        assert p[1] in (4,5,6) and 0 < p[6] <= 16*1048576 and p[5] <= p[6]
        assert p[2]+p[5] <= len(data) and p[2] % 4096 == p[3] % 4096
        assert base+p[3]+p[6] < 1 << 31
    off = struct.unpack_from('<Q',data,40)[0]; width,count = struct.unpack_from('<HH',data,58)
    assert width == 64 and 1 <= count <= 4096 and off+64*count <= len(data)
    sections = [struct.unpack_from('<IIQQQQIIQQ',data,off+64*i) for i in range(count)]
    tables = [s for s in sections if s[1] == 11]; assert len(tables) == 1
    table = tables[0]
    assert table[9] == 24 and table[5] % 24 == 0 and table[5]//24 <= 4096
    assert table[4]+table[5] <= len(data) and table[6] < count
    strings = sections[table[6]]; assert strings[1] == 3 and strings[4]+strings[5] <= len(data)
    names = data[strings[4]:strings[4]+strings[5]]; hits = []
    for at in range(table[4],table[4]+table[5],24):
        name,info,other,section,value,size = struct.unpack_from('<IBBHQQ',data,at)
        assert name < len(names) and b'\0' in names[name:]
        if names[name:].split(b'\0',1)[0] == b'li2_e9_record':
            assert info == 0x12 and section != 0 and value == hook['entry'] and 0 < size <= 4096
            owners = [p for p in loads if p[1] == 5 and p[3] <= value and value+size <= p[3]+p[5]]
            assert len(owners) == 1
            p = owners[0]; start = p[2]+value-p[3]
            hits.append(dict(entry=base+value,bytes=data[start:start+size].hex(),
                loads=[dict(start=base+p[3],end=base+p[3]+p[6],flags=p[1]) for p in loads]))
    assert len(hits) == 1
    return hits[0]


def hook_maps(data, hook, mappings, pages):
    """Every hook LOAD, including writable data, has exact mapping bytes/flags."""
    off = struct.unpack_from('<Q',data,32)[0]; count = struct.unpack_from('<H',data,56)[0]
    headers = [struct.unpack_from('<IIQQQQQQ',data,off+56*i) for i in range(count)]
    for p in (p for p in headers if p[0] == 1):
        _,flags,offset,va,_,fs,ms,_ = p
        start = hook['base']+va; end = start+ms
        prot = 1 | (4 if flags & 1 else 0) | (2 if flags & 2 else 0)
        expected = data[offset:offset+fs]+bytes(ms-fs)
        cursor = start
        while cursor < end:
            owners = [m for m in mappings if m['kind']=='trampoline' and m['va']<=cursor<m['va']+m['length']]
            assert len(owners)==1 and owners[0]['prot']==prot
            page=cursor&~4095; amount=min(end-cursor,4096-(cursor-page))
            assert pages[page][0]==flags
            assert pages[page][1][cursor-page:cursor-page+amount]==expected[cursor-start:cursor-start+amount]
            cursor+=amount


def callback_rows(rows, cursor, start, code, return_pc, logical):
    """Saved byte/edge path and exact RET; live ISA/stackless proof stays explicit."""
    assert 0 < len(code) <= 4096
    assert rows[cursor] == ['journal-hook',str(start),str(return_pc),str(logical),code.hex()]
    cursor += 1; pc = start; charged = 0; ranges = {}
    while True:
        row = rows[cursor]; cursor += 1
        assert len(row) == 4 and row[0] == 'journal-step' and int(row[1]) == pc
        raw = bytes.fromhex(row[3]); dest = int(row[2])
        assert raw.hex() == row[3] and 1 <= len(raw) <= 15 and start <= pc and pc+len(raw) <= start+len(code)
        assert code[pc-start:pc-start+len(raw)] == raw
        assert all(a == pc or pc+len(raw) <= a or a+n <= pc for a,n in ranges.items())
        if pc in ranges: assert ranges[pc] == len(raw)
        ranges[pc] = len(raw); charged += 1; assert charged <= 20000
        if raw == b'\xc3':
            assert dest == return_pc
            break
        assert raw[0] not in (0xc2,0xca,0xcb,0xcc,0xcd,0xce,0xcf,0xe8,0x9a,0xea,0xf4)
        assert not raw.startswith((b'\x0f\x05',b'\x0f\x34',b'\x0f\x0b'))
        if len(raw) == 2 and (raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f):
            target = pc+2+struct.unpack('<b',raw[1:])[0]
            assert dest in ((target,) if raw[0] == 0xeb else (pc+2,target))
        elif len(raw) == 5 and raw[0] == 0xe9:
            assert dest == pc+5+struct.unpack('<i',raw[1:])[0]
        elif len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
            assert dest in (pc+6,pc+6+struct.unpack('<i',raw[2:])[0])
        else:
            assert dest == pc+len(raw)
        assert start <= dest < start+len(code)
        pc = dest
    return cursor, charged


def core_trace(data, walk, logical):
    """Remove only independently checked callback rows; old router parser sees all its rows."""
    rows = [r.split('\t') for r in data.decode('ascii').splitlines()]
    assert data.endswith(b'\n')
    callbacks = [(p,n,b) for p,n,b in walk if p == CORE_HOOK]
    assert len(callbacks) <= 1
    out = []; cursor = 0; count = 0
    while cursor < len(rows):
        row = rows[cursor]
        if row[0] == 'journal-hook':
            assert callbacks and count == 0
            p,n,b = callbacks[0]; assert len(b) == CORE_HOOK_BYTES
            cursor, steps = callback_rows(rows,cursor,p,b,n,logical)
            assert rows[cursor] == ['prefix',str(p),str(n),b.hex()]
            count += 1
        else:
            assert row[0] != 'journal-step'
            out.append(row); cursor += 1
    assert count == len(callbacks)
    return ('\n'.join('\t'.join(r) for r in out)+'\n').encode(), (steps-1 if count else 0)


def e9_trace(data, walk, clean, hook, logical, operations):
    rows = [r.split('\t') for r in data.decode('ascii').splitlines()]
    assert data.endswith(b'\n') and rows[0] == ['phase','before_pc','after_pc','bytes']
    cursor = 1; charged = 0
    for p,n,b in walk:
        assert rows[cursor] == ['prefix',str(p),str(n),b.hex()]; cursor += 1; charged += 1
    if clean is not None:
        expected = clean_prefix(clean['entry'],logical,hook['entry'])
        assert clean == dict(entry=clean['entry'],hook=hook['entry'],return_pc=clean['entry']+len(BEFORE)+12,bytes=expected.hex())
        for p,n,b in clean_instructions(clean['entry'],logical,hook['entry']):
            assert rows[cursor] == ['clean-prefix',str(p),str(n),b.hex()]; cursor += 1; charged += 1
            if b[0] == 0xe8:
                cursor, count = callback_rows(rows,cursor,hook['entry'],bytes.fromhex(hook['bytes']),clean['return_pc'],logical)
                charged += count
    for i,r in enumerate(operations):
        assert rows[cursor] == ['operation-'+str(i),str(r['pc']),str(r['next']),r['bytes']]
        cursor += 1; charged += 1
    assert cursor == len(rows) and charged <= 20000
    return charged
