"""Pure retained ELF/stdout reader for the first integrated one-shot fixture.

No process is executed here. Whole-program status, stderr report completion,
namespace/source/tool closure and cleanup are additional mandatory gates.
"""
import hashlib
import struct

U64 = (1 << 64)-1
SITES = ('li2_oneshot_entry', 'li2_oneshot_seeded', 'li2_oneshot_write_self',
         'li2_oneshot_write_entry', 'li2_oneshot_write_record', 'li2_oneshot_exit')
MARKER = b'ONESHOT-READY!!\n'
# Exactly four output words contain observed time, all from RAX/RDX of RDTSC.
CLOCK_OFFSETS = (26, 34, 170, 186)
SEEDS = [0xa501020304050607, 0x1122334455667701, 0xb608090a0b0c0d0e,
         0x1122334455667703, 0, *[0x1122334455667700+i for i in range(5, 16)]]


def need(value, label):
    if not value:
        raise ValueError(label)


def native_policy(data):
    """Independent emitted-byte counterpart of the pinned native_policy.c.

    This cannot grant admission. Actual two main native admissions are also
    mandatory in reports.completed; a build with an accidental barrier fails.
    """
    prefixes = set(range(0x40, 0x50)) | {0x66,0x67,0xf0,0xf2,0xf3,0x26,0x2e,0x36,0x3e,0x64,0x65}
    blocks = 0
    for i, byte in enumerate(data):
        p = data[i:]
        if len(p) >= 2:
            if p[:2] == b'\xcd\x80': blocks |= 1
            if p[:2] in (b'\xc7\xf8', b'\xc6\xf8'): blocks |= 4
            if p[0] == 0x0f:
                if p[1] in (0xa2,0x31,0x05,0x34,0xc7): blocks |= 1
                if p[1] in (0x01,0xae,0x07,0x35,0x37,0xaa): blocks |= 2
                if len(p) >= 3 and p[1] == 0x38 and p[2] in (0xf5,0xf6): blocks |= 2
        if byte not in (0xf2,0xf3): continue
        j, limit = i+1, min(len(data),i+15)
        while j < limit and data[j] in prefixes:
            if data[j] == 0xf0: blocks |= 4
            j += 1
        if j < limit and (data[j] in (0x86,0x87) or byte == 0xf3 and data[j] in (0x88,0x89,0xc6,0xc7)): blocks |= 4
        k = i
        while k and i-k < 14 and data[k-1] in prefixes:
            if data[k-1] == 0xf0: blocks |= 4
            k -= 1
    return blocks


def elf(data, interpreter):
    need(type(data) is bytes and len(data) >= 64, 'complete actual ELF')
    h = struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:4] == (3,62,1) and
         h[4] == 4096 and h[8:10] == (64,56) and h[11] == 64, 'actual PIE x86-64 entry and metadata')
    def extent(off, size):
        need(0 <= off <= len(data) and 0 <= size <= len(data)-off, 'actual ELF extent')
        return data[off:off+size]
    ph = [struct.unpack('<IIQQQQQQ',extent(h[5]+56*i,56)) for i in range(h[10])]
    loads = [p for p in ph if p[0] == 1]
    need(len(loads) == 3 and [p[1] for p in loads] == [4,5,6] and loads[0][2:4] == (0,0) and
         loads[0][5] <= 4096 and loads[1][2:4] == (4096,4096) and loads[1][5:7] == (8192,8192) and
         loads[2][2:4] == (12288,12288), 'separate R metadata, two full RX pages, RW data')
    need(all(p[7] == 4096 and p[5] <= p[6] for p in loads) and not any(p[0] == 7 for p in ph), 'page load geometry; no TLS')
    ips = [p for p in ph if p[0] == 3]
    need(len(ips) == 1 and extent(ips[0][2],ips[0][5]) == interpreter.encode()+b'\0', 'actual system interpreter')
    ss = [struct.unpack('<IIQQQQIIQQ',extent(h[6]+64*i,64)) for i in range(h[12])]
    need(not any(s[1] in (4,9) and s[5] for s in ss), 'no source relocations or source fixups')
    symbols = {}
    tables = [s for s in ss if s[1] == 2]
    need(len(tables) == 1 and tables[0][9] == 24, 'one complete actual symbol table')
    t = tables[0]; strings = ss[t[6]]; names = extent(strings[4],strings[5])
    for off in range(t[4],t[4]+t[5],24):
        n,info,other,index,value,size = struct.unpack('<IBBHQQ',extent(off,24))
        if n:
            name = names[n:names.index(b'\0',n)].decode()
            need(name not in symbols, 'unique emitted symbol')
            symbols[name] = (value,size,info,index)
    def read(address,size):
        out = bytearray()
        while size:
            p = next((p for p in loads if p[3] <= address < p[3]+p[5]), None)
            need(p is not None, 'symbol/halo outside complete file-backed LOAD')
            take = min(size,p[3]+p[5]-address)
            out.extend(extent(p[2]+address-p[3],take));address += take;size -= take
        return bytes(out)
    offsets = {name:symbols[name][0] for name in SITES}
    need(offsets[SITES[0]] == symbols['_start'][0] == 4096 and offsets[SITES[1]] == 4352 and
         len(set(offsets.values())) == 6, 'entry is actual first RDTSC and six distinct sites')
    for i,name in enumerate(SITES):
        pc = offsets[name]
        need(4096 <= pc <= 8192-5 and read(pc,5) == bytes.fromhex('0f31' if i < 2 else '0f05')+b'\x90'*3,
             'same-page exact five bytes and original PC+2 continuation')
    need(symbols['li2_helper_seed'][0] == 8192 and 8192 < symbols['li2_helper_capture'][0] < 12288,
         'real separate native seed/capture page')
    halo = read(8192-14,4096+28)
    need(native_policy(halo) == 0 and native_policy(read(4096,4096)) != 0,
         'actual emitted helper page/halos admitted by unchanged policy; selected page blocked')
    start,end = symbols['li2_oneshot_record'][0],symbols['li2_oneshot_record_end'][0]
    need(end-start == 328 and read(start,328) == MARKER+bytes(312), 'independent initial data image')
    return dict(elf_sha256=hashlib.sha256(data).hexdigest(),entry=4096,source_pages=2,
                patch_sites=offsets,original_five_bytes=['0f31909090']*2+['0f05909090']*4,
                helper_policy=0,record_bytes=328,stdout_bytes=338)


def output(data):
    need(type(data) is bytes and len(data) == 338 and data[:10] == bytes.fromhex('0f059090900f31909090'),
         'actual self-SYSCALL and entry-RDTSC source bytes read by kernel')
    p = data[10:]
    need(p[:16] == MARKER, 'independent fixed output marker')
    entry = struct.unpack_from('<2Q',p,16)
    before,after = struct.unpack_from('<16Q',p,32),struct.unpack_from('<16Q',p,160)
    need(list(before) == SEEDS, 'all independently seeded pre-RDTSC GPR values; RSP normalized only after equality')
    need(all(after[i] == before[i] for i in range(16) if i not in (0,2)), 'all fourteen non-destinations including checked RSP')
    raw = (*entry,after[0],after[2])
    need(all(x <= 0xffffffff for x in raw), 'both actual RAX/RDX results zero-extend')
    clocks = [entry[0] | entry[1]<<32, after[0] | after[2]<<32]
    need(all(0 < x <= U64 for x in clocks), 'actual nonzero clocks, no exact native-clock expectation')
    need(struct.unpack_from('<2Q',p,288) == (0xed7,0xed7), 'complete flags and DF preserved across seeded RDTSC')
    selectors = struct.unpack_from('<12H',p,304)
    need(selectors[:6] == selectors[6:] and selectors[:2] == (0x33,0x2b), 'all six selectors preserved')
    normalized = bytearray(data)
    for off in CLOCK_OFFSETS: normalized[off:off+8] = bytes(8)
    return dict(clocks=clocks,raw_clock_words=list(raw),flags=[0xed7,0xed7],selectors=list(selectors[:6]),
                nondestination_registers=14,restored_source_bytes=data[:10].hex(),
                stdout_sha256=hashlib.sha256(data).hexdigest(),deterministic_sha256=hashlib.sha256(normalized).hexdigest()),bytes(normalized)


def compare_outputs(native, gated):
    n,nb = output(native);g,gb = output(gated)
    need(nb == gb, 'every output byte equal except four explicit clock words')
    return dict(native=n,gated=g,clock_word_offsets=list(CLOCK_OFFSETS),nonclock_bytes_equal=True)
