"""Independent normal-loader application model and full-frame integration seam.

Output alone does not accept publication. The enclosing evaluator must also
join genuine NX/UD/restoration/effect/rseq records, using frame_join(), plus the
unchanged external cohorts. No source/protection authority is inferred here.
"""
import hashlib
import struct

MAGIC = 0x315050415032494c
FP = 65536
LIVE = 2116
PAGE = 4096
FLAGS = 0xed7
U64 = (1 << 64) - 1
GREG = (13, 14, 12, 11, 15, 10, 9, 8, 0, 1, 2, 3, 4, 5, 6, 7)
SYMBOLS = ('cpuid', 'getpid', 'rdtsc')
KINDS = (1, 7, 5)
ENCODINGS = (b'\x0f\xa2', b'\x0f\x05', b'\x0f\x31')
SCRIPT_CPUID = ((0x13579bdf, 0x2468ace0, 0x10203040, 0xa5a5a5a5),
                (0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00))
SCRIPT_PID = (173, 179)
SCRIPT_CLOCK = (0x1234567887654321, 0xfedcba9876543210)
VECTORS = bytes(1+(r*17+i*13)%255 for r in range(32) for i in range(64))
MASKS = b''.join(struct.pack('<Q', 0x1020304050607080+r*0x0101010101010101) for r in range(8))
LIVE_SEED = VECTORS + MASKS + bytes.fromhex('7f030030')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def q(data):
    need(type(data) is bytes and len(data) % 8 == 0, 'whole raw words')
    return struct.unpack('<' + 'Q' * (len(data) // 8), data)


def elf(data, module, native_policy):
    """Read the emitted conventional PIE/DSO; no guessed linker addresses."""
    need(type(data) is bytes and type(module) is int and module in (0, 1), 'typed ELF/module')
    def take(at, size):
        need(0 <= at <= len(data) and 0 <= size <= len(data) - at, 'complete ELF extent')
        return data[at:at + size]
    h = struct.unpack('<16sHHIQQQIHHHHHH', take(0, 64))
    need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:4] == (3, 62, 1) and
         h[8:10] == (64, 56) and h[11] == 64, 'actual conventional x86-64 ET_DYN')
    ph = [struct.unpack('<IIQQQQQQ', take(h[5] + 56 * i, 56)) for i in range(h[10])]
    loads = [p for p in ph if p[0] == 1]
    need(loads and all(p[5] <= p[6] and p[7] in (4096, 2097152) and
                      not (p[1] & 3 == 3) for p in loads), 'bounded non-WX load segments')
    def mapped(address, size):
        matches = [p for p in loads if p[3] <= address and size <= p[5] and address - p[3] <= p[5] - size]
        need(len(matches) == 1, 'one exact file-backed load range')
        p = matches[0]
        return p, p[2] + address - p[3]
    def read(address, size):
        _, at = mapped(address, size)
        return take(at, size)
    ip = [p for p in ph if p[0] == 3]
    need(len(ip) == (0 if module else 1), 'real system PT_INTERP only in main')
    interpreter = take(ip[0][2], ip[0][5]) if ip else b''
    if not module:
        need(interpreter.startswith(b'/') and interpreter.endswith(b'\0') and
             b'\0' not in interpreter[:-1], 'exact absolute interpreter name')
    dynamic = [p for p in ph if p[0] == 2]
    need(len(dynamic) == 1 and dynamic[0][5] % 16 == 0, 'one real dynamic table')
    dyn = [struct.unpack('<QQ', take(dynamic[0][2] + i, 16)) for i in range(0, dynamic[0][5], 16)]
    need(any(tag == 0 for tag, _ in dyn), 'terminated dynamic table')
    dyn = dyn[:next(i for i, row in enumerate(dyn) if row[0] == 0)]
    def one(tag):
        v = [value for t, value in dyn if t == tag]
        need(len(v) == 1, 'unique required dynamic tag')
        return v[0]
    strings = read(one(5), one(10))
    def string(at):
        need(at < len(strings) and b'\0' in strings[at:], 'complete dynamic string')
        return strings[at:strings.index(b'\0', at)].decode()
    needed = [string(v) for t, v in dyn if t == 1]
    need(len(needed) == len(set(needed)) and not any(t == 22 or (t == 30 and v & 4) for t, v in dyn),
         'complete dependency list and no text relocations')
    if module:
        need(string(one(14)) == 'libli2-provider-app.so', 'actual DSO SONAME')
    else:
        need('libli2-provider-app.so' in needed and 'libc.so.6' in needed, 'normal libc and real needed DSO')
    sections = [struct.unpack('<IIQQQQIIQQ', take(h[6] + i * 64, 64)) for i in range(h[12])]
    tables = [s for s in sections if s[1] == 2]
    need(len(tables) == 1 and tables[0][9] == 24, 'one full emitted symbol table')
    t = tables[0]; st = sections[t[6]]; names = take(st[4], st[5])
    prefix = 'pa_dso_' if module else 'pa_main_'
    wanted = {prefix + n for n in ('page', 'page_end', 'helper_page', 'helper_end', 'seed_x87',
                                   'capture_before', 'capture_after', *SYMBOLS,
                                   *(n + '_next' for n in SYMBOLS))} | {'stack'}
    symbols = {}
    for at in range(t[4], t[4] + t[5], 24):
        n, info, other, section, value, size = struct.unpack('<IBBHQQ', take(at, 24))
        need(n < len(names) and b'\0' in names[n:], 'complete symbol name')
        name = names[n:names.index(b'\0', n)].decode()
        if name in wanted:
            need(name not in symbols and section != 0, 'one actual defined fixture symbol')
            symbols[name] = value
    need(set(symbols) == wanted, 'all exact module/site/stack/endpoint symbols')
    page = symbols[prefix + 'page']; end = symbols[prefix + 'page_end']
    p, page_offset = mapped(page, PAGE)
    need(page % PAGE == 0 and end == page + PAGE and p[1] == 5 and
         page_offset > 0 and page_offset % PAGE == 0,
         'one complete original RX site page, outside the reconstructed ELF-header page')
    code = read(page, PAGE); expected = bytearray(b'\xcc' * PAGE); sites = []
    helper = symbols[prefix + 'helper_page']
    need(helper % PAGE == 0 and symbols[prefix + 'helper_end'] == helper + PAGE and
         helper <= symbols[prefix + 'capture_before'] < symbols[prefix + 'capture_after'] < helper + PAGE and
         helper <= symbols[prefix + 'seed_x87'] < symbols[prefix + 'capture_before'] and
         read(symbols[prefix + 'seed_x87'], 2) == b'\xd9\xeb' and
         native_policy(read(helper-14, PAGE+28)) == 0,
         'actual complete native helper and both halos; no instruction-policy exemption')
    for k, (name, offset) in enumerate(zip(SYMBOLS, (128, 160, 192))):
        pc = symbols[prefix + name]; nxt = symbols[prefix + name + '_next']
        need(pc == page + offset and nxt == pc + 2, 'exact exported original and next instruction offsets')
        literal = ENCODINGS[k] + b'\x90' * 3
        displacement = symbols[prefix + 'capture_after'] - (pc + 10)
        need(-(1 << 31) <= displacement < 1 << 31, 'actual relative continuation range')
        expected[offset:offset + 10] = literal + b'\xe9' + struct.pack('<i', displacement)
        sites.append(dict(kind=KINDS[k], pc=pc, next_pc=nxt, file_offset=page_offset + offset,
                          original=literal, symbol=prefix + name))
    need(code == bytes(expected), 'whole emitted site page including every fill byte and continuation')
    return dict(module=module, bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                interpreter=interpreter[:-1].decode() if interpreter else None, needed=needed,
                loads=loads, page=page, page_offset=page_offset, source=code, sites=sites,
                stack=symbols['stack'] + 16384 - 256, endpoint=symbols[prefix + 'capture_after'],
                pre_endpoint=symbols[prefix + 'capture_before'], helper=helper,
                x87_pc=symbols[prefix + 'seed_x87'])


def expected(before, module, kind, scripted, pid, cpuid, actual_clock, next_pc):
    """Independent instruction algebra; never call the runtime effect helper."""
    out = list(before)
    if kind == 0:
        values = SCRIPT_CPUID[module] if scripted else cpuid
        for register, value in zip((0, 3, 1, 2), values):
            out[register] = value
    elif kind == 1:
        out[0] = SCRIPT_PID[module] if scripted else pid
        out[1] = next_pc; out[11] = before[16]
    else:
        value = SCRIPT_CLOCK[module] if scripted else actual_clock
        need(type(value) is int and 0 < value <= U64, 'actual or scripted clock scalar')
        out[0] = value & 0xffffffff; out[2] = value >> 32
    return tuple(out)


def output(raw, images, *, pid, cpu, mode, policy, xstate):
    """Application output validation only; runtime publication remains required."""
    need(type(raw) is bytes and len(raw) < 16 << 20 and len(images) == 2 and
         mode in ('state', 'stress') and policy in ('native', 'scripted'), 'fixed typed app lane')
    at = 0
    def take(n):
        nonlocal at
        need(0 <= n <= len(raw) - at, 'complete app wire')
        b = raw[at:at+n]; at += n; return b
    h = q(take(256)); rounds = 3 if mode == 'state' else 1536; scripted = int(policy == 'scripted')
    need(h[:8] == (MAGIC, 1, int(mode == 'state'), scripted, rounds, rounds*6, pid, pid) and
         h[8] == cpu and not any(h[16:]), 'actual child fixed lane and full header')
    permissions = q(take(16)); cp = [struct.unpack('<6I', take(24)) for _ in range(67)]
    facts = xstate.profile(cp, h[10], *permissions, h[8], h[9])
    need(facts['extent'] == h[11] and facts['mask'] & 0xe7 == 0xe7 and
         cp[2][3] & 0x40010000 == 0x40010000,
         'same actual standard XSAVE format and required AVX512F/BW live-seed domain')
    machine = q(take(64)); rseq = q(take(72)); image_rows = [q(take(88)) for _ in range(2)]
    need(machine[1] > 0 and machine[3:5] == (0x33, 0x2b) and machine[5:] == (0, 0, 0),
         'actual Linux user selectors and retained segment bases')
    offset = rseq[1] if rseq[1] < 1 << 63 else rseq[1] - (1 << 64)
    need(rseq[0] == machine[1] and rseq[4] == rseq[0] + offset and rseq[4] % 32 == 0 and
         20 <= rseq[2] <= PAGE and rseq[3] == 0 and rseq[5:] == (cpu, cpu, 0, 0),
         'actual libc TLS/rseq observations; runtime registration still required')
    sources = [take(PAGE) for _ in range(2)]
    need(h[12] != h[13] and h[14] > 0 and h[15] > 0, 'two distinct observed loader images')
    for module, image in enumerate(images):
        base = h[12+module]; row = image_rows[module]
        need(image['module'] == module and row == (module, base+image['page'], base+image['page']+PAGE,
             base+image['stack'], *[base+s['pc'] for s in image['sites']],
             *[base+s['next_pc'] for s in image['sites']], base+image['endpoint']),
             'all actual runtime addresses joined to exact ELF symbols')
        need(sources[module] == image['source'], 'complete original live RX page equals emitted ELF')
    rows = []; last_clock = [0, 0]; calculated = [[0]*14 for _ in range(6)]
    if mode == 'state':
        for iteration in range(rounds):
            for module in range(2):
                for kind in range(3):
                    index = 3*module+kind; image = images[module]; base = h[12+module]
                    spec = image['sites'][kind]; words = q(take(96)); before = q(take(136)); after = q(take(136))
                    pre_live, post_live = take(LIVE), take(LIVE); original = int.from_bytes(spec['original'], 'little')
                    need(words == (module, kind, iteration, iteration*6+index, base+spec['pc'], base+spec['next_pc'],
                         base+image['endpoint'], base+image['stack'], h[10], h[11], original, 0),
                         'every actual live capture row and restored five bytes')
                    seeded = [0x1111000000000000+(module << 40)+(iteration << 16)+(kind << 8)+i for i in range(16)]
                    seeded[4] = base+image['stack']; seeded.append(FLAGS)
                    if kind == 0: seeded[0] = seeded[1] = 0
                    if kind == 1: seeded[0] = 39
                    need(before == tuple(seeded), 'complete independently seeded all-GPR/full-flags input')
                    clock = after[0] | (after[2] << 32)
                    if kind == 2:
                        need(after[0] <= 0xffffffff and after[2] <= 0xffffffff and
                             (scripted or clock > last_clock[module]), 'actual Native clock limbs and sequence')
                        last_clock[module] = clock
                    need(after == expected(before, module, kind, scripted, pid, cp[0][2:], clock, words[5]),
                         'all actual resumed GPRs/flags satisfy the independent effect model')
                    need(pre_live == post_live == LIVE_SEED,
                         'every actual seeded live ZMM/K/FCW/FSW byte; this is not an XSAVE record')
                    s = calculated[index]; s[0]=module; s[1]=kind; s[2]+=1
                    if s[2] == 1: s[3:7]=after[:4]
                    s[7:11]=after[:4]; s[11]=((s[11] << 7) | (s[11] >> 57)) & U64
                    s[11] ^= after[0] ^ after[1] ^ after[2] ^ after[3]; s[12]=words[5]; s[13]=original
                    rows.append(dict(index=words[3], module=module, kind=kind, site=words[4], next_pc=words[5],
                                     before=before, after=after, before_live=pre_live, after_live=post_live,
                                     x87_pc=base+image['x87_pc']))
    clocks = [q(take(rounds*8)) for _ in range(2)]
    for module, values in enumerate(clocks):
        need(values == (SCRIPT_CLOCK[module],)*rounds if scripted else
             all(0 < value <= U64 for value in values) and all(a < b for a, b in zip(values, values[1:])),
             'every actual clock value retained, with exact Scripted or strict Native sequence')
    if mode == 'state':
        for row in rows:
            if row['kind'] == 2:
                need(row['after'][0] | (row['after'][2] << 32) ==
                     clocks[row['module']][row['index']//6], 'all full-state clock rows match compact stream')
    else:
        # The long workload retains every nondeterministic scalar clock (24 KiB),
        # so all aggregate fields are recomputed rather than accepted as counts.
        for iteration in range(rounds):
            for module in range(2):
                for kind in range(3):
                    base = h[12+module]; image = images[module]; spec = image['sites'][kind]
                    seeded = [0x1111000000000000+(module << 40)+(iteration << 16)+(kind << 8)+i for i in range(16)]
                    seeded[4] = base+image['stack']; seeded.append(FLAGS)
                    if kind == 0: seeded[0] = seeded[1] = 0
                    if kind == 1: seeded[0] = 39
                    after = expected(seeded, module, kind, scripted, pid, cp[0][2:],
                                     clocks[module][iteration], base+spec['next_pc'])
                    s = calculated[3*module+kind]; s[0]=module; s[1]=kind; s[2]+=1
                    if s[2] == 1: s[3:7]=after[:4]
                    s[7:11]=after[:4]; s[11]=((s[11] << 7) | (s[11] >> 57)) & U64
                    s[11] ^= after[0] ^ after[1] ^ after[2] ^ after[3]
                    s[12]=base+spec['next_pc']; s[13]=int.from_bytes(spec['original'], 'little')
    statistics = [q(take(112)) for _ in range(6)]
    for index, s in enumerate(statistics):
        module, kind = divmod(index, 3); spec = images[module]['sites'][kind]
        need(s[:3] == (module, kind, rounds) and s[12:] ==
             (h[12+module]+spec['next_pc'], int.from_bytes(spec['original'], 'little')),
             'all six fixed successful effect populations and original windows')
        need(s == tuple(calculated[index]), 'all aggregate words recomputed from literal inputs and retained actual outcomes')
    need(q(take(64)) == machine and q(take(72)) == rseq, 'terminal whole machine/TLS/rseq observations exact')
    need([take(PAGE) for _ in range(2)] == sources, 'both full original live code pages after all effects')
    need(q(take(64)) == (MAGIC ^ 1, 1, rounds, rounds*6, 6, 0, 0, 0) and at == len(raw),
         'complete terminal application marker and no omitted suffix')
    return dict(application_completed=True, publication_qualified=False, full_state_qualified=False, mode=mode, policy=policy,
                operations=rounds*6, rounds=rounds, pid=pid, cpu=cpu, header=h, machine=machine, rseq=rseq,
                images=image_rows, rows=rows, statistics=statistics, clocks=clocks, format=facts,
                bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def frame_join(sample, before, after, layout, facts, *, machine, landing_pc, seed_profile, seed_probe):
    """Small full-frame seam for the source-pinned observer, not self-described ABI.

    before/after contain actual complete UC and initialized FP bytes, actual
    signal-frame/FP addresses, DS/ES/FS/GS-base observations. The enclosing
    record reader authenticates these fields from actual DWARF and raw captures,
    all struct padding, frame allocation, signal origin and publication owner.
    This function never converts an arbitrary supplied dictionary to authority.
    """
    seed_pointers = seed_probe.require(seed_profile, facts, cpu=facts['cpu'])
    need(set(layout) == {'uc_bytes', 'greg', 'fp_pointer', 'sigmask'} and
         all(type(v) is int for v in layout.values()), 'independent actual emitted UC layout')
    n, go, fo, mo = (layout[k] for k in ('uc_bytes', 'greg', 'fp_pointer', 'sigmask'))
    need(0 < n <= 2048 and 0 <= go <= n-184 and 0 <= fo <= n-8 and 0 <= mo <= n-8,
         'complete original frame extents')
    required = {'uc', 'fp', 'frame_address', 'fp_address', 'ds', 'es', 'fs_base', 'gs_base'}
    for f in (before, after):
        need(set(f) == required and type(f['uc']) is bytes and len(f['uc']) == n and
             type(f['fp']) is bytes and len(f['fp']) == facts['extent']+4 and
             all(type(f[k]) is int for k in required-{'uc','fp'}) and f['frame_address'] > 0 and
             f['fp_address'] > 0 and f['fp_address'] % 16 == 0 and
             struct.unpack_from('<Q', f['uc'], fo)[0] == f['fp_address'], 'actual complete frame and FP ownership')
    need(all(before[k] == after[k] for k in required-{'uc'}) and before['fp'] == after['fp'],
         'same complete frame/FP owner, initialized FP bytes, actual bases and selectors')
    # Complete raw signal FP is invariant above, including every inactive byte.
    # The separate live view proves only the named registers survived sigreturn.
    for live, f in ((sample['before_live'], before), (sample['after_live'], after)):
        fp=f['fp']; extent=facts['extent']; mask=facts['mask']
        need(live == LIVE_SEED and struct.unpack_from('<IIQI',fp,464) ==
             (0x46505853,extent+4,mask,extent) and not any(fp[484:512]) and
             struct.unpack_from('<I',fp,extent)[0] == 0x46505845 and
             struct.unpack_from('<Q',fp,512)[0] & 0xe7 == 0xe7 and
             not struct.unpack_from('<Q',fp,512)[0] & ~mask and not any(fp[520:576]),
             'actual complete standard kernel FP envelope, active seeds and reserved bytes')
        components={bit:(start,end) for start,end,bit in facts['components']}
        need(set((2,5,6,7)) <= components.keys(), 'all seeded standard components physically present')
        for reg in range(32):
            if reg<16:
                payload=fp[160+16*reg:176+16*reg]
                off=components[2][0]+16*reg; payload+=fp[off:off+16]
                off=components[6][0]+32*reg; payload+=fp[off:off+32]
            else:
                off=components[7][0]+64*(reg-16); payload=fp[off:off+64]
            need(payload == live[reg*64:(reg+1)*64], 'actual full live/kernel ZMM join')
        a,b=components[5]
        need(fp[a:b] == live[2048:2112] and fp[:4] == live[2112:] and
             fp[8:24] == seed_pointers,
             'actual full live/kernel K, x87 controls and independently qualified exact FIP/FDP')
    b = struct.unpack_from('<23Q', before['uc'], go)
    a = struct.unpack_from('<23Q', after['uc'], go)
    need(type(landing_pc) is int and landing_pc > 0 and b[16] == landing_pc and
         tuple(b[i] for i in GREG) == sample['before'][:16] and b[17] == FLAGS | 0x10000,
         'genuine landed pre-effect all-GPR state and retained hardware RF')
    need(len(machine) == 8 and struct.unpack_from('<Q', before['uc'], mo)[0] == machine[0] and
         (before['fs_base'], before['gs_base']) == tuple(machine[1:3]) and
         (before['ds'] | (before['es'] << 16)) == machine[5] and
         b[18] == (machine[3] | ((machine[6] >> 16) << 16) |
                   ((machine[6] & 0xffff) << 32) | (machine[4] << 48)),
         'complete actual application signal mask, bases and selectors')
    need(tuple(a[i] for i in GREG) == sample['after'][:16] and a[16:18] == (sample['next_pc'], FLAGS),
         'actual committed complete effect and logical next PC')
    wanted = bytearray(before['uc'])
    for index, value in zip(GREG, sample['after'][:16]):
        struct.pack_into('<Q', wanted, go+8*index, value)
    struct.pack_into('<Q', wanted, go+16*8, sample['next_pc'])
    struct.pack_into('<Q', wanted, go+17*8, FLAGS)
    need(bytes(wanted) == after['uc'], 'entire raw ucontext exact write set; no unrelated-byte mask')
    return dict(full_uc_bytes=n, full_fp_bytes=len(before['fp']), architectural_bytes_excluded=0,
                native_xstate_joined=False, full_state_qualified=False)


def native_pair(native, gated):
    """ASLR differences are bound to each actual ELF; no blanket byte mask."""
    need(native['mode'] == gated['mode'] and native['policy'] == 'native' and
         native['cpu'] == gated['cpu'] and native['operations'] == gated['operations'] and
         native['format'] == gated['format'], 'same workload and independently qualified actual CPU format')
    need(native['machine'][0] == gated['machine'][0] and native['machine'][2:] == gated['machine'][2:] and
         native['rseq'][1:4] == gated['rseq'][1:4] and native['rseq'][5:] == gated['rseq'][5:],
         'same signal mask/selectors/GS and libc registration shape; each FS base is bound to its actual TLS')
    need(len(native['rows']) == len(gated['rows']), 'same complete state population')
    for n, g in zip(native['rows'], gated['rows']):
        need((n['index'], n['module'], n['kind']) == (g['index'], g['module'], g['kind']), 'same logical operation')
        need(tuple(n['before'][i] for i in range(17) if i != 4) ==
             tuple(g['before'][i] for i in range(17) if i != 4),
             'all literal input registers and flags equal; each RSP separately bound to its actual private stack')
        need(n['before_live'] == n['after_live'] == g['before_live'] == g['after_live'] == LIVE_SEED,
             'independent native and gated live seed/capture equality; not full-XSTATE credit')
    return dict(native_reference_joined=True, operations=native['operations'],
                live_state_samples=len(native['rows']), publication_qualified=False, full_state_qualified=False)


def summary(value):
    """Compact public application facts; never project addresses or raw frames."""
    return dict(mode=value['mode'], policy=value['policy'], operations=value['operations'],
                rounds=value['rounds'], sites=6, sites_per_image=3, images=2,
                live_state_samples=len(value['rows']), output_bytes=value['bytes'],
                output_sha256=value['sha256'], application_completed=value['application_completed'],
                publication_qualified=False, full_state_qualified=False)
