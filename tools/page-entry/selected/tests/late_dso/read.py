"""Exact late-loader application live captures; no UC/XSAVE or unmap authority.

read() consumes original emitted ELF bytes and the actual child stdout. The
caller owns source/build/launch/namespace/exit/cleanup evidence. pair() reads
both raw records again and compares independent Native operations. Its only
cross-process relations are explicit ELF-relative addresses, actual PIDs,
TLS-relative rseq observations and independently retained native clocks.
"""
import hashlib
import struct

MAGIC = 0x314554414c32494c
LEAF_MAGIC = 0x314641454c32494c
RECORD_BYTES = 91032
CYCLE_BYTES = 44376
CYCLES_OFFSET = 2216
EFFECTS_OFFSET = 16776
EFFECT_BYTES = 4600
FP = 65536
LIVE = 2116
PAGE = 4096
FLAGS = 0xed7
U64 = (1 << 64) - 1
MASK = U64 ^ sum(1 << (signal - 1) for signal in (4, 5, 9, 11, 19, 31))
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
    need(type(data) is bytes and type(module) is int and module in (0, 1) and 64 <= len(data) <= 16 << 20, 'typed ELF/module')
    def take(at, size):
        need(0 <= at <= len(data) and 0 <= size <= len(data) - at, 'complete ELF extent')
        return data[at:at + size]
    h = struct.unpack('<16sHHIQQQIHHHHHH', take(0, 64))
    need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:4] == (3, 62, 1) and
         h[8:10] == (64, 56) and 1 <= h[10] <= 32 and h[11] == 64, 'actual conventional x86-64 ET_DYN')
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
    need(not any(t in (15, 29, 0x6ffffefc, 0x6ffffefb, 0x7fffffff, 0x7ffffffd) for t, _ in dyn),
         'no embedded search/audit/filter policy')
    if module:
        need(string(one(14)) == 'libli2-late.so' and 'libli2-late-leaf.so' in needed,
             'actual late DSO SONAME and transitive leaf dependency')
    else:
        need('libc.so.6' in needed and not {'libli2-late.so', 'libli2-late-leaf.so'} & set(needed),
             'normal libc and neither late object in main DT_NEEDED')
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
    stack = symbols['stack']
    stack_owners = [p for p in loads if p[1] == 6 and p[3] <= stack and
                    stack - p[3] <= p[6] and 16384 <= p[6] - (stack - p[3])]
    need(stack % 64 == 0 and len(stack_owners) == 1, 'complete private stack in one writable load')
    helper = symbols[prefix + 'helper_page']
    need(helper != page and mapped(helper, PAGE)[0][1] == 5 and
         helper % PAGE == 0 and symbols[prefix + 'helper_end'] == helper + PAGE and
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
    return dict(module=module, phnum=h[10], bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
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


def read(data, pid, cpu, original_elf, late_elf, *, native_policy, xstate):
    """Validate one complete Native record; return private state and summary."""
    need(type(data) is bytes and len(data) == RECORD_BYTES and
         type(pid) is int and 0 < pid < 1 << 31 and type(cpu) is int and cpu >= 0,
         'fixed complete late record and actual child identity')
    images = [elf(blob, module, native_policy) for module, blob in enumerate((original_elf, late_elf))]
    at = 0
    def take(size):
        nonlocal at
        need(0 <= size <= len(data) - at, 'complete fixed record field')
        value = data[at:at + size]; at += size; return value
    head = q(take(128)); permissions = q(take(16))
    need(head[:8] == (MAGIC, 1, 0, 2, 12, pid, pid, cpu) and
         head[11] == 6 and 0 < head[12] <= U64 and head[12] % PAGE == 0 and
         head[13] == images[0]['phnum'] and head[14:] == (RECORD_BYTES, 0),
         'actual single-thread Native-only lane, image and terminal header')
    hardware = tuple(struct.unpack('<6I', take(24)) for _ in range(67))
    facts = xstate.profile(hardware, head[9], *permissions, cpu, head[8])
    need(facts['extent'] == head[10] and facts['mask'] & 0xe7 == 0xe7 and
         hardware[2][3] & 0x40010000 == 0x40010000,
         'complete observed CPUID/XCR0 format and required AVX512F/BW live-state domain')
    machines = [q(take(64)) for _ in range(2)]
    need(machines[0] == machines[1] and machines[0][0] == MASK and machines[0][1] > 0 and
         machines[0][3:5] == (0x33, 0x2b) and machines[0][5:] == (0, 0, 0),
         'whole terminal machine identity, exact selected mask, actual bases and Linux user selectors')
    registrations = [q(take(72)) for _ in range(2)]
    rseq = registrations[0]; offset = rseq[1] if rseq[1] < 1 << 63 else rseq[1] - (1 << 64)
    need(registrations[1] == rseq and rseq[0] == machines[0][1] and
         0 < rseq[0] + offset <= U64 and rseq[4] == rseq[0] + offset and rseq[4] % 32 == 0 and
         20 <= rseq[2] <= PAGE and rseq[3] == 0 and rseq[5:] == (cpu, cpu, 0, 0),
         'default libc TLS/rseq observations remain inactive and exact at both outer boundaries')
    notes = tuple(q(take(32)) for _ in range(6))
    need(notes == tuple((cycle, kind, LEAF_MAGIC + kind, 0) for cycle in range(2) for kind in (1, 2, 3)),
         'actual constructor/function/destructor order twice, with reloaded leaf counter reset')
    need(at == CYCLES_OFFSET, 'exact fixed record prefix')
    cycles = []; rows = []; clocks = []; previous_after = None
    for iteration in range(2):
        begin = at
        inventories = tuple(q(take(72)) for _ in range(3))
        before_load, loaded, after_close = inventories
        for inventory in (before_load, after_close):
            need(inventory[0] > 0 and inventory[1:7] == (0,) * 6,
                 'both late names absent from actual loader inventory')
        need(loaded[0] == before_load[0] + 2 and loaded[1:3] == (1, 1) and
             0 < loaded[3] != loaded[4] > 0 and loaded[3] % PAGE == loaded[4] % PAGE == 0 and
             loaded[5] == images[1]['phnum'] and 1 <= loaded[6] <= 32 and
             loaded[7:] == (before_load[7] + 2, before_load[8]) and
             after_close[0] == before_load[0] and after_close[7:] == (loaded[7], loaded[8] + 2),
             'two exact loaded objects and actual add/sub counters around each genuine close')
        if previous_after is not None:
            need(before_load == previous_after, 'complete loader inventory continuity between cycles')
        previous_after = after_close
        bases = (head[12], loaded[3]); image_rows = tuple(q(take(88)) for _ in range(2))
        need(bases[0] != bases[1], 'main and late object have distinct observed bases')
        for module, image in enumerate(images):
            base = bases[module]
            addresses = (image['page'], image['page'] + PAGE, image['stack'],
                         *[s['pc'] for s in image['sites']], *[s['next_pc'] for s in image['sites']],
                         image['endpoint'])
            need(all(0 <= v <= U64 - base for v in addresses) and
                 image_rows[module] == (module, *(base + v for v in addresses)),
                 'every observed page/stack/site/endpoint address joins the exact emitted ELF')
        sources = tuple(take(PAGE) for _ in range(2)); restored = tuple(take(PAGE) for _ in range(2))
        need(sources == restored == tuple(image['source'] for image in images),
             'all original site pages and every restored byte equal the independently emitted ELF')
        need(at - begin == EFFECTS_OFFSET, 'exact fixed effect offset')
        for module in range(2):
            image = images[module]; base = bases[module]
            for kind in range(3):
                words = q(take(96)); before = q(take(136)); after = q(take(136))
                pre_live, post_live = take(LIVE), take(LIVE)
                spec = image['sites'][kind]; index = iteration * 6 + module * 3 + kind
                need(words == (module, kind, iteration, index, base + spec['pc'], base + spec['next_pc'],
                     base + image['endpoint'], base + image['stack'], head[9], head[10],
                     int.from_bytes(spec['original'], 'little'), 0),
                     'every actual effect identity, logical PC, format and self-read restored five bytes')
                seeded = [0x1111000000000000 + (module << 40) + (iteration << 16) + (kind << 8) + i
                          for i in range(16)]
                seeded[4] = base + image['stack']; seeded.append(FLAGS)
                if kind == 0: seeded[0] = seeded[1] = 0
                if kind == 1: seeded[0] = 39
                need(before == tuple(seeded), 'all sixteen seeded GPRs and complete logical flags')
                clock = after[0] | (after[2] << 32)
                if kind == 2:
                    need(after[0] <= 0xffffffff and after[2] <= 0xffffffff and 0 < clock <= U64 and
                         (not clocks or clocks[-1] < clock), 'all four actual native clocks strictly increase on the pinned CPU')
                    clocks.append(clock)
                need(after == expected(before, module, kind, False, pid, hardware[0][2:], clock, words[5]),
                     'complete actual resumed GPR/flags satisfy independent Native effect algebra')
                need(pre_live == post_live == LIVE_SEED,
                     'every live ZMM/K/FCW/FSW byte matches the literal independent seed')
                rows.append(dict(words=words, before=before, after=after, pre_live=pre_live, post_live=post_live))
        need(at - begin == CYCLE_BYTES, 'one complete fixed cycle with all six effect records')
        cycles.append(dict(inventories=inventories, bases=bases, images=image_rows,
                           sources=sources, restored=restored))
    need(q(take(64)) == (MAGIC ^ 1, 1, 2, 12, 6, 0, 0, 0) and at == len(data),
         'complete successful terminal marker and no trailing/omitted bytes')
    summary = dict(scope='actual_application_live_captures_and_loader_observations', policy='native',
                   application_completed=True, publication_qualified=False, full_xstate_qualified=False,
                   kernel_unmap_qualified=False, runtime_lifecycle_qualified=False,
                   bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), pid=pid, cpu=cpu, node=head[8],
                   cycles=2, effects=12, cpuid=4, getpid=4, rdtsc=4, notes=6, loader_inventories=6,
                   original_restored_site_pages=8, live_state_snapshots=24, live_bytes_per_snapshot=LIVE,
                   xcr0=head[9], xstate_format_extent=head[10], cpuid_leaf0=hardware[0][2:], clocks=clocks,
                   images=[{k:im[k] for k in ('module', 'bytes', 'sha256')} for im in images])
    return dict(summary=summary, header=head, permissions=permissions, hardware=hardware, format=facts,
                machine=machines[0], rseq=rseq, notes=notes, images=images, cycles=cycles, rows=rows)


def pair(native_data, gated_data, *, native_pid, gated_pid, cpu, original_elf, late_elf, native_policy, xstate):
    """Re-read both actual captures; never treat supplied summary status as proof."""
    n = read(native_data, native_pid, cpu, original_elf, late_elf, native_policy=native_policy, xstate=xstate)
    g = read(gated_data, gated_pid, cpu, original_elf, late_elf, native_policy=native_policy, xstate=xstate)
    need(native_pid != gated_pid and n['hardware'] == g['hardware'] and n['permissions'] == g['permissions'] and
         n['format'] == g['format'] and n['notes'] == g['notes'],
         'separate actual children, complete same-CPU hardware format and all six lifecycle notes')
    need(n['machine'][0] == g['machine'][0] and n['machine'][2:] == g['machine'][2:] and
         n['rseq'][1:4] == g['rseq'][1:4] and n['rseq'][5:] == g['rseq'][5:],
         'exact masks/selectors/GS and TLS-relative registration; actual FS/TP addresses are process-local')
    for nc, gc in zip(n['cycles'], g['cycles'], strict=True):
        need(nc['sources'] == gc['sources'] == nc['restored'] == gc['restored'], 'every whole original/restored page agrees')
        for ni, gi in zip(nc['inventories'], gc['inventories'], strict=True):
            need(ni[:3] == gi[:3] and ni[5:] == gi[5:],
                 'all loader counts, name multiplicities, PHDR sizes and add/sub observations agree')
    for nr, gr in zip(n['rows'], g['rows'], strict=True):
        module, kind, iteration, index = nr['words'][:4]
        need(gr['words'][:4] == (module, kind, iteration, index) and nr['words'][8:] == gr['words'][8:],
             'same complete effect identity, format and original opcode bytes')
        nbase = n['cycles'][iteration]['bases'][module]; gbase = g['cycles'][iteration]['bases'][module]
        need(tuple(v - nbase for v in nr['words'][4:8]) == tuple(v - gbase for v in gr['words'][4:8]),
             'all site/next/endpoint/stack observations agree at exact module-relative addresses')
        before = list(nr['before']); before[4] = gr['words'][7]
        after = list(nr['after']); after[4] = gr['words'][7]
        if kind == 1:
            after[0] = gated_pid; after[1] = gr['words'][5]
        elif kind == 2:
            # Two different real executions have different hardware clocks.
            # Their exact limbs and strict ordered values were checked above.
            after[0] = gr['after'][0]; after[2] = gr['after'][2]
        need(gr['before'] == tuple(before) and gr['after'] == tuple(after) and
             nr['pre_live'] == nr['post_live'] == gr['pre_live'] == gr['post_live'] == LIVE_SEED,
             'all cross-process seeded/resumed live state under explicit PID/address/clock relations')
    return dict(scope='native_and_gated_native_application_live_pair', compared_effect_pairs=12,
                actual_effects=24, complete_gpr_flags_live_pairs=12, actual_loader_cycles=4,
                native=n['summary'], gated=g['summary'], publication_qualified=False,
                full_xstate_qualified=False, kernel_unmap_qualified=False, runtime_lifecycle_qualified=False)


def controls(data, pid, cpu, original_elf, late_elf, *, native_policy, xstate):
    """Supplied corruptions of an accepted actual record; no additional target runs."""
    accepted = read(data, pid, cpu, original_elf, late_elf, native_policy=native_policy, xstate=xstate)
    first = CYCLES_OFFSET + EFFECTS_OFFSET
    cases = {'short': data[:-1], 'trailing': data + b'\0'}
    offsets = dict(scripted_header=16, constructor_note=2024+8,
                   before_load_present=CYCLES_OFFSET+8, after_close_present=CYCLES_OFFSET+144+8,
                   original_page=CYCLES_OFFSET+392, restored_page=CYCLES_OFFSET+8584,
                   input_gpr=first+96+40, output_gpr=first+232+40,
                   live_zmm=first+368, live_k=first+368+2048,
                   live_fcw=first+368+2112, live_fsw=first+368+2114,
                   syscall_pid=first+EFFECT_BYTES+232, inactive_rseq=1880+56,
                   terminal_marker=RECORD_BYTES-64)
    for name, offset in offsets.items():
        altered = bytearray(data); altered[offset] ^= 1; cases[name] = bytes(altered)
    # Preserve complete scalar limbs while violating the real clock sequence.
    altered = bytearray(data); value = accepted['summary']['clocks'][0]
    second_clock = first + 5 * EFFECT_BYTES + 232
    struct.pack_into('<Q', altered, second_clock, value & 0xffffffff)
    struct.pack_into('<Q', altered, second_clock + 16, value >> 32)
    cases['native_clock_order'] = bytes(altered)
    altered = bytearray(data)
    for offset in (1752, 1816): struct.pack_into('<Q', altered, offset, 0)
    cases['selected_application_mask'] = bytes(altered)
    for name, altered in cases.items():
        try:
            read(altered, pid, cpu, original_elf, late_elf, native_policy=native_policy, xstate=xstate)
        except ValueError:
            continue
        raise ValueError('supplied record corruption accepted: ' + name)
    return dict(scope='supplied_record_corruptions_only', cases=len(cases), rejected=len(cases), names=list(cases))
