"""Application stdout/native reference only. Protected owner joins are separate.

No call to read() qualifies generated execution. The actual-owner reader must
join every app entry, whole FP/frame/data/stack and publication/cleanup record.
"""
import hashlib
import struct

PAGE, FP, UC, LIVE = 4096, 65536, 1024, 2116
PREFIX, SUFFIX, FRAME = 14528, 217464, 66784
MAGIC = 0x315050414855494c
DATA, STACK = 0x500000000000, 0x500000100000
RSP = STACK + 4096 + 131072 - 504
U64, TF, RF = (1 << 64) - 1, 0x100, 0x10000
MASK = 0xffffffffbffbfae7
BODY = bytes.fromhex('4889d84883c10148c1e0054801c34801d30fb61184d275e8')
NUL = (1, 2, 63, 64, 65, 2, 64, 0, 0)
COPIES = (1, 2, 63, 64, 65, 2, 64, 0, 63)
GREG = (13, 14, 12, 11, 15, 10, 9, 8, 0, 1, 2, 3, 4, 5, 6, 7)
VECTORS = b''.join(struct.pack('<Q', 0x3141592653589793 + i + 1) for i in range(256))
MASKS = struct.pack('<8Q', 0x0123456789abcdef, 0xfedcba9876543210, 0xaaaaaaaa55555555,
                    0x0f0ff0f0a5a55a5a, 0x1111222233334444, 0x8877665544332211,
                    0xffff00000000ffff, 0x5a5a5a5aa5a5a5a5)
LIVE_SEED = VECTORS + MASKS + bytes.fromhex('7f030030')


def need(ok, why):
    if not ok:
        raise ValueError(why)


def q(data, at=0, count=1):
    return struct.unpack_from('<' + 'Q' * count, data, at)


def u(data, at=0, count=1):
    return struct.unpack_from('<' + 'I' * count, data, at)


def elf(data, native_policy, *, current_custody=False):
    need(type(current_custody) is bool, 'explicit typed current-custody ELF profile')
    need(type(data) is bytes and 64 <= len(data) <= 16 << 20, 'complete bounded ELF')
    def take(at, n):
        need(type(at) is int and type(n) is int and 0 <= at <= len(data) and 0 <= n <= len(data) - at, 'ELF range')
        return data[at:at + n]
    h = struct.unpack('<16sHHIQQQIHHHHHH', take(0, 64))
    need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:4] == (2, 62, 1) and h[8:10] == (64, 56) and 0 < h[10] <= 32 and h[11] == 64 and 0 < h[12] <= 256, 'exact ET_EXEC x86-64 header')
    ph = [struct.unpack('<IIQQQQQQ', take(h[5] + i * 56, 56)) for i in range(h[10])]
    loads = [p for p in ph if p[0] == 1]
    need(loads and all(p[5] <= p[6] and p[3] <= U64 - p[6] and p[7] in (4096, 2097152) and p[1] & 3 != 3 for p in loads), 'complete non-WX loads')
    for p in loads:
        take(p[2], p[5])
    def memory(pc, n):
        owners = [p for p in loads if p[3] <= pc and n <= p[5] and pc - p[3] <= p[5] - n]
        need(len(owners) == 1, 'one complete file backed range')
        p = owners[0]
        return p, take(p[2] + pc - p[3], n)
    interp = [p for p in ph if p[0] == 3]
    need(len(interp) == 1, 'actual system interpreter')
    path = take(interp[0][2], interp[0][5])
    need(path.startswith(b'/') and path.endswith(b'\0') and b'\0' not in path[:-1], 'complete interpreter name')
    sections = [struct.unpack('<IIQQQQIIQQ', take(h[6] + i * 64, 64)) for i in range(h[12])]
    tables = [s for s in sections if s[1] == 2]
    need(len(tables) == 1 and tables[0][9] == 24 and tables[0][5] % 24 == 0, 'one complete symtab')
    t = tables[0]
    need(t[6] < len(sections), 'symbol string index')
    strings = sections[t[6]]; names = take(strings[4], strings[5])
    wanted = {'unrolled_app_' + n for n in ('head', 'stop', 'source_end', 'helper', 'helper_end', 'enter', 'capture', 'seed_x87', 'pure', 'pure_end', 'capture_high', 'entry_jump', 'head_pointer', 'return_end')} | {'ua_' + n for n in ('vectors', 'masks', 'host', 'host_fcw', 'input', 'before', 'after', 'before_live', 'after_live')}
    if current_custody:
        wanted |= {'unrolled_current_head', 'unrolled_current_end', 'unrolled_current_return_high'}
    symbols = {}; symbol_sizes = {}
    for at in range(t[4], t[4] + t[5], 24):
        name, _, _, section, value, size = struct.unpack('<IBBHQQ', take(at, 24))
        need(name < len(names) and b'\0' in names[name:], 'whole symbol name')
        name = names[name:names.index(b'\0', name)].decode()
        if name in wanted:
            need(name not in symbols and section != 0, 'unique defined fixture symbol')
            symbols[name] = value; symbol_sizes[name] = size
    need(set(symbols) == wanted, 'all actual fixture symbols')
    head, stop = symbols['unrolled_app_head'], symbols['unrolled_app_stop']
    p, source = memory(head, PAGE)
    need(head % PAGE == 0 and stop == head + 24 and symbols['unrolled_app_source_end'] == head + PAGE and p[1] == 5 and p[2] + head - p[3] >= PAGE, 'complete RX source outside ELF header')
    delta = symbols['unrolled_app_capture'] - (head + 31)
    need(-(1 << 31) <= delta < 1 << 31 and source == BODY + b'\x89\xdb\xe9' + struct.pack('<i', delta) + b'\xcc' * (PAGE - 31), 'whole actual loop/guard/direct continuation/fill')
    for prefix in ('helper', 'pure'):
        address = symbols['unrolled_app_' + prefix]
        need(address != head and address % PAGE == 0 and symbols['unrolled_app_' + prefix + '_end'] == address + PAGE and memory(address, PAGE)[0][1] == 5 and native_policy(memory(address - 14, PAGE + 28)[1]) == 0, 'complete actual native helper plus halos, no policy exemption')
    pure = symbols['unrolled_app_pure']
    pure_load, pure_image = memory(0x200000000, 3 * PAGE)
    need(pure == 0x200001000 and pure_load[1] == 5 and pure_load[3] == 0x200000000 and
         pure_load[5] == pure_load[6] == 3 * PAGE and
         pure_image[:PAGE] == pure_image[2 * PAGE:] == b'\xcc' * PAGE,
         'actual separate high RX helper load with complete unchanged-policy halos')
    helper = symbols['unrolled_app_helper']; capture = symbols['unrolled_app_capture']
    high_capture = symbols['unrolled_app_capture_high']; transfer = symbols['unrolled_app_entry_jump']
    machine_load, machine_image = memory(0x200020000, 3 * PAGE)
    need(helper == 0x200021000 and machine_load[1] == 5 and machine_load[3] == 0x200020000 and
         machine_load[5] == machine_load[6] == 3 * PAGE and
         machine_image[:PAGE] == machine_image[2 * PAGE:] == b'\xcc' * PAGE,
         'actual separate high assembly RX load and complete CC halos')
    need(PAGE <= head < 1 << 31 and PAGE <= capture < 1 << 31 and head != capture and
         capture % PAGE == 0 and symbols['unrolled_app_return_end'] == capture + PAGE and
         memory(capture, PAGE)[0][1] == 5 and memory(capture, PAGE)[1] ==
         b'\xff\x25\0\0\0\0' + struct.pack('<Q', high_capture) + b'\xcc' * (PAGE - 14),
         'complete low return page with transparent original-PC JMP and exact immutable high target')
    entry_pointer = head
    if current_custody:
        entry_pointer = symbols['unrolled_current_head']
        high_return = symbols['unrolled_current_return_high']
        prefix_load, prefix_image = memory(entry_pointer, PAGE)
        need(PAGE <= entry_pointer < 1 << 31 and entry_pointer % PAGE == 0 and
             entry_pointer not in (head, capture) and symbols['unrolled_current_end'] == entry_pointer + PAGE and
             prefix_load[1] == 5 and prefix_image == bytes.fromhex('669066906690ff2500000000') +
             struct.pack('<Q', high_return) + b'\xcc' * (PAGE - 20),
             'whole distinct low current-TF NOP/transparent-transfer page and immutable high target')
        need(helper <= high_return and high_return + 16 <= helper + PAGE and
             memory(high_return, 16)[1] == bytes.fromhex('f390ff2500000000') + struct.pack('<Q', head),
             'exact native-policy-qualified PAUSE/transparent-return stub without a runtime routing exemption')
    ro, constants = memory(0x200010000, PAGE)
    need(ro[1] == 4 and ro[3] == 0x200010000 and ro[5] == ro[6] == PAGE and
         symbols['ua_vectors'] == ro[3] and symbols['ua_masks'] == ro[3] + 2048 and
         symbols['unrolled_app_head_pointer'] == ro[3] + 2112 and
         constants == VECTORS + MASKS + struct.pack('<Q', entry_pointer) + bytes(PAGE - 2120),
         'complete immutable nonexecuting assembly constants and actual low head pointer')
    state_loads = [x for x in loads if x[3] == 0x200030000]
    need(len(state_loads) == 1 and state_loads[0][1] == 6 and state_loads[0][5:7] == (0, 2 * PAGE),
         'separate zero-initialized nonexecuting assembly state load')
    extents = []
    for name, size in (('input', 152), ('before', 152), ('after', 152),
                       ('before_live', LIVE), ('after_live', LIVE), ('host', 64), ('host_fcw', 2)):
        address = symbols['ua_' + name]
        need(symbol_sizes['ua_' + name] == size and 0x200030000 <= address <= 0x200032000 - size and
             all(address + size <= a or a + n <= address for a, n in extents),
             'complete distinct assembly state objects in the exact high RW load')
        extents.append((address, size))
    displacement = symbols['unrolled_app_head_pointer'] - (transfer + 6)
    need(helper <= symbols['unrolled_app_enter'] <= symbols['unrolled_app_seed_x87'] - 4 and
         symbols['unrolled_app_seed_x87'] < transfer and transfer + 6 == high_capture < helper + PAGE and
         memory(symbols['unrolled_app_seed_x87'] - 4, 6)[1] == b'\xdb\xe3\xd9\xe8\xd9\xeb' and
         -(1 << 31) <= displacement < 1 << 31 and
         memory(transfer, 6)[1] == b'\xff\x25' + struct.pack('<i', displacement),
         'exact seed/entry/capture positions and transparent high-to-low immutable-pointer JMP')
    result = dict(symbols=symbols, head=head, stop=stop, source=source, interpreter=path[:-1].decode(), sha256=hashlib.sha256(data).hexdigest(), bytes=len(data), phnum=h[10])
    if current_custody:
        result['current'] = dict(head=entry_pointer, high_return=high_return, source=prefix_image)
    return result


def live(data):
    need(len(data) == 152 and data[148:] == bytes(4), 'complete live state and reserved tail')
    return q(data, 0, 16), q(data, 128)[0], data[136:148]


def state(seed, memory, copies, fault=False, guard=False):
    out = list(seed)
    for i in range(copies + int(fault)):
        out[0] = (out[3] << 5) & U64; out[1] += 1
        out[3] = (out[3] + out[0] + out[2]) & U64
        if fault and i == copies:
            break
        need(DATA <= out[1] < DATA + 8192, 'independent model bounded actual data')
        out[2] = memory[out[1] - DATA]
    if guard:
        out[3] &= 0xffffffff
    return tuple(out)


def reference_frame(data, prefix, layout, kind, steps, copies):
    need(len(data) == FRAME, 'complete native reference frame')
    h = q(data, 0, 12); si = data[96:224]; uc = data[224:1248]; fp = data[1248:]
    sig = 11 if kind in (0, 3) else 5
    need(h[:5] == (1, kind, steps, copies, sig) and h[7] == 968 and 580 <= h[9] <= FP and h[10] % PAGE == 0 and h[11] == 524288, 'native frame header')
    observations = ((h[5], si), (h[6], uc[:968]), (h[8], fp[:h[9]]))
    for a, value in observations:
        need(h[10] <= a <= h[10] + h[11] - len(value), 'actual altstack bounded view')
        for b, other in observations:
            lo, hi = max(a, b), min(a + len(value), b + len(other))
            if lo < hi:
                need(value[lo - a:hi - a] == other[lo - b:hi - b], 'complete aliased physical kernel view')
    need(h[8] % 16 == 0 and q(uc, 224)[0] == h[8] and uc[968:] == bytes(56) and fp[h[9]:] == bytes(FP - h[9]), 'actual FP pointer and full unused capacities')
    need(u(fp, 464, 2) == (0x46505853, h[9]) and u(fp, 480)[0] == h[9] - 4 and u(fp, h[9] - 4)[0] == 0x46505845 and q(fp, 520)[0] == 0, 'complete standard kernel FP geometry')
    need(q(uc, 296)[0] == prefix['machine'][0] and q(uc, 16)[0] == h[10] and u(uc, 24)[0] == 0 and q(uc, 32)[0] == h[11], 'actual application mask and altstack')
    g = q(uc, 40, 23); pc = layout['head'] + (17 if kind == 3 else 24 if kind == 2 else 0)
    need(u(si, 0, 3) == (sig, 0, 2) and g[16] == pc and g[19:21] == ((21, 14) if kind == 0 else (4, 14) if kind == 3 else (0, 1)), 'genuine native signal origin')
    if kind in (0, 3):
        address = DATA + 8192 if kind == 3 else pc
        need(q(si, 16)[0] == address and g[22] == address, 'real source NX/data fault address')
    expected = prefix['seed'][0] if kind == 0 else state(prefix['seed'][0], prefix['data'], copies, kind == 3)
    need(tuple(g[i] for i in GREG) == expected and g[18] == 0x2b000000000033 and g[21] == MASK, 'complete actual native GPR model')
    if kind == 0:
        need(g[17] == prefix['seed'][1] | RF, 'actual NX seed flags')
    else:
        need(g[17] & (TF | RF) == (TF | (RF if kind == 3 else 0)), 'actual reference observer flags')
    need(h[9] <= prefix['header'][15] + 4 and q(fp, 512)[0] & ~prefix['header'][14] == 0 and q(fp, 512)[0] & 0xe7 == 0xe7, 'full bounded standard enabled state')
    for reg in range(32):
        for word in range(8):
            if reg >= 16:
                feature, offset = 7, (reg - 16) * 64 + word * 8
            elif word >= 4:
                feature, offset = 6, reg * 32 + (word - 4) * 8
            elif word >= 2:
                feature, offset = 2, reg * 16 + (word - 2) * 8
            else:
                feature, offset = 0, 160 + reg * 16 + word * 8
            if feature:
                row = prefix['hardware'][3 + feature]
                need(offset + 8 <= row[2], 'whole vector component')
                offset += row[3]
            need(offset + 8 <= h[9] - 4 and q(fp, offset)[0] == 0x3141592653589793 + reg * 8 + word + 1, 'every actual vector word')
    opmask = prefix['hardware'][8]
    need(opmask[2] >= 64 and fp[opmask[3]:opmask[3] + 64] == MASKS, 'every actual opmask byte')
    # The unchanged independent seed probe qualifies these exact zero pointers,
    # including observations before and after FNSTCW/FNSTSW. No byte is ignored.
    need(fp[8:24] == bytes(16) and struct.unpack_from('<HH', fp) == (0x37f, 0x3000) and fp[4] == 0xc0 and u(fp, 24)[0] == 0x1f80, 'independently qualified exact zero FIP/FDP and initial scalar FP')
    return dict(header=h, si=si, uc=uc, fp=fp, greg=g)


def _prefix(data, mode, native, layout, pid, cpu, seed_reference):
    need(type(data) is bytes and len(data) == PREFIX and type(mode) is int and 0 <= mode < 9 and type(native) is bool, 'exact typed application prefix')
    p = data; h = q(p, 0, 32); hardware = [u(p, 256 + i * 24, 6) for i in range(67)]
    seed = live(p[1864:2016]); machine = q(p, 2016, 8); source, stack, memory = p[2080:6176], p[6176:6336], p[6336:]
    need(h[:9] == (MAGIC, 1, PREFIX, SUFFIX, mode, int(native), pid, pid, cpu) and h[10:14] == (layout['head'], layout['stop'], DATA, STACK) and h[16:26] == (NUL[mode], int(mode >= 7), layout['symbols']['unrolled_app_seed_x87'], 968, FRAME, 40, 224, 296, 16, 16) and h[26] == h[28] == 0 and h[30:] == (0, 0), 'exact application prefix/schema/ELF/process and successful permission observations')
    need(type(pid) is int and 0 < pid < 1 << 31 and type(cpu) is int and cpu >= 0 and h[9] <= 0xffffffff, 'actual process and CPU')
    need(source == layout['source'] and machine[0] == MASK and machine[1] > 0 and machine[3:5] == (0x33, 0x2b) and machine[5:] == (0, 0, 0), 'full ELF source and real application machine')
    need([x[:2] for x in hardware] == [(0, 0), (1, 0), (7, 0)] + [(13, i) for i in range(64)] and hardware[0][2] >= 13 and hardware[1][4] & 0x0c000000 == 0x0c000000 and hardware[2][3] & 0x40010000 == 0x40010000, 'actual complete CPUID inputs')
    need(h[14] & 0xe7 == 0xe7 and h[15] == hardware[3][3] and 576 <= h[15] <= FP, 'actual XCR0/standard capacity')
    seed_probe, xstate, profile, facts = seed_reference
    need(seed_probe.require(profile, facts, cpu=cpu) == bytes(16) and
         xstate.profile(hardware, h[14], h[27], h[29], cpu, h[9]) == facts,
         'same reserved CPU and complete actual CPUID/XCR0/permission seed profile')
    for i in range(2, 64):
        if h[14] >> i & 1:
            row = hardware[3 + i]
            need(row[2] > 0 and row[3] >= 576 and row[3] + row[2] <= h[15] and row[4] & 1 == 0, 'actual standard component geometry')
    first = 8128 if mode == 6 else 8192 if mode == 7 else 8129 if mode == 8 else 128
    want = [0x3141592600000000 + i * 0x102030405 for i in range(16)]
    want[1:4] = [DATA + first - 1, 0xfedcba9876543280 if mode == 5 else 0x41, U64 - 3 if mode == 5 else 0x123456789abcdef0]; want[4] = RSP
    need(seed == (tuple(want), 0xad7 if mode == 5 else 0x202, bytes(12)), 'whole fixed seed including reserved selectors')
    want_data = bytearray(1 + (i * 17) % 255 for i in range(8192))
    if NUL[mode]:
        want_data[first + NUL[mode] - 1] = 0
    need(memory == want_data and stack == bytes((i * 29 + 7) & 255 for i in range(160)), 'whole actual initial stack/data')
    result = dict(header=h, hardware=hardware, seed=seed, machine=machine, source=source, stack=stack, data=memory, suffix=None, frames=[])
    return result


def control_prefix(data, control, exit_status, layout, pid, cpu, seed_reference):
    need(type(control) is int and 1 <= control <= 7 and type(exit_status) is int and exit_status == 125, 'fixed required owner control outcome')
    return _prefix(data, 0, False, layout, pid, cpu, seed_reference)


def read(data, mode, native, exit_status, layout, pid, cpu, seed_reference):
    need(type(data) is bytes and type(mode) is int and 0 <= mode < 9 and type(native) is bool and type(exit_status) is int and exit_status == (125 if mode >= 7 else 0), 'typed actual application outcome')
    full = native or mode < 7
    need(len(data) == PREFIX + (SUFFIX if full else 0), 'complete prefix/terminal extent; no failed-operation completion')
    result = _prefix(data[:PREFIX], mode, native, layout, pid, cpu, seed_reference)
    seed, memory, stack, source = (result[k] for k in ('seed', 'data', 'stack', 'source'))
    if not full:
        return result
    s = data[PREFIX:]; end = q(s, 0, 16); before, after = live(s[128:280]), live(s[280:432]); a, b = s[432:2548], s[2548:4664]
    count = 3 if native and mode == 4 else 2 if native else 0
    need(end == (MAGIC ^ 1, 1, mode, int(native), 0, 1, count, COPIES[mode] * 8 + (5 if mode >= 7 else 0) if native else 0, COPIES[mode] if native else 0, int(mode >= 7), 0, 0, 0, 0, 0, 0), 'complete terminal or native failure observation')
    selectors = struct.pack('<6H', 0x33, 0x2b, 0, 0, 0, 0)
    need(before == (seed[0], seed[1], selectors) and after[2] == selectors and after[1] & (TF | RF) == 0 and a == b == LIVE_SEED, 'whole common live GPR/flags/selectors/vector state')
    need(after[0] == state(seed[0], memory, COPIES[mode], mode >= 7, mode < 7), 'complete independent postguard/fault GPR model')
    need(s[4664:8760] == source and s[8760:8920] == stack and s[8920:17112] == memory, 'whole actual after source/stack/data')
    kinds = [0, 1, 2] if mode == 4 else [0, 3 if mode >= 7 else 2]
    for i in range(3):
        value = s[17112 + i * FRAME:17112 + (i + 1) * FRAME]
        if i >= count:
            need(value == bytes(FRAME), 'complete unused native frame capacity')
        else:
            kind = kinds[i]; n = 0 if kind == 0 else 64 if kind == 1 else COPIES[mode]
            result['frames'].append(reference_frame(value, result, layout, kind, n * 8 + (5 if kind == 3 else 0), n))
    if native:
        need(all(f['fp'] == result['frames'][0]['fp'] for f in result['frames']), 'whole65536 native saved FP conservation')
        final = result['frames'][-1]['greg']
        need(after[1] == final[17] & ~(TF | RF), 'all application status flags including actual AF')
    result['suffix'] = dict(before=before, after=after, live=a, end=end)
    return result


def pair(native, gated, owner):
    """Called only after both app readers and B0's actual owner reader pass.

    Every RF/TF/ERR/TRAP/CR2 difference below is the exact hardware event origin;
    the remaining full register words and all AF/status bits must match.
    """
    nh, gh = native['header'], gated['header']; mode = nh[4]
    need(nh[5] == 1 and gh[5] == 0 and gh[4] == mode and owner['control'] == 0, 'real ordinary original/generated pair')
    need(nh[8:19] == gh[8:19] and native['hardware'] == gated['hardware'] and all(native[k] == gated[k] for k in ('seed', 'source', 'stack', 'data')), 'same actual source/hardware/full input')
    need(native['machine'][0] == gated['machine'][0] == MASK and native['machine'][3:] == gated['machine'][3:], 'whole application mask/selectors')
    entries = owner['entries']
    need(len(entries) == (2 if mode == 4 else 1) and len(native['frames']) == len(entries) + 1, 'all actual application chunks and original endpoints')
    def compare(actual, reference, fault=False):
        need(type(actual['greg']) is tuple and len(actual['greg']) == 23 and type(actual['fp']) is bytes and len(actual['fp']) == FP and actual['fp_bytes'] == reference['header'][9] and actual['mask'] == MASK, 'complete typed saved frame')
        want = list(reference['greg'])
        if fault:
            want[16] = actual['greg'][16];want[17] &= ~TF
        else:
            want[17] = (want[17] & ~TF) | RF
            want[19], want[20], want[22] = 21, 14, want[16]
        need(actual['greg'] == tuple(want) and actual['fp'] == reference['fp'], 'whole actual GPR/flags/AF/FP original-to-generated comparison')
        need((actual['fs'], actual['gs']) == gated['machine'][1:3], 'actual owner TLS matches unchanged application TLS')
    for i, entry in enumerate(entries):
        need(entry['source_page'] == entry['terminal_source_page'] == native['source'], 'whole original source before/after generated ownership')
        for memory in (entry['before_memory'], entry['after_memory']):
            need(memory['data'] == native['data'] and memory['stack'] == native['stack'], 'actual complete data and stack observations including failed operation')
        compare(entry['before'], native['frames'][i])
        fault = mode >= 7
        end = entry['unexpected'] if fault else entry['after']
        need((entry['after'] is None) == fault and (entry['unexpected'] is not None) == fault, 'required failure has no invented successful after frame')
        if fault:
            mapped = entry['mapped']
            need(mapped == dict(version=1, ready=1, copy_index=COPIES[mode], source_offset=17, source_length=3, generated_length=3, original_pc=nh[10] + 17, generated_pc=entry['entry'] + COPIES[mode] * 28 + 17, kind=1, reserved=0) and end['greg'][16] == mapped['generated_pc'], 'exact actual generated MOVZX fault association')
        compare(end, native['frames'][i + 1], fault)
    if mode < 7:
        need(native['suffix']['before'] == gated['suffix']['before'] and native['suffix']['after'] == gated['suffix']['after'] and native['suffix']['live'] == gated['suffix']['live'], 'whole actual common postguard state including undefined AF')
        last = entries[-1]['after']['greg']
        want = tuple(last[r] & (0xffffffff if r == 11 else U64) for r in GREG)
        need(gated['suffix']['after'][0] == want and gated['suffix']['after'][1] == last[17] & ~RF, 'actual89db zero-extension and complete flags join')
    else:
        need(gated['suffix'] is None, 'failed generated operation cannot have application completion')
    return dict(qualified_case=1, completed_application=int(mode < 7), required_read_failure=int(mode >= 7), application_entries=len(entries), application_head_exits=int(mode == 4), application_stop_exits=int(mode < 7), application_iterations=NUL[mode] if mode < 7 else COPIES[mode], native_reference_steps=COPIES[mode] * 8 + (5 if mode >= 7 else 0), generated_fault_copy=COPIES[mode] if mode >= 7 else -1)


def controls(check_pair, native_output, gated_output, mode):
    """Supplied refusals after the actual pair passed; callback re-reads raws.

    The callback must repeat both application readers, the unchanged actual
    owner reader and pair(), with the original owner record and identities.
    No positive input is constructed, and only ValueError counts as refusal.
    """
    need(type(mode) is int and 0 <= mode < 9, 'fixed application control mode')
    def flip(data, offset, value=1):
        changed = bytearray(data);changed[offset] ^= value;return bytes(changed)
    native_mutations = [('version', 8), ('mode', 32), ('pid', 48), ('source_tail', 6175),
        ('input_stack_tail', 6335), ('input_data_tail', PREFIX - 1), ('seed_RDX', 1864 + 16),
        ('hardware', 256), ('mask', 2016), ('cleanup', PREFIX + 40),
        ('after_GPR', PREFIX + 280), ('after_AF', PREFIX + 408),
        ('selector', PREFIX + 416), ('before_live', PREFIX + 432),
        ('after_live', PREFIX + 4663), ('after_stack', PREFIX + 8919),
        ('after_data', PREFIX + 17111), ('frame_UC_tail', PREFIX + 17112 + 1247),
        ('frame_FP_tail', PREFIX + 17112 + FRAME - 1), ('frame_FIP', PREFIX + 17112 + 1248 + 8)]
    trials = [(name, flip(native_output, at, 0x10 if name == 'after_AF' else 1), gated_output) for name, at in native_mutations]
    trials += [('native_truncated', native_output[:-1], gated_output),
               ('gated_truncated', native_output, gated_output[:-1]),
               ('gated_appended', native_output, gated_output + b'\0'),
               ('gated_data', native_output, flip(gated_output, PREFIX - 1))]
    # Conserve every native recorded FP snapshot coherently: the independent
    # actual gated owner FP must still reject this changed hardware reference.
    changed = bytearray(native_output)
    for i in range(3 if mode == 4 else 2):
        changed[PREFIX + 17112 + i * FRAME + 1248 + 48] ^= 1
    trials.append(('coherent_native_FP', bytes(changed), gated_output))
    if mode < 7:
        trials.append(('gated_actual_AF', native_output, flip(gated_output, PREFIX + 408, 0x10)))
    else:
        final_frame = PREFIX + 17112 + FRAME
        trials.append(('actual_fault_CR2', flip(native_output, final_frame + 224 + 40 + 22 * 8), gated_output))
    need(len(trials) == 26 and len({name for name, _, _ in trials}) == 26, 'all fixed unique application supplied refusals')
    for name, n, g in trials:
        rejected = False
        try:
            check_pair(n, g)
        except ValueError:
            rejected = True
        need(rejected, 'application reader accepted ' + name)
    return dict(supplied_refusals=26, native_operations=0)
