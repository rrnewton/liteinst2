"""Complete saved native state18 reader; no execution or normalized state bytes.

The caller supplies the unchanged app checker/native-policy function and original
b2_reference xstate/boundary modules. Parent input/capture custody is separate.
"""
import hashlib
import os
import struct

MAGIC = 0x3146455250504150
SIZE, POINT, ROW = 3938248, 107120, 214648
PAGE, STACK, FP = 4096, 16384, 65536
REGS = ('r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8',
        'rax','rcx','rdx','rsi','rdi','orig_rax','rip','cs','eflags','rsp',
        'ss','fs_base','gs_base','ds','es','fs','gs')
GPRS = ('rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi',
        'r8','r9','r10','r11','r12','r13','r14','r15')


def need(ok, why):
    if not ok:
        raise ValueError(why)


def words(b):
    need(type(b) is bytes and len(b) % 8 == 0, 'whole actual native words')
    return struct.unpack('<'+'Q'*(len(b)//8), b)


def registers(b):
    need(len(b) == 216, 'complete actual GETREGS')
    return dict(zip(REGS, words(b)))


def _main(data):
    """One extra defined main symbol after app.elf validates the same ELF."""
    h = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, h[6]+64*i) for i in range(h[12])]
    tables = [s for s in sections if s[1] == 2]
    need(len(tables) == 1, 'one full emitted main symbol table')
    t = tables[0]; st = sections[t[6]]; names = data[st[4]:st[4]+st[5]]; result = []
    for at in range(t[4], t[4]+t[5], 24):
        n, _, _, section, value, _ = struct.unpack_from('<IBBHQQ', data, at)
        name = names[n:names.index(0, n)]
        if name == b'main':
            need(section != 0, 'actual defined main symbol'); result.append(value)
    need(len(result) == 1, 'unique main symbol')
    return result[0]


def _maps(raw):
    need(raw.endswith(b'\n') and b'\0' not in raw, 'complete actual maps text')
    rows = []
    for line in raw.splitlines():
        p = line.split(None, 5)
        need(len(p) >= 5, 'complete maps row')
        lo, hi = (int(x, 16) for x in p[0].split(b'-'))
        major, minor = (int(x, 16) for x in p[3].split(b':'))
        need(0 <= lo < hi < 1 << 64 and len(rows) < 512 and (not rows or rows[-1][1] <= lo) and
             len(p[1]) == 4 and p[1][3:] in (b'p', b's'), 'ordered actual mapping ranges')
        rows.append((lo, hi, p[1], int(p[2], 16), major, minor, int(p[4])))
    return rows


def _nt(fp, facts, live, qualified_pointers):
    need(len(fp) == facts['extent'] and words(fp[464:472]) == (facts['mask'],) and
         not any(fp[472:512]) and not any(fp[520:576]),
         'complete actual NT standard layout, OS mask and reserved bytes')
    active = words(fp[512:520])[0]
    need(active & 0xe7 == 0xe7 and not active & ~facts['mask'], 'all seeded active components')
    components = {bit: (a, b) for a, b, bit in facts['components']}
    need({2, 5, 6, 7} <= components.keys(), 'all independently qualified component ranges')
    for r in range(32):
        if r < 16:
            a = components[2][0]+16*r; b = components[6][0]+32*r
            payload = fp[160+16*r:176+16*r]+fp[a:a+16]+fp[b:b+32]
        else:
            a = components[7][0]+64*(r-16); payload = fp[a:a+64]
        need(payload == live[64*r:64*(r+1)], 'every native NT/live ZMM byte')
    a, b = components[5]
    need(fp[a:b] == live[2048:2112] and fp[:4] == live[2112:] and
         fp[8:24] == qualified_pointers, 'all native K/x87 controls and independently qualified exact FIP/FDP')


def read(data, stdout, stderr, elf_bytes, app, native_policy, xstate, *, tracer_pid, pid, cpu,
         seed_raw, seed_elf, seed_pid, seed_probe):
    need(type(data) is bytes and len(data) == SIZE and type(stdout) is bytes and
         type(stderr) is bytes and len(elf_bytes) == 2 and type(pid) is int and pid > 0 and
         type(tracer_pid) is int and tracer_pid > 0 and tracer_pid != pid and
         type(cpu) is int and cpu >= 0, 'exact full native record and explicit child identity')
    h = words(data[:256])
    # Header: magic/version/size/parent/child/completed/error/errno/start/duration,
    # final wait/reaped/pidfd-ready/ECHILD/spawn/exit/waits/startCPU/endCPU,
    # stdout/stderr/maps/exec/main-stop/files-stable/original-mask/restored-mask,
    # cleanup-kill/cleanup-failed/reserved/mainDR6/mainDR7.
    need(h[:3] == (MAGIC, 1, SIZE) and h[3] == tracer_pid and h[4:8] == (pid, 18, 0, 0) and
         h[8] > 0 and 0 < h[9] < 15_000_000_000 and h[10:17] == (0, 1, 1, 1, 1, 1, 58) and
         h[17:21] == (cpu, cpu, len(stdout), 0) and not stderr and 0 < h[21] < 65536 and
         h[22:25] == ((4 << 16) | (5 << 8) | 0x7f, (5 << 8) | 0x7f, 1) and
         h[26:30] == (1, 0, 0, 0) and h[30] & 15 == 1 and h[31] == 1,
         'all eighteen complete effects, exact bounded stops, real zero exit/reap, stable inputs and clean owner')
    images = [app.elf(b, m, native_policy) for m, b in enumerate(elf_bytes)]
    application = app.output(stdout, images, pid=pid, cpu=cpu, mode='state', policy='native', xstate=xstate)
    seed_profile = seed_probe.read(seed_raw, seed_elf, application['format'], xstate, cpu=cpu, pid=seed_pid)
    qualified_pointers = seed_probe.require(seed_profile, application['format'], cpu=cpu)
    need(type(qualified_pointers) is bytes and qualified_pointers == bytes(16), 'exact independently qualified zero seed pointers')
    need(h[25] == application['machine'][0], 'original application mask preserved through real exec')
    image_words = []; at = 256
    for module, image in enumerate(images):
        w = words(data[at:at+128]); source = data[at+128:at+4224]; at += 4224
        base = application['header'][12+module]
        need(w[0] > 0 and w[1] > 0 and w[2] == len(elf_bytes[module]) and w[3:13] ==
             (base, base+image['page'], image['page_offset'], base+image['pre_endpoint'],
              base+image['endpoint'], base+image['stack']-(STACK-256), base+image['x87_pc'],
              *(base+s['pc'] for s in image['sites'])) and
             w[13] == (0 if module else base+_main(elf_bytes[0])) and
             w[14] == application['header'][14+module] and w[15] == 0 and source == image['source'],
             'complete held-ELF symbols, bytes, independently observed ASLR bias and private stack')
        image_words.append(w)
    maps_raw = data[at:at+h[21]]
    need(not any(data[at+h[21]:at+65536]), 'unused maps capacity stays zero'); at += 65536
    maps = _maps(maps_raw)
    for w in image_words:
        identity = (os.major(w[0]), os.minor(w[0]), w[1])
        need([r[0] for r in maps if r[3] == 0 and r[4:] == identity] == [w[3]], 'unique actual file mapping identity')
        code = [r for r in maps if r[0] <= w[4] and w[4]+PAGE <= r[1] and
                r[2] == b'r-xp' and r[4:] == identity and r[3]+w[4]-r[0] == w[5]]
        need(len(code) == 1, 'full original RX page maps exact opened ELF offset')
        cursor = w[8]
        for lo, hi, perm, *_ in maps:
            if lo <= cursor < hi and perm == b'rw-p': cursor = min(hi, w[8]+STACK)
        need(cursor == w[8]+STACK, 'whole actual private RW/NX stack extent')
    main_regs = registers(data[at:at+216]); main_si = data[at+216:at+344]; at += 344
    need(main_regs['rip'] == image_words[0][13] and struct.unpack_from('<3i', main_si) == (5, 0, 4),
         'genuine main hardware stop after the real dynamic loader')
    rows = []
    for index, sample in enumerate(application['rows']):
        raw = data[at:at+ROW]; at += ROW; rh = words(raw[:64]); module = (index % 6)//3; kind = index % 3
        need(rh[:5] == (index, module, kind, index//6, 1) and rh[5] & 15 == 1 and rh[6:] == (1, 0),
             'exact six-site order three times and exclusive hardware helper stop')
        helper = registers(raw[64:280]); helper_si = raw[280:408]
        need(helper['rip'] == image_words[module][6] and struct.unpack_from('<3i', helper_si) == (5, 0, 4),
             'real capture_before stop, never a fabricated selected-fault frame')
        points = []
        for phase in range(2):
            p = raw[408+POINT*phase:408+POINT*(phase+1)]; ph = words(p[:64])
            trap = registers(p[64:280]); state = registers(p[280:496]); si = p[496:624]
            site = sample['site']+2*phase; page = image_words[module][4]; shift = 8*(site & 7)
            off = (site-page) & ~7; word = int.from_bytes(images[module]['source'][off:off+8], 'little')
            patched = (word & ~(255 << shift)) | (0xcc << shift)
            need(ph == (1, application['format']['extent'], application['machine'][0], site,
                        word, patched, word, (5 << 8) | 0x7f),
                 'exact original/INT3/readback/restored words and complete stopped snapshot')
            need(struct.unpack_from('<3i', si) in ((5, 0, 1), (5, 0, 128)), 'actual software breakpoint trap')
            expected_trap = dict(state, rip=site+1)
            need(trap == expected_trap, 'RIP-only original-byte breakpoint rewind; all other raw registers exact')
            g = sample['after' if phase else 'before']; machine = application['machine']
            expected = dict(zip(GPRS, g[:16]))
            expected.update(orig_rax=(1 << 64)-1, rip=site, eflags=g[16], cs=machine[3], ss=machine[4],
                            fs_base=machine[1], gs_base=machine[2], ds=machine[5] & 65535,
                            es=machine[5] >> 16, fs=machine[6] & 65535, gs=machine[6] >> 16)
            need(state == expected, 'all 27 actual registers, exact logical flags/PC, actual PID/clock and selectors')
            fp = p[624:624+ph[1]]
            need(not any(p[624+ph[1]:624+FP]), 'unused NT storage zero')
            _nt(fp, application['format'], sample['before_live'], qualified_pointers)
            source = p[624+FP:624+FP+2*PAGE]; stack = p[624+FP+2*PAGE:]
            need(source == images[0]['source']+images[1]['source'] and stack == b'\x5a'*(2*STACK),
                 'both whole pages original and both full private stacks unchanged at every observation')
            points.append(dict(registers=state, trap_registers=trap, siginfo=si, xstate=fp,
                               mask=ph[2], source=source, stack=stack, raw=p))
        need(points[0]['xstate'] == points[1]['xstate'], 'entire actual native NT_X86_XSTATE unchanged across effect')
        rows.append(dict(index=index, module=module, kind=kind, before=points[0], after=points[1]))
    need(at == len(data) and len(rows) == 18, 'no unparsed record fields or trailing bytes')
    return dict(application=application, images=images, rows=rows, maps=maps_raw, pid=pid, cpu=cpu, seed_profile=seed_profile,
                raw_sha256=hashlib.sha256(data).hexdigest(), native_complete=True,
                native_xstate_joined=False, full_state_qualified=False, publication_qualified=False)


def pair(reference, gated_application, frames, layout, app, xstate, boundary, *, seed_probe):
    """Frames come from the independently authenticated gate observer reader.

    This deliberately retains exact xstate.pair/fp_payload, including FIP/FDP.
    The independently qualified seed profile requires exact zero FIP/FDP.
    No signal envelope or architectural byte is fabricated or rewritten. Publication custody is
    still the enclosing gate reader's obligation.
    """
    app.native_pair(reference['application'], gated_application)
    need(type(frames) is list and len(frames) == len(reference['rows']) == 18,
         'complete independent native/gated state population')
    facts = reference['application']['format']
    for native, sample, frame in zip(reference['rows'], gated_application['rows'], frames):
        need(set(frame) == {'index','before','after','landing_pc'} and
             native['index'] == sample['index'] == frame['index'], 'exact actual operation join')
        app.frame_join(sample, frame['before'], frame['after'], layout, facts,
                       machine=gated_application['machine'], landing_pc=frame['landing_pc'],
                       seed_profile=reference['seed_profile'], seed_probe=seed_probe)
        for phase in ('before', 'after'):
            xstate.pair(native[phase]['xstate'], frame[phase]['fp'], facts, boundary)
    return dict(native_xstate_joined=True, native_operations=18, complete_signal_frames=36,
                architectural_bytes_excluded=0, full_state_qualified=False, publication_qualified=False)
