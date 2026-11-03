"""Actual far-AUX native bytes and complete frames; separate from owner admission."""
import hashlib
import struct
from types import SimpleNamespace

PAGE, FRAME, RECORD, TRACE = 4096, 67072, 293184, 328
MAGIC, REC_MAGIC, END = 0x31414C4632494C, 0x31524C4632494C, 0x31454C4632494C
TF, RF, MASK = 0x100, 0x10000, (1 << 64)-1
REG = (13, 14, 12, 11, 15, 10, 9, 8, 0, 1, 2, 3, 4, 5, 6, 7)


def need(ok, message):
    if not ok:
        raise ValueError(message)


def q(raw, n, at=0):
    return struct.unpack_from('<'+'Q'*n, raw, at)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def configured(common):
    need(callable(common.frame) and common.FRAME == FRAME and common.FP == 65536,
         'original complete direct-call native signal-frame validator')

    def read(stdout, stderr):
        need(type(stdout) is bytes and stderr == b'' and len(stdout) == 512+18*RECORD+64,
             'one complete eighteen-lane native observation under original sixteen-MiB limit')
        h = q(stdout, 64)
        need(h[:13] == (MAGIC, 1, 512, RECORD, FRAME, 968, 128, 65536, 16384, PAGE, 6, 3, 18) and
             h[13:15] == (0, 0) and h[15] > 0 and h[17] in (0, MASK-21, MASK-37) and h[18] == 0 and
             h[19] & 3 == 3 and 512 <= h[20] <= 65536, 'exact native ABI, populations and CET/xstate facts')
        need(h[21] == 0x700000000000 and h[23] == h[21]+0x2000 and h[25] == 262144 and
             h[26:36] == (0x10000000, 0x10010000, 0x12000000, 0x13000000,
                          0x11000000, 0x11008000, 2368, TRACE, 64, 152) and
             h[22] > 0 and h[22] % PAGE == 0 and h[24] > 0 and h[24] % PAGE == 0 and
             not any(h[36:48]) and not any(h[57:]), 'exact high-source/low-AUX extents and zero reserved header')
        model = h[48:57]
        need(model[0] == 4096 and 4096 < model[1] < 1 << 64 and model[2] == 2*model[1] < 1 << 64 and
             model[3:] == (16, 16, 2368, 128, 7600, 4), 'separate full model/byte mutation/literal refusal populations')
        pc, target, code, spill = h[21]+0xffa, h[23]+512, h[26], h[27]
        encoded = b'\xe9'+struct.pack('<i', target-(pc+5))
        source = b'\xcc'*0xffa+encoded+b'\xcc'
        owner = struct.pack('<3Q2IQ', h[28], h[30], h[31], 1, 0, h[29])
        binding = owner+struct.pack('<2Q2I', code, spill, 0, 0)
        outcomes = []; visited = 0; trace_total = 0; full_frames = []
        for identity in range(6):
            mode, flags = identity % 3, 0x202 if identity < 3 else 0xed7
            seed = tuple(h[22]+2*PAGE+512 if i == 4 else
                         0x13579bdf00110000+0x100010001*i+identity for i in range(16))
            lanes = []
            for which in range(3):
                raw = stdout[512+(3*identity+which)*RECORD:512+(3*identity+which+1)*RECORD]
                v = q(raw, 64)
                need(v[:12] == (REC_MAGIC, RECORD, identity, which, mode, pc, target, code,
                               h[31]+512, flags, seed[4], 0 if mode == 2 else 2) and
                     v[12] == v[13] > 0 and v[14] == 0 and v[15] == 2 and v[18] == 1 and
                     v[19:21] == (0, 0) and not any(v[22:]), 'exact lane/caller identities; no decoder call during execution/recovery')
                before_raw, after_raw = raw[512:512+FRAME], raw[512+FRAME:512+2*FRAME]
                before = common.frame(before_raw, h, 0); after = common.frame(after_raw, h, 1)
                bh, bg, bf = before; ah, ag, af = after
                first = code if which else pc
                need(bh[:4] == (11, 2, 0, first) and bg[16] == first and
                     bg[20] == 14 and bg[19] & 16 == 16 and bg[22] == first and
                     tuple(bg[i] for i in REG) == seed and bg[17] & ~RF == flags,
                     'actual initial NX and whole sixteen-GPR seed before original or generated execution')
                need(tuple(ag[i] for i in REG) == seed and ag[17] & ~(TF | RF) == flags and
                     af == bf and ah[8:10] == bh[8:10], 'all native integer/flag/65536-FP/TLS values preserved')
                need(all(bg[i] == ag[i] for i in (18, 21)) and before_raw[312:320] == after_raw[312:320],
                     'remaining architectural segment/mask GREG and complete kernel mask preserved')
                plan_at = 512+2*FRAME; plan = raw[plan_at:plan_at+2368]
                need(struct.unpack_from('<4I', plan) == (2, 1, 0, 0) and plan[16:80] == binding,
                     'distinct actual far AUX version and exact immutable owner binding')
                pr = struct.unpack_from('<12I', plan, 80)
                need(pr == (2, 1, 0, 215, 37, 209, 153, 0, 0, 1, 2, 3), 'exact shared far recovery geometry')
                boundaries = [struct.unpack_from('<6I', plan, 128+24*i) for i in range(37)]
                need(len({b[0] for b in boundaries}) == 37 and boundaries[0][0] == 0 and
                     all(0 < b[1] <= 15 and b[0]+b[1] <= 215 and b[2] <= 15 and
                         b[3] & ~b[2] == 0 and b[4] <= 2 and b[5] <= 1 for b in boundaries) and
                     not any(plan[128+24*37:1664]), 'complete unique initialized recovery rows and canonical unused capacity')
                decoded = struct.pack('<QQ10I', pc, pc+5, 1, 0, 696, 0, 16, 0, 0, 5, 5, 0)+encoded+bytes(11)
                descriptor = decoded+struct.pack('<2Q8I', target, 0, 1, 1, 0, 5, 2, 16, 1, 0)
                need(plan[1664:1784] == descriptor and q(plan, 2, 1784) == (code, spill) and
                     plan[1800:1840] == owner and not any(plan[1840:1856]), 'original literal source and actual final-address placement')
                image = plan[1856:2368]
                need(image[153:167] == b'\xff\x25\0\0\0\0'+struct.pack('<Q', pc) and
                     not any(image[215:]) and all(not (159 <= b[0] < 167) for b in boundaries),
                     'complete immutable far miss literal is data and never a recovery boundary')
                trace_at = plan_at+2368; memory = trace_at+64*TRACE
                original = raw[memory:memory+PAGE]; generated = raw[memory+PAGE:memory+2*PAGE]
                rows = raw[memory+2*PAGE:memory+3*PAGE]; directory = raw[memory+3*PAGE:memory+6*PAGE]
                need(original == source and generated == image+bytes(PAGE-512) and not any(rows),
                     'whole actual source/auxiliary page/owner rows')
                expected_dir = struct.pack('<4Q', 1, 0 if mode == 2 else 2, 73, 0)
                if mode != 2:
                    expected_dir += struct.pack('<3Q2I', target+1, h[30]+512, 90, 0, 1)
                    expected_dir += struct.pack('<3Q2I', target+(2 if mode == 1 else 0), h[31]+512, 91, 1, 1)
                need(directory == expected_dir+bytes(3*PAGE-len(expected_dir)), 'whole actual sealed directory and all unused rows')
                at = memory+6*PAGE
                sb, sa = raw[at:at+4*PAGE], raw[at+4*PAGE:at+8*PAGE]; at += 8*PAGE
                spb, spa = raw[at:at+PAGE], raw[at+PAGE:at+2*PAGE]; at += 2*PAGE
                need(sb == sa == bytes((0x5a+37*i+identity) & 255 for i in range(4*PAGE)) and
                     spb == bytes((0xa7+19*i+identity) & 255 for i in range(PAGE)), 'whole actual native stack and initial private spill bytes')
                if which:
                    expected_spill = struct.pack('<4Q', *seed[:4])
                    expected_spill += spb[32:40] if mode else struct.pack('<Q', h[31]+512)
                    need(spa == expected_spill+spb[40:], 'only four initialized spills and the hit-only target cell changed')
                else:
                    need(spa == spb, 'ordinary E9 leaves the entire auxiliary spill page unchanged')
                need(raw[at:at+16*PAGE] == b'\xcc'*(16*PAGE) and
                     raw[at+16*PAGE:] == b'\xcc'*PAGE, 'whole owner images and original target remain intact')
                if which == 2:
                    need(2 <= v[17] <= 64 and v[16] == v[17], 'one initial NX plus every actual TRACE observation')
                    seen = 0
                    for i in range(v[17]):
                        tr = raw[trace_at+i*TRACE:trace_at+(i+1)*TRACE]
                        t = q(tr, 22); recovery = q(tr, 18, 176)
                        matches = [j for j, b in enumerate(boundaries) if code+b[0] == t[0]]
                        need(len(matches) == 1 and recovery[:16] == seed and
                             recovery[16] == flags+(RF if i == 0 else TF) and recovery[17] == pc and
                             struct.unpack_from('<2I', tr, 320) == (0, 1), 'actual stopped boundary returns original complete state through typed recovery')
                        need(t[1] & (TF | RF) == (RF if i == 0 else TF), 'actual NX/TRACE flags retained through recovery')
                        seen |= 1 << matches[0]
                    need(not any(raw[trace_at+v[17]*TRACE:memory]) and seen == v[21], 'complete actual trace roster and zero unused trace capacity')
                    final = code+(153 if mode else 209)
                    need(ah[:4] == (5, 2, 0, final) and ag[16] == final and ag[20] == 1 and
                         ag[19] == 0 and ag[22] == code and ag[17] == flags+TF,
                         'actual final pre-transfer TRACE; no fabricated saved PC or execution of literal bytes')
                    visited |= seen; trace_total += v[17]
                else:
                    final = pc if mode else h[31]+512 if which else target
                    need(v[16] == 2 and v[17] == v[21] == 0 and not any(raw[trace_at:memory]) and
                         ah[:4] == (11, 2, 0, final) and ag[16] == final and ag[20] == 14 and
                         ag[19] & 16 == 16 and ag[22] == final and ag[17] & ~RF == flags,
                         'actual original/generated hit or miss NX with exact physical destination')
                full_frames += [digest(before_raw), digest(after_raw)]
                lanes.append((before, after, raw))
            # Both independent native lanes have the exact same guest state;
            # only the explicitly translated hit PC and its fault CR2 differ.
            left, right = lanes[0][1], lanes[1][1]
            need(all(left[1][i] == right[1][i] for i in range(23) if i not in (16, 22)) and
                 left[2] == right[2] and left[0][8:10] == right[0][8:10],
                 'whole twenty-three-GREG native pair with only exact hit address translation, plus all FP/TLS')
            outcomes.append(dict(id=identity, mode=('hit', 'row_miss', 'empty_miss')[mode], flags=flags))
        need(visited == (1 << 37)-1 and q(stdout[-64:], 8) ==
             (END, 1, 18, len(stdout), visited, 0, 0, 0), 'every actual recovery boundary and complete final output footer')
        return dict(profile='far-aux-model-native-v1', native_pairs=6, native_lanes=18,
            generated_lanes=12, actual_trace_boundaries=trace_total, unique_recovery_boundaries=37,
            full_frames=36, model_cases=model[0], model_steps=model[1], model_recoveries=model[2],
            far_adapters=model[3], near_equivalences=model[4], whole_byte_mutations=model[5],
            literal_refusals=model[6], nonboundary_refusals=model[7], typed_refusals=model[8],
            pid=h[15], cpu=h[16], pairs=outcomes, full_frames_sha256=digest(''.join(full_frames).encode()),
            raw_sha256=digest(stdout), owner_credit=False, qualification_credit=False, performance_credit=False)

    return SimpleNamespace(read=read)
