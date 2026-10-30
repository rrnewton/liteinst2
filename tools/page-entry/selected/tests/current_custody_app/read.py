"""Actual current-prefix stdout extension; all old application checks retained.

No ownership/custody credit comes from application-writable stdout. The separate
protected reader must bind the real prefix events and typed API chronology.
"""
import importlib.util
from pathlib import Path
import struct

_path = Path(__file__).resolve().parents[1] / 'unrolled_hash_app/read.py'
_spec = importlib.util.spec_from_file_location('current_tf_original_app', _path)
legacy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(legacy)
need, q, u = legacy.need, legacy.q, legacy.u
PAGE, FP, MASK, TF, RF, GREG = legacy.PAGE, legacy.FP, legacy.MASK, legacy.TF, legacy.RF, legacy.GREG
PREFIX, SUFFIX, FRAME = legacy.PREFIX, legacy.SUFFIX, legacy.FRAME
SIZE, SAMPLE, MAGIC = 304896, 75152, 0x315446435541494c


def elf(data, native_policy):
    return legacy.elf(data, native_policy, current_custody=True)


def extension(data, app, layout, native, mode, fallback):
    need(type(data) is bytes and len(data) == SIZE and type(fallback) is bool,
         'complete typed current-prefix application extension')
    h = q(data, 0, 24); current = layout['current']
    need(h[:8] == (MAGIC, 1, SIZE, int(native), mode, current['head'], layout['head'], SAMPLE) and
         h[8:10] == ((4, 1) if native else (0, 0)) and h[13:16] == (int(fallback), 1, current['high_return']) and
         h[16:] == (0,) * 8, 'exact current-prefix profile, count, cleanup and reserved fields')
    if fallback:
        need(PAGE <= h[10] <= (1 << 47) - PAGE and h[10] % PAGE == 0 and h[11:13] == (1, 0),
             'actual successful same-RW initial-stack protection request')
    else:
        need(h[10:13] == (0, 0, 0), 'no invented fallback syscall observation')
    need(data[192:4288] == current['source'], 'complete immutable ELF-bound prefix page')
    frames = []
    if not native:
        need(data[4288:] == bytes(4 * SAMPLE), 'gated application cannot manufacture native frames')
    else:
        need(len(app['frames']) in (2, 3), 'actual unchanged hash reference precedes prefix qualification')
        reference = app['frames'][0]
        for index in range(4):
            value = data[4288 + index * SAMPLE:4288 + (index + 1) * SAMPLE]
            fh = q(value, 0, 12); si = value[96:224]; uc = value[224:1248]; fp = value[1248:FRAME]
            tls = q(value, FRAME, 2); stack = value[FRAME + 16:FRAME + 176]; memory = value[FRAME + 176:]
            sig = 11 if index == 0 else 5; pc = current['head'] + 2 * index
            need(fh[:5] == (1, index, index, 0, sig) and fh[7] == 968 and
                 fh[9] == reference['header'][9] and fh[10:12] == reference['header'][10:12],
                 'actual same-altstack native prefix signal extent and ordered boundary')
            observations = ((fh[5], si), (fh[6], uc[:968]), (fh[8], fp[:fh[9]]))
            for address, raw in observations:
                need(fh[10] <= address <= fh[10] + fh[11] - len(raw), 'actual native prefix altstack bounds')
                for other_address, other in observations:
                    lo, hi = max(address, other_address), min(address + len(raw), other_address + len(other))
                    if lo < hi:
                        need(raw[lo - address:hi - address] == other[lo - other_address:hi - other_address],
                             'complete physically aliased native prefix kernel views')
            need(fh[8] % 16 == 0 and q(uc, 224)[0] == fh[8] and uc[968:] == bytes(56) and
                 q(uc, 16)[0] == fh[10] and u(uc, 24)[0] == 0 and q(uc, 32)[0] == fh[11] and
                 q(uc, 296)[0] == MASK, 'actual native prefix FP pointer, altstack, mask and complete unused UC capacity')
            g = q(uc, 40, 23)
            need(tuple(g[r] for r in GREG) == app['seed'][0] and g[16] == pc and
                 g[17] == app['seed'][1] | (RF if index == 0 else TF) and
                 g[18] == 0x2b000000000033 and g[19:21] == ((21, 14) if index == 0 else (0, 1)) and
                 g[21] == MASK, 'whole actual prefix GPR/flags including AF/selectors and genuine trap origin')
            need(u(si, 0, 3) == (sig, 0, 2) and q(si, 16)[0] == pc and
                 (index != 0 or g[22] == pc), 'actual prefix NX/TRACE signal address and NX CR2')
            # Every byte, including reserved and inactive capacity, is compared
            # with the independently qualified, actual same-process hash frame.
            need(fp == reference['fp'], 'all65536 prefix FP bytes equal actual original hash-entry hardware state')
            need(tls == app['machine'][1:3] and stack == app['stack'] and memory == app['data'],
                 'actual prefix TLS and complete stack/data observations')
            frames.append(dict(header=fh, si=si, uc=uc, fp=fp, greg=g, fs=tls[0], gs=tls[1],
                               fp_bytes=fh[9], mask=MASK, stack=stack, data=memory))
    return dict(header=h, source=data[192:4288], frames=frames, fallback=fallback)


def read(data, mode, native, exit_status, layout, pid, cpu, seed_reference, *, fallback=False):
    need(type(data) is bytes and type(native) is bool, 'actual current-prefix application bytes and role')
    complete = native or mode < 7
    expected = PREFIX + (SUFFIX + SIZE if complete else 0)
    need(len(data) == expected, 'exact whole current-profile stdout extent; no appended or omitted bytes')
    old = data[:PREFIX + (SUFFIX if complete else 0)]
    app = legacy.read(old, mode, native, exit_status, layout, pid, cpu, seed_reference)
    app['current'] = extension(data[-SIZE:], app, layout, native, mode, fallback) if complete else None
    return app


def control_prefix(data, control, exit_status, layout, pid, cpu, seed_reference):
    app = legacy.control_prefix(data, control, exit_status, layout, pid, cpu, seed_reference)
    app['current'] = None
    return app


def pair(native, gated, owner):
    return legacy.pair(native, gated, owner)


def controls(check_pair, native_output, gated_output, mode):
    # These original26 mutations still target the exact old prefix/suffix bytes.
    # Their callback must re-read both complete new streams and protected wire.
    return legacy.controls(check_pair, native_output, gated_output, mode)


def current_controls(check_pair, native_output, gated_output, mode):
    """New supplied controls are additive and never count as native subjects."""
    start = PREFIX + SUFFIX; frame = start + 4288
    changes = [('version', start + 8), ('count', start + 64), ('cleanup', start + 112),
               ('source_tail', start + 4287), ('NX_AF', frame + 224 + 40 + 17 * 8),
               ('TRACE_AF', frame + SAMPLE + 224 + 40 + 17 * 8),
               ('TRACE_RAX', frame + SAMPLE + 224 + 40 + 13 * 8),
               ('TRACE_PC', frame + SAMPLE + 224 + 40 + 16 * 8),
               ('TRACE_FP', frame + SAMPLE + 1248 + 48),
               ('TRACE_FP_tail', frame + SAMPLE + FRAME - 1),
               ('TRACE_UC_tail', frame + SAMPLE + 1247),
               ('TRACE_TLS', frame + SAMPLE + FRAME),
               ('TRACE_stack', frame + SAMPLE + FRAME + 16),
               ('TRACE_data', frame + SAMPLE + SAMPLE - 1)]
    trials = []
    for name, offset in changes:
        changed = bytearray(native_output);changed[offset] ^= 0x10 if name.endswith('_AF') else 1
        trials.append((name, bytes(changed), gated_output))
    if mode < 7:
        changed = bytearray(gated_output);changed[start + 4288] ^= 1
        trials.append(('invented_gated_native_frame', native_output, bytes(changed)))
    else:
        trials.append(('invented_failed_extension', native_output, gated_output + bytes(SIZE)))
    need(len(trials) == 15 and len({x[0] for x in trials}) == 15, 'all15 unique additive prefix supplied refusals')
    for name, n, g in trials:
        refused = False
        try:
            check_pair(n, g)
        except ValueError:
            refused = True
        need(refused, 'current-prefix reader accepted ' + name)
    return dict(supplied_refusals=15, native_operations=0)
