"""Distinct scalar-span metadata and full-state hardware records. No owner credit."""
import importlib.util
import json
import struct
from pathlib import Path
_spec=importlib.util.spec_from_file_location(__name__+'_model',Path(__file__).with_name('model.py'))
model=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(model)
PAGE, FP, DATA, STACK = 4096, 65536, 8192, 131072
TF, RF, MASK64 = 0x100, 0x10000, (1 << 64) - 1
REGS = (13, 14, 12, 11, 15, 10, 9, 8, 0, 1, 2, 3, 4, 5, 6, 7)
OBS_BYTES, WIRE_BYTES, FIRST_OBS = 272288, 612096, 67520
NATIVE_MODES=58

def need(ok, why):
    if not ok:
        raise ValueError(why)

def q(data, at=0, n=1):
    return struct.unpack_from('<' + 'Q' * n, data, at)

def u(data, at=0, n=1):
    return struct.unpack_from('<' + 'I' * n, data, at)

def json_row(data):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            need(key not in out, 'duplicate_key')
            out[key] = value
        return out
    need(type(data) is bytes and len(data) <= 2048, 'stdout_bound')
    row = json.loads(data, object_pairs_hook=unique)
    need(type(row) is dict and all(type(x) is int for x in row.values()), 'integer_row')
    need(json.dumps(row, separators=(',', ':')).encode() + b'\n' == data, 'canonical_row')
    return row

def live(data):
    need(len(data) == 152 and data[148:] == b'\0' * 4, 'live_extent')
    return q(data, 0, 16), q(data, 128)[0], data[136:148]

def frame(data, h):
    need(len(data) == 65792, 'frame_extent')
    g = q(data, 0, 23)
    mask, address, count, initialized = q(data, 184, 4)
    need(mask == h[13] and initialized == count and 580 <= count <= FP, 'frame_header')
    need(address % 16 == 0 and h[12] + 4096 <= address <= h[12] + 4096 + 524288 - count, 'frame_storage')
    need(data[216:256] == b'\0' * 40, 'frame_padding')
    fp = data[256:]
    need(fp[count:] == b'\0' * (FP - count), 'frame_unused')
    need(u(fp, 464)[0] == 0x46505853 and u(fp, 468)[0] == count and u(fp, 480)[0] == count - 4 and u(fp, count - 4)[0] == 0x46505845 and q(fp, 520)[0] == 0, 'kernel_standard_fp')
    return g, fp, count, mask

def seed_fp(fp, layout, xsave_bytes):
    need(len(fp) == FP and struct.unpack_from('<HH', fp) == (0x37f, 0x3000) and fp[4] == 0xc0 and u(fp, 24)[0] == 0x1f80, 'seed_x87_mxcsr')
    bv, comp = q(fp, 512, 2)
    need(bv & 0xe7 == 0xe7 and comp == 0, 'seed_xstate')
    for reg in range(32):
        for word in range(8):
            if reg >= 16:
                feature, off = 7, (reg - 16) * 64 + word * 8
            elif word >= 4:
                feature, off = 6, reg * 32 + (word - 4) * 8
            elif word >= 2:
                feature, off = 2, reg * 16 + (word - 2) * 8
            else:
                feature, off = 0, 160 + reg * 16 + word * 8
            if feature:
                present, base, size = layout[feature]
                need(present == 1 and off + 8 <= size, 'seed_component')
                off += base
            need(off + 8 <= xsave_bytes and q(fp, off)[0] == 0x3141592653589793 + reg * 8 + word + 1, 'seed_vector')
    masks = (0x0123456789abcdef, 0xfedcba9876543210, 0xaaaaaaaa55555555, 0x0f0ff0f0a5a55a5a, 0x1111222233334444, 0x8877665544332211, 0xffff00000000ffff, 0x5a5a5a5aa5a5a5a5)
    need(layout[5][0] == 1 and layout[5][2] >= 64 and q(fp, layout[5][1], 8) == masks, 'seed_opmask')

def metadata(stdout, stderr, exit_status):
    need(type(exit_status) is int and exit_status == 0 and stderr == b'', 'metadata_exit')
    result=dict(schema=1,code_forms=131,accepted=1283,old_accepts=53,refusals=26,plan_controls=49,none_checks=1283,max_register_rows=4,postseal_equal=1)
    need(json_row(stdout)==result,'exact_metadata_population')
    return result


def fixture(h):
    mode=h[3];seed=[0x3141592600000000+i*0x102030405 for i in range(16)]
    seed[0]=0xfedcba9880000001;seed[1]=3
    seed[2]=h[11]+(DATA if mode==2 else 512);seed[3]=0x8877665544332211
    seed[4]=h[10]+PAGE+STACK-504
    if mode in (6,7):seed[0]=int(mode==7)
    if mode>=10:
        group,variant=divmod(mode-10,8);width=64 if group%2 else 32
        seed[1]=width if variant==6 else 0xfedcba988000003f
    data=bytes(1+(i*17)%255 for i in range(DATA))
    stack=bytes((i*29+7)&255 for i in range(160))
    operands=struct.pack('<QQ',0x8877665544332211,0x1122334455667788)
    need(h[31:35]==(0,seed[4]+0x50,seed[4]+0x58,h[11]+DATA if mode in (8,9) else 0),'actual_operand_fault_geometry')
    need(seed[4]%16==8 and h[10]+PAGE<=seed[4]-128 and seed[4]+0x60<=h[10]+PAGE+STACK,'full_stack_geometry')
    return tuple(seed),data,stack,operands


def trace_path(h,rows):
    if h[3] in (8,9):return tuple(h[8]+r['offset']+len(r['raw']) for r in rows[:h[3]-8])
    if h[3]==6:return (h[8]+0x103,h[8]+0x109,h[8]+0x10d)
    return tuple(h[8]+r['offset']+len(r['raw']) for r in rows)


def observation(data, h, seed, layout, memory, stack, operands, which, rows):
    need(len(data) == OBS_BYTES, 'observation_extent')
    before, after = live(data[:152]), live(data[152:304])
    xbefore, xafter = data[304:65840], data[65840:131376]
    entry, ending = frame(data[131376:197168], h), frame(data[197168:262960], h)
    entry_si, exit_si = data[262960:263088], data[263088:263216]
    got_stack, got_memory, got_operands = data[263216:263376], data[263376:271568], data[271568:271584]
    trace, meta = q(data, 271584, 64), q(data, 272096, 24)
    mode, fault = h[3], h[3] in (8,9)
    head = mode-8 if fault else len(rows)-1
    raw_pc = h[9] + rows[head]['generated_offset'] if which and fault else h[35]
    expected_meta = (which, 2 if which and not fault else 1, 0 if which else h[24], 2 if fault else 1, raw_pc, h[35])
    need(meta[:6] == expected_meta and meta[8:] == (1, 1, h[34], head, rows[head]['offset'] if fault else h[35]-h[8], rows[head]['generated_offset'] if fault else MASK64, h[13], 0, h[24], 1, 1, meta[6], meta[7], h[13], 0, 0), 'complete_event_metadata')
    path = trace_path(h,rows)
    need(trace == ((0,) * 64 if which else path + (0,) * (64 - len(path))), 'actual_complete_trace_path')
    need(before[0] == seed and before[1] == h[23] and before[2] == after[2], 'complete_seed_and_selectors')
    need(xbefore == xafter and entry[1:] == ending[1:], 'complete_fp_and_mask')
    for fp in (xbefore, xafter, entry[1], ending[1]):
        seed_fp(fp, layout, h[7])
    need(got_stack == stack and got_memory == memory and got_operands == operands, 'every_stack_data_operand_byte')
    need(tuple(entry[0][r] for r in REGS) == seed and entry[0][16] == h[8] + 0x100 and entry[0][17] == h[23] | RF and entry[0][19:] == (21, 14, h[13], h[8] + 0x100), 'authentic_original_nx_entry')
    need(u(entry_si, 0, 3) == (11, 0, 2) and q(entry_si, 16)[0] == h[8] + 0x100, 'entry_siginfo')
    need(tuple(ending[0][r] for r in REGS) == after[0] and ending[0][16] == raw_pc and ending[0][21] == h[13], 'actual_ending_state')
    flags = after[1] | (RF if which or fault else TF) | (TF if fault and not which else 0)
    need(ending[0][17] == flags and not after[1] & (TF | RF), 'full_flags_including_af')
    cs, ss, ds, es, fs, gs = struct.unpack('<6H', before[2])
    need(entry[0][18] == ending[0][18] == cs | gs << 16 | fs << 32 | ss << 48, 'actual_live_signal_selectors')
    if fault:
        need(ending[0][19:21] == (4, 14) and ending[0][22] == h[34] and u(exit_si, 0, 3) == (11, 0, 2) and q(exit_si, 16)[0] == h[34], 'genuine_read_fault')
    elif which:
        need(ending[0][19:21] == (21, 14) and ending[0][22] == h[35] and u(exit_si, 0, 3) == (11, 0, 2) and q(exit_si, 16)[0] == h[35], 'genuine_original_nx_exit')
    else:
        need(ending[0][19:21] == (0, 1) and ending[0][22] == h[8] + 0x100 and u(exit_si, 0, 3) == (5, 0, 2), 'actual_reference_trace')
    return before, after, xbefore, xafter, entry, ending, meta, got_stack, got_memory, got_operands

def check(record, stdout, stderr, exit_status, mode):
    need(type(mode) is int and 0 <= mode < NATIVE_MODES and type(exit_status) is int and exit_status == (125 if mode in (8,9) else 0), 'actual_required_exit')
    need(type(record) is bytes and len(record) == WIRE_BYTES and stderr == b'', 'whole_closed_capture')
    h = q(record, 0, 48)
    need(h[:6] == (0x314e50534332494c, 1, 48, mode, 0, 1) and h[14:20] == (57184, 65792, FP, DATA, 160, 2), 'complete_header')
    need(h[6] & 0xe7 == 0xe7 and 576 <= h[7] <= FP and h[8] + PAGE == h[9] and all(x > 0 and x % PAGE == 0 for x in h[8:13]), 'actual_mapping_layout')
    ranges = ((h[8], 2 * PAGE), (h[10], STACK + 2 * PAGE), (h[11], DATA + PAGE), (h[12], 524288 + 2 * PAGE))
    need(all(a + n <= b or b + m <= a for i, (a, n) in enumerate(ranges) for b, m in ranges[i + 1:]), 'disjoint_owned_ranges')
    need(h[13] == MASK64 & ~sum(1 << (sig - 1) for sig in (11, 5, 31, 9, 19)), 'exact_application_mask')
    try:
        rows,want_source,want_image,want_plan=model.plan(h)
    except (struct.error, OverflowError) as error:
        raise ValueError('unrepresentable fixed fixture geometry') from error
    heads=len(rows);image_bytes=u(want_plan,36)[0];interiors=image_bytes-heads-1
    steps=len(trace_path(h,rows));fault=mode in (8,9)
    need(h[20:26] == (4,heads+1,interiors,0x202 if mode%2 else 0xad7,steps,int(fault)), 'fixed_native_population')
    need(h[26] > 0 and h[28] > 0 and h[26] != h[28] and h[27] == h[29] and h[30] == 15, 'actual_distinct_sealed_files')
    need(h[36:] == (OBS_BYTES,48,heads,3 if mode in (6,7) else 1,1,image_bytes,u(want_plan,32)[0],heads+1,interiors,0,0,0), 'fixed_abi_census')
    expected_pc = h[8]+(rows[mode-8]['offset'] if fault else 0x100+u(want_plan,32)[0])
    need(h[35] == expected_pc, 'fixed_terminal_pc')
    seed, data, stack, operands = fixture(h)
    need(q(record, 384, 16) == seed, 'exact_initial_registers')
    layout = tuple(q(record, 512 + i * 24, 3) for i in range(64))
    for feature, (present, offset, size) in enumerate(layout):
        if feature < 2 or not (h[6] >> feature & 1):
            need((present, offset, size) == (0, 0, 0), 'unused_cpuid_row')
        else:
            need(present == 1 and offset >= 576 and size > 0 and offset + size <= h[7], 'actual_cpuid_component')
    stats = record[2048:2096]
    need(stats == record[2096:2144] and u(stats, 0, 4) == (1, 2, 0, 0) and q(stats, 16)[0] == 2 << 20 and 0 < q(stats, 24)[0] <= 2 << 20, 'complete_postseal_allocator_equality')
    source, image, p = record[2144:6240], record[6240:10336], record[10336:FIRST_OBS]
    need(source == want_source, 'whole_source_snapshot')
    need(image == want_image, 'whole_emitted_image')
    need(p == want_plan, 'complete_actual_plan_and_every_descriptor')
    n = observation(record[FIRST_OBS:FIRST_OBS + OBS_BYTES], h, seed, layout, data, stack, operands, 0, rows)
    g = observation(record[FIRST_OBS + OBS_BYTES:], h, seed, layout, data, stack, operands, 1, rows)
    need(n[:4] == g[:4] and n[4][0] == g[4][0] and n[4][1:] == g[4][1:] and n[5][1:] == g[5][1:] and n[6][6:8] == g[6][6:8] and n[7:] == g[7:], 'full_native_generated_state')
    expected = list(n[5][0])
    expected[17] &= ~TF
    if mode in (8,9):
        expected[16] = h[9]+rows[mode-8]['generated_offset']
    else:
        expected[17] |= RF; expected[19] = 21; expected[20] = 14; expected[22] = h[35]
    need(tuple(expected) == g[5][0], 'all_23_actual_gregs_with_exact_event_association')
    result = dict(schema=1, mode=mode, qualified_comparison=1, completed_path=int(mode not in (8,9)), required_read_failure=int(mode in (8,9)), cleanup=1, reference_trace=steps, generated_trace=0, exit_kind=2 if mode in (8,9) else 1, authority_controls=4, head_checks=heads+1, interior_misses=interiors, postseal_equal=1)
    need(json_row(stdout) == result, 'exact_numeric_summary')
    return result

def controls(record, stdout, stderr, exit_status, mode):
    """Call only after the actual record passed check(); no fabricated baseline."""
    a, b = FIRST_OBS, FIRST_OBS + OBS_BYTES
    locations = [('version', 8), ('error', 32), ('cleanup', 40), ('mode', 24), ('abi', 112), ('seed', 384), ('cpuid_unused', 512), ('allocator_before', 2080), ('allocator_after', 2128), ('source_tail', 6239), ('image_tail', 10335), ('plan_source', 10336 + 80), ('plan_effect', 10336 + 8272 + 292), ('plan_unused', 10336 + 8272 + 63 * 336), ('plan_map', 10336 + 54064 + 32), ('reference_before', a), ('reference_after', a + 152), ('reference_af', a + 280), ('reference_selectors', a + 288), ('before_fp_tail', a + 65839), ('after_fp_tail', a + 131375), ('entry_fp_tail', a + 197167), ('exit_fp_tail', a + 262959), ('entry_si', a + 262960), ('stack_tail', a + 263375), ('data_tail', a + 271567), ('operand_tail', a + 271583), ('trace_path', a + 271584), ('actual_fs', a + 272096 + 48), ('generated_gpr', b + 152), ('generated_af', b + 280), ('generated_fp_tail', b + 131375), ('generated_stack', b + 263375), ('generated_operand', b + 271583), ('generated_trace', b + 272096 + 16), ('generated_nx', b + 272096 + 8), ('restored_stack', b + 272096 + 120), ('before_fs', b + 272096 + 152), ('before_mask', b + 272096 + 168)]
    locations += [('fourth_register_row',10336+8272+192),('rip_target',10336+8272+248),('relocation_offset',10336+8272+324),('address_count',10336+8272+288),('emitted_rip',10336+30112+248)]
    trials = []
    for name, offset in locations:
        value = bytearray(record); value[offset] ^= 0x10 if name.endswith('_af') else 1
        trials.append((name, (bytes(value), stdout, stderr, exit_status, mode)))
    # Coherent aliases leave all old cross-lane/live/frame equalities intact.
    for name, offsets in [('coherent_live_cs', (a + 136, a + 288, b + 136, b + 288)), ('coherent_signal_cs', (a + 131376 + 18 * 8, a + 197168 + 18 * 8, b + 131376 + 18 * 8, b + 197168 + 18 * 8))]:
        value = bytearray(record)
        for at in offsets:
            value[at] ^= 1
        trials.append((name, (bytes(value), stdout, stderr, exit_status, mode)))
    trials += [('truncated', (record[:-1], stdout, stderr, exit_status, mode)), ('appended', (record + b'\0', stdout, stderr, exit_status, mode)), ('extra_stdout', (record, stdout + b'\n', stderr, exit_status, mode)), ('stderr', (record, stdout, b'x', exit_status, mode)), ('wrong_exit', (record, stdout, stderr, 0 if exit_status else 125, mode))]
    if mode in (8,9):
        for name, at in [('fault_cr2', b + 197168 + 22 * 8), ('fault_pc', b + 197168 + 16 * 8), ('fault_tf', b + 197168 + 17 * 8 + 1)]:
            value = bytearray(record); value[at] ^= 1
            trials.append((name, (bytes(value), stdout, stderr, exit_status, mode)))
    row = json.loads(stdout); row['qualified_comparison'] = True
    trials.append(('bool_output', (record, json.dumps(row, separators=(',', ':')).encode() + b'\n', stderr, exit_status, mode)))
    need(len(trials) == 52 + 3 * int(mode in (8,9)) and len({name for name, _ in trials}) == len(trials), 'fixed_unique_reader_controls')
    for name, arguments in trials:
        try:
            check(*arguments)
        except ValueError:
            continue
        raise ValueError('accepted supplied mutation ' + name)
    return [name for name, _ in trials]
