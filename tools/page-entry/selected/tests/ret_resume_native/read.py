#!/usr/bin/env python3
"""Read the fixed real-C3/owned-TF ordering observations; no production continuation authority."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

PAGE, FP, STACK, FRAME, RECORD = 4096, 65536, 16384, 67072, 191928
MAGIC, REC_MAGIC, END = 0x3153525232494C, 0x3152525232494C, 0x3145525232494C
REG = (13, 14, 12, 11, 15, 10, 9, 8, 0, 1, 2, 3, 4, 5, 6, 7)
GREG_NAMES = ('r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
              'rdi', 'rsi', 'rbp', 'rbx', 'rdx', 'rax', 'rcx', 'rsp',
              'rip', 'eflags', 'csgsfs', 'err', 'trapno', 'oldmask', 'cr2')
MASK64 = (1 << 64)-1


def need(value, message):
    if not value:
        raise ValueError(message)


def words(raw, count, offset=0):
    return struct.unpack_from('<'+'Q'*count, raw, offset)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def flags(value):
    return 0x202 | sum(1 << bit for i, bit in enumerate((0, 2, 4, 6, 7, 11)) if value & (1 << i))


def frame(raw, header, phase):
    need(len(raw) == FRAME, 'whole frame')
    h, greg = words(raw, 16), words(raw, 23, 128)
    mask, info, context, fp = raw[312:440], raw[440:568], raw[568:1536], raw[1536:]
    need(h[11] == header[16] and h[12] == phase, 'actual CPU and event order')
    need(header[24] <= h[10] < header[24]+header[25] and
         header[24] <= h[6] <= header[24]+header[25]-h[7], 'actual alternate-stack geometry')
    need(512 <= h[7] <= FP and not any(fp[h[7]:]), 'whole FP extent and zero unused tail')
    magic = struct.unpack_from('<I', fp, 464)[0]
    if magic == 0x46505853:
        need(struct.unpack_from('<I', fp, 468)[0] == h[7] and h[7] >= 576 and
             struct.unpack_from('<I', fp, h[7]-4)[0] == 0x46505845 and
             struct.unpack_from('<I', fp, 480)[0] <= h[7]-4, 'actual xstate framing')
    else:
        need(h[7] == 512, 'legacy FP framing')
    need(words(context, 23, 40) == greg and words(context, 1, 224)[0] == h[6] and
         context[296:424] == mask and words(context, 2) == h[4:6], 'whole ucontext joins')
    need(mask == bytes(mask[:8])+bytes(info[:120]) and context[304:432] == info,
         'whole captured mask128 is kernel mask8 plus event siginfo120; whole embedded siginfo128')
    sig, error, code = struct.unpack_from('<iii', info)
    need((sig, error & MASK64, code & MASK64) == (h[0], h[2], h[1]) and
         words(info, 1, 16)[0] == h[3], 'whole siginfo joins')
    need((greg[20], greg[19], greg[22]) == h[13:16], 'raw trap/error/CR2 joins')
    return h, greg, fp



def normalized_context(raw, greg, info):
    context = bytearray(raw[568:1536])
    context[40:224] = struct.pack('<23Q', *greg)
    context[224:232] = bytes(8)  # actual FP pointer is independently joined to its full captured storage
    # frame() first authenticates all128 embedded bytes against this separate
    # siginfo capture; pair() changes only its exact architectural endpoint.
    context[304:432] = info
    return bytes(context)


def configuration(identity, header):
    kind, route = divmod(identity, 3)
    targets = (header[23]+64, header[23]+PAGE+64, header[31]+64,
               0x0100000000000000, 0x8000000000000000)
    status = flags((kind*11) & 63) | (0x400 if kind & 1 else 0)
    return kind, route, header[22]+2*PAGE+512, targets[kind], status


def target_image():
    page = bytearray(b'\xcc'*PAGE)
    page[64:74] = bytes.fromhex('48 8d 40 01 48 8d 64 24 10 cc')
    page[128:138] = bytes.fromhex('48 8d 40 02 48 8d 64 24 20 cc')
    return bytes(page)*2


def lane(raw, header, identity):
    need(len(raw) == RECORD, 'whole ordering record')
    h, armed = words(raw, 32), words(raw, 23, 256)
    kind, route, guest_sp, target, status = configuration(identity, header)
    pc, cell = header[21]+0x100, header[30]+256
    operand_sp = cell if route == 2 else guest_sp
    armed_flags = status | (0x100 if route else 0)
    replacement = header[23]+128
    expected = [REC_MAGIC, RECORD, identity, route, kind, pc, pc+1, target,
                guest_sp, operand_sp, status, armed_flags, target if route == 2 else 0,
                1, 0, 2, 2, replacement, target, replacement if route == 2 else target,
                cell, target if route == 2 else 0, int(bool(route)), 1 if route == 2 else 3,
                3, 5 if kind == 0 else 1 if kind == 1 else 0, int(route == 2), 1, 0, 0, 0, 0]
    need(h == tuple(expected), 'all fixed identity, load/poison/permission and unused metadata cells')
    before_raw, after_raw = raw[440:440+FRAME], raw[440+FRAME:440+2*FRAME]
    before, after = frame(before_raw, header, 0), frame(after_raw, header, 1)
    bh, bg, bf = before; ah, ag, af = after
    seed = [(0x13579BDF00110000+0x100010001*i+kind) & MASK64 for i in range(16)]
    seed[4] = guest_sp
    need(tuple(bg[k] for k in REG) == tuple(seed) and bg[16] == pc and bg[17] == status|0x10000,
         'actual NX-before full GPR/flags, without injected TF')
    need(bh[:4] == (11, 2, 0, pc) and bg[19:21] == (21, 14) and bg[22] == pc,
         'exact original NX fetch before any C3')
    want_armed = list(bg)
    if route == 0:
        want_armed[16], want_armed[15] = header[28:30]
        want_armed[17] &= ~(0x10000 | 0x100)
    else:
        want_armed[15] = operand_sp
        want_armed[17] = armed_flags
    need(armed == tuple(want_armed), 'actual complete recovery frame: original reload or direct owned-TF C3')
    need(bf == af and bh[4:6] == ah[4:6] and bh[7:10] == ah[7:10] and
         bg[18] == ag[18] and bg[21] == ag[21] and before_raw[312:320] == after_raw[312:320],
         'all65536 FP bytes, TLS, UC flags/link, segments and actual kernel mask unchanged')
    at = 440+2*FRAME
    initial, final = raw[at:at+STACK], raw[at+STACK:at+2*STACK]
    stack = bytearray((0x5a+37*i+kind) & 255 for i in range(STACK))
    struct.pack_into('<Q', stack, guest_sp-header[22], target)
    need(initial == stack, 'whole original stack and original guest target word')
    if route == 2:
        struct.pack_into('<Q', stack, guest_sp-header[22], replacement)
    need(final == stack, 'whole final guest stack; only the declared saved-route poison changed')
    source = raw[at+2*STACK:at+2*STACK+4*PAGE]
    code = bytearray(b'\xcc'*(2*PAGE));code[0x100] = 0xc3
    need(source == code+target_image(), 'whole C3 and both literal target-effect pages')
    cell_initial = raw[-2*PAGE:-PAGE];cell_final = raw[-PAGE:]
    cell_image = bytearray((0xa7+19*i+kind) & 255 for i in range(PAGE))
    need(cell_initial == cell_image, 'whole initial private page with poisoned qword')
    if route == 2:
        struct.pack_into('<Q', cell_image, 256, target)
    need(cell_final == cell_image, 'whole private page; saved operand is the only written qword')

    # The raw frame decides TRACE-versus-fetch ordering. Both routes with TF
    # must agree exactly after the explicitly declared operand-SP coordinate.
    want = list(seed);want[4] = operand_sp
    if kind == 0 and route == 0:
        want[0] += 1;want[4] += 24
        need(ah[:4] == (5, 128, 0, 0) and ag[16] == target+10 and ag[19:21] == (0, 3),
             'unstepped RX control executes both distinct target effects then INT3')
        event = 'target_effects_then_int3'
    elif kind < 3:
        want[4] += 8
        if ah[:4] == (5, 2, 0, target) and ag[16] == target and ag[19:21] == (0, 1):
            need(route != 0, 'TRACE belongs only to owned-TF route')
            event = 'trace_before_target_instruction'
        else:
            need(kind in (1, 2) and ah[:4] == (11, 2 if kind == 1 else 1, 0, target) and
                 ag[16] == target and ag[19:21] == (21 if kind == 1 else 20, 14),
                 'literal canonical NX/unmapped fetch fault, no unknown or normalized endpoint')
            event = 'target_fetch_fault_before_trace' if route else 'target_fetch_fault'
        if kind == 0:
            need(event == 'trace_before_target_instruction', 'owned TF stops before the first RX target instruction')
    else:
        need(ah[:4] == (11, 128, 0, 0) and ag[16] == pc and ag[19:21] == (0, 13),
             'noncanonical target faults at actual C3 before stack-pointer commitment')
        event = 'noncanonical_gp_before_commit'
    want_flags = armed_flags | (0x10000 if ag[20] in (13, 14) else 0)
    need(tuple(ag[k] for k in REG) == tuple(want) and ag[17] == want_flags,
         'all16 actual GPRs and exact flags; no target instruction or SP effect hidden')
    need(ag[22] == (target if ag[20] == 14 else pc), 'actual fault CR2 or inherited before-event CR2')
    logical = list(ag)
    if route == 2:
        # This is a reported coordinate, not a write into any kernel frame.
        need(ag[15] in (cell, cell+8), 'private C3 is either uncommitted or committed exactly once')
        logical[15] = guest_sp+(ag[15]-cell)
    return dict(id=identity, kind=kind, route=route, target=target, guest_rsp=guest_sp,
        private_cell=cell, physical_operand_rsp=operand_sp, actual_rsp=ag[15], logical_rsp=logical[15],
        input_flags=status, owned_tf=bool(route), event=event,
        signal=ah[0], si_code=ah[1], si_address=ah[3], trapno=ag[20], error=ag[19], cr2=ag[22],
        before_greg=list(bg), armed_greg=list(armed), after_greg=list(ag), logical_after_greg=logical,
        saved_target=target if route == 2 else None, guest_word_after=replacement if route == 2 else target,
        fp_storage_unchanged=True, tls_unchanged=True, kernel_mask_unchanged=True,
        target_effect_executed=(kind == 0 and route == 0), raw_record_sha256=digest(raw),
        full_fp_sha256=digest(bf), stack_before_sha256=digest(initial), stack_after_sha256=digest(final),
        private_before_sha256=digest(cell_initial), private_after_sha256=digest(cell_final))


def read_file(path, cpu, pid):
    raw = path.read_bytes();h = words(raw, 32)
    need(len(raw) == 2879240 < 16 << 20 and h[:15] ==
         (MAGIC, 1, 256, RECORD, FRAME, 968, 128, FP, STACK, 16384, 15, 0, 0, 15, 15),
         'complete fixed5-target by3-route ABI, population and whole raw extent')
    need(h[15] == pid > 0 and h[16] == cpu and h[19] & 3 == 3 and 512 <= h[20] <= FP and
         h[25:28] == (262144, 0, 15) and h[28] and h[29] and h[31] == h[23]+2*PAGE,
         'actual process PID/CPU/FP/bootstrap and exact deliberately unmapped page')
    need((h[17] == 0 and h[18] == 0) or h[17] in ((-22)&MASK64, (-38)&MASK64),
         'actual CET-disabled prerequisite queried, never changed by this fixture')
    need(all(h[i] and h[i] % PAGE == 0 for i in (21, 22, 23, 24, 30, 31)), 'actual page bases')
    spans = sorted(((h[21],h[21]+2*PAGE),(h[22],h[22]+STACK),(h[23],h[23]+3*PAGE),
                    (h[24]-PAGE,h[24]+h[25]+PAGE),(h[30],h[30]+PAGE)))
    need(all(a < b for a,b in spans) and all(spans[i][1] <= spans[i+1][0] for i in range(4)),
         'all source/stack/target-reservation/alternate/private allocations disjoint')
    need(words(raw, 8, len(raw)-64) == (END, 1, 15, len(raw), 0, 0, 0, 0), 'whole completed footer')
    rows = [lane(memoryview(raw)[256+i*RECORD:256+(i+1)*RECORD],h,i) for i in range(15)]
    for kind in range(5):
        original, calibrated, saved = rows[3*kind:3*kind+3]
        need(original['route'] == 0 and calibrated['route'] == 1 and saved['route'] == 2,
             'every target has its complete fixed three-route comparison')
        need(calibrated['event'] == saved['event'] and
             calibrated['after_greg'] == saved['logical_after_greg'] and
             tuple(calibrated[k] for k in ('signal','si_code','si_address','trapno','error','cr2')) ==
             tuple(saved[k] for k in ('signal','si_code','si_address','trapno','error','cr2')),
             'private saved-word and original-stack owned-TF routes have exact logical event/GREG equality')
        need(calibrated['full_fp_sha256'] == saved['full_fp_sha256'] == original['full_fp_sha256'],
             'all three routes retain the same seeded complete FP storage')
        for phase, offset in (('before', 440), ('after', 440+FRAME)):
            ca = 256+(3*kind+1)*RECORD+offset
            sa = 256+(3*kind+2)*RECORD+offset
            cr, sr = memoryview(raw)[ca:ca+FRAME], memoryview(raw)[sa:sa+FRAME]
            ch, cg, cf = frame(cr, h, int(phase == 'after'))
            sh, sg, sf = frame(sr, h, int(phase == 'after'))
            logical = list(sg)
            if phase == 'after':
                logical[15] = saved['logical_rsp']
            need(tuple(logical) == cg and cf == sf and ch[4:6] == sh[4:6] and
                 ch[7:10] == sh[7:10] and cr[312:440] == sr[312:440],
                 'literal full FP/mask/TLS/UC fields and all23 GREGs with only declared private-RSP translation')
            ci, si = bytes(cr[440:568]), bytes(sr[440:568])
            need(ci == si and normalized_context(cr, cg, ci) == normalized_context(sr, logical, si),
                 'complete siginfo and normalized whole context; only independently checked FP pointer and RSP differ')

    return dict(schema=1,status='hardware_ordering_observed_unqualified',cases=15,targets=5,routes=3,
        cpu=cpu,source=dict(bytes=len(raw),sha256=digest(raw),pid=pid),observations=rows,
        rx_pre_instruction_trace_observed=True,
        canonical_fetch_order=[dict(kind=k,unstepped=rows[3*k]['event'],owned_tf=rows[3*k+1]['event'],
            saved_word=rows[3*k+2]['event']) for k in (1,2)],
        noncanonical_original_rsp_mapping_observed=True,saved_word_poison_controls=5,
        loaded_miss_continuation_implemented=False,production_owner_authority=False,
        original_RET32_replaced=False,original_RET_adapter_cases_replaced=False,
        qualification_credit=False,performance_credit=False,
        scope='Fixed actual hardware ordering only. No asynchronous/nested owner, drain, signal delivery, or resumed guest integration proof.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-cpu',type=int,required=True)
    parser.add_argument('--expect-pid',type=int,required=True)
    parser.add_argument('capture',type=Path)
    args = parser.parse_args()
    need(args.expect_cpu >= 0 and args.expect_pid > 0, 'actual reserved CPU and owned child PID')
    print(json.dumps(read_file(args.capture,args.expect_cpu,args.expect_pid),sort_keys=True,indent=2))


if __name__ == '__main__':
    main()
