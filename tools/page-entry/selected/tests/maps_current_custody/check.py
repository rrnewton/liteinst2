"""Actual lifecycle-TU component only; no executed instruction/frame credit."""
import copy
import json

KEYS = ('version mode differential component_only supplied_boundary required_refusal '
        'state_injections ticket_refusals cleanup decoder io events').split()
CURRENT = (2, 4, 6, 8)
PHYSICAL = (3, 5, 7, 9)
OPS = (
    (1, *CURRENT, 10, *CURRENT, 26),
    (1, *CURRENT, 11, *PHYSICAL, 10, 12, *PHYSICAL, 11, *CURRENT, 26),
    (1, *PHYSICAL, 10, 12, *PHYSICAL, 26),
    (1, *CURRENT, 10, 13, 24, 26),
    (1, 14, 24, 26),
    (1, 2, 16, 26), (1, 2, 17, 26), (1, 2, 18, 26),
    (1, 3, 19, 26), (1, 3, 20, 26), (1, 3, 21, 26),
    (1, 3, 5, 7, 22, 26), (1, 2, 4, 6, 23, 26),
    (1, *CURRENT, 15, 11, 25, 26),
)
FIELDS = ('op result phase epoch current_owned current_bound borrow_sequence held fetch_error '
          'current_phase current_serial current_before current_after current_kind '
          'physical_phase physical_serial physical_before physical_after physical_kind '
          'proof_epoch proof_kind proof_complete proof_consumed proof_origin '
          'attempts current_stages current_seeds physical_fallbacks retained_stages retained_checks commits cancels current_error '
          'physical_seeds physical_retained_stages physical_retained_checks physical_commits '
          'acquisitions fresh_calls handler mutation active valid maps_poisoned '
          'queries hits refreshes comparisons mismatches view_poisoned').split()
MAP_FIELDS = 'acquisition handler mutation kind io opened close_started closed bytes rows'.split()
FIELDS += [prefix + '_' + name for prefix in ('baseline', 'query', 'physical') for name in MAP_FIELDS]
MAX_OUTPUT = 32768
CONTROL_COUNT = 25


def need(value, message):
    if not value:
        raise ValueError(message)


def numbers(value, size):
    need(type(value) is list and len(value) == size and
         all(type(x) is int and 0 <= x < 2**64 for x in value), 'bounded exact numeric extent')


def receipt(row, offset, kinds, io):
    a, h, epoch, kind, actual_io, opened, started, closed, size, rows = row[offset:offset + 10]
    need(a > 0 and kind in kinds and actual_io == io and opened == started == closed == 1 and
         size > 0 and 0 < rows <= 2048 and a <= row[37] and epoch <= row[40],
         'actual complete typed maps receipt')
    need((0 < h <= row[39]) if kind in (1, 3, 4) else h == 0,
         'actual physical/query handler provenance')


def check(stdout, stderr, exit_status, mode, differential):
    need(type(mode) is int and 0 <= mode < 14 and type(differential) is int and differential in (0, 1),
         'fixed component mode/profile')
    need(type(stderr) is bytes and not stderr and type(exit_status) is int and
         exit_status == (0 if mode < 3 else 125), 'actual component outcome')
    need(type(stdout) is bytes and 0 < len(stdout) <= MAX_OUTPUT, 'bounded component stdout')

    def unique(pairs):
        need(len(pairs) == len({key for key, _ in pairs}), 'duplicate component key')
        return dict(pairs)

    value = json.loads(stdout, object_pairs_hook=unique)
    need(json.dumps(value, separators=(',', ':')).encode() + b'\n' == stdout, 'canonical complete JSON line')
    need(type(value) is dict and list(value) == KEYS, 'exact component schema')
    need(all(type(value[k]) is int for k in KEYS[:8]), 'exact scalar types')
    need([value[k] for k in KEYS[:8]] == [1, mode, differential, 1, 1, int(mode >= 3),
         22 if mode == 0 else int(mode in (3, 4, 13)), 29 if mode == 0 else 0],
         'fixed supplied-state and real-refusal populations')
    clean, decoder, io, events = (value[k] for k in KEYS[8:])
    numbers(clean, 4); numbers(decoder, 8); numbers(io, 5)
    need(clean[:3] == [1, 2, int(mode < 3)], 'actual source revocation/unmap/descriptor/release cleanup')
    need(decoder[:5] == [1, 2, 0, 0, 2 * 1024 * 1024] and 0 < decoder[5] <= decoder[4] and
         decoder[6] > 0 and decoder[7] <= decoder[6], 'actual sealed default decoder statistics')
    need(io[0] == io[2] == io[3] == clean[3] and io[0] > 0 and io[1] > io[2] and io[4] > 0,
         'actual physical open/read/EOF/close census')
    need(type(events) is list and len(events) == len(OPS[mode]), 'complete fixed event sequence')
    for row in events:
        numbers(row, 80)
    need(tuple(row[0] for row in events) == OPS[mode], 'exact cross-API operations')
    expected_stats = [0] * 13  # Both distinct custody producers, fields24..36.
    current = [0] * 5
    physical = [0] * 5
    proof = [0] * 5
    bound = 0
    borrow = 1
    first_error = 0
    prior = None
    for row in events:
        op = row[0]
        expected_result = 1 if op == 12 else 302 if 16 <= op <= 21 else 303 if 22 <= op <= 25 else 0
        need(row[1] == expected_result, 'exact API refusal, never exception-as-success')
        if op == 1:
            need(row[2] == 0 and row[3] > 0, 'actual empty startup epoch')
        elif op == 26:
            need(row[1:] == [0] + prior[2:], 'exact retained terminal prefix')
        elif op in (2, 3):
            cold = prior[2] == 0
            need(cold or prior[2] == 2, 'cold or genuine retained entry')
            target = current if op == 2 else physical
            target[:] = [2, target[1] + 1, borrow, 0, (3 if cold else 4) if op == 2 else (1 if cold else 2)]
            if op == 2:
                if cold:
                    expected_stats[0] += 1; expected_stats[1] += 1
                    proof[:] = [row[3], 3, 1, 1, borrow]; bound = 1
                else:
                    expected_stats[4] += 1; expected_stats[5] += 1; proof[1] = 4
            elif not cold:
                expected_stats[10] += 1; expected_stats[11] += 1
            need(row[2] == 4 and (row[3] >= prior[3] if cold else row[3] == prior[3]),
                 'staged shared epoch')
        elif op in (4, 5):
            target = current if op == 4 else physical
            need(prior[2] == 4, 'commit follows stage')
            borrow += 1; target[0] = 4; target[3] = borrow
            if op == 4 and target[4] == 4:
                expected_stats[5] += 1
            if op == 5 and target[4] == 2:
                expected_stats[11] += 1
            need(row[2] == 5 and row[3] == prior[3], 'committed shared epoch')
        elif op in (6, 7):
            target = current if op == 6 else physical
            need(prior[2] == 5, 'publish follows commit')
            if op == 6:
                expected_stats[2] += int(target[4] == 3); expected_stats[6] += 1
            else:
                expected_stats[9] += int(target[4] == 1); expected_stats[12] += 1
            need(row[2] == 6 and row[3] == prior[3], 'published return epoch')
        elif op in (8, 9, 10):
            need(prior[2] == (6 if op in (8, 9) else 1) and row[2] == (1 if op in (8, 9) else 2) and
                 row[3] == prior[3], 'actual return/boundary transition')
        elif op == 11:
            need(row[2:4] == ([7, 2**64 - 1] if mode == 13 else [0, prior[3] + 1]),
                 'discard invalidates or poisons without rollover')
        elif op == 12:
            need(row[2:4] == prior[2:4] and row[2] == 2 and row[4] == 0 and not row[8],
                 'exact physical ENTRY fallback has no current authority')
        elif op == 13:
            need(row[2:4] == [2, prior[3] + 1], 'explicit stale-epoch stimulus')
        elif op == 14:
            need(row[2:4] == [2, prior[3]], 'explicit missing-origin stimulus')
        elif op == 15:
            need(row[2:4] == [1, 2**64 - 1], 'explicit epoch exhaustion stimulus')
        elif 16 <= op <= 25:
            if op == 17:
                need(row[2:4] == prior[2:4], 'old cancel refuses without inventing discard')
            else:
                first_error = expected_result
                need(row[2:4] == ([7, 2**64 - 1] if op == 25 else [0, prior[3] + 1]),
                     'first error with exact terminal invalidation')
            if op in (19, 20, 21, 22, 24, 25):
                expected_stats[8] = expected_result
        need(row[4:9] == [int(bool(bound and row[3] == proof[0] and row[2] != 0)), bound, borrow, 1, first_error],
             'current ownership requires the live shared epoch and held borrow')
        need(row[9:14] == current and row[14:19] == physical and row[19:24] == proof,
             'distinct stage/provenance and exact borrow sequence chronology')
        need(row[24:37] == expected_stats, 'exact separate custody producer counters')
        need(row[37] == row[38] == row[46] + row[47] and row[37] > 0 and row[39] > 0 and
             row[41:44] == [1, 1, 0] and row[44] == row[45] + row[46] and
             row[47] == differential * row[45] and row[48:50] == [0, 0],
             'complete maintained-view and actual physical census')
        if bound:
            receipt(row, 50, (0, 1), 1)
            receipt(row, 60, (3,) if differential else (4,), differential)
            need(row[50] == row[60] and row[52] <= row[62] and row[69] > 0,
                 'current query is bound to its real physical baseline')
            if prior and op != 2:
                need(row[50:70] == prior[50:70], 'retained current receipts are historical, never fabricated')
            elif prior and op == 2 and prior[2] == 2:
                need(row[50:70] == prior[50:70], 'retained stage keeps exact originating receipts')
        else:
            need(row[50:70] == [0] * 20, 'no invented current origin')
        if physical[4]:
            receipt(row, 70, (1,), 1)
            if prior and not (op == 3 and prior[2] == 0):
                need(row[70:80] == prior[70:80], 'retained physical origin is unchanged')
        else:
            need(row[70:80] == [0] * 10, 'no invented physical origin')
        if prior:
            need(all(row[i] >= prior[i] for i in (37, 38, 39, 40, 44, 45, 46, 47)),
                 'monotonic actual maps observations')
        prior = row
    need(clean[3] >= events[-1][38], 'cleanup physical I/O retained')
    return value


def controls(stdout, stderr, exit_status, mode, differential):
    """Copied-record refusals only, after the actual native result passes."""
    actual = check(stdout, stderr, exit_status, mode, differential)
    mutations = [
        ('version', lambda v: v.__setitem__('version', 2)),
        ('scope', lambda v: v.__setitem__('component_only', 0)),
        ('boundary', lambda v: v.__setitem__('supplied_boundary', 0)),
        ('refusal', lambda v: v.__setitem__('required_refusal', 1 - v['required_refusal'])),
        ('injection', lambda v: v.__setitem__('state_injections', v['state_injections'] + 1)),
        ('tickets', lambda v: v.__setitem__('ticket_refusals', v['ticket_refusals'] + 1)),
        ('map_cleanup', lambda v: v['cleanup'].__setitem__(0, 0)),
        ('fd_cleanup', lambda v: v['cleanup'].__setitem__(1, 1)),
        ('release', lambda v: v['cleanup'].__setitem__(2, 1 - v['cleanup'][2])),
        ('postseal', lambda v: v['decoder'].__setitem__(1, 1)),
        ('fatal', lambda v: v['decoder'].__setitem__(2, 102)),
        ('physical_close', lambda v: v['io'].__setitem__(3, v['io'][3] + 1)),
        ('population', lambda v: v['events'].pop()),
    ]
    # Coherent changes to every retained alias cannot hide behind final-prefix equality.
    for name, index in [('phase', 2), ('owned', 4), ('held', 7), ('borrow', 6),
                        ('fetch_error', 8), ('stage_kind', 13), ('commits', 30),
                        ('maps_valid', 42), ('comparison', 47)]:
        def change(v, field=index):
            for row in v['events']:
                row[field] ^= 1
        mutations.append((name, change))
    need(len(mutations) == 22, 'fixed meaningful record mutations')
    for _, mutate in mutations:
        value = copy.deepcopy(actual); mutate(value)
        try:
            check(json.dumps(value, separators=(',', ':')).encode() + b'\n', stderr, exit_status, mode, differential)
        except ValueError:
            pass
        else:
            raise ValueError('required copied-record refusal missing')
    malformed = (stdout + b' ', stdout.replace(b'{', b'{"version":1,', 1), stdout[:-1])
    for data in malformed:
        try:
            check(data, stderr, exit_status, mode, differential)
        except ValueError:
            pass
        else:
            raise ValueError('required protocol refusal missing')
    return {'refusals': CONTROL_COUNT, 'native_operations': 0}
