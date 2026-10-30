"""Strict selected accuracy wire; structural joins grant no hardware authority.

The caller authenticates these source modules, the actual process/closure, the
complete ELF/caller geometry and its unsafe ABI before using this pure decoder.
This module never executes a producer, repairs a row or selects a trial subset.
"""
import importlib.util
import json
from pathlib import Path
import sys

if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
shared = _load('_accuracy_shared_wire', HERE.parent / 'ordinary-leaf-set-session/output.py')
truth = _load('_accuracy_independent_truth', HERE / 'truth.py')
VERSION = 'selected-accuracy-session-v1'
OPERATION = 'exact_work_nonempty'
ABI = 'sysv-amd64-u64-pointer-length-v1'
CAP, LINE = 8 * 1024 * 1024, 350
RECORDS = 2048
U64, U32 = (1 << 64) - 1, (1 << 32) - 1


class Refused(ValueError):
    """The original streams remain available even for incomplete/invalid output."""
    def __init__(self, reason, stdout, stderr):
        super().__init__(reason)
        self.reason, self.raw, self.stderr = reason, stdout, stderr


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def integer(value, lo=0, hi=U64):
    need(type(value) is int and lo <= value <= hi, 'integer authority')
    return value


def uint(word, hi=U64):
    value = shared.uint(word)
    need(value <= hi, 'unsigned field range')
    return value


def signed(word, bits=64):
    need(type(word) is str and 0 < len(word) <= 20, 'signed field width')
    if word.startswith('-'):
        need(len(word) > 1 and word[1] in '123456789' and word[1:].isdigit(), 'signed syntax')
    else:
        need(word == '0' or (word[0] in '123456789' and word.isdigit()), 'signed syntax')
    value = int(word)
    need(-(1 << (bits - 1)) <= value < (1 << (bits - 1)), 'signed range')
    return value


def optional(word, parse):
    return None if word == '-' else parse(word)


def hex_bytes(word, size):
    need(len(word) == 2 * size and all(c in '0123456789abcdef' for c in word), 'hex bytes')
    return bytes.fromhex(word)


def _unique(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out, 'duplicate manifest key')
        out[key] = value
    return out


def authority(manifest_bytes, input_bytes, selected_bytes, truth_bytes,
              table, caller, body_bytes, abi, policy, cpus):
    need(type(manifest_bytes) is bytes and 0 < len(manifest_bytes) <= 65536, 'manifest bound')
    manifest = json.loads(manifest_bytes.decode('ascii'), object_pairs_hook=_unique)
    need(type(manifest) is dict, 'manifest object')
    files, expected = truth.artifacts(manifest['master'], manifest['phase'],
                                      manifest['trial'], manifest['workload'])
    need(manifest_bytes == truth.canonical(expected), 'exact independent manifest')
    for supplied, name in ((input_bytes, 'input.csv'), (selected_bytes, 'selected.txt'),
                           (truth_bytes, 'truth.csv')):
        need(type(supplied) is bytes and supplied == files[name], 'complete original input/table/truth')
    need(type(body_bytes) is bytes and body_bytes == truth.BODY and abi == ABI, 'literal body/ABI')
    shared._geometry(table, caller, cpus, (OPERATION,))
    need(len(table) == 1 and table[0] == dict(function_id=41, operation=OPERATION,
         policy='whole', elf_va=table[0]['elf_va'], extent=37, returns=(36,)), 'exact selected geometry')
    need(type(policy) is dict and set(policy) == {'k', 'period_ms', 'epochs', 'phase', 'delay_ns'}, 'policy fields')
    integer(policy['epochs'], 1, 520)
    choice = {key: policy[key] for key in ('k', 'period_ms', 'phase', 'delay_ns')}
    for key in ('k', 'period_ms', 'delay_ns'):
        integer(choice[key])
    need(choice in expected['policies'], 'exact requested policy')
    rows = truth.population(expected['seed'], expected['workload'])
    need(len(rows) == RECORDS, 'full truth denominator')
    records = tuple(row['payload'] for row in rows)
    semantics = tuple(dict(csv_fields=1, exact_work_nonempty=row['value']) for row in rows)
    return expected, rows, records, semantics


def framing(stdout, stderr, epochs):
    need(type(stdout) is bytes and type(stderr) is bytes, 'raw stream types')
    need(0 < len(stdout) <= CAP and stdout.endswith(b'\n'), 'finite complete stream')
    need(stderr == b'', 'nonempty terminal stderr remains a refusal')
    # New bound 4C + R + 3E + 6N + 14, with the exact one-leaf population.
    need(stdout.count(b'\n') <= 4 * RECORDS + RECORDS + 3 * epochs + 20, 'finite row count')
    lines = stdout.decode('ascii')[:-1].split('\n')
    need(all(0 < len(line) + 1 <= LINE and '\r' not in line for line in lines), 'line framing')
    return [line.split(',') for line in lines]


def syscall(result, errno):
    r, e = signed(result), optional(errno, lambda v: signed(v, 32))
    need((r < 0) == (e is not None), 'syscall result/errno presence')
    return dict(result=r, errno=e)


def read_fields(cells, operation):
    need(len(cells) == 6, 'counter field count')
    if cells[0] == '0':
        need(cells[1:] == ['-'] * 5, 'absent counter encoding')
        return None
    need(cells[0] == '1' and uint(cells[1], 4) == operation, 'counter presence/operation')
    raw = syscall(cells[2], cells[3])
    length = uint(cells[4], 32)
    expected = (8 if operation == 0 and raw['result'] == 0 else
                min(raw['result'], 32) if operation == 2 and raw['result'] >= 0 else 0)
    need(length == expected, 'returned prefix length')
    return dict(operation=operation, **raw, data_len=length, data=hex_bytes(cells[5], 32))


def successful(raw):
    return raw is not None and raw['result'] == 0 and raw['errno'] is None


def words(raw):
    if raw is None or raw['operation'] != 2 or raw['result'] != 32 or raw['errno'] is not None or raw['data_len'] != 32:
        return None
    return tuple(int.from_bytes(raw['data'][i:i + 8], 'little') for i in range(0, 32, 8))


def event_id(raw):
    if raw is not None and raw['operation'] == 0 and successful(raw) and raw['data_len'] == 8:
        return int.from_bytes(raw['data'][:8], 'little')
    value = words(raw)
    return None if value is None else value[3]


def requested_attributes():
    raw = bytearray(128)
    raw[4:8] = (128).to_bytes(4, 'little')
    raw[8:16] = (1).to_bytes(8, 'little')
    raw[32:40] = (7).to_bytes(8, 'little')
    raw[40:48] = ((1 << 0) | (1 << 2) | (1 << 5) | (1 << 6) | (1 << 20)).to_bytes(8, 'little')
    return bytes(raw)


def acquisition(rows, at, ready):
    block = rows[at:at + 7]
    need(len(block) == 7 and len(block[0]) == 5 and block[0][0] == 'PMUOPEN', 'acquisition block')
    pid, tid = uint(block[0][1], U32), uint(block[0][2])
    need((pid, tid) == (ready['pid'], ready['worker_tid']), 'acquisition owner')
    opened = syscall(*block[0][3:])
    need(opened['result'] <= (1 << 31) - 1, 'fd range')
    attributes = []
    for kind in range(2):
        raw = b''
        for chunk, offset in enumerate((0, 64)):
            row = block[1 + kind * 2 + chunk]
            need(len(row) == 4 and row[:3] == ['PMUATTR', str(kind), str(offset)], 'whole attribute ordering')
            raw += hex_bytes(row[3], 64)
        attributes.append(raw)
    need(attributes[0] == requested_attributes(), 'exact requested event')
    controls = []
    for role, row in zip((0, 1), block[5:]):
        need(len(row) == 8 and row[:2] == ['PMUCTL', str(role)], 'acquisition control ordering')
        controls.append(read_fields(row[2:], role))
    need(all((c is not None) == (opened['result'] >= 0) for c in controls), 'acquisition control presence')
    return dict(pid=pid, tid=tid, open=opened, requested_attributes=attributes[0],
                attributes_after_open=attributes[1], id=controls[0], enable=controls[1]), at + 7


def endpoint(row, ordinal, side, opened):
    need(len(row) == 18 and row[:4] == ['PMU', str(ordinal), '0', str(side)], 'endpoint order/key')
    pid, tid = uint(row[4], U32), uint(row[5])
    before = dict(ticks=uint(row[6]), aux=uint(row[7], U32))
    after = dict(ticks=uint(row[8]), aux=uint(row[9], U32))
    owner = uint(row[10], 1)
    match = optional(row[11], lambda x: uint(x, 1))
    raw = read_fields(row[12:], 2)
    need(owner == int((pid, tid) == (opened['pid'], opened['tid'])), 'endpoint owner flag')
    need((raw is not None) == (bool(owner) and opened['open']['result'] >= 0), 'endpoint read presence')
    a, b = event_id(opened['id']), event_id(raw)
    expected = None if a is None or b is None else int(a == b)
    need(match == expected, 'event ID comparison flag')
    return dict(ordinal=ordinal, index=0, side=side, pid=pid, tid=tid, before=before,
                after=after, owner_matches=bool(owner), id_matches=match, read=raw)


def close_block(rows, at, opened):
    block = rows[at:at + 3]
    need(len(block) == 3 and len(block[0]) == 3 and block[0][0] == 'PMUCLOSE', 'close block')
    pid, tid = uint(block[0][1], U32), uint(block[0][2])
    controls = []
    for role, row in zip((3, 4), block[1:]):
        need(len(row) == 8 and row[:2] == ['PMUCTL', str(role)], 'close control order')
        controls.append(read_fields(row[2:], role))
    owned = (pid, tid) == (opened['pid'], opened['tid'])
    need(all((c is not None) == (owned and opened['open']['result'] >= 0) for c in controls), 'close custody')
    return dict(pid=pid, tid=tid, owner_matches=owned, disable=controls[0], close=controls[1]), at + 3


def arithmetic(start, end):
    a, b = words(start['read']), words(end['read'])
    issues = []
    for label, value in (('start', a), ('end', b)):
        if value is not None and value[2] > value[1]:
            issues.append(label + '_running_exceeds_enabled')
    if a is None or b is None:
        return dict(kind='missing', missing='both' if a is b is None else 'start' if a is None else 'end',
                    start=a, end=b, deltas=None, issues=issues)
    deltas = tuple(y - x if y >= x else None for x, y in zip(a[:3], b[:3]))
    for label, delta in zip(('value', 'enabled', 'running'), deltas):
        if delta is None:
            issues.append(label + '_regressed')
    value, enabled, running = deltas
    if running is not None and enabled is not None and running > enabled:
        issues.append('running_delta_exceeds_enabled')
    if running == 0 and value is not None and value > 0:
        issues.append('value_changed_without_running')
    kind = ('rejected' if issues else 'zero_running' if running == 0 else
            'full_running' if running == enabled else 'multiplexed')
    return dict(kind=kind, start=a, end=b, deltas=deltas, issues=issues)


def metric_reasons(opened, start, end, normal, count):
    reasons = []
    if opened['open']['result'] < 0:
        reasons.append('open_failed')
    if opened['requested_attributes'] != opened['attributes_after_open']:
        reasons.append('attributes_changed')
    if not successful(opened['id']):
        reasons.append('id_unavailable')
    if not successful(opened['enable']):
        reasons.append('enable_failed_or_absent')
    for label, e in (('start', start), ('end', end)):
        if not e['owner_matches']:
            reasons.append(label + '_owner_mismatch')
        if e['id_matches'] != 1:
            reasons.append(label + '_id_unresolved_or_mismatch')
        raw = e['read']
        if raw is None:
            reasons.append(label + '_read_absent')
        elif raw['result'] < 0:
            reasons.append(label + '_read_error')
        elif raw['result'] != 32:
            reasons.append(label + '_read_length')
        if e['before']['aux'] != e['after']['aux']:
            reasons.append(label + '_reader_aux_changed')
        if e['after']['ticks'] < e['before']['ticks']:
            reasons.append(label + '_reader_ticks_regressed')
    clocks = ((normal['start_ticks'], normal['start_aux']),
              (start['before']['ticks'], start['before']['aux']),
              (start['after']['ticks'], start['after']['aux']),
              (normal['end_ticks'], normal['end_aux']),
              (end['before']['ticks'], end['before']['aux']),
              (end['after']['ticks'], end['after']['aux']))
    if len({aux for _, aux in clocks}) != 1:
        reasons.append('interval_aux_changed')
    if any(b[0] < a[0] for a, b in zip(clocks, clocks[1:])):
        reasons.append('interval_ticks_regressed')
    if count['kind'] != 'full_running':
        reasons.append('counter_' + count['kind'])
    return reasons


def check(stdout, stderr, *, manifest_bytes, input_bytes, selected_bytes, truth_bytes,
          table, caller, body_bytes, abi, policy, cpus):
    """Return every joined row, or Refused retaining both exact original streams.

    table/caller/abi must be separately admitted against actual immutable ELF,
    caller instructions, ownership and execution premises. Body equality here is
    only one join and cannot create that authority. No campaign feeder exists.
    """
    try:
        return _check(stdout, stderr, manifest_bytes, input_bytes, selected_bytes, truth_bytes,
                      table, caller, body_bytes, abi, policy, cpus)
    except (AssertionError, ValueError, KeyError, TypeError, IndexError, UnicodeError) as error:
        raise Refused(str(error) or 'strict structural guard', stdout, stderr) from error


def _check(stdout, stderr, manifest_bytes, input_bytes, selected_bytes, truth_bytes,
           table, caller, body_bytes, abi, policy, cpus):
    manifest, originals, records, semantics = authority(manifest_bytes, input_bytes, selected_bytes,
        truth_bytes, table, caller, body_bytes, abi, policy, cpus)
    rows = framing(stdout, stderr, policy['epochs'])
    # Header/geometry stays byte-for-byte observed. The shared checker rechecks
    # every cell after the additional evidence families have been joined below.
    need(len(rows) >= 3 and rows[0][:2] == ['READY', VERSION] and rows[1][0] == 'LEAF'
         and rows[2] == ['RET', '0', '36'], 'initial selected header')
    need(len(rows[0]) == 19, 'READY width')
    ready = dict(pid=uint(rows[0][11], U32), worker_tid=uint(rows[0][13]))
    opened, at = acquisition(rows, 3, ready)
    base = rows[:3]
    arms, endpoints, closed = [], [], None
    published, armed, results = [], set(), 0
    while at < len(rows):
        row = rows[at]
        tag = row[0]
        if tag == 'ARM':
            need(closed is None and len(row) == 7, 'ARM shape/order')
            number, generation, due, started, completed, accepted = map(uint, row[1:])
            need(number == len(arms) + 1 <= policy['epochs'] and published and
                 generation == published[-1] and generation not in armed, 'ARM publication identity')
            need(len(published) == number and rows[at - 1][0] == 'HISTORY' and
                 rows[at - 1][3:] == ['published', str(generation)], 'ARM immediately follows publication')
            need(due == (number - 1) * policy['period_ms'] * 1000000 and
                 due <= started <= completed and (not arms or arms[-1]['completed_ns'] <= started), 'original ARM clock order')
            need(accepted == int(completed <= due + 2000000), 'ARM outcome mismatch')
            need(accepted == 1, 'original 2ms ARM deadline failed')
            arms.append(dict(number=number, generation=generation, due_ns=due,
                             started_ns=started, completed_ns=completed, accepted=bool(accepted)))
            armed.add(generation)
        elif tag == 'PMUCLOSE':
            need(closed is None and base[-1][0] == 'COVERAGE', 'close after complete coverage')
            closed, at = close_block(rows, at, opened)
            continue
        else:
            need(tag in shared.FIELDS or tag == 'RESULT', 'unknown/duplicate evidence tag')
            if closed is not None:
                need(tag in ('IO', 'DONE'), 'rows after close')
            if tag == 'HISTORY' and len(row) == 5 and row[3] == 'published':
                published.append(uint(row[4]))
            if tag == 'CALL':
                need(len(row) == 19 and (uint(row[5]) == 0 or uint(row[5]) in armed), 'call before arm observation')
            base.append(row)
            if tag == 'RESULT':
                results += 1
                need(results <= RECORDS and at + 2 < len(rows), 'full endpoint population')
                endpoints.append((endpoint(rows[at + 1], results, 0, opened),
                                  endpoint(rows[at + 2], results, 1, opened)))
                at += 2
        at += 1
    need(closed is not None and results == RECORDS and len(endpoints) == RECORDS and
         published == [a['generation'] for a in arms], 'complete evidence population')
    # Reuse the original validator on unchanged observed base row cells. No
    # version, period, result, history, identity or counter value is fabricated.
    base_bytes = ('\n'.join(','.join(row) for row in base) + '\n').encode('ascii')
    numeric = shared._check(base_bytes, stderr, records=records, table=table, caller=caller,
        k=policy['k'], epochs=policy['epochs'], outcome='eof', input_error='none', cpus=cpus,
        operations=(OPERATION,), version=VERSION, semantic_rows=semantics,
        command='normal-selected-accuracy-session', status='STRUCTURALLY_COMPLETE',
        accuracy_policy={k: policy[k] for k in ('k', 'period_ms', 'epochs')})
    need(numeric['totals']['epochs'] == len(arms), 'complete ARM denominator')
    joined = []
    for original, normal, scalar, (start, end) in zip(originals, numeric['rows']['CALL'],
                                                     numeric['rows']['RESULT'], endpoints):
        count = arithmetic(start, end)
        joined.append(dict(original=original, call=normal, result=scalar, start=start, end=end,
                           counter_arithmetic=count, hardware_status='UNRESOLVED',
                           observed_limitations=metric_reasons(opened, start, end, normal, count)))
    need(len(joined) == RECORDS, 'joined full denominator')
    close_limitations = []
    if not closed['owner_matches']:
        close_limitations.append('close_owner_mismatch')
    for role in ('disable', 'close'):
        if not successful(closed[role]):
            close_limitations.append(role + '_failed_or_absent')
    return dict(status='STRUCTURALLY_COMPLETE', raw=stdout, stderr=stderr, wire_rows=rows,
        manifest=manifest, policy=dict(policy), geometry=table, caller=caller, abi=abi,
        numeric=numeric, acquisition=opened, close=closed, arms=arms, calls=joined,
        totals=numeric['totals'], recorded_arm_deadlines_satisfied=True,
        session_limitations=close_limitations,
        hardware_status='UNRESOLVED', requested_phase_status='UNRESOLVED',
        metric_scope='Raw instrumented callback counter windows and all original-work truths; '
        'no scaling, body-only counts, perf attribution, calibrated clocks or accuracy verdict.',
        external_scope='Actual process/closure, whole ELF/caller authority, journals, source '
        'custody, physical returns, shutdown deadline and native full-state checks remain external.')
